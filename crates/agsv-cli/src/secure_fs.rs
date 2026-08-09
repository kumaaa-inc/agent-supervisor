use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, flock, fsync, mkdirat, open, openat, renameat, unlinkat,
};
use serde_json::json;

use crate::output::CliError;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) struct SecureWorkspace {
    root: SecureDir,
}

pub(crate) struct SecureDir {
    fd: OwnedFd,
    display: PathBuf,
}

impl SecureWorkspace {
    pub(crate) fn open(root: &Path) -> Result<Self, CliError> {
        let canonical = fs::canonicalize(root)
            .map_err(|error| CliError::io("canonicalize workspace", root, &error))?;
        let fd = open(&canonical, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|error| path_error("open workspace directory", &canonical, error))?;
        Ok(Self {
            root: SecureDir {
                fd,
                display: canonical,
            },
        })
    }

    pub(crate) const fn root(&self) -> &SecureDir {
        &self.root
    }

    pub(crate) fn display(&self) -> &Path {
        &self.root.display
    }

    pub(crate) fn open_regular_relative(&self, relative: &Path) -> Result<File, CliError> {
        let components = relative_components(relative)?;
        let (file_name, directory_components) = components
            .split_last()
            .ok_or_else(|| invalid_relative_path(relative))?;
        let mut current = self.root.reopen()?;
        for component in directory_components {
            current = current.open_dir(component)?;
        }
        current.open_regular(file_name)
    }

    pub(crate) fn check_directory_relative(&self, relative: &Path) -> Result<bool, CliError> {
        let components = relative_components(relative)?;
        let mut current = self.root.reopen()?;
        for component in components {
            let Some(next) = current.open_dir_optional(component)? else {
                return Ok(false);
            };
            current = next;
        }
        Ok(true)
    }
}

impl SecureDir {
    pub(crate) fn ensure_dir(&self, name: &str) -> Result<Self, CliError> {
        validate_name(name)?;
        match mkdirat(&self.fd, name, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => self.open_dir(OsStr::new(name)),
            Err(error) => Err(path_error(
                "create managed directory",
                &self.child(name),
                error,
            )),
        }
    }

    pub(crate) fn open_dir_optional(
        &self,
        name: impl AsRef<OsStr>,
    ) -> Result<Option<Self>, CliError> {
        let name = name.as_ref();
        validate_component(name)?;
        match openat(&self.fd, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(Some(Self {
                fd,
                display: self.display.join(name),
            })),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(path_error(
                "open managed directory",
                &self.display.join(name),
                error,
            )),
        }
    }

    pub(crate) fn open_regular_optional(&self, name: &str) -> Result<Option<File>, CliError> {
        validate_name(name)?;
        match openat(&self.fd, name, READ_FILE_FLAGS, Mode::empty()) {
            Ok(fd) => {
                let file = File::from(fd);
                ensure_regular(&file, &self.child(name))?;
                Ok(Some(file))
            }
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(path_error("open managed file", &self.child(name), error)),
        }
    }

    pub(crate) fn open_regular(&self, name: &OsStr) -> Result<File, CliError> {
        validate_component(name)?;
        let display = self.display.join(name);
        let fd = openat(&self.fd, name, READ_FILE_FLAGS, Mode::empty())
            .map_err(|error| path_error("open managed file", &display, error))?;
        let file = File::from(fd);
        ensure_regular(&file, &display)?;
        Ok(file)
    }

    pub(crate) fn create_regular_if_missing(
        &self,
        name: &str,
        contents: &str,
    ) -> Result<bool, CliError> {
        validate_name(name)?;
        let display = self.child(name);
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(&self.fd, name, flags, Mode::from_raw_mode(0o666)) {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(contents.as_bytes())
                    .map_err(|error| CliError::io("write", &display, &error))?;
                file.sync_all()
                    .map_err(|error| CliError::io("sync", &display, &error))?;
                Ok(true)
            }
            Err(rustix::io::Errno::EXIST) => {
                self.open_regular(OsStr::new(name))?;
                Ok(false)
            }
            Err(error) => Err(path_error("create managed file", &display, error)),
        }
    }

    pub(crate) fn lock_file(&self, name: &str) -> Result<File, CliError> {
        validate_name(name)?;
        let display = self.child(name);
        let create_flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let open_flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = None;
        for _ in 0..16 {
            match openat(&self.fd, name, create_flags, Mode::from_raw_mode(0o600)) {
                Ok(created) => {
                    fd = Some(created);
                    break;
                }
                Err(rustix::io::Errno::EXIST) => {
                    match openat(&self.fd, name, open_flags, Mode::empty()) {
                        Ok(existing) => {
                            fd = Some(existing);
                            break;
                        }
                        Err(rustix::io::Errno::NOENT) => std::thread::yield_now(),
                        Err(error) => {
                            return Err(path_error("open initialization lock", &display, error));
                        }
                    }
                }
                Err(rustix::io::Errno::NOENT) => std::thread::yield_now(),
                Err(error) => {
                    return Err(path_error("create initialization lock", &display, error));
                }
            }
        }
        let fd = fd.ok_or_else(|| {
            CliError::unsafe_path(
                format!(
                    "initialization lock did not stabilize: {}",
                    display.display()
                ),
                json!({ "path": display }),
            )
        })?;
        let file = File::from(fd);
        ensure_regular(&file, &display)?;
        flock(&file, FlockOperation::LockExclusive)
            .map_err(|error| path_error("lock initialization", &display, error))?;
        Ok(file)
    }

    pub(crate) fn update_ignore(
        &self,
        name: &str,
        required_entries: &[&'static str],
    ) -> Result<Vec<&'static str>, CliError> {
        validate_name(name)?;
        let display = self.child(name);
        let (mut existing, mode) = match self.open_regular_optional(name)? {
            Some(mut file) => {
                let mode = file
                    .metadata()
                    .map_err(|error| CliError::io("inspect", &display, &error))?
                    .permissions()
                    .mode();
                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .map_err(|error| CliError::io("read", &display, &error))?;
                (contents, mode)
            }
            None => (String::new(), 0o666),
        };
        let missing = required_entries
            .iter()
            .copied()
            .filter(|entry| {
                !existing
                    .lines()
                    .any(|line| line.trim_end_matches('\r') == *entry)
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(missing);
        }

        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        for entry in &missing {
            existing.push_str(entry);
            existing.push('\n');
        }

        self.atomic_replace(name, existing.as_bytes(), mode)?;
        Ok(missing)
    }

    fn open_dir(&self, name: &OsStr) -> Result<Self, CliError> {
        validate_component(name)?;
        let display = self.display.join(name);
        let fd = openat(&self.fd, name, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|error| path_error("open managed directory", &display, error))?;
        Ok(Self { fd, display })
    }

    fn reopen(&self) -> Result<Self, CliError> {
        let fd = openat(&self.fd, ".", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|error| path_error("reopen managed directory", &self.display, error))?;
        Ok(Self {
            fd,
            display: self.display.clone(),
        })
    }

    fn atomic_replace(&self, name: &str, contents: &[u8], mode: u32) -> Result<(), CliError> {
        let serial = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".agsv-{name}.tmp.{}.{serial}", std::process::id());
        let temporary_display = self.child(&temporary);
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = openat(
            &self.fd,
            temporary.as_str(),
            flags,
            Mode::from_raw_mode(
                (mode & 0o7777)
                    .try_into()
                    .expect("permission bits fit the platform mode type"),
            ),
        )
        .map_err(|error| path_error("create temporary file", &temporary_display, error))?;
        let mut file = File::from(fd);
        let write_result = file
            .write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|error| CliError::io("write atomic replacement", &temporary_display, &error));
        if let Err(error) = write_result {
            let _ = unlinkat(&self.fd, temporary.as_str(), AtFlags::empty());
            return Err(error);
        }
        drop(file);

        if let Err(error) = renameat(&self.fd, temporary.as_str(), &self.fd, name) {
            let _ = unlinkat(&self.fd, temporary.as_str(), AtFlags::empty());
            return Err(path_error("replace managed file", &self.child(name), error));
        }
        fsync(&self.fd)
            .map_err(|error| path_error("sync managed directory", &self.display, error))?;
        Ok(())
    }

    fn child(&self, name: &str) -> PathBuf {
        self.display.join(name)
    }
}

fn ensure_regular(file: &File, path: &Path) -> Result<(), CliError> {
    let metadata = file
        .metadata()
        .map_err(|error| CliError::io("inspect", path, &error))?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(CliError::unsafe_path(
            format!("managed path is not a regular file: {}", path.display()),
            json!({ "path": path, "expected": "regular_file" }),
        ))
    }
}

fn relative_components(path: &Path) -> Result<Vec<&OsStr>, CliError> {
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => result.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::ParentDir
            | Component::CurDir => {
                return Err(invalid_relative_path(path));
            }
        }
    }
    if result.is_empty() {
        Err(invalid_relative_path(path))
    } else {
        Ok(result)
    }
}

fn validate_name(name: &str) -> Result<(), CliError> {
    validate_component(OsStr::new(name))
}

fn validate_component(name: &OsStr) -> Result<(), CliError> {
    let path = Path::new(name);
    if matches!(
        path.components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ) {
        Ok(())
    } else {
        Err(invalid_relative_path(path))
    }
}

fn invalid_relative_path(path: &Path) -> CliError {
    CliError::unsafe_path(
        format!(
            "managed path must be non-empty, workspace-relative, and contain no `.` or `..`: {}",
            path.display()
        ),
        json!({ "path": path }),
    )
}

fn path_error(action: &'static str, path: &Path, error: rustix::io::Errno) -> CliError {
    let io_error = std::io::Error::from(error);
    CliError::unsafe_path(
        format!("could not {action} {}: {io_error}", path.display()),
        json!({ "action": action, "path": path, "os_error": io_error.to_string() }),
    )
}
