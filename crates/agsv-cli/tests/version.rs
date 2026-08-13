use std::process::Command;

#[test]
fn reported_version_matches_cargo_package_version_without_ambient_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .env_clear()
        .arg("--version")
        .output()
        .expect("agsv --version should execute without inherited environment variables");

    assert!(
        output.status.success(),
        "agsv --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output should be UTF-8"),
        format!("agsv {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty(), "version output should use stdout");
}
