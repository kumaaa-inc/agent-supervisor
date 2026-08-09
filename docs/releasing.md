# Release process

Agent Supervisor uses [git-cliff](https://git-cliff.org/) for changelog updates
and [dist](https://opensource.axo.dev/cargo-dist/) for GitHub Release artifacts.
The committed `.github/workflows/release.yml` is generated from
`dist-workspace.toml` and must not be edited by hand.

## Prepare a release pull request

1. Choose a SemVer version and update the workspace version in `Cargo.toml`.
2. Update internal dependency versions in crate manifests when the workspace
   version changes.
3. Prepend the new release notes without replacing earlier curated entries:

   ```bash
   git-cliff --unreleased --tag vX.Y.Z --prepend CHANGELOG.md
   ```

4. Review the generated notes for user-facing accuracy and remove internal or
   duplicate history.
5. Regenerate and verify the release workflow:

   ```bash
   dist generate
   dist generate --check
   dist plan --tag vX.Y.Z
   ```

6. Run the repository quality gates documented in `CLAUDE.md`, then merge the
   release pull request only after CI is green.

## Publish

GitHub artifact attestations require a public repository on GitHub Free. Make
the repository public before publishing the first release.

From an up-to-date, clean `main` checkout, create and push an annotated tag:

```bash
git tag -a vX.Y.Z -m "Agent Supervisor vX.Y.Z"
git push origin vX.Y.Z
```

The tag starts the Release workflow. Do not create a second release manually.
Wait for every workflow job to pass, then verify that the GitHub Release has:

- archives for Apple Silicon and Intel macOS;
- `.sha256` files and the unified `sha256.sum`;
- `agsv-cli-installer.sh`;
- GitHub artifact attestations; and
- release notes matching `CHANGELOG.md`.

Finally, install through the published installer in a clean shell and run:

```bash
agsv --version
agsv --help
```
