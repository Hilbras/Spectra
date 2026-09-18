# Release Process

## Spectra v0.1.0 Release Checklist

### Pre-Release

- [ ] All tests pass: `cargo test --workspace`
- [ ] Clippy clean: `cargo clippy --workspace -- -D warnings`
- [ ] Rustfmt clean: `cargo fmt --all -- --check`
- [ ] Cargo audit clean: `cargo audit`
- [ ] Documentation complete
- [ ] CHANGELOG updated
- [ ] Version synchronized across all crates

### Release

- [ ] Create release branch: `git checkout -b release/v0.1.0`
- [ ] Final test run
- [ ] Create git tag: `git tag -a v0.1.0 -m "Spectra v0.1.0"`
- [ ] Push tag: `git push origin v0.1.0`
- [ ] Create GitHub Release with notes
- [ ] Build release artifacts
- [ ] Upload artifacts to GitHub Release

### Post-Release

- [ ] Verify clean clone build
- [ ] Verify npm package (if applicable)
- [ ] Announce release
- [ ] Merge to main branch

## Version Sources

All must report `0.1.0`:

| Source | Location |
|--------|----------|
| Workspace | `Cargo.toml` `[workspace.package] version` |
| All crates | `version.workspace = true` |
| CLI | `spectra --version` |
| API | Health check response |
| npm | `package.json` version |
| Git tag | `v0.1.0` |
| GitHub Release | `Spectra v0.1.0` |

## Release Artifacts

Build for supported platforms:

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Linux aarch64
cargo build --release --target aarch64-unknown-linux-gnu

# macOS x86_64
cargo build --release --target x86_64-apple-darwin

# macOS aarch64
cargo build --release --target aarch64-apple-darwin

# Windows x86_64
cargo build --release --target x86_64-pc-windows-msvc
```

Generate checksums:

```bash
sha256sum spectra-* > checksums.txt
```

## GitHub Release Notes Template

```markdown
# Spectra v0.1.0

## What's New

- [Feature 1]
- [Feature 2]

## Installation

### From Source

\```bash
git clone https://github.com/spectra/spectra.git
cd spectra
cargo build --release
\```

### Binary Download

Download the appropriate binary for your platform from the assets below.

## Architecture

[Link to ARCHITECTURE.md]

## Known Limitations

- [Limitation 1]
- [Limitation 2]

## Security

See SECURITY.md for reporting vulnerabilities.

## License

MIT
```

## npm Publishing (Future)

```bash
cd packages/sdk
npm install
npm run build
npm pack --dry-run
npm publish
```

## Rollback Plan

If a critical issue is found after release:

1. Yank the npm package (if applicable)
2. Mark GitHub Release as pre-release
3. Create hotfix branch
4. Release v0.1.1 with fix
5. Update CHANGELOG
