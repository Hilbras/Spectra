# Release Process

## v0.1.0 Release Checklist

### Pre-Release

- [x] All tests pass: `cargo test --workspace` (387+ tests)
- [x] Clippy clean: `cargo clippy --workspace -- -D warnings`
- [x] Rustfmt clean: `cargo fmt --all -- --check`
- [x] Documentation complete
- [x] CHANGELOG updated
- [x] Version synchronized: all crates report `0.1.0`

### Release

- [x] Git tag: `v0.1.0`
- [x] Push tag: `git push origin v0.1.0`
- [x] GitHub repository: `https://github.com/Hilbras/Spectra`

### npm Publishing

- [x] Package name: `@hilbras/spectra`
- [x] Version: `0.1.0`
- [x] Published to npm registry

### Post-Release

- [ ] GitHub Release with notes (create via GitHub UI)
- [ ] Build release artifacts (see below)
- [ ] Verify clean clone build
- [ ] Announce release

## Version Sources

All must report `0.1.0`:

| Source | Location |
|--------|----------|
| Workspace | `Cargo.toml` `[workspace.package] version` |
| All crates | `version.workspace = true` |
| CLI | `spectra --version` |
| API | Health check response |
| npm | `npm/package.json` version |
| Git tag | `v0.1.0` |

## Building Release Artifacts

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Linux aarch64
cargo build --release --target aarch64-unknown-linux-gnu

# macOS x86_64
cargo build --release --target x86_64-apple-darwin

# macOS aarch64
cargo build --release --target aarch64-apple-darwin
```

Generate checksums:
```bash
sha256sum spectra-* > checksums.txt
```

## GitHub Release Notes Template

```markdown
# Spectra v0.1.0

## What's New

- 21-crate Rust workspace
- Target management with scope enforcement
- Web crawler with robots.txt support
- 60+ technology fingerprinting rules
- SQL injection, XSS, and directory search scanners
- Evidence engine with redaction and integrity
- Observation model with 13 types
- Detection engine with AND/OR logic
- Verification with confidence scoring
- Plugin system with sandbox
- 387+ tests, no unsafe code

## Installation

### npm
```bash
npm install -g @hilbras/spectra
```

### From Source
```bash
git clone https://github.com/Hilbras/Spectra.git
cd Spectra
cargo build --release
```

## Known Limitations

- No built-in API authentication
- PostgreSQL storage not yet wired (in-memory only)
- No Redis-backed scheduler
- No WASM/Python plugin sandboxing

## Security

See SECURITY.md for vulnerability reporting.

## License

AGPL-3.0
```

## npm Publishing

```bash
cd npm
npm publish --access public
```

## Rollback Plan

If a critical issue is found after release:

1. Mark GitHub Release as pre-release
2. Create hotfix branch: `git checkout -b hotfix/v0.1.1`
3. Release v0.1.1 with fix
4. Update CHANGELOG
5. Publish npm update: `npm version patch && npm publish --access public`
