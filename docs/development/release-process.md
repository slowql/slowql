# Release Process

## Versioning

SlowQL follows semantic versioning (`MAJOR.MINOR.PATCH`):

- **MAJOR**: Breaking CLI or API changes
- **MINOR**: New rules, new dialect support, backward-compatible features
- **PATCH**: Bug fixes, false positive corrections, performance improvements

## Pre-release Checklist

```bash
# Run full test suite
cargo test

# Format
cargo fmt --all

# Build release
cargo build --release

# Verify version
./target/release/slowql --version
```
## Version Bump
Update version in `Cargo.toml`:
``` TOML
[package]
version = "2.1.0"
```
## Changelog
Update `CHANGELOG.md` with the new version entry before tagging.

## Tagging
``` Bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "release: v2.1.0"
git tag v2.1.0
git push origin main --tags
```

## GitHub Release
1. Go to Releases on Github
2. Create a release from the tag
3. Paste the CHANGELOG entry for this version
4. Attach pre-built bonaries if available

## Binary Distribution
The CI pipeline builds binaries for:
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Docker
After tagging, the CI pipeline builds and pushes:
- `ghcr.io/slowql/slowql:latest`
- `ghcr.io/slowql/slowql:v2.1.0`\

## Install from Cargo
``` Bash
cargo install slowql
```

