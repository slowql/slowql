# Installation

## From Source (Recommended)

Requires the [Rust toolchain](https://rustup.rs/).

```bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo install --path .
```
This installs the `slowql` binary to `~/.cargo/bin`.

## Docker
``` Bash
docker run --rm -v $(pwd):/src ghcr.io/slowql/slowql /src
```

## Verify Installation

``` Bash
slowql --version
# slowql 2.0.0
```
