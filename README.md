# tfswitcher

Terraform and OpenTofu version switcher written in Rust.

## Installation

### Homebrew

To install via Homebrew, run:

```bash
brew install asleepycat/tap/tfswitcher
```

This will build from source.

### Cargo

To install with `cargo`, run:

```bash
cargo install tfswitcher
```

There are also prebuilt binaries available with each release for Linux, macOS and Windows.

## Usage

To see available flags and arguments, run `tfswitcher -h` or `tfswitcher --help`.

You can also use a configuration file to automatically set certain flags or arguments. Simply place a file called `.tfswitch.toml` either in your current working directory or in your `$HOME` directory.

```toml
bin = "$HOME/.local/bin/terraform"
list_all = false
opentofu = false
force_remove = false
verbose = false
version = "1.0.0"
```

## Shell Completions

`tfswitcher` can generate tab-completion scripts for your desired shell. To see which shells are supported, see the `--help` text.

For example, for Bash:

```bash
tfswitcher -c bash >> ~/.local/share/bash-completion/completions/tfswitcher
```

Alternatively, you can source the tab-completion script inside your shell's start up script:

```bash
echo "source <(tfswitcher -c bash)" >> ~/.bashrc
```

## Caveats

This has not been tested on Windows or macOS, so YMMV.

## Where's `v0.1.0`?

`v0.1.0` used FFI with Cgo in order to use HashiCorp's [`terraform-config-inspect`](https://github.com/hashicorp/terraform-config-inspect) library.
This was inadvertently published as the Windows and macOS builds were broken and is yanked.

`v0.2.0` replaced the Go library with a partially-reimplemented Rust library to eliminate FFI and makes building for Windows and macOS a lot less painful.
