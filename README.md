# tfswitcher
[`tfswitch`](https://github.com/warrensbox/terraform-switcher/)-like program but written in Rust.

# Installation
To install, simply run `cargo install tfswitcher`. There are also prebuilt binaries available with each release for Linux, macOS and Windows.

# Motivations
* Improved performance on WSL (if `$PATH` contains Windows directories)
* Better code quality
  * This is somewhat subjective, but I found debugging on `tfswitch` to be pretty cumbersome with all the `os.Exit()`s there are
* I wanted to try out Rust

# Caveats
This is not a complete reimplementation of `tfswitch`, as there are some missing flags that haven't been implemented. If you rely on these missing flags, raise an issue and I'll add it in.

This is also my first non-trivial public Rust project; if there is a mistake I've made that doesn't conform to standard Rust coding practices, please raise an issue about it.

This has not been tested on Windows or macOS, so YMMV.

# Where's `v0.1.0`?
`v0.1.0` used FFI with Cgo in order to use HashiCorp's [`terraform-config-inspect`](https://github.com/hashicorp/terraform-config-inspect) library.
This was inadvertently published as the Windows and macOS builds were broken and is yanked.

`v0.2.0` replaced the Go library with a partially-reimplemented Rust library to eliminate FFI and makes building for Windows and macOS a lot less painful.
