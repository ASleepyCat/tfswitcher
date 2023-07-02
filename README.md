# tfswitcher
[tfswitch](https://github.com/warrensbox/terraform-switcher/)-like program but written in Rust.

# Motivations
* Improved performance on WSL (if `$PATH` contains Windows directories)
* Better code quality
  * This is somewhat subjective, but I found debugging on `tfswitch` to be pretty cumbersome with all the `os.Exit()`s there are
* I wanted to try out Rust

# Caveats
This is not a pure Rust implementation, as it relies on [HashiCorp's `terraform-config-inspect`](https://github.com/hashicorp/terraform-config-inspect) library, which does not have a Rust equivalent. Raise an issue/submit a Pull Request if there is one! For now, we have to rely on some FFI without having to go through the effort of reimplementing it.

This is also not a complete reimplementation of `tfswitch`, as there are some missing flags that haven't been implemented. If you rely on these missing flags, raise an issue and I'll add it in.

This is also my first non-trivial Rust project; if there is a mistake I've made that doesn't conform to standard Rust coding practices, please raise an issue about it.

This has not been tested on Windows or macOS, so YMMV.