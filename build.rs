use std::{error::Error, env::set_current_dir, fs::create_dir_all, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    create_dir_all("src/go/out")?;
    let out = PathBuf::from("src/go/out").canonicalize()?;

    set_current_dir("src/go")?;
    gobuild::Build::new()
        .file("./main.go")
        .out_dir(out)
        .compile("get_version_from_module");

    Ok(())
}
