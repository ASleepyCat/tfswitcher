use std::{env::set_current_dir, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    set_current_dir("src/go")?;
    gobuild::Build::new()
        .file("./main.go")
        .compile("get_version_from_module");

    Ok(())
}
