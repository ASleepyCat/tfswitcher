use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use reqwest::blocking::{get, Response};
use std::{
    env::{self, consts},
    error::Error,
    fmt,
    fs::File,
    io::{copy, Cursor, BufReader},
    os::unix::prelude::PermissionsExt,
    path::PathBuf,
};
use zip::ZipArchive;

const PROGRAM_NAME: &str = "terraform";
const ARCHIVE_URL: &str = "https://releases.hashicorp.com/terraform";

#[derive(Clone, Debug)]
struct PathError;

impl Error for PathError {}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unable to find terraform directory")
    }
}

fn get_http(url: &str) -> Result<Response, Box<dyn Error>> {
    let response = get(url)?;
    match response.error_for_status_ref() {
        Ok(_) => return Ok(response),
        Err(e) => return Err(Box::new(e)),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let program_path = find_program_path(PROGRAM_NAME)?;

    let versions = get_terraform_versions(ARCHIVE_URL)?;

    let version = prompt_version_to_user(&versions)?;

    install_version(program_path, version)?;

    Ok(())
}

fn find_program_path(program_name: &str) -> Result<PathBuf, PathError> {
    if let Ok(path_var) = env::var("PATH") {
        let separator = if cfg!(windows) { ';' } else { ':' };

        for path in path_var.split(separator) {
            let program_path = PathBuf::from(path).join(program_name);
            if program_path.exists() {
                return Ok(program_path);
            }
        }
    }

    match home::home_dir() {
        Some(mut path) => {
            path.push(format!(".local/bin/{program_name}"));
            println!("could not locate {program_name}, installing to {path:?}\nmake sure to include the directory into your $PATH");
            Ok(path)
        }
        None => Err(PathError),
    }
}

fn get_terraform_versions(url: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut versions = vec![];

    let response = get_http(url)?;
    let contents = response.text()?;
    let lines: Vec<_> = contents.split('\n').collect();

    // From https://github.com/warrensbox/terraform-switcher/blob/d7dfd1b44605b095937e94b981d24305b858ff8c/lib/list_versions.go#L54
    let re = Regex::new(r#"\/(\d+\.\d+\.\d+)\/?""#)?;
    let trim_matches: &[_] = &['/', '"'];
    for text in lines {
        if let Some(capture) = re.captures(text) {
            if let Some(mat) = capture.get(0) {
                versions.push(mat.as_str().trim_matches(trim_matches).to_string());
            }
        }
    }

    Ok(versions)
}

fn prompt_version_to_user(versions: &Vec<String>) -> Result<&String, Box<dyn Error>> {
    println!("select a terraform version to install");
    let selection = Select::with_theme(&ColorfulTheme::default())
        .items(&versions)
        .default(0)
        .interact()?;

    Ok(&versions[selection])
}

fn install_version(program_path: PathBuf, version: &str) -> Result<(), Box<dyn Error>> {
    println!("{PROGRAM_NAME} {version} will be installed to {program_path:?}");

    let os = consts::OS;
    let arch = match consts::ARCH {
        "x86" => "386",
        "x86_64" => "amd64",
        _ => consts::ARCH,
    };

    let url = format!("{ARCHIVE_URL}/{version}/terraform_{version}_{os}_{arch}.zip");
    println!("downloading archive from {url}");

    let response = get_http(&url)?;
    extract_zip_archive_from_http_response(&program_path, response)?;

    Ok(())
}

fn extract_zip_archive_from_http_response(
    program_path: &PathBuf,
    mut response: Response,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = Vec::new();
    copy(&mut response, &mut buffer)?;

    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor)?;

    let mut file = archive.by_index(0)?;
    let file_name = file.name();
    println!("extracting {file_name} to {program_path:?}");

    // Create a new file for the extracted file and set rwxr-xr-x
    let mut outfile = File::create(program_path)?;
    let mut perms = outfile.metadata()?.permissions();
    perms.set_mode(0o755);
    outfile.set_permissions(perms)?;

    // Write the contents of the file to the output file
    copy(&mut file, &mut outfile)?;

    println!("extracted archive to {program_path:?}");
    Ok(())
}
