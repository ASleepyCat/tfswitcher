mod ffi;

use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use reqwest::blocking::{get, Response};
use semver::{Version, VersionReq};
use std::{
    env::{self, consts},
    error::Error,
    fs::{File, self},
    io::{copy, Cursor},
    os::unix::prelude::PermissionsExt,
    path::PathBuf,
    str::FromStr,
};
use zip::ZipArchive;

const ARCHIVE_URL: &str = "https://releases.hashicorp.com/terraform";
const DEFAULT_LOCATION: &str = ".local/bin";
const PROGRAM_NAME: &str = "terraform";

#[derive(Parser, Debug)]
struct Args {
    /// Include pre-release versions
    #[arg(short, long = "list-all", default_value_t = false)]
    list_all: bool,

    #[arg(short = 'i', long = "install", env = "TF_VERSION")]
    version: Option<String>,
}

fn find_program_path(program_name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = env::var("PATH") {
        let separator = if cfg!(windows) { ';' } else { ':' };

        for path in path_var.split(separator) {
            let program_path = PathBuf::from(path).join(program_name);
            if program_path.exists() {
                return Some(program_path);
            }
        }
    }

    None
}

fn get_http(url: &str) -> Result<Response, Box<dyn Error>> {
    let response = get(url)?;
    match response.error_for_status_ref() {
        Ok(_) => Ok(response),
        Err(e) => Err(Box::new(e)),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let Some(program_path) = find_terraform_program_path() else {
        panic!("could not find path to install terraform");
    };

    let version = get_version_to_install(args)?;

    install_version(program_path, &version)?;

    Ok(())
}

fn find_terraform_program_path() -> Option<PathBuf> {
    if let Some(path) = find_program_path(PROGRAM_NAME) {
        return Some(path);
    }

    match home::home_dir() {
        Some(mut path) => {
            path.push(format!("{DEFAULT_LOCATION}/{PROGRAM_NAME}"));
            println!("could not locate {PROGRAM_NAME}, installing to {path:?}\nmake sure to include the directory into your $PATH");
            Some(path)
        }
        None => None,
    }
}

fn get_version_to_install(args: Args) -> Result<String, Box<dyn Error>> {
    if let Some(version) = args.version {
        return Ok(version);
    }

    let versions = get_terraform_versions(args, ARCHIVE_URL)?;

    if let Some(version_from_module) = get_version_from_module(&versions)? {
        return Ok(version_from_module);
    }

    get_version_from_user_prompt(&versions)
}

fn get_terraform_versions(args: Args, url: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut versions = vec![];

    let response = get_http(url)?;
    let contents = response.text()?;
    let lines: Vec<_> = contents.split('\n').collect();

    // From https://github.com/warrensbox/terraform-switcher/blob/d7dfd1b44605b095937e94b981d24305b858ff8c/lib/list_versions.go#L28-L35
    let re = if args.list_all {
        Regex::new(r#"/(\d+\.\d+\.\d+)(-[a-zA-z]+\d*)?/?""#).expect("Invalid regex")
    } else {
        Regex::new(r#"/(\d+\.\d+\.\d+)/?""#).expect("Invalid regex")
    };
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

fn get_version_from_module(versions: &Vec<String>) -> Result<Option<String>, Box<dyn Error>> {
    let version_constraint = match ffi::get_version_from_module() {
        Some(constraint) => constraint,
        None => return Ok(None),
    };

    println!("module constraint is {version_constraint}");

    let req = VersionReq::parse(&version_constraint)?;
    for version in versions {
        let v = Version::from_str(version)?;
        if req.matches(&v) {
            return Ok(Some(version.to_owned()));
        }
    }

    Ok(None)
}

fn get_version_from_user_prompt(versions: &[String]) -> Result<String, Box<dyn Error>> {
    let version = prompt_version_to_user(versions)?;

    Ok(version.to_owned())
}

fn prompt_version_to_user(versions: &[String]) -> Result<&String, Box<dyn Error>> {
    println!("select a terraform version to install");
    let selection = Select::with_theme(&ColorfulTheme::default())
        .items(versions)
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

    let archive = get_terraform_version_zip(version, os, arch)?;
    extract_zip_archive(&program_path, archive)
}

fn get_terraform_version_zip(version: &str, os: &str, arch: &str) -> Result<ZipArchive<Cursor<Vec<u8>>>, Box<dyn Error>> {
    let zip_name = format!("terraform_{version}_{os}_{arch}.zip");

    if let Some(path) = home::home_dir().as_mut() {
        path.push(format!("{DEFAULT_LOCATION}/{zip_name}"));

        if path.exists() {
            println!("using cached archive at {path:?}");
            let buffer = fs::read(path)?;
            let cursor = Cursor::new(buffer);
            let archive = ZipArchive::new(cursor)?;
            return Ok(archive);
        }
    }

    download_and_save_terraform_version_zip(version, &zip_name)
}

fn download_and_save_terraform_version_zip(version: &str, zip_name: &str) -> Result<ZipArchive<Cursor<Vec<u8>>>, Box<dyn Error>> {
    let url = format!("{ARCHIVE_URL}/{version}/{zip_name}");
    println!("downloading archive from {url}");

    let response = get_http(&url)?;
    let buffer = response.bytes()?.to_vec();

    match home::home_dir() {
        Some(mut path) => {
            path.push(format!("{DEFAULT_LOCATION}/{zip_name}"));
            fs::write(path, &buffer)?;
        }
        None => println!("unable to cache archive")
    }

    let cursor = Cursor::new(buffer);
    Ok(ZipArchive::new(cursor)?)
}

fn extract_zip_archive(
    program_path: &PathBuf,
    mut archive: ZipArchive<Cursor<Vec<u8>>>,
) -> Result<(), Box<dyn Error>> {
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
