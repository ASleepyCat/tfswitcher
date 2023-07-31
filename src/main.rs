use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use reqwest::blocking::Response;
use semver::{Version, VersionReq};
use std::{
    env::consts,
    error::Error,
    fs::{self, File},
    io::{self, Cursor},
    path::{Path, PathBuf},
    str::FromStr,
};
use zip::ZipArchive;

#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;

const ARCHIVE_URL: &str = "https://releases.hashicorp.com/terraform";
const DEFAULT_LOCATION: &str = ".local/bin";
const DEFAULT_CACHE_LOCATION: &str = ".cache/tfswitcher";
const PROGRAM_NAME: &str = "terraform";

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Include pre-release versions
    #[arg(short, long = "list-all", default_value_t = false)]
    list_all: bool,

    #[arg(long = "install", env = "TF_VERSION")]
    install_version: Option<String>,
}

fn get_http(url: &str) -> Result<Response, Box<dyn Error>> {
    let response = reqwest::blocking::get(url)?;
    match response.error_for_status_ref() {
        Ok(_) => Ok(response),
        Err(e) => Err(Box::new(e)),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let Some(program_path) = find_terraform_program_path() else {
        println!("Could not find path to install Terraform");
        return Ok(());
    };

    if let Some(version) = get_version_to_install(args)? {
        install_version(&program_path, &version)?;
    } else {
        println!("No version to install");
    }

    Ok(())
}

fn find_terraform_program_path() -> Option<PathBuf> {
    if let Some(path) = pathsearch::find_executable_in_path(PROGRAM_NAME) {
        return Some(path);
    }

    match home::home_dir() {
        Some(mut path) => {
            path.push(format!("{DEFAULT_LOCATION}/{PROGRAM_NAME}"));
            println!("Could not locate {PROGRAM_NAME}, installing to {path:?}\nMake sure to include the directory in your $PATH environment variable");
            Some(path)
        }
        None => None,
    }
}

fn get_version_to_install(args: Args) -> Result<Option<String>, Box<dyn Error>> {
    if let Some(version) = args.install_version {
        return Ok(Some(version));
    }

    let versions = get_terraform_versions(args, ARCHIVE_URL)?;

    if let Some(version_from_module) = get_version_from_module(&versions)? {
        return Ok(Some(version_from_module));
    }

    get_version_from_user_prompt(&versions)
}

fn get_terraform_versions(args: Args, url: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let response = get_http(url)?;
    let contents = response.text()?;

    let versions = capture_terraform_versions(args, &contents);

    Ok(versions)
}

fn capture_terraform_versions(args: Args, contents: &str) -> Vec<String> {
    let mut versions = vec![];

    let lines: Vec<_> = contents.split('\n').collect();
    // From https://github.com/warrensbox/terraform-switcher/blob/d7dfd1b44605b095937e94b981d24305b858ff8c/lib/list_versions.go#L28-L35
    let re = if args.list_all {
        Regex::new(r#"/(\d+\.\d+\.\d+)(?:-[a-zA-Z0-9-]+)?/?""#).expect("Invalid regex")
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

    versions
}

fn get_version_from_module(versions: &[String]) -> Result<Option<String>, Box<dyn Error>> {
    let module = tfconfig::load_module(Path::new("."), false)?;
    let version_constraint = match module.required_core.first() {
        Some(version) => version,
        None => return Ok(None),
    };

    println!("Module constraint is {version_constraint}");

    let req = VersionReq::parse(version_constraint)?;
    for version in versions {
        let v = Version::from_str(version)?;
        if req.matches(&v) {
            return Ok(Some(version.to_owned()));
        }
    }

    Ok(None)
}

fn get_version_from_user_prompt(versions: &[String]) -> Result<Option<String>, Box<dyn Error>> {
    println!("Select a terraform version to install");
    match Select::with_theme(&ColorfulTheme::default())
        .items(versions)
        .default(0)
        .interact_opt()?
    {
        Some(selection) => Ok(Some(versions[selection].to_owned())),
        None => Ok(None),
    }
}

fn install_version(program_path: &Path, version: &str) -> Result<(), Box<dyn Error>> {
    println!("Terraform {version} will be installed to {program_path:?}");

    let os = consts::OS;
    let arch = get_arch(consts::ARCH);

    let archive = get_terraform_version_zip(version, os, arch)?;
    extract_zip_archive(program_path, archive)
}

fn get_arch(arch: &str) -> &str {
    match arch {
        "x86" => "386",
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => arch,
    }
}

fn get_terraform_version_zip(
    version: &str,
    os: &str,
    arch: &str,
) -> Result<ZipArchive<Cursor<Vec<u8>>>, Box<dyn Error>> {
    let zip_name = format!("terraform_{version}_{os}_{arch}.zip");

    if let Some(path) = home::home_dir().as_mut() {
        path.push(format!("{DEFAULT_CACHE_LOCATION}/{zip_name}"));

        if path.exists() {
            println!("Using cached archive at {path:?}");
            let buffer = fs::read(path)?;
            let cursor = Cursor::new(buffer);
            let archive = ZipArchive::new(cursor)?;
            return Ok(archive);
        }
    }

    download_and_save_terraform_version_zip(version, &zip_name)
}

fn download_and_save_terraform_version_zip(
    version: &str,
    zip_name: &str,
) -> Result<ZipArchive<Cursor<Vec<u8>>>, Box<dyn Error>> {
    let url = format!("{ARCHIVE_URL}/{version}/{zip_name}");
    println!("Downloading archive from {url}");

    let response = get_http(&url)?;
    let buffer = response.bytes()?.to_vec();

    match home::home_dir() {
        Some(mut path) => {
            path.push(DEFAULT_CACHE_LOCATION);
            println!("Caching archive to {path:?}");
            if let Err(e) = cache_zip_file(&mut path, zip_name, &buffer) {
                println!("Unable to cache archive: {e}");
            };
        }
        None => println!("Unable to cache archive: could not find home directory"),
    }

    let cursor = Cursor::new(buffer);
    Ok(ZipArchive::new(cursor)?)
}

fn cache_zip_file(
    cache_location: &mut PathBuf,
    zip_name: &str,
    buffer: &[u8],
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&cache_location)?;
    cache_location.push(zip_name);
    fs::write(cache_location, buffer)?;

    Ok(())
}

fn extract_zip_archive(
    program_path: &Path,
    mut archive: ZipArchive<Cursor<Vec<u8>>>,
) -> Result<(), Box<dyn Error>> {
    let mut file = archive.by_index(0)?;
    let file_name = file.name();
    println!("Extracting {file_name} to {program_path:?}");

    // Create a new file for the extracted file and set rwxr-xr-x
    let mut outfile = create_output_file(program_path)?;

    // Write the contents of the file to the output file
    io::copy(&mut file, &mut outfile)?;

    println!("Extracted archive to {program_path:?}");
    Ok(())
}

#[cfg(unix)]
fn create_output_file(program_path: &Path) -> Result<File, Box<dyn Error>> {
    let file = File::create(program_path)?;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms)?;

    Ok(file)
}

#[cfg(windows)]
fn create_output_file(program_path: &Path) -> Result<File, Box<dyn Error>> {
    Ok(File::create(program_path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, io::Write, path::Path};
    use tempdir::TempDir;

    const LINES: &str = r#"<html><head>
        <title>Terraform Versions | HashiCorp Releases</title>

    </head>
    <body>
        <ul>
            <li>
            <a href="../">../</a>
            </li>
            <li>
            <a href="/terraform/1.3.0/">terraform_1.3.0</a>
            </li>
            <li>
            <a href="/terraform/1.3.0-rc1/">terraform_1.3.0-rc1</a>
            </li>
            <li>
            <a href="/terraform/1.3.0-beta1/">terraform_1.3.0-beta1</a>
            </li>
            <li>
            <a href="/terraform/1.3.0-alpha20220608/">terraform_1.3.0-alpha20220608</a>
            </li>
            <li>
            <a href="/terraform/1.2.0/">terraform_1.2.0</a>
            </li>
            <li>
            <a href="/terraform/1.2.0-rc1/">terraform_1.2.0-rc1</a>
            </li>
            <li>
            <a href="/terraform/1.2.0-beta1/">terraform_1.2.0-beta1</a>
            </li>
            <li>
            <a href="/terraform/1.2.0-alpha20220413/">terraform_1.2.0-alpha20220413</a>
            </li>
            <li>
            <a href="/terraform/1.2.0-alpha-20220328/">terraform_1.2.0-alpha-20220328</a>
            </li>
            <li>
            <a href="/terraform/1.1.0/">terraform_1.1.0</a>
            </li>
            <li>
            <a href="/terraform/1.1.0-rc1/">terraform_1.1.0-rc1</a>
            </li>
            <li>
            <a href="/terraform/1.1.0-beta1/">terraform_1.1.0-beta1</a>
            </li>
            <li>
            <a href="/terraform/1.1.0-alpha20211029/">terraform_1.1.0-alpha20211029</a>
            </li>
            <li>
            <a href="/terraform/1.0.0/">terraform_1.0.0</a>
            </li>
            <li>
            <a href="/terraform/0.15.0/">terraform_0.15.0</a>
            </li>
            <li>
            <a href="/terraform/0.15.0-rc1/">terraform_0.15.0-rc1</a>
            </li>
            <li>
            <a href="/terraform/0.15.0-beta1/">terraform_0.15.0-beta1</a>
            </li>
            <li>
            <a href="/terraform/0.15.0-alpha20210107/">terraform_0.15.0-alpha20210107</a>
            </li>
            
        </ul>

</body></html>"#;

    #[test]
    fn test_capture_terraform_versions() -> Result<(), Box<dyn Error>> {
        let expected_versions = vec!["1.3.0", "1.2.0", "1.1.0", "1.0.0", "0.15.0"];
        let args = Args {
            list_all: false,
            install_version: None,
        };
        let actual_versions = capture_terraform_versions(args, LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_capture_terraform_versions_list_all() -> Result<(), Box<dyn Error>> {
        let expected_versions = vec![
            "1.3.0",
            "1.3.0-rc1",
            "1.3.0-beta1",
            "1.3.0-alpha20220608",
            "1.2.0",
            "1.2.0-rc1",
            "1.2.0-beta1",
            "1.2.0-alpha20220413",
            "1.2.0-alpha-20220328",
            "1.1.0",
            "1.1.0-rc1",
            "1.1.0-beta1",
            "1.1.0-alpha20211029",
            "1.0.0",
            "0.15.0",
            "0.15.0-rc1",
            "0.15.0-beta1",
            "0.15.0-alpha20210107",
        ];
        let args = Args {
            list_all: true,
            install_version: None,
        };
        let actual_versions = capture_terraform_versions(args, LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_get_version_from_module() -> Result<(), Box<dyn Error>> {
        const EXPECTED_VERSION: &str = "1.0.0";
        let versions = vec![EXPECTED_VERSION.to_string()];

        let tmp_dir = TempDir::new("test_get_version_from_module")?;
        let file_path = tmp_dir.path().join("version.tf");
        let mut file = File::create(file_path)?;
        file.write_all(b"terraform { required_version = \"~>1.0.0\" }")?;
        let current_dir = env::current_dir()?;
        env::set_current_dir(Path::new(&tmp_dir.path()))?;

        let actual_version = get_version_from_module(&versions)?;
        assert!(actual_version.is_some());
        assert_eq!(EXPECTED_VERSION, actual_version.unwrap());

        env::set_current_dir(current_dir)?;
        Ok(())
    }

    #[test]
    fn test_get_arch_x86() {
        let expected_arch = "386";
        let actual_arch = get_arch("x86");
        assert_eq!(expected_arch, actual_arch);
    }

    #[test]
    fn test_get_arch_x64_64() {
        let expected_arch = "amd64";
        let actual_arch = get_arch("x86_64");
        assert_eq!(expected_arch, actual_arch);
    }

    #[test]
    fn test_get_arch_aarch64() {
        let expected_arch = "arm64";
        let actual_arch = get_arch("aarch64");
        assert_eq!(expected_arch, actual_arch);
    }

    #[test]
    fn test_cache_zip_file() -> Result<(), Box<dyn Error>> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_cache_zip_file")?;
        let sub_dir = tmp_dir.path().join("tfswitcher");
        let file_path = sub_dir.join(ZIP_NAME);
        let buffer = vec![];

        cache_zip_file(&mut sub_dir.to_owned(), ZIP_NAME, &buffer)?;

        assert!(file_path.exists());

        Ok(())
    }

    #[test]
    fn test_cache_zip_file_dir_exists() -> Result<(), Box<dyn Error>> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_cache_zip_file_dir_exists")?;
        let sub_dir = tmp_dir.path().join("tfswitcher");
        fs::create_dir_all(&sub_dir)?;
        let file_path = sub_dir.join(ZIP_NAME);
        let buffer = vec![];

        cache_zip_file(&mut sub_dir.to_owned(), ZIP_NAME, &buffer)?;

        assert!(file_path.exists());

        Ok(())
    }
}
