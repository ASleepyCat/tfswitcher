use anyhow::{bail, Context, Ok, Result};
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use reqwest::blocking::Response;
use semver::{Version, VersionReq};
use std::{
    env::consts,
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

#[derive(Parser, Default, Debug)]
#[command(version)]
struct Args {
    /// Include pre-release versions
    #[arg(short, long = "list-all", default_value_t = false)]
    list_all: bool,

    #[arg(long = "install", env = "TF_VERSION")]
    install_version: Option<String>,
}

fn get_http(url: &str) -> Result<Response> {
    let response = reqwest::blocking::get(url)
        .with_context(|| format!("failed to send HTTP request to {url}"))?
        .error_for_status()
        .with_context(|| format!("server returned error from {url}"))?;

    Ok(response)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let Some(program_path) = find_terraform_program_path() else {
        bail!("could not find path to install Terraform");
    };

    if let Some(version) = get_version_to_install(args)? {
        install_version(&program_path, &version)?;
    } else {
        bail!("no version to install");
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

fn get_version_to_install(args: Args) -> Result<Option<String>> {
    if let Some(version) = args.install_version {
        return Ok(Some(version));
    }

    let contents = get_terraform_versions(ARCHIVE_URL)?;
    let versions = capture_terraform_versions(&args, &contents);

    if let Some(version_from_module) = get_version_from_module(&versions)? {
        return Ok(Some(version_from_module.to_owned()));
    }

    get_version_from_user_prompt(&versions)
}

fn get_terraform_versions(url: &str) -> Result<String> {
    let response = get_http(url)?;
    let contents = response
        .text()
        .with_context(|| "failed to get Terraform versions")?;

    Ok(contents)
}

fn capture_terraform_versions<'a>(args: &Args, contents: &'a str) -> Vec<&'a str> {
    let re = if args.list_all {
        Regex::new(r#"terraform_(?<version>(\d+\.\d+\.\d+)(?:-[a-zA-Z0-9-]+)?)"#)
            .expect("Invalid regex")
    } else {
        Regex::new(r#"terraform_(?<version>\d+\.\d+\.\d+)<"#).expect("Invalid regex")
    };

    let versions = re
        .captures_iter(contents)
        .filter_map(|c| c.name("version").map(|v| v.as_str()))
        .collect();

    versions
}

fn get_version_from_module<'a>(versions: &'a [&'a str]) -> Result<Option<&'a str>> {
    let module = tfconfig::load_module(Path::new("."), false)?;
    let version_constraint = match module.required_core.first() {
        Some(version) => version,
        None => return Ok(None),
    };

    println!("Module constraint is {version_constraint}");

    let req = VersionReq::parse(version_constraint)
        .with_context(|| format!("failed to parse version constraint {version_constraint}"))?;
    for version in versions {
        let v = Version::from_str(version)
            .with_context(|| format!("failed to parse version {version}"))?;
        if req.matches(&v) {
            return Ok(Some(version));
        }
    }

    Ok(None)
}

fn get_version_from_user_prompt(versions: &[&str]) -> Result<Option<String>> {
    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a Terraform version to install")
        .items(versions)
        .default(0)
        .interact_opt()
        .with_context(|| "failed to get version from user prompt")?
    {
        Some(selection) => Ok(Some(versions[selection].to_owned())),
        None => Ok(None),
    }
}

fn install_version(program_path: &Path, version: &str) -> Result<()> {
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
) -> Result<ZipArchive<Cursor<Vec<u8>>>> {
    let zip_name = format!("terraform_{version}_{os}_{arch}.zip");

    if let Some(cursor) = get_cached_zip(home::home_dir().as_mut(), &zip_name)? {
        let archive = ZipArchive::new(cursor).with_context(|| "failed to read cached archive")?;
        return Ok(archive);
    }

    download_and_save_terraform_version_zip(version, &zip_name)
}

fn get_cached_zip(
    home_dir: Option<&mut PathBuf>,
    zip_name: &str,
) -> Result<Option<Cursor<Vec<u8>>>> {
    match home_dir {
        Some(path) => {
            path.push(format!("{DEFAULT_CACHE_LOCATION}/{zip_name}"));
            if !path.exists() {
                return Ok(None);
            }

            println!("Using cached archive at {path:?}");
            let buffer = fs::read(&path)
                .with_context(|| format!("failed to read cached archive at {path:?}"))?;
            let cursor = Cursor::new(buffer);

            Ok(Some(cursor))
        }
        None => Ok(None),
    }
}

fn download_and_save_terraform_version_zip(
    version: &str,
    zip_name: &str,
) -> Result<ZipArchive<Cursor<Vec<u8>>>> {
    let url = format!("{ARCHIVE_URL}/{version}/{zip_name}");
    println!("Downloading archive from {url}");

    let response = get_http(&url)?;
    let contents = response
        .bytes()
        .with_context(|| "failed to read HTTP response")?
        .to_vec();

    match home::home_dir() {
        Some(mut path) => {
            path.push(DEFAULT_CACHE_LOCATION);
            println!("Caching archive to {path:?}");
            if let Err(e) = cache_zip_archive(&mut path, zip_name, &contents) {
                println!("Unable to cache archive: {e}");
            };
        }
        None => println!("Unable to cache archive: could not find home directory"),
    }

    let cursor = Cursor::new(contents);
    Ok(ZipArchive::new(cursor).with_context(|| "failed to read HTTP response as ZIP archive")?)
}

fn cache_zip_archive(cache_location: &mut PathBuf, zip_name: &str, buffer: &[u8]) -> Result<()> {
    fs::create_dir_all(&cache_location)?;
    cache_location.push(zip_name);
    fs::write(cache_location, buffer)?;

    Ok(())
}

fn extract_zip_archive(
    program_path: &Path,
    mut archive: ZipArchive<Cursor<Vec<u8>>>,
) -> Result<()> {
    let mut file = archive
        .by_index(0)
        .with_context(|| "could not get item in archive")?;
    let file_name = file.name();
    println!("Extracting {file_name} to {program_path:?}");

    // Create a new file for the extracted file and set rwxr-xr-x
    let mut outfile = create_output_file(program_path)?;

    // Write the contents of the file to the output file
    io::copy(&mut file, &mut outfile).with_context(|| "failed to extract zip archive")?;

    println!("Extracted archive to {program_path:?}");
    Ok(())
}

#[cfg(unix)]
fn create_output_file(program_path: &Path) -> Result<File> {
    let file = File::create(program_path)
        .with_context(|| format!("failed to create file at {program_path:?}"))?;
    let mut perms = file
        .metadata()
        .with_context(|| "could not get file metadata")?
        .permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms)
        .with_context(|| "could not set file permissions")?;

    Ok(file)
}

#[cfg(windows)]
fn create_output_file(program_path: &Path) -> Result<File> {
    Ok(File::create(program_path)
        .with_context(|| format!("failed to create file at {program_path:?}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use html_to_string_macro::html;
    use once_cell::sync::Lazy;
    use std::{env, io::Write, path::Path};
    use tempdir::TempDir;

    static LINES: Lazy<String> = Lazy::new(|| {
        html!(
        <html>
            <head>
                <title>"Terraform Versions | HashiCorp Releases"</title>
            </head>

            <body>
                <ul>
                    <li>
                    <a href="../">"../"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.3.0/">"terraform_1.3.0"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.3.0-rc1/">"terraform_1.3.0-rc1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.3.0-beta1/">"terraform_1.3.0-beta1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.3.0-alpha20220608/">"terraform_1.3.0-alpha20220608"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.2.0/">"terraform_1.2.0"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.2.0-rc1/">"terraform_1.2.0-rc1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.2.0-beta1/">"terraform_1.2.0-beta1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.2.0-alpha20220413/">"terraform_1.2.0-alpha20220413"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.2.0-alpha-20220328/">"terraform_1.2.0-alpha-20220328"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.1.0/">"terraform_1.1.0"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.1.0-rc1/">"terraform_1.1.0-rc1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.1.0-beta1/">"terraform_1.1.0-beta1"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.1.0-alpha20211029/">"terraform_1.1.0-alpha20211029"</a>
                    </li>
                    <li>
                    <a href="/terraform/1.0.0/">"terraform_1.0.0"</a>
                    </li>
                    <li>
                    <a href="/terraform/0.15.0/">"terraform_0.15.0"</a>
                    </li>
                    <li>
                    <a href="/terraform/0.15.0-rc1/">"terraform_0.15.0-rc1"</a>
                    </li>
                    <li>
                    <a href="/terraform/0.15.0-beta1/">"terraform_0.15.0-beta1"</a>
                    </li>
                    <li>
                    <a href="/terraform/0.15.0-alpha20210107/">"terraform_0.15.0-alpha20210107"</a>
                    </li>
                </ul>
            </body>
        </html>
        )
    });

    #[test]
    fn test_capture_terraform_versions() -> Result<()> {
        let expected_versions = vec!["1.3.0", "1.2.0", "1.1.0", "1.0.0", "0.15.0"];
        let actual_versions = capture_terraform_versions(&Args::default(), &LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_capture_terraform_versions_list_all() -> Result<()> {
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
        let actual_versions = capture_terraform_versions(&args, &LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_get_version_from_module() -> Result<()> {
        const EXPECTED_VERSION: &str = "1.0.0";
        let versions = vec![EXPECTED_VERSION];

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
    fn test_get_cached_zip_not_exists() -> Result<()> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_get_cached_zip_not_exists")?;

        let file = get_cached_zip(Some(&mut tmp_dir.path().to_path_buf()), ZIP_NAME)?;
        assert!(file.is_none());

        Ok(())
    }

    #[test]
    fn test_get_cached_zip_home_dir_not_exists() -> Result<()> {
        let file = get_cached_zip(None, "")?;
        assert!(file.is_none());

        Ok(())
    }

    #[test]
    fn test_get_cached_zip_exists() -> Result<()> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_get_cached_zip_exists")?;
        let cache_dir = tmp_dir.path().join(DEFAULT_CACHE_LOCATION);
        let file_path = cache_dir.join(ZIP_NAME);
        fs::create_dir_all(cache_dir)?;
        fs::write(file_path, "")?;

        let file = get_cached_zip(Some(&mut tmp_dir.path().to_path_buf()), ZIP_NAME)?;
        assert!(file.is_some());

        Ok(())
    }

    #[test]
    fn test_cache_zip_file() -> Result<()> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_cache_zip_file")?;
        let sub_dir = tmp_dir.path().join("tfswitcher");
        let file_path = sub_dir.join(ZIP_NAME);
        let buffer = vec![];

        cache_zip_archive(&mut sub_dir.to_owned(), ZIP_NAME, &buffer)?;

        assert!(file_path.exists());

        Ok(())
    }

    #[test]
    fn test_cache_zip_file_dir_exists() -> Result<()> {
        const ZIP_NAME: &str = "test_archive.zip";

        let tmp_dir = TempDir::new("test_cache_zip_file_dir_exists")?;
        let sub_dir = tmp_dir.path().join("tfswitcher");
        fs::create_dir_all(&sub_dir)?;
        let file_path = sub_dir.join(ZIP_NAME);
        let buffer = vec![];

        cache_zip_archive(&mut sub_dir.to_owned(), ZIP_NAME, &buffer)?;

        assert!(file_path.exists());

        Ok(())
    }
}
