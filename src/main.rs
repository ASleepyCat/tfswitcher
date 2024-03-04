use anyhow::{bail, Context, Ok, Result};
use clap::{CommandFactory, Parser};
use core::fmt;
use dialoguer::{theme::ColorfulTheme, Select};
use env_logger::TimestampPrecision;
use futures_util::stream::StreamExt;
use indicatif::{MultiProgress, ProgressBar};
use indicatif_log_bridge::LogWrapper;
use log::{debug, info, LevelFilter};
use regex::Regex;
use reqwest::Response;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    cmp,
    env::consts,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    vec,
};
use zip::ZipArchive;

const TERRAFORM_ARCHIVE_URL: &str = "https://releases.hashicorp.com/terraform";
const OPENTOFU_ARCHIVE_URL: &str = "https://github.com/opentofu/opentofu/releases/download";
const CONFIG_FILE_NAME: &str = ".tfswitch.toml";
const DEFAULT_LOCATION: &str = ".local/bin";
const DEFAULT_CACHE_LOCATION: &str = ".cache/tfswitcher";

#[derive(Parser, Default, Debug, Serialize, Deserialize, PartialEq)]
#[command(version, about)]
struct Args {
    /// Location of terraform binary
    #[arg(short, long = "bin")]
    #[serde(rename = "bin")]
    binary_location: Option<PathBuf>,

    /// Include pre-release versions
    #[arg(short, long)]
    #[serde(default)]
    list_all: bool,

    /// Install OpenTofu
    #[arg(short, long)]
    #[serde(default)]
    opentofu: bool,

    /// Remove file at install location before extracting archive.
    /// Removes symlinks but does not follow them
    #[arg(short = 'F', long)]
    #[serde(default)]
    force_remove: bool,

    /// Enable verbose logs
    #[arg(short, long)]
    #[serde(default)]
    verbose: bool,

    #[arg(env = "TF_VERSION")]
    #[serde(rename = "version")]
    install_version: Option<String>,

    /// Generate tab-completion scripts for the specified shell
    #[arg(short = 'c', long = "completions", id = "SHELL")]
    #[serde(skip)]
    generator: Option<clap_complete::Shell>,
}

#[derive(Clone, Debug, PartialEq)]
enum ProgramName {
    Terraform,
    OpenTofu,
}

impl ProgramName {
    fn eq(&self, other: &str) -> bool {
        match self {
            ProgramName::Terraform => other == "terraform",
            ProgramName::OpenTofu => other == "tofu",
        }
    }
}

impl fmt::Display for ProgramName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramName::Terraform => write!(f, "terraform"),
            ProgramName::OpenTofu => write!(f, "tofu"),
        }
    }
}

impl Args {
    fn get_program_name(&self) -> ProgramName {
        if self.opentofu {
            return ProgramName::OpenTofu;
        }
        ProgramName::Terraform
    }

    fn get_version_list(&self) -> VersionList {
        if self.opentofu {
            return VersionList::OpenTofu;
        }
        VersionList::Terraform
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ReleaseInfo {
    program_name: ProgramName,
    version: String,
}

impl ReleaseInfo {
    fn new(program_name: ProgramName, version: String) -> ReleaseInfo {
        ReleaseInfo {
            program_name,
            version,
        }
    }

    fn get_binary_name(&self) -> String {
        let target = get_target_platform();
        format!("{}_{}_{target}", self.program_name, self.version)
    }

    fn get_zip_name(&self) -> String {
        let target = get_target_platform();
        format!("{}_{}_{target}.zip", self.program_name, self.version)
    }

    fn get_download_url(&self) -> String {
        let zip_name = self.get_zip_name();
        match self.program_name {
            ProgramName::Terraform => {
                format!("{TERRAFORM_ARCHIVE_URL}/{}/{zip_name}", self.version)
            }
            ProgramName::OpenTofu => format!("{OPENTOFU_ARCHIVE_URL}/v{}/{zip_name}", self.version),
        }
    }
}

trait ListVersions {
    fn get_versions(&self) -> Vec<String>;
}

impl ListVersions for Vec<ReleaseInfo> {
    fn get_versions(&self) -> Vec<String> {
        self.iter().map(|r| r.version.to_owned()).collect()
    }
}

enum VersionList {
    Terraform,
    OpenTofu,
}

impl VersionList {
    async fn get_versions(&self, args: &Args) -> Result<Vec<ReleaseInfo>> {
        match self {
            VersionList::Terraform => Ok(get_versions_terraform(args).await?),
            VersionList::OpenTofu => Ok(get_versions_opentofu(args).await?),
        }
    }
}

/// Creates appropriate platform archive suffix.
///
/// Converts Rust constants `OS` and `ARCH` to equivalent Go runtime package `GOOS` and `GOARCH`.
/// https://docs.rs/rustc-std-workspace-std/latest/std/env/consts/constant.ARCH.html
/// https://docs.rs/rustc-std-workspace-std/latest/std/env/consts/constant.OS.html
/// https://pkg.go.dev/runtime#pkg-constants
fn get_target_platform() -> &'static str {
    match (consts::OS, consts::ARCH) {
        ("freebsd", "arm") => "freebsd_arm",
        ("freebsd", "x86") => "freebsd_386",
        ("freebsd", "x86_64") => "freebsd_amd64",
        ("linux", "aarch64") => "linux_arm64",
        ("linux", "arm") => "linux_arm",
        ("linux", "x86") => "linux_386",
        ("linux", "x86_64") => "linux_amd64",
        ("macos", "aarch64") => "darwin_arm64",
        ("macos", "x86_64") => "darwin_amd64",
        ("openbsd", "x86") => "openbsd_386",
        ("openbsd", "x86_64") => "openbsd_amd64",
        ("solaris", "x86_64") => "solaris_amd64",
        ("windows", "x86") => "windows_386",
        ("windows", "x86_64") => "windows_amd64",
        _ => panic!("Unsupported platform"),
    }
}

async fn get_versions_terraform(args: &Args) -> Result<Vec<ReleaseInfo>> {
    let response = get_http(TERRAFORM_ARCHIVE_URL).await?;
    let contents = response
        .text()
        .await
        .with_context(|| "failed to get Terraform versions")?;

    Ok(capture_terraform_versions(args, &contents))
}

fn capture_terraform_versions(args: &Args, contents: &str) -> Vec<ReleaseInfo> {
    let re = if args.list_all {
        Regex::new(r"terraform_(?<version>(\d+\.\d+\.\d+)(?:-[a-zA-Z0-9-]+)?)")
            .expect("Invalid regex")
    } else {
        Regex::new(r"terraform_(?<version>\d+\.\d+\.\d+)<").expect("Invalid regex")
    };

    let versions = re
        .captures_iter(contents)
        .filter_map(|c| {
            c.name("version")
                .map(|v| ReleaseInfo::new(args.get_program_name(), v.as_str().to_owned()))
        })
        .collect();

    versions
}

async fn get_versions_opentofu(args: &Args) -> Result<Vec<ReleaseInfo>> {
    let releases = octocrab::instance()
        .repos("opentofu", "opentofu")
        .releases()
        .list()
        .send()
        .await
        .with_context(|| "failed to get releases from opentofu github repo")?;

    let versions = releases
        .into_iter()
        .filter(|r| !r.prerelease || args.list_all)
        .map(|r| {
            let version = match r.tag_name.strip_prefix('v') {
                Some(v) => v.to_owned(),
                None => r.tag_name.clone(),
            };
            ReleaseInfo::new(args.get_program_name(), version)
        })
        .collect();

    Ok(versions)
}

async fn get_http(url: &str) -> Result<Response> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to send HTTP request to {url}"))?
        .error_for_status()
        .with_context(|| format!("server returned error from {url}"))?;

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    parse_config_arguments(".".into(), &mut args)?;
    let multi = init_logger(&args)?;

    if let Some(generator) = args.generator {
        clap_complete::generate(
            generator,
            &mut Args::command_for_update(),
            clap::crate_name!(),
            &mut io::stdout(),
        );
        return Ok(());
    }

    let Some(program_path) = find_terraform_program_path(&args) else {
        bail!(
            "could not find path to install {:?}",
            args.get_program_name()
        );
    };

    match get_version_to_install(&args).await? {
        Some(version) => Ok(install_version(&args, multi, &program_path, version).await?),
        None => bail!("no version to install"),
    }
}

fn init_logger(args: &Args) -> Result<MultiProgress> {
    let (ts_precision, level_filter) = if args.verbose {
        (Some(TimestampPrecision::default()), LevelFilter::Debug)
    } else {
        (None, LevelFilter::Info)
    };

    let logger = env_logger::Builder::new()
        .format_target(args.verbose)
        .format_level(args.verbose)
        .format_timestamp(ts_precision)
        .filter_level(level_filter)
        .build();
    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init()?;

    Ok(multi)
}

fn parse_config_arguments(cwd: PathBuf, args: &mut Args) -> Result<()> {
    if let Some(config) = load_config_file(cwd, home::home_dir())? {
        if args.binary_location.is_none() {
            args.binary_location = config.binary_location
        }
        args.list_all |= config.list_all;
        args.opentofu |= config.opentofu;
        args.force_remove |= config.force_remove;
        if args.install_version.is_none() {
            args.install_version = config.install_version
        }
    }

    if let Some(binary_location) = args.binary_location.as_ref() {
        args.binary_location = Some(shellexpand::path::full(binary_location)?.into());
    }

    Ok(())
}

fn load_config_file(mut cwd: PathBuf, mut home_dir: Option<PathBuf>) -> Result<Option<Args>> {
    cwd.push(CONFIG_FILE_NAME);
    if cwd.exists() {
        let config = fs::read_to_string(&cwd)
            .with_context(|| format!("failed to read config file in cwd at {:?}", cwd))?;
        let toml_file = toml::from_str(&config)
            .with_context(|| format!("failed to parse config in cwd at {cwd:?}"))?;
        return Ok(Some(toml_file));
    }

    match home_dir.as_mut() {
        Some(home) => {
            home.push(CONFIG_FILE_NAME);
            if !home.exists() {
                return Ok(None);
            }

            let config = fs::read_to_string(&home)
                .with_context(|| format!("failed to read config file in home at {home:?}"))?;
            let toml_file = toml::from_str(&config)
                .with_context(|| format!("failed to parse config in home at {home:?}"))?;
            Ok(Some(toml_file))
        }
        None => Ok(None),
    }
}

fn find_terraform_program_path(args: &Args) -> Option<PathBuf> {
    if args.binary_location.is_some() {
        return args.binary_location.clone();
    }

    let program_name = args.get_program_name();

    if let Some(path) = pathsearch::find_executable_in_path(&program_name.to_string()) {
        return Some(path);
    }

    match home::home_dir() {
        Some(mut path) => {
            path.push(format!("{DEFAULT_LOCATION}/{program_name}"));
            info!(
                "Could not locate {program_name:?}, installing to {path:?}. Make sure to include the directory in your $PATH environment variable"
            );
            Some(path)
        }
        None => None,
    }
}

async fn get_version_to_install(args: &Args) -> Result<Option<ReleaseInfo>> {
    if let Some(version) = &args.install_version {
        return Ok(Some(ReleaseInfo::new(
            args.get_program_name(),
            version.into(),
        )));
    }

    let version_constraint = get_version_from_module(Path::new("."))?;
    if let Some(version_constraint) = version_constraint.clone() {
        if !args.force_remove {
            if let Some((_, version)) =
                find_cached_binary(args, home::home_dir().as_mut(), &version_constraint)?
            {
                let release = ReleaseInfo::new(args.get_program_name(), version);
                return Ok(Some(release));
            }
        }
    }

    let versions = args.get_version_list().get_versions(args).await?;
    if let Some(version_constraint) = version_constraint {
        if let Some(version_from_module) = match_module_version(&version_constraint, &versions)? {
            return Ok(Some(version_from_module));
        }
    }

    get_version_from_user_prompt(args.get_program_name(), &versions)
}

fn get_version_from_module(cwd: &Path) -> Result<Option<VersionReq>> {
    let module =
        tfconfig::load_module(cwd, false).with_context(|| "failed to load terraform modules")?;
    match module.required_core.first() {
        Some(version) => {
            debug!("Module constraint is {version}");
            let req = VersionReq::parse(version)
                .with_context(|| format!("failed to parse version constraint {version}"))?;
            Ok(Some(req))
        }
        None => Ok(None),
    }
}

fn match_module_version(
    version_constraint: &VersionReq,
    versions: &Vec<ReleaseInfo>,
) -> Result<Option<ReleaseInfo>> {
    for version in versions {
        let v = Version::from_str(&version.version)
            .with_context(|| format!("failed to parse version {}", version.version))?;
        if version_constraint.matches(&v) {
            return Ok(Some(version.clone()));
        }
    }

    Ok(None)
}

fn get_version_from_user_prompt(
    program_name: ProgramName,
    versions: &Vec<ReleaseInfo>,
) -> Result<Option<ReleaseInfo>> {
    let prompt = match program_name {
        ProgramName::Terraform => format!("Select a {program_name:?} version to install"),
        ProgramName::OpenTofu => format!("Select an {program_name:?} version to install"),
    };
    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(&versions.get_versions())
        .default(0)
        .interact_opt()
        .with_context(|| "failed to get version from user prompt")?
    {
        Some(selection) => Ok(versions.get(selection).cloned()),
        None => Ok(None),
    }
}

async fn install_version(
    args: &Args,
    multi: MultiProgress,
    program_path: &Path,
    release: ReleaseInfo,
) -> Result<()> {
    debug!(
        "{:?} {} will be installed to {program_path:?}",
        args.get_program_name(),
        release.version
    );

    let binary = get_binary(args, multi, &release).await?;
    remove_file(args, program_path)?;

    // Create a new file for the extracted file
    let mut outfile = create_output_file(program_path)?;
    debug!("Copying binary to {program_path:?}");

    // Write the contents of the file to the output file
    outfile
        .write_all(&binary)
        .with_context(|| "failed to copy binary")?;

    info!(
        "Installed {:?} to {program_path:?}",
        args.get_program_name()
    );
    Ok(())
}

async fn get_binary(args: &Args, multi: MultiProgress, release: &ReleaseInfo) -> Result<Vec<u8>> {
    if let Some(buffer) = get_cached_binary(home::home_dir().as_mut(), &release.version, args)? {
        return Ok(buffer);
    }

    Ok(download_and_cache_bin(multi, release).await?)
}

fn find_cached_binary(
    args: &Args,
    home_dir: Option<&mut PathBuf>,
    version: &VersionReq,
) -> Result<Option<(PathBuf, String)>> {
    if let Some(path) = home_dir {
        path.push(DEFAULT_CACHE_LOCATION);
        if !path.exists() {
            return Ok(None);
        }

        let mut files: Vec<_> = fs::read_dir(path)?
            .filter_map(Result::ok)
            .filter(|f| f.path().extension() != Some("zip".as_ref()))
            .collect();
        files.sort_by_key(|d| d.path());
        files.reverse();
        for file in files {
            let file_name = file.file_name();
            if let Some(bin_version) = file_name.to_str() {
                let mut split = bin_version.split("_");
                let bin = match split.nth(0) {
                    Some(b) => b,
                    None => continue,
                };
                let version_split = match split.nth(0) {
                    Some(v) => v,
                    None => continue,
                };
                if args.get_program_name().eq(bin) {
                    if version.matches(
                        &Version::from_str(version_split)
                            .with_context(|| format!("failed to parse {version_split}"))?,
                    ) {
                        return Ok(Some((file.path(), version_split.to_string())));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn get_cached_binary(
    home_dir: Option<&mut PathBuf>,
    version: &str,
    args: &Args,
) -> Result<Option<Vec<u8>>> {
    let version = VersionReq::parse(version).with_context(|| "failed to parse {version}")?;
    match find_cached_binary(args, home_dir, &version)? {
        Some((path, _)) => {
            debug!("Using cached binary at {path:?}");
            let buffer = fs::read(&path)
                .with_context(|| format!("failed to read cached binary at {path:?}"))?;

            Ok(Some(buffer))
        }
        None => Ok(None),
    }
}

async fn download_and_cache_bin(multi: MultiProgress, release: &ReleaseInfo) -> Result<Vec<u8>> {
    let binary: Vec<u8>;
    if let Some(cursor) = get_cached_zip(home::home_dir().as_mut(), &release.get_zip_name())? {
        let archive = ZipArchive::new(cursor).with_context(|| "failed to read cached archive")?;
        binary = extract_zip_archive(&release.program_name, archive)?;
    } else {
        binary = download_bin(multi, release).await?;
    }

    cache_binary(
        home::home_dir().as_mut(),
        &release.get_binary_name(),
        &binary,
    )?;
    Ok(binary)
}

/// This is a holdover from old code that used to cache the archive instead of the binary
/// We do this so we can clean up old archives instead of redownloading them
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

            debug!("Using cached archive at {path:?}");
            let buffer = fs::read(&path)
                .with_context(|| format!("failed to read cached archive at {path:?}"))?;
            fs::remove_file(&path)
                .with_context(|| "could not clean up cached archive at {path:?}")?;
            let cursor = Cursor::new(buffer);

            Ok(Some(cursor))
        }
        None => Ok(None),
    }
}

async fn download_bin(multi: MultiProgress, release: &ReleaseInfo) -> Result<Vec<u8>> {
    let archive = download_zip(multi, release).await?;
    Ok(extract_zip_archive(&release.program_name, archive)?)
}

async fn download_zip(
    multi: MultiProgress,
    release: &ReleaseInfo,
) -> Result<ZipArchive<Cursor<Vec<u8>>>> {
    let url = release.get_download_url();
    info!("Downloading archive from {url}");
    let response = get_http(&url).await?;

    let mut contents = vec![];
    if let Some(total_size) = response.content_length() {
        let pb = multi.add(ProgressBar::new(total_size));
        let mut downloaded = 0;
        let mut stream = response.bytes_stream();

        while let Some(item) = stream.next().await {
            let chunk = item.with_context(|| "failed to download chunk")?;
            contents.append(&mut chunk.to_vec());

            let new = cmp::min(downloaded + (chunk.len() as u64), total_size);
            downloaded = new;
            pb.set_position(new);
        }

        pb.finish_and_clear();
    } else {
        contents = response
            .bytes()
            .await
            .with_context(|| "failed to read HTTP response")?
            .to_vec();
    }

    let cursor = Cursor::new(contents);
    Ok(ZipArchive::new(cursor).with_context(|| "failed to read HTTP response as ZIP archive")?)
}

fn extract_zip_archive(
    program_name: &ProgramName,
    mut archive: ZipArchive<Cursor<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let mut file = archive
        .by_name(&program_name.to_string())
        .with_context(|| "could not get item in archive")?;

    let mut buf = vec![];
    file.read_to_end(&mut buf)
        .with_context(|| "failed to read archive")?;

    Ok(buf)
}

fn cache_binary(cache_location: Option<&mut PathBuf>, bin_name: &str, buffer: &[u8]) -> Result<()> {
    match cache_location {
        Some(path) => {
            path.push(DEFAULT_CACHE_LOCATION);
            debug!("Caching binary to {path:?}");
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create cache directory at {path:?}"))?;
            path.push(bin_name);
            fs::write(path, buffer).with_context(|| "failed to cache binary")?;
        }
        None => debug!("Unable to cache binary: could not find cache directory"),
    }

    Ok(())
}

fn remove_file(args: &Args, program_path: &Path) -> Result<()> {
    if !args.force_remove {
        return Ok(());
    }

    debug!("Removing binary at {program_path:?}");
    fs::remove_file(program_path)?;

    Ok(())
}

#[cfg(unix)]
fn create_output_file(program_path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = program_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create missing parent directories to {program_path:?}")
        })?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o777)
        .open(program_path)
        .with_context(|| format!("failed to create file at {program_path:?}"))?;

    Ok(file)
}

#[cfg(windows)]
fn create_output_file(program_path: &Path) -> Result<File> {
    if let Some(parent) = program_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(File::create(program_path)
        .with_context(|| format!("failed to create file at {program_path:?}"))?)
}

#[cfg(test)]
mod tests {
    use std::env;

    use html_to_string_macro::html;
    use once_cell::sync::Lazy;
    use tempdir::TempDir;

    use super::*;

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
    fn test_parse_config_arguments_bool_flags_disabled_from_cli() -> Result<()> {
        let config_file = r#"list_all = true
opentofu = true"#;

        let tmp_dir = TempDir::new("test_parse_config_arguments_bool_flags_disabled_from_cli")?;
        let tmp_dir_path = tmp_dir.path();
        let file_path = tmp_dir_path.join(CONFIG_FILE_NAME);
        fs::write(file_path, config_file)?;

        let mut args = Args::default();
        parse_config_arguments(tmp_dir_path.to_path_buf(), &mut args)?;
        assert!(args.list_all);
        assert!(args.opentofu);

        Ok(())
    }

    #[test]
    fn test_parse_config_arguments_bool_flags_enabled_from_cli() -> Result<()> {
        let tmp_dir = TempDir::new("test_parse_config_arguments_bool_flags_enabled_from_cli")?;
        let tmp_dir_path = tmp_dir.path();
        let file_path = tmp_dir_path.join(CONFIG_FILE_NAME);
        File::create(file_path)?;

        let mut args = Args {
            list_all: true,
            opentofu: true,
            ..Default::default()
        };
        parse_config_arguments(tmp_dir_path.to_path_buf(), &mut args)?;
        assert!(args.list_all);
        assert!(args.opentofu);

        Ok(())
    }

    #[test]
    fn test_parse_config_arguments_path_with_env_var() -> Result<()> {
        const EXPECTED_PATH: &str = "path/htap";

        env::set_var("A", "path");

        let mut args = Args {
            binary_location: Some("$A/htap".into()),
            ..Default::default()
        };

        parse_config_arguments("".into(), &mut args)?;

        assert_eq!(Some(EXPECTED_PATH.into()), args.binary_location);

        Ok(())
    }

    #[test]
    fn test_load_config_file_in_cwd() -> Result<()> {
        let expected_config_file = Args {
            binary_location: Some("test_load_config_file_in_cwd".into()),
            list_all: true,
            opentofu: true,
            force_remove: true,
            verbose: true,
            install_version: Some("test_load_config_file_in_cwd".to_owned()),
            generator: None,
        };
        let config_file = r#"bin = "test_load_config_file_in_cwd"
list_all = true
opentofu = true
force_remove = true
verbose = true
version = "test_load_config_file_in_cwd""#;

        let tmp_dir = TempDir::new("test_load_config_file_in_cwd")?;
        let tmp_dir_path = tmp_dir.path();
        let file_path = tmp_dir_path.join(CONFIG_FILE_NAME);
        fs::write(file_path, config_file)?;

        let actual_config_file = load_config_file(tmp_dir_path.to_path_buf(), None)?;
        assert_eq!(Some(expected_config_file), actual_config_file);

        Ok(())
    }

    #[test]
    fn test_load_config_file_in_home() -> Result<()> {
        let expected_config_file = Args {
            binary_location: Some("test_load_config_file_in_home".into()),
            list_all: true,
            opentofu: true,
            force_remove: true,
            verbose: true,
            install_version: Some("test_load_config_file_in_home".to_owned()),
            generator: None,
        };
        let config_file = r#"bin = "test_load_config_file_in_home"
list_all = true
opentofu = true
force_remove = true
verbose = true
version = "test_load_config_file_in_home""#;

        let tmp_dir = TempDir::new("test_load_config_file_in_home")?;
        let tmp_dir_path = tmp_dir.path();
        let file_path = tmp_dir_path.join(CONFIG_FILE_NAME);
        fs::write(file_path, config_file)?;

        let actual_config_file = load_config_file(".".into(), Some(tmp_dir_path.to_path_buf()))?;
        assert_eq!(Some(expected_config_file), actual_config_file);

        Ok(())
    }

    #[test]
    fn test_load_config_file_not_present() -> Result<()> {
        let tmp_dir = TempDir::new("test_load_config_file_not_present")?;
        let tmp_dir_path = tmp_dir.path();

        let actual_config_file = load_config_file(".".into(), Some(tmp_dir_path.to_path_buf()))?;
        assert!(actual_config_file.is_none());

        Ok(())
    }

    #[test]
    fn test_capture_terraform_versions() -> Result<()> {
        let expected_versions: Vec<ReleaseInfo> =
            vec!["1.3.0", "1.2.0", "1.1.0", "1.0.0", "0.15.0"]
                .into_iter()
                .map(|v| ReleaseInfo::new(ProgramName::Terraform, v.into()))
                .collect();
        let actual_versions = capture_terraform_versions(&Args::default(), &LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_capture_terraform_versions_list_all() -> Result<()> {
        let expected_versions: Vec<ReleaseInfo> = vec![
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
        ]
            .into_iter()
            .map(|v| ReleaseInfo::new(ProgramName::Terraform, v.into()))
            .collect();
        let args = Args {
            list_all: true,
            ..Default::default()
        };
        let actual_versions = capture_terraform_versions(&args, &LINES);

        assert_eq!(expected_versions, actual_versions);

        Ok(())
    }

    #[test]
    fn test_get_version_from_module() -> Result<()> {
        const EXPECTED_VERSION: &str = "~>1.0.0";
        let expected_req = VersionReq::parse(EXPECTED_VERSION)?;

        let tmp_dir = TempDir::new("test_get_version_from_module")?;
        let tmp_dir_path = tmp_dir.path();
        let file_path = tmp_dir_path.join("version.tf");
        fs::write(
            file_path,
            format!(r#"terraform {{ required_version = "{EXPECTED_VERSION}" }}"#),
        )?;

        let actual_version = get_version_from_module(tmp_dir_path)?;
        assert_eq!(Some(expected_req), actual_version);

        Ok(())
    }

    #[test]
    fn test_match_module_version() -> Result<()> {
        const VERSION_CONSTRAINT: &str = "1.0.0";
        let req = VersionReq::parse(VERSION_CONSTRAINT)?;
        let expected_release = ReleaseInfo::new(ProgramName::Terraform, VERSION_CONSTRAINT.into());
        let versions = vec![expected_release.clone()];

        let actual_release = match_module_version(&req, &versions)?;
        assert_eq!(Some(expected_release), actual_release);

        Ok(())
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
        File::create(&file_path)?;

        let file = get_cached_zip(Some(&mut tmp_dir.path().to_path_buf()), ZIP_NAME)?;
        assert!(file.is_some());
        assert!(!file_path.exists());

        Ok(())
    }

    #[test]
    fn test_cache_binary_file() -> Result<()> {
        const BIN_NAME: &str = "test_binary";

        let tmp_dir = TempDir::new("test_cache_binary_file")?;
        let mut sub_dir = tmp_dir.path().join("tfswitcher");
        let buffer = vec![];

        cache_binary(Some(&mut sub_dir), BIN_NAME, &buffer)?;

        assert!(sub_dir.exists());

        Ok(())
    }

    #[test]
    fn test_cache_binary_file_dir_exists() -> Result<()> {
        const BIN_NAME: &str = "test_binary";

        let tmp_dir = TempDir::new("test_cache_binary_file_dir_exists")?;
        let mut sub_dir = tmp_dir.path().join("tfswitcher");
        fs::create_dir_all(&sub_dir)?;
        let buffer = vec![];

        cache_binary(Some(&mut sub_dir), BIN_NAME, &buffer)?;

        assert!(sub_dir.exists());

        Ok(())
    }

    #[test]
    fn test_remove_file() -> Result<()> {
        let tmp_dir = TempDir::new("test_remove_file")?;
        let path = tmp_dir.path().join("terraform");
        File::create(&path)?;
        let args = Args {
            force_remove: true,
            ..Default::default()
        };

        remove_file(&args, &path)?;

        assert!(!path.exists());

        Ok(())
    }

    /// Equivalent test for Windows doesn't exist due to symlink creation being a privileged action
    #[cfg(unix)]
    #[test]
    fn test_remove_file_symlink() -> Result<()> {
        let tmp_dir = TempDir::new("test_remove_file_symlink")?;
        let symlink = tmp_dir.path().join("symlink");
        let path = tmp_dir.path().join("terraform");
        File::create(&path)?;
        std::os::unix::fs::symlink(&path, &symlink)?;
        let args = Args {
            force_remove: true,
            ..Default::default()
        };

        remove_file(&args, &symlink)?;

        assert!(path.exists());
        assert!(!symlink.exists());

        Ok(())
    }

    #[test]
    fn test_create_output_file() -> Result<()> {
        let tmp_dir = TempDir::new("test_create_output_file")?;
        let path = tmp_dir.path().join("subdir/tfswitcher");

        create_output_file(&path)?;

        Ok(())
    }
}
