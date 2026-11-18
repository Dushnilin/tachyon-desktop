use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use gpui::component::Sizable as _;
#[cfg(target_os = "windows")]
use gpui::component::input::{Input, InputEvent, InputState};
#[cfg(target_os = "windows")]
use gpui::prelude::*;
#[cfg(target_os = "windows")]
use gpui::{
    App, AppContext, Bounds, Context, Entity, FontWeight, Render, Subscription, TitlebarOptions,
    Window, WindowBounds, WindowControlArea, WindowDecorations, WindowOptions, div, px, size, svg,
};

#[cfg(target_os = "windows")]
use crate::icons::TachyonAssetSource;
#[cfg(target_os = "windows")]
use crate::state::PersistedState;
#[cfg(target_os = "windows")]
use crate::theme::Theme;

/// 8-байтовый маркер в конце исполняемого файла, помечающий его как установщик.
pub const INSTALLER_MAGIC: &[u8; 8] = b"TCHYINST";

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
const UNINSTALL_REG_KEY_CU: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Tachyon";
#[cfg(target_os = "windows")]
const UNINSTALL_REG_KEY_LM: &str =
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Tachyon";
#[cfg(target_os = "windows")]
const URI_SCHEME_REG_KEY: &str = r"HKCU\Software\Classes\tachyon";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallerMode {
    InstallGui,
    InstallSilent { dir: Option<PathBuf> },
    UninstallGui,
    UninstallSilent { purge: bool },
}

/// Проверяет, завершается ли файл 8-байтовым маркером `TCHYINST`.
pub fn has_installer_trailer(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if meta.len() < INSTALLER_MAGIC.len() as u64 {
        return false;
    }
    if file
        .seek(SeekFrom::End(-(INSTALLER_MAGIC.len() as i64)))
        .is_err()
    {
        return false;
    }
    let mut tail = [0u8; 8];
    if file.read_exact(&mut tail).is_err() {
        return false;
    }
    &tail == INSTALLER_MAGIC
}

/// Отрезает маркер установщика `TCHYINST` с конца образа, чтобы установленный бинарник
/// запускался в режиме обычного клиента.
pub fn strip_installer_trailer(mut bytes: &[u8]) -> &[u8] {
    while bytes.ends_with(INSTALLER_MAGIC) {
        bytes = &bytes[..bytes.len() - INSTALLER_MAGIC.len()];
    }
    bytes
}

/// Определяет режим запуска (установщик / деинсталлятор / обычный клиент) по аргументам и имени файла.
pub fn detect_installer_mode(args: &[String], exe_path: &Path) -> Option<InstallerMode> {
    let tail = args.get(1..).unwrap_or(&[]);

    let mut has_install = false;
    let mut has_install_silent = false;
    let mut has_uninstall = false;
    let mut has_silent = false;
    let mut has_purge = false;
    let mut dir: Option<PathBuf> = None;

    let mut idx = 0usize;
    while idx < tail.len() {
        let arg = tail[idx].as_str();
        if arg == "--run-core"
            || arg == "--version"
            || arg == "version"
            || arg == "-v"
            || arg == "--help"
            || arg == "-h"
        {
            return None;
        }
        if arg.eq_ignore_ascii_case("--uninstall") || arg.eq_ignore_ascii_case("/uninstall") {
            has_uninstall = true;
        } else if arg.eq_ignore_ascii_case("--install-silent")
            || arg.eq_ignore_ascii_case("/install-silent")
        {
            has_install_silent = true;
        } else if arg.eq_ignore_ascii_case("--install")
            || arg.eq_ignore_ascii_case("/install")
            || arg.eq_ignore_ascii_case("--setup")
            || arg.eq_ignore_ascii_case("/setup")
        {
            has_install = true;
        } else if arg.eq_ignore_ascii_case("--silent") || arg.eq_ignore_ascii_case("/s") {
            has_silent = true;
        } else if arg.eq_ignore_ascii_case("--purge") || arg.eq_ignore_ascii_case("/purge") {
            has_purge = true;
        } else if arg.eq_ignore_ascii_case("--dir") {
            if let Some(next_val) = tail.get(idx + 1) {
                if !next_val.trim().is_empty() {
                    dir = Some(PathBuf::from(next_val.trim()));
                }
                idx += 1;
            }
        } else if let Some(val) = arg
            .strip_prefix("--dir=")
            .or_else(|| arg.strip_prefix("--DIR="))
            .or_else(|| arg.strip_prefix("/D="))
            .or_else(|| arg.strip_prefix("/d="))
        {
            if !val.trim().is_empty() {
                dir = Some(PathBuf::from(val.trim()));
            }
        }
        idx += 1;
    }

    if has_uninstall {
        return Some(if has_silent {
            InstallerMode::UninstallSilent { purge: has_purge }
        } else {
            InstallerMode::UninstallGui
        });
    }

    if has_install_silent {
        return Some(InstallerMode::InstallSilent { dir });
    }

    if has_install {
        return Some(if has_silent {
            InstallerMode::InstallSilent { dir }
        } else {
            InstallerMode::InstallGui
        });
    }

    let file_name = exe_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if file_name.contains("uninstall") {
        return Some(if has_silent {
            InstallerMode::UninstallSilent { purge: has_purge }
        } else {
            InstallerMode::UninstallGui
        });
    }

    let looks_like_installer_name = (file_name.contains("setup") || file_name.contains("install"))
        && !file_name.contains("uninstall");

    if has_installer_trailer(exe_path) || looks_like_installer_name {
        return Some(if has_silent {
            InstallerMode::InstallSilent { dir }
        } else {
            InstallerMode::InstallGui
        });
    }

    None
}

/// Запускает режим установщика или деинсталлятора, если он определён из аргументов или трейлера.
pub fn maybe_run_installer_or_uninstaller(args: &[String]) -> Option<i32> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = args;
        None
    }

    #[cfg(target_os = "windows")]
    {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("Tachyon.exe"));
        let mode = detect_installer_mode(args, &exe_path)?;
        let cli_flags = parse_silent_cli_flags(args);
        let code = match mode {
            InstallerMode::InstallGui => run_install_gui(),
            InstallerMode::InstallSilent { dir } => {
                let mut opts = InstallOptions::default_for_user();
                if let Some(d) = dir {
                    opts.install_dir = d;
                }
                cli_flags.apply_to_install_options(&mut opts);
                match perform_install_internal(&opts, !cli_flags.elevated, &|_, _| {}) {
                    Ok(report) => {
                        if opts.launch_after && !cli_flags.elevated {
                            let _ = Command::new(&report.installed_exe).spawn();
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("install error: {e}");
                        1
                    }
                }
            }
            InstallerMode::UninstallGui => run_uninstall_gui(),
            InstallerMode::UninstallSilent { purge } => {
                let mut target_dir = cli_flags.dir.clone();
                if target_dir.is_none() {
                    target_dir = detect_existing_installation().map(|i| i.install_dir);
                }
                match perform_uninstall_internal(
                    purge,
                    target_dir,
                    true,
                    !cli_flags.elevated,
                    &|_, _| {},
                ) {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("uninstall error: {e}");
                        1
                    }
                }
            }
        };
        Some(code)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub install_dir: PathBuf,
    pub create_desktop_shortcut: bool,
    pub create_start_menu: bool,
    pub register_uri_scheme: bool,
    pub add_firewall_rule: bool,
    pub add_to_path: bool,
    pub autostart: bool,
    pub launch_after: bool,
}

#[cfg(target_os = "windows")]
impl InstallOptions {
    pub fn default_for_user() -> Self {
        let install_dir = detect_existing_installation()
            .map(|info| info.install_dir)
            .unwrap_or_else(default_user_install_dir);
        let persisted = PersistedState::load();
        Self {
            install_dir,
            create_desktop_shortcut: true,
            create_start_menu: true,
            register_uri_scheme: true,
            add_firewall_rule: true,
            add_to_path: false,
            autostart: persisted.vpn_prefs.autostart,
            launch_after: true,
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct SilentCliFlags {
    elevated: bool,
    dir: Option<PathBuf>,
    no_desktop: bool,
    no_start_menu: bool,
    no_uri: bool,
    no_firewall: bool,
    set_path: Option<bool>,
    set_autostart: Option<bool>,
    set_launch: Option<bool>,
}

#[cfg(target_os = "windows")]
impl SilentCliFlags {
    fn apply_to_install_options(&self, opts: &mut InstallOptions) {
        if self.no_desktop {
            opts.create_desktop_shortcut = false;
        }
        if self.no_start_menu {
            opts.create_start_menu = false;
        }
        if self.no_uri {
            opts.register_uri_scheme = false;
        }
        if self.no_firewall {
            opts.add_firewall_rule = false;
        }
        if let Some(v) = self.set_path {
            opts.add_to_path = v;
        }
        if let Some(v) = self.set_autostart {
            opts.autostart = v;
        }
        // По умолчанию при тихой установке не запускаем GUI без явного --launch.
        opts.launch_after = self.set_launch.unwrap_or(false);
    }
}

#[cfg(target_os = "windows")]
fn parse_silent_cli_flags(args: &[String]) -> SilentCliFlags {
    let mut flags = SilentCliFlags::default();
    let tail = args.get(1..).unwrap_or(&[]);
    let mut idx = 0usize;
    while idx < tail.len() {
        let arg = tail[idx].as_str();
        if arg.eq_ignore_ascii_case("--elevated") {
            flags.elevated = true;
        } else if arg.eq_ignore_ascii_case("--no-desktop") {
            flags.no_desktop = true;
        } else if arg.eq_ignore_ascii_case("--no-start-menu") {
            flags.no_start_menu = true;
        } else if arg.eq_ignore_ascii_case("--no-uri") {
            flags.no_uri = true;
        } else if arg.eq_ignore_ascii_case("--no-firewall") {
            flags.no_firewall = true;
        } else if arg.eq_ignore_ascii_case("--add-path") {
            flags.set_path = Some(true);
        } else if arg.eq_ignore_ascii_case("--no-path") {
            flags.set_path = Some(false);
        } else if arg.eq_ignore_ascii_case("--autostart") {
            flags.set_autostart = Some(true);
        } else if arg.eq_ignore_ascii_case("--no-autostart") {
            flags.set_autostart = Some(false);
        } else if arg.eq_ignore_ascii_case("--launch") {
            flags.set_launch = Some(true);
        } else if arg.eq_ignore_ascii_case("--no-launch") {
            flags.set_launch = Some(false);
        } else if arg.eq_ignore_ascii_case("--dir") {
            if let Some(next_val) = tail.get(idx + 1) {
                if !next_val.trim().is_empty() {
                    flags.dir = Some(PathBuf::from(next_val.trim()));
                }
                idx += 1;
            }
        }
        idx += 1;
    }
    flags
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ExistingInstallInfo {
    install_dir: PathBuf,
    version: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct InstallReport {
    installed_exe: PathBuf,
    used_uac: bool,
    firewall_ok: bool,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct UninstallTarget {
    install_dir: PathBuf,
    target_exe: PathBuf,
    needs_delayed_delete: bool,
}

#[cfg(target_os = "windows")]
fn default_user_install_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.trim().is_empty() {
            return PathBuf::from(local).join("Programs").join("Tachyon");
        }
    }
    crate::vpn::app_data_dir().join("App")
}

#[cfg(target_os = "windows")]
fn default_system_install_dir() -> PathBuf {
    if let Ok(pf) = std::env::var("ProgramFiles").or_else(|_| std::env::var("PROGRAMFILES")) {
        if !pf.trim().is_empty() {
            return PathBuf::from(pf).join("Tachyon");
        }
    }
    PathBuf::from(r"C:\Program Files\Tachyon")
}

#[cfg(target_os = "windows")]
fn query_reg_value(key: &str, value_name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new("reg")
        .args(["query", key, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed
            .to_ascii_lowercase()
            .starts_with(&value_name.to_ascii_lowercase())
        {
            continue;
        }
        if let Some(pos) = trimmed.find("REG_SZ") {
            let val = trimmed[pos + "REG_SZ".len()..].trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        } else if let Some(pos) = trimmed.find("REG_EXPAND_SZ") {
            let val = trimmed[pos + "REG_EXPAND_SZ".len()..].trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn detect_existing_installation() -> Option<ExistingInstallInfo> {
    for reg_key in [UNINSTALL_REG_KEY_CU, UNINSTALL_REG_KEY_LM] {
        if let Some(loc) = query_reg_value(reg_key, "InstallLocation") {
            let dir = PathBuf::from(loc.trim().trim_matches('"'));
            let exe = dir.join("Tachyon.exe");
            if exe.exists() {
                let version = query_reg_value(reg_key, "DisplayVersion");
                return Some(ExistingInstallInfo {
                    install_dir: dir,
                    version,
                });
            }
        }
    }
    for dir in [default_user_install_dir(), default_system_install_dir()] {
        if dir.join("Tachyon.exe").exists() {
            return Some(ExistingInstallInfo {
                install_dir: dir,
                version: None,
            });
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn paths_equal_windows(a: &Path, b: &Path) -> bool {
    let sa = fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
    let sb = fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
    sa.to_string_lossy()
        .eq_ignore_ascii_case(&sb.to_string_lossy())
}

#[cfg(target_os = "windows")]
fn stop_other_tachyon_processes() {
    use std::os::windows::process::CommandExt;

    let stop_file = crate::vpn::app_data_dir().join("config.stop");
    let _ = fs::write(&stop_file, b"stop");
    crate::vpn::set_system_proxy(false);
    std::thread::sleep(Duration::from_millis(250));

    let self_pid = std::process::id();
    for image_name in ["Tachyon.exe", "tachyon.exe"] {
        let filter = format!("IMAGENAME eq {image_name}");
        let Ok(out) = Command::new("tasklist")
            .args(["/FI", &filter, "/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('"') {
                continue;
            }
            let cols: Vec<&str> = trimmed.split("\",\"").collect();
            if cols.len() >= 2 {
                let pid_str = cols[1].trim_matches('"').trim();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if pid != 0 && pid != self_pid {
                        let _ = Command::new("taskkill")
                            .args(["/F", "/PID", &pid.to_string(), "/T"])
                            .creation_flags(CREATE_NO_WINDOW)
                            .status();
                    }
                }
            }
        }
    }
    let _ = fs::remove_file(&stop_file);
}

#[cfg(target_os = "windows")]
fn is_permission_denied(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(5)
}

#[cfg(target_os = "windows")]
fn run_elevated_self(extra_args: &[String]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к текущему файлу: {e}"))?;
    let mut quoted_args = Vec::with_capacity(extra_args.len());
    for a in extra_args {
        quoted_args.push(format!("'{}'", a.replace('\'', "''")));
    }
    let arg_list = quoted_args.join(",");
    let ps_cmd = format!(
        "$p = Start-Process -FilePath $env:TACHYON_UAC_EXE -ArgumentList @({arg_list}) -Verb RunAs -WindowStyle Hidden -Wait -PassThru; if ($null -eq $p) {{ exit 1 }}; exit $p.ExitCode"
    );

    let out = Command::new("powershell")
        .env("TACHYON_UAC_EXE", &current_exe)
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запросить права администратора: {e}"))?;

    if !out.status.success() {
        return Err("Операция отменена или не хватило прав администратора (UAC)".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn copy_clean_binary(target_exe: &Path) -> std::io::Result<usize> {
    let current_exe = std::env::current_exe()?;
    let raw_bytes = fs::read(&current_exe)?;
    let clean_bytes = strip_installer_trailer(&raw_bytes);
    if clean_bytes.is_empty() || !clean_bytes.starts_with(b"MZ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Некорректный формат исполняемого образа",
        ));
    }

    if paths_equal_windows(&current_exe, target_exe) && !raw_bytes.ends_with(INSTALLER_MAGIC) {
        return Ok(clean_bytes.len());
    }

    let tmp_path = target_exe.with_extension("exe.tmp");
    let old_path = target_exe.with_extension("exe.old");
    let _ = fs::remove_file(&old_path);
    let _ = fs::remove_file(&tmp_path);

    fs::write(&tmp_path, clean_bytes)?;
    if target_exe.exists() {
        if let Err(err) = fs::remove_file(target_exe) {
            if fs::rename(target_exe, &old_path).is_err() {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
        }
    }
    if let Err(err) = fs::rename(&tmp_path, target_exe) {
        if old_path.exists() {
            let _ = fs::rename(&old_path, target_exe);
        }
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    let _ = fs::remove_file(&old_path);
    Ok(clean_bytes.len())
}

#[cfg(target_os = "windows")]
fn special_folders() -> (PathBuf, PathBuf) {
    use std::os::windows::process::CommandExt;

    let ps = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); \
              Write-Output ([Environment]::GetFolderPath('Desktop')); \
              Write-Output ([Environment]::GetFolderPath('Programs'))";
    if let Ok(out) = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut lines = text.lines().map(str::trim).filter(|s| !s.is_empty());
            if let (Some(desk), Some(prog)) = (lines.next(), lines.next()) {
                return (PathBuf::from(desk), PathBuf::from(prog));
            }
        }
    }

    let desktop = std::env::var("USERPROFILE")
        .map(|u| PathBuf::from(u).join("Desktop"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Public\Desktop"));
    let programs = std::env::var("APPDATA")
        .map(|a| {
            PathBuf::from(a)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
        })
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs"));
    (desktop, programs)
}

#[cfg(target_os = "windows")]
fn create_windows_shortcut(
    lnk_path: &Path,
    target_path: &Path,
    args: &str,
    working_dir: &Path,
    icon_path: &Path,
    description: &str,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    if let Some(parent) = lnk_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Не удалось создать папку для ярлыка {}: {e}",
                parent.display()
            )
        })?;
    }

    let ps = r#"$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($env:TACHYON_LNK_PATH); $sc.TargetPath = $env:TACHYON_LNK_TARGET; $sc.Arguments = $env:TACHYON_LNK_ARGS; $sc.WorkingDirectory = $env:TACHYON_LNK_WORKDIR; $sc.IconLocation = "$($env:TACHYON_LNK_ICON),0"; $sc.Description = $env:TACHYON_LNK_DESC; $sc.Save()"#;
    let out = Command::new("powershell")
        .env("TACHYON_LNK_PATH", lnk_path)
        .env("TACHYON_LNK_TARGET", target_path)
        .env("TACHYON_LNK_ARGS", args)
        .env("TACHYON_LNK_WORKDIR", working_dir)
        .env("TACHYON_LNK_ICON", icon_path)
        .env("TACHYON_LNK_DESC", description)
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Ошибка запуска PowerShell для создания ярлыка: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "Не удалось создать ярлык {}: {}",
            lnk_path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_add_sz(key: &str, value_name: Option<&str>, data: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let mut args = vec!["add", key];
    if let Some(name) = value_name {
        args.push("/v");
        args.push(name);
    } else {
        args.push("/ve");
    }
    args.extend(["/t", "REG_SZ", "/d", data, "/f"]);

    let status = Command::new("reg")
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("Ошибка вызова reg.exe: {e}"))?;
    if !status.success() {
        return Err(format!("Не удалось записать ключ реестра {key}"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_add_dword(key: &str, value_name: &str, data: u32) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let data_str = data.to_string();
    let status = Command::new("reg")
        .args([
            "add",
            key,
            "/v",
            value_name,
            "/t",
            "REG_DWORD",
            "/d",
            &data_str,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("Ошибка вызова reg.exe: {e}"))?;
    if !status.success() {
        return Err(format!("Не удалось записать DWORD {value_name} в {key}"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_delete_key(key: &str) {
    use std::os::windows::process::CommandExt;
    let _ = Command::new("reg")
        .args(["delete", key, "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(target_os = "windows")]
fn register_uninstall_entry(
    install_dir: &Path,
    target_exe: &Path,
    estimated_kb: u32,
) -> Result<(), String> {
    let icon = format!("{},0", target_exe.display());
    let uninstall_cmd = format!("\"{}\" --uninstall", target_exe.display());
    let quiet_uninstall_cmd = format!("\"{}\" --uninstall --silent", target_exe.display());

    reg_add_sz(UNINSTALL_REG_KEY_CU, Some("DisplayName"), "Tachyon")?;
    reg_add_sz(
        UNINSTALL_REG_KEY_CU,
        Some("DisplayVersion"),
        env!("CARGO_PKG_VERSION"),
    )?;
    reg_add_sz(UNINSTALL_REG_KEY_CU, Some("Publisher"), "Dushnilin")?;
    reg_add_sz(UNINSTALL_REG_KEY_CU, Some("DisplayIcon"), &icon)?;
    reg_add_sz(
        UNINSTALL_REG_KEY_CU,
        Some("InstallLocation"),
        &install_dir.to_string_lossy(),
    )?;
    reg_add_sz(
        UNINSTALL_REG_KEY_CU,
        Some("UninstallString"),
        &uninstall_cmd,
    )?;
    reg_add_sz(
        UNINSTALL_REG_KEY_CU,
        Some("QuietUninstallString"),
        &quiet_uninstall_cmd,
    )?;
    reg_add_sz(
        UNINSTALL_REG_KEY_CU,
        Some("URLInfoAbout"),
        "https://github.com/Dushnilin/tachyon-desktop",
    )?;
    reg_add_dword(UNINSTALL_REG_KEY_CU, "NoModify", 1)?;
    reg_add_dword(UNINSTALL_REG_KEY_CU, "NoRepair", 1)?;
    reg_add_dword(UNINSTALL_REG_KEY_CU, "EstimatedSize", estimated_kb.max(1))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn register_uri_scheme(target_exe: &Path) -> Result<(), String> {
    let icon = format!("\"{}\",0", target_exe.display());
    let cmd = format!("\"{}\" \"%1\"", target_exe.display());
    let icon_key = format!(r"{URI_SCHEME_REG_KEY}\DefaultIcon");
    let cmd_key = format!(r"{URI_SCHEME_REG_KEY}\shell\open\command");

    reg_add_sz(URI_SCHEME_REG_KEY, None, "URL:Tachyon Protocol")?;
    reg_add_sz(URI_SCHEME_REG_KEY, Some("URL Protocol"), "")?;
    reg_add_sz(&icon_key, None, &icon)?;
    reg_add_sz(&cmd_key, None, &cmd)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn add_firewall_rule(target_exe: &Path) -> bool {
    use std::os::windows::process::CommandExt;

    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=Tachyon"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    let prog_arg = format!("program={}", target_exe.display());
    let in_ok = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Tachyon",
            "dir=in",
            "action=allow",
            &prog_arg,
            "enable=yes",
            "profile=any",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let out_ok = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Tachyon",
            "dir=out",
            "action=allow",
            &prog_arg,
            "enable=yes",
            "profile=any",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    in_ok || out_ok
}

#[cfg(target_os = "windows")]
fn delete_firewall_rules() {
    use std::os::windows::process::CommandExt;
    for rule_name in ["Tachyon", "tachyon_killswitch", "Tachyon_KS_Block"] {
        let arg = format!("name={rule_name}");
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &arg])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
}

#[cfg(target_os = "windows")]
fn update_user_path(dir: &Path, add: bool) {
    use std::os::windows::process::CommandExt;

    let ps = r#"
$target = $env:TACHYON_PATH_ENTRY.Trim().TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($target)) { exit 0 }
$cur = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -eq $cur) { $cur = '' }
$parts = @()
foreach ($p in ($cur -split ';')) {
    $clean = $p.Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { continue }
    if ($clean.TrimEnd('\').Equals($target, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    $parts += $clean
}
if ($env:TACHYON_PATH_ADD -eq '1') {
    $parts += $target
}
$next = ($parts -join ';')
[Environment]::SetEnvironmentVariable('Path', $next, 'User')
"#;

    let _ = Command::new("powershell")
        .env("TACHYON_PATH_ENTRY", dir)
        .env("TACHYON_PATH_ADD", if add { "1" } else { "0" })
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(target_os = "windows")]
fn remove_windows_shortcuts() {
    let (desktop, programs) = special_folders();
    let _ = fs::remove_file(desktop.join("Tachyon.lnk"));
    let start_dir = programs.join("Tachyon");
    if start_dir.exists() {
        let _ = fs::remove_dir_all(&start_dir);
    }
}

#[cfg(target_os = "windows")]
fn pick_folder_dialog(initial: &Path) -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;

    let ps = r#"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.ShowNewFolderButton = $true
if (-not [string]::IsNullOrWhiteSpace($env:TACHYON_INIT_DIR) -and (Test-Path -LiteralPath $env:TACHYON_INIT_DIR)) {
    $d.SelectedPath = $env:TACHYON_INIT_DIR
}
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    Write-Output $d.SelectedPath
}
"#;
    let out = Command::new("powershell")
        .env("TACHYON_INIT_DIR", initial)
        .args([
            "-NoProfile",
            "-Sta",
            "-WindowStyle",
            "Hidden",
            "-Command",
            ps,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let selected = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if selected.is_empty() {
        None
    } else {
        Some(PathBuf::from(selected))
    }
}

#[cfg(target_os = "windows")]
fn perform_install_internal(
    opts: &InstallOptions,
    allow_uac: bool,
    on_progress: &dyn Fn(u8, &str),
) -> Result<InstallReport, String> {
    if opts.install_dir.as_os_str().is_empty() {
        return Err("Не указан каталог установки".to_string());
    }

    on_progress(12, "Остановка активных процессов Tachyon...");
    stop_other_tachyon_processes();

    let target_exe = opts.install_dir.join("Tachyon.exe");
    let mut used_uac = false;

    on_progress(32, "Копирование исполняемого файла...");
    let copied_len =
        match fs::create_dir_all(&opts.install_dir).and_then(|_| copy_clean_binary(&target_exe)) {
            Ok(len) => len,
            Err(err) if allow_uac && is_permission_denied(&err) => {
                on_progress(40, "Запрос прав администратора для записи в каталог...");
                let mut uac_args = vec![
                    "--install-silent".to_string(),
                    "--dir".to_string(),
                    opts.install_dir.to_string_lossy().to_string(),
                    "--elevated".to_string(),
                    "--no-launch".to_string(),
                ];
                if !opts.create_desktop_shortcut {
                    uac_args.push("--no-desktop".to_string());
                }
                if !opts.create_start_menu {
                    uac_args.push("--no-start-menu".to_string());
                }
                if !opts.register_uri_scheme {
                    uac_args.push("--no-uri".to_string());
                }
                if !opts.add_firewall_rule {
                    uac_args.push("--no-firewall".to_string());
                }
                uac_args.push(if opts.add_to_path {
                    "--add-path".to_string()
                } else {
                    "--no-path".to_string()
                });
                uac_args.push(if opts.autostart {
                    "--autostart".to_string()
                } else {
                    "--no-autostart".to_string()
                });
                run_elevated_self(&uac_args)?;
                used_uac = true;
                fs::metadata(&target_exe)
                    .map(|m| m.len() as usize)
                    .unwrap_or(18 * 1024 * 1024)
            }
            Err(err) => {
                return Err(format!(
                    "Не удалось установить файл в {}: {err}",
                    target_exe.display()
                ));
            }
        };

    on_progress(58, "Создание ярлыков...");
    let (desktop_dir, programs_dir) = special_folders();
    if opts.create_desktop_shortcut {
        create_windows_shortcut(
            &desktop_dir.join("Tachyon.lnk"),
            &target_exe,
            "",
            &opts.install_dir,
            &target_exe,
            "Tachyon — клиент маршрутизации и туннелирования",
        )?;
    }
    if opts.create_start_menu {
        let start_dir = programs_dir.join("Tachyon");
        create_windows_shortcut(
            &start_dir.join("Tachyon.lnk"),
            &target_exe,
            "",
            &opts.install_dir,
            &target_exe,
            "Tachyon — клиент маршрутизации и туннелирования",
        )?;
        create_windows_shortcut(
            &start_dir.join("Удалить Tachyon.lnk"),
            &target_exe,
            "--uninstall",
            &opts.install_dir,
            &target_exe,
            "Удаление Tachyon с компьютера",
        )?;
    }

    on_progress(74, "Регистрация в Windows...");
    let estimated_kb = (copied_len / 1024).max(1) as u32;
    register_uninstall_entry(&opts.install_dir, &target_exe, estimated_kb)?;

    if opts.register_uri_scheme {
        register_uri_scheme(&target_exe)?;
    }

    on_progress(86, "Настройка сети и переменных среды...");
    let firewall_ok = if opts.add_firewall_rule {
        add_firewall_rule(&target_exe)
    } else {
        false
    };

    update_user_path(&opts.install_dir, opts.add_to_path);

    crate::set_autostart_for_exe(&target_exe, opts.autostart);
    let mut persisted = PersistedState::load();
    if persisted.vpn_prefs.autostart != opts.autostart {
        persisted.vpn_prefs.autostart = opts.autostart;
        persisted.save();
    }

    on_progress(100, "Установка завершена");
    Ok(InstallReport {
        installed_exe: target_exe,
        used_uac,
        firewall_ok,
    })
}

#[cfg(target_os = "windows")]
fn schedule_self_delete(install_dir: &Path, target_exe: &Path) {
    use std::os::windows::process::CommandExt;

    let cmd_script = format!(
        "ping 127.0.0.1 -n 2 > nul & del /f /q \"{}\" > nul 2>&1 & rmdir /s /q \"{}\" > nul 2>&1",
        target_exe.display(),
        install_dir.display()
    );
    let _ = Command::new("cmd.exe")
        .args(["/C", &cmd_script])
        .current_dir(std::env::temp_dir())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

#[cfg(target_os = "windows")]
fn perform_uninstall_internal(
    purge_user_data: bool,
    dir_override: Option<PathBuf>,
    trigger_delayed_delete: bool,
    allow_uac: bool,
    on_progress: &dyn Fn(u8, &str),
) -> Result<UninstallTarget, String> {
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("Tachyon.exe"));
    let install_dir = dir_override
        .or_else(|| detect_existing_installation().map(|i| i.install_dir))
        .or_else(|| exe_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(default_user_install_dir);
    let target_exe = install_dir.join("Tachyon.exe");

    on_progress(15, "Остановка служб и процессов Tachyon...");
    stop_other_tachyon_processes();

    on_progress(35, "Сброс системного прокси и правил сети...");
    crate::vpn::set_system_proxy(false);
    crate::set_autostart_for_exe(&target_exe, false);
    delete_firewall_rules();

    on_progress(55, "Удаление записей реестра и ярлыков...");
    reg_delete_key(UNINSTALL_REG_KEY_CU);
    reg_delete_key(UNINSTALL_REG_KEY_LM);
    reg_delete_key(URI_SCHEME_REG_KEY);
    remove_windows_shortcuts();
    update_user_path(&install_dir, false);

    if purge_user_data {
        on_progress(72, "Удаление пользовательских настроек и кэша...");
        let local_data = crate::vpn::app_data_dir();
        if local_data.exists() {
            let _ = fs::remove_dir_all(&local_data);
        }
        if let Ok(roaming) = std::env::var("APPDATA") {
            let roaming_tachyon = PathBuf::from(roaming).join("tachyon");
            if roaming_tachyon.exists() {
                let _ = fs::remove_dir_all(&roaming_tachyon);
            }
        }
    }

    on_progress(88, "Удаление файлов программы...");
    let is_self_in_target = paths_equal_windows(&exe_path, &target_exe);
    let mut needs_delayed_delete = false;

    if install_dir.exists() {
        let probe = install_dir.join(".tachyon_uninst_probe");
        match File::create(&probe) {
            Ok(_) => {
                let _ = fs::remove_file(&probe);
                if is_self_in_target {
                    needs_delayed_delete = true;
                    if trigger_delayed_delete {
                        schedule_self_delete(&install_dir, &target_exe);
                    }
                } else {
                    if target_exe.exists() {
                        let _ = fs::remove_file(&target_exe);
                    }
                    if fs::remove_dir_all(&install_dir).is_err() {
                        needs_delayed_delete = true;
                        if trigger_delayed_delete {
                            schedule_self_delete(&install_dir, &target_exe);
                        }
                    }
                }
            }
            Err(err) if allow_uac && is_permission_denied(&err) => {
                let mut uac_args = vec![
                    "--uninstall".to_string(),
                    "--silent".to_string(),
                    "--elevated".to_string(),
                    "--dir".to_string(),
                    install_dir.to_string_lossy().to_string(),
                ];
                if purge_user_data {
                    uac_args.push("--purge".to_string());
                }
                if is_self_in_target && !trigger_delayed_delete {
                    needs_delayed_delete = true;
                } else {
                    run_elevated_self(&uac_args)?;
                }
            }
            Err(err) => {
                return Err(format!(
                    "Нет доступа для удаления каталога {}: {err}",
                    install_dir.display()
                ));
            }
        }
    }

    on_progress(100, "Удаление завершено");
    Ok(UninstallTarget {
        install_dir,
        target_exe,
        needs_delayed_delete,
    })
}

#[cfg(target_os = "windows")]
#[derive(Clone, PartialEq, Eq)]
enum InstallStage {
    Options,
    Working,
    Done,
    Error(String),
}

#[cfg(target_os = "windows")]
struct TachyonInstallerView {
    options: InstallOptions,
    dir_input: Entity<InputState>,
    _input_sub: Subscription,
    existing: Option<ExistingInstallInfo>,
    light_theme: bool,
    is_en: bool,
    stage: InstallStage,
    progress_pct: u8,
    progress_text: String,
    report: Option<InstallReport>,
    picking_folder: bool,
    worker_state: Arc<Mutex<InstallerWorkerState>>,
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct InstallerWorkerState {
    pct: u8,
    step: String,
    result: Option<Result<InstallReport, String>>,
    picked_folder: Option<Option<PathBuf>>,
}

#[cfg(target_os = "windows")]
impl TachyonInstallerView {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let state = PersistedState::load();
        crate::theme::sync_kit_theme(state.light_theme, cx);
        let options = InstallOptions::default_for_user();
        let initial_dir = options.install_dir.to_string_lossy().to_string();
        let existing = detect_existing_installation();
        let worker_state = Arc::new(Mutex::new(InstallerWorkerState::default()));

        let dir_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(initial_dir)
                .placeholder(r"C:\Users\...\Programs\Tachyon")
        });
        let input_sub = cx.subscribe_in(&dir_input, window, |this, state, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                let raw = state.read(cx).value().to_string();
                let trimmed = raw.trim();
                this.options.install_dir = if trimmed.is_empty() {
                    PathBuf::new()
                } else {
                    PathBuf::from(trimmed)
                };
                cx.notify();
            }
        });

        cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                let keep = this
                    .update_in(cx, |view, window, cx| {
                        view.poll_worker(window, cx);
                    })
                    .is_ok();
                if !keep {
                    break;
                }
            }
        })
        .detach();

        Self {
            options,
            dir_input,
            _input_sub: input_sub,
            existing,
            light_theme: state.light_theme,
            is_en: state.language.eq_ignore_ascii_case("en"),
            stage: InstallStage::Options,
            progress_pct: 0,
            progress_text: String::new(),
            report: None,
            picking_folder: false,
            worker_state,
        }
    }

    fn tr(&self, ru: &'static str, en: &'static str) -> &'static str {
        if self.is_en { en } else { ru }
    }

    fn poll_worker(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut changed = false;
        let mut finished: Option<Result<InstallReport, String>> = None;
        let mut picked: Option<Option<PathBuf>> = None;

        if let Ok(mut guard) = self.worker_state.lock() {
            if self.stage == InstallStage::Working {
                if self.progress_pct != guard.pct || self.progress_text != guard.step {
                    self.progress_pct = guard.pct;
                    self.progress_text = guard.step.clone();
                    changed = true;
                }
                if guard.result.is_some() {
                    finished = guard.result.take();
                }
            }
            if self.picking_folder && guard.picked_folder.is_some() {
                picked = guard.picked_folder.take();
            }
        }

        if let Some(pick_res) = picked {
            self.picking_folder = false;
            if let Some(path) = pick_res {
                let final_path = if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("tachyon"))
                {
                    path
                } else {
                    path.join("Tachyon")
                };
                self.options.install_dir = final_path.clone();
                let next_str = final_path.to_string_lossy().to_string();
                self.dir_input.update(cx, |s, cx| {
                    s.set_value(next_str, window, cx);
                });
            }
            changed = true;
        }

        if let Some(res) = finished {
            match res {
                Ok(rep) => {
                    self.progress_pct = 100;
                    self.report = Some(rep);
                    self.stage = InstallStage::Done;
                }
                Err(err) => {
                    self.stage = InstallStage::Error(err);
                }
            }
            changed = true;
        }

        if changed {
            cx.notify();
        }
    }

    fn start_install(&mut self, cx: &mut Context<Self>) {
        if self.stage == InstallStage::Working {
            return;
        }
        self.stage = InstallStage::Working;
        self.progress_pct = 5;
        self.progress_text = self
            .tr("Подготовка к установке...", "Preparing installation...")
            .to_string();
        if let Ok(mut guard) = self.worker_state.lock() {
            guard.pct = 5;
            guard.step = self.progress_text.clone();
            guard.result = None;
        }

        let opts = self.options.clone();
        let ws = self.worker_state.clone();
        std::thread::spawn(move || {
            let res = perform_install_internal(&opts, true, &|pct, step| {
                if let Ok(mut g) = ws.lock() {
                    g.pct = pct;
                    g.step = step.to_string();
                }
            });
            if let Ok(mut g) = ws.lock() {
                g.result = Some(res);
            }
        });
        cx.notify();
    }

    fn browse_folder(&mut self, cx: &mut Context<Self>) {
        if self.picking_folder || self.stage == InstallStage::Working {
            return;
        }
        self.picking_folder = true;
        if let Ok(mut guard) = self.worker_state.lock() {
            guard.picked_folder = None;
        }
        let init_dir = self.options.install_dir.clone();
        let ws = self.worker_state.clone();
        std::thread::spawn(move || {
            let picked = pick_folder_dialog(&init_dir);
            if let Ok(mut g) = ws.lock() {
                g.picked_folder = Some(picked);
            }
        });
        cx.notify();
    }

    fn render_option_card<F>(
        &self,
        id: &'static str,
        title: &'static str,
        subtitle: &'static str,
        checked: bool,
        t: Theme,
        on_click: F,
    ) -> impl IntoElement
    where
        F: Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
    {
        div()
            .id(id)
            .flex_1()
            .p(px(10.0))
            .rounded(px(8.0))
            .bg(t.bg_elev)
            .border_1()
            .border_color(if checked { t.accent_border } else { t.border })
            .hover(|s| s.bg(t.bg_hover))
            .cursor_pointer()
            .on_click(on_click)
            .flex()
            .items_center()
            .justify_between()
            .gap(px(8.0))
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .text_size(px(11.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text)
                            .child(title),
                    )
                    .child(
                        div()
                            .text_size(px(9.5))
                            .text_color(t.text_dim)
                            .child(subtitle),
                    ),
            )
            .child(
                div()
                    .w(px(30.0))
                    .h(px(16.0))
                    .p(px(2.0))
                    .rounded(px(8.0))
                    .bg(if checked { t.accent } else { t.bg_card })
                    .flex()
                    .items_center()
                    .justify_end()
                    .when(!checked, |el| el.justify_start())
                    .child(
                        div()
                            .w(px(12.0))
                            .h(px(12.0))
                            .rounded(px(6.0))
                            .bg(if checked {
                                gpui::rgb(0x0B0B0D)
                            } else {
                                t.text_dim
                            }),
                    ),
            )
    }

    fn render_titlebar(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let app_ver = env!("CARGO_PKG_VERSION");
        div()
            .h(px(44.0))
            .w_full()
            .bg(t.bg_card)
            .border_b_1()
            .border_color(t.border)
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .id("inst-titlebar-drag")
                    .flex_1()
                    .h_full()
                    .pl(px(16.0))
                    .pr(px(8.0))
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .window_control_area(WindowControlArea::Drag)
                    .child(
                        div()
                            .w(px(26.0))
                            .h(px(26.0))
                            .rounded(px(7.0))
                            .bg(t.accent_bg)
                            .border_1()
                            .border_color(t.accent_border)
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(
                                svg()
                                    .path("icons/bolt.svg")
                                    .size(px(14.0))
                                    .text_color(t.accent),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr("Установка Tachyon", "Tachyon Setup")),
                            )
                            .child(
                                div()
                                    .px(px(6.0))
                                    .py(px(1.0))
                                    .rounded(px(4.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .text_size(px(10.0))
                                    .text_color(t.text_dim)
                                    .child(format!("v{app_ver}")),
                            ),
                    ),
            )
            .child(
                div()
                    .pr(px(12.0))
                    .h_full()
                    .occlude()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        div()
                            .id("inst-lang-toggle")
                            .h(px(26.0))
                            .px(px(7.0))
                            .rounded(px(6.0))
                            .bg(t.bg_elev)
                            .border_1()
                            .border_color(t.border)
                            .hover(|s| s.bg(t.bg_hover))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(10.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(t.accent)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.is_en = !this.is_en;
                                cx.notify();
                            }))
                            .child(if self.is_en { "EN" } else { "RU" }),
                    )
                    .child(
                        div()
                            .id("inst-theme-toggle")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.bg_hover))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.light_theme = !this.light_theme;
                                crate::theme::sync_kit_theme(this.light_theme, cx);
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path(if t.is_light {
                                        "icons/moon.svg"
                                    } else {
                                        "icons/sun.svg"
                                    })
                                    .size(px(13.0))
                                    .text_color(t.text_dim),
                            ),
                    )
                    .child(
                        div()
                            .id("inst-win-min")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.bg_hover))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(|_, window, _| {
                                window.minimize_window();
                            })
                            .child(
                                svg()
                                    .path("icons/min.svg")
                                    .size(px(12.0))
                                    .text_color(t.text_dim),
                            ),
                    )
                    .child(
                        div()
                            .id("inst-win-close")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.red_bg))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(|_, _, _| {
                                std::process::exit(0);
                            })
                            .child(
                                svg()
                                    .path("icons/close.svg")
                                    .size(px(12.0))
                                    .text_color(t.text_dim),
                            ),
                    ),
            )
    }
}

#[cfg(target_os = "windows")]
impl Render for TachyonInstallerView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = Theme::for_mode(self.light_theme);
        let user_dir = default_user_install_dir();
        let sys_dir = default_system_install_dir();
        let is_user_preset = paths_equal_windows(&self.options.install_dir, &user_dir);
        let is_sys_preset = paths_equal_windows(&self.options.install_dir, &sys_dir);
        let core_ver = option_env!("TACHYON_CORE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));

        let status_label = match &self.existing {
            Some(ex) => {
                if let Some(ver) = &ex.version {
                    if self.is_en {
                        format!(
                            "Installed copy found: v{ver} ({}) — will be updated",
                            ex.install_dir.display()
                        )
                    } else {
                        format!(
                            "Найдена установленная версия v{ver} ({}) — будет обновлена",
                            ex.install_dir.display()
                        )
                    }
                } else if self.is_en {
                    format!(
                        "Existing binary found in {} — will be updated",
                        ex.install_dir.display()
                    )
                } else {
                    format!(
                        "Найдена копия в {} — будет обновлена",
                        ex.install_dir.display()
                    )
                }
            }
            None => self
                .tr(
                    "Новая установка на компьютер (ядро tachyon-core встроено в бинарник)",
                    "Fresh system installation (tachyon-core engine embedded in binary)",
                )
                .to_string(),
        };

        div()
            .w_full()
            .h_full()
            .bg(t.bg)
            .text_color(t.text)
            .border_1()
            .border_color(t.border)
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(self.render_titlebar(t, cx))
            .child(
                div()
                    .flex_1()
                    .p(px(16.0))
                    .flex()
                    .flex_col()
                    .gap(px(12.0))
                    .child(
                        div()
                            .w_full()
                            .p(px(12.0))
                            .rounded(px(10.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap(px(12.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .text_size(px(13.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Клиент маршрутизации и туннелирования Tachyon",
                                                "Tachyon Routing & Tunneling Client",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(status_label),
                                    ),
                            )
                            .child(
                                div()
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .text_size(px(10.0))
                                    .text_color(t.text_soft)
                                    .child(format!("core {core_ver}")),
                            ),
                    )
                    .when(self.stage == InstallStage::Options, |el| {
                        el.child(
                            div()
                                .w_full()
                                .p(px(12.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .gap(px(8.0))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.text)
                                        .child(self.tr("Каталог установки", "Installation Directory")),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .gap(px(8.0))
                                        .child(
                                            div()
                                                .id("preset-user-dir")
                                                .flex_1()
                                                .p(px(8.0))
                                                .rounded(px(8.0))
                                                .bg(if is_user_preset { t.accent_bg } else { t.bg_elev })
                                                .border_1()
                                                .border_color(if is_user_preset {
                                                    t.accent_border
                                                } else {
                                                    t.border
                                                })
                                                .hover(|s| s.bg(t.bg_hover))
                                                .cursor_pointer()
                                                .on_click(cx.listener(move |this, _, window, cx| {
                                                    let dir = default_user_install_dir();
                                                    this.options.install_dir = dir.clone();
                                                    this.dir_input.update(cx, |s, cx| {
                                                        s.set_value(
                                                            dir.to_string_lossy().to_string(),
                                                            window,
                                                            cx,
                                                        );
                                                    });
                                                    cx.notify();
                                                }))
                                                .flex()
                                                .flex_col()
                                                .gap(px(2.0))
                                                .child(
                                                    div()
                                                        .text_size(px(11.0))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .text_color(if is_user_preset {
                                                            t.accent
                                                        } else {
                                                            t.text
                                                        })
                                                        .child(self.tr(
                                                            "Текущий пользователь",
                                                            "Current User",
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(9.5))
                                                        .text_color(t.text_dim)
                                                        .child(self.tr(
                                                            "%LOCALAPPDATA%\\Programs\\Tachyon (без UAC)",
                                                            "%LOCALAPPDATA%\\Programs\\Tachyon (no UAC)",
                                                        )),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .id("preset-sys-dir")
                                                .flex_1()
                                                .p(px(8.0))
                                                .rounded(px(8.0))
                                                .bg(if is_sys_preset { t.accent_bg } else { t.bg_elev })
                                                .border_1()
                                                .border_color(if is_sys_preset {
                                                    t.accent_border
                                                } else {
                                                    t.border
                                                })
                                                .hover(|s| s.bg(t.bg_hover))
                                                .cursor_pointer()
                                                .on_click(cx.listener(move |this, _, window, cx| {
                                                    let dir = default_system_install_dir();
                                                    this.options.install_dir = dir.clone();
                                                    this.dir_input.update(cx, |s, cx| {
                                                        s.set_value(
                                                            dir.to_string_lossy().to_string(),
                                                            window,
                                                            cx,
                                                        );
                                                    });
                                                    cx.notify();
                                                }))
                                                .flex()
                                                .flex_col()
                                                .gap(px(2.0))
                                                .child(
                                                    div()
                                                        .text_size(px(11.0))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .text_color(if is_sys_preset {
                                                            t.accent
                                                        } else {
                                                            t.text
                                                        })
                                                        .child(self.tr(
                                                            "Все пользователи (Program Files)",
                                                            "All Users (Program Files)",
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(9.5))
                                                        .text_color(t.text_dim)
                                                        .child(self.tr(
                                                            "Потребуется подтверждение UAC",
                                                            "Requires administrator (UAC)",
                                                        )),
                                                ),
                                        ),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .items_center()
                                        .gap(px(8.0))
                                        .child(
                                            div().flex_1().h(px(34.0)).child(
                                                Styled::h(
                                                    Input::new(&self.dir_input)
                                                        .small()
                                                        .cleanable(true)
                                                        .text_size(px(11.5))
                                                        .bg(t.bg_elev)
                                                        .border_color(t.border)
                                                        .rounded(px(8.0)),
                                                    px(34.0),
                                                ),
                                            ),
                                        )
                                        .child(
                                            div()
                                                .id("btn-browse-dir")
                                                .h(px(34.0))
                                                .px(px(12.0))
                                                .rounded(px(8.0))
                                                .bg(t.bg_elev)
                                                .border_1()
                                                .border_color(t.border)
                                                .hover(|s| s.bg(t.bg_hover))
                                                .cursor_pointer()
                                                .flex()
                                                .items_center()
                                                .gap(px(6.0))
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.browse_folder(cx);
                                                }))
                                                .child(
                                                    svg()
                                                        .path("icons/folder.svg")
                                                        .size(px(13.0))
                                                        .text_color(t.text_dim),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(11.5))
                                                        .font_weight(FontWeight::MEDIUM)
                                                        .text_color(t.text_soft)
                                                        .child(if self.picking_folder {
                                                            self.tr("Выбор...", "Browsing...")
                                                        } else {
                                                            self.tr("Обзор...", "Browse...")
                                                        }),
                                                ),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .w_full()
                                .p(px(12.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .gap(px(8.0))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.text)
                                        .child(self.tr(
                                            "Интеграция в систему",
                                            "System Integration",
                                        )),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .gap(px(8.0))
                                        .child(self.render_option_card(
                                            "opt-desktop-lnk",
                                            self.tr("Ярлык на Рабочем столе", "Desktop Shortcut"),
                                            self.tr("Создать Tachyon.lnk", "Create Tachyon.lnk"),
                                            self.options.create_desktop_shortcut,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.create_desktop_shortcut =
                                                    !this.options.create_desktop_shortcut;
                                                cx.notify();
                                            }),
                                        ))
                                        .child(self.render_option_card(
                                            "opt-start-menu",
                                            self.tr("Меню «Пуск»", "Start Menu"),
                                            self.tr(
                                                "Запуск и деинсталлятор",
                                                "App & Uninstaller links",
                                            ),
                                            self.options.create_start_menu,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.create_start_menu =
                                                    !this.options.create_start_menu;
                                                cx.notify();
                                            }),
                                        )),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .gap(px(8.0))
                                        .child(self.render_option_card(
                                            "opt-uri-scheme",
                                            self.tr("Ссылки tachyon://", "tachyon:// URI Scheme"),
                                            self.tr(
                                                "Открытие профилей из браузера",
                                                "Import links from browser",
                                            ),
                                            self.options.register_uri_scheme,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.register_uri_scheme =
                                                    !this.options.register_uri_scheme;
                                                cx.notify();
                                            }),
                                        ))
                                        .child(self.render_option_card(
                                            "opt-firewall-rule",
                                            self.tr("Правило брандмауэра", "Firewall Exception"),
                                            self.tr(
                                                "Разрешить трафик ядра",
                                                "Allow core network traffic",
                                            ),
                                            self.options.add_firewall_rule,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.add_firewall_rule =
                                                    !this.options.add_firewall_rule;
                                                cx.notify();
                                            }),
                                        )),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .gap(px(8.0))
                                        .child(self.render_option_card(
                                            "opt-add-path",
                                            self.tr("Добавить в PATH", "Add to User PATH"),
                                            self.tr(
                                                "Запуск tachyon из консоли",
                                                "Run tachyon from terminal",
                                            ),
                                            self.options.add_to_path,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.add_to_path =
                                                    !this.options.add_to_path;
                                                cx.notify();
                                            }),
                                        ))
                                        .child(self.render_option_card(
                                            "opt-autostart-win",
                                            self.tr("Автозапуск с Windows", "Launch at Startup"),
                                            self.tr(
                                                "Старт при входе в систему",
                                                "Start when signing in",
                                            ),
                                            self.options.autostart,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.autostart = !this.options.autostart;
                                                cx.notify();
                                            }),
                                        )),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .child(self.render_option_card(
                                            "opt-launch-after",
                                            self.tr(
                                                "Запустить Tachyon после завершения установки",
                                                "Launch Tachyon after installation completes",
                                            ),
                                            self.tr(
                                                "Открыть установленный клиент автоматически",
                                                "Start the installed application automatically",
                                            ),
                                            self.options.launch_after,
                                            t,
                                            cx.listener(|this, _, _, cx| {
                                                this.options.launch_after =
                                                    !this.options.launch_after;
                                                cx.notify();
                                            }),
                                        )),
                                ),
                        )
                    })
                    .when(self.stage == InstallStage::Working, |el| {
                        let pct = self.progress_pct.min(100) as f32 / 100.0;
                        el.child(
                            div()
                                .flex_1()
                                .p(px(20.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .justify_center()
                                .gap(px(14.0))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .child(
                                            div()
                                                .text_size(px(13.0))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(t.text)
                                                .child(self.progress_text.clone()),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(12.0))
                                                .font_weight(FontWeight::BOLD)
                                                .text_color(t.accent)
                                                .child(format!("{}%", self.progress_pct)),
                                        ),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .h(px(8.0))
                                        .rounded(px(4.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .overflow_hidden()
                                        .child(
                                            div()
                                                .h_full()
                                                .w(gpui::relative(pct))
                                                .rounded(px(4.0))
                                                .bg(t.accent),
                                        ),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.0))
                                        .text_color(t.text_dim)
                                        .child(format!("-> {}", self.options.install_dir.display())),
                                ),
                        )
                    })
                    .when(self.stage == InstallStage::Done, |el| {
                        let fw_note = match &self.report {
                            Some(r) if self.options.add_firewall_rule && !r.firewall_ok => self.tr(
                                "Правило брандмауэра не добавлено (требуется запуск от администратора); ярлыки и запись в списке программ созданы.",
                                "Firewall rule skipped (requires administrator); shortcuts and Apps registry entry created.",
                            ),
                            Some(r) if r.used_uac => self.tr(
                                "Установка выполнена с повышением прав (UAC).",
                                "Installed using administrator elevation (UAC).",
                            ),
                            _ => self.tr(
                                "Приложение зарегистрировано в меню «Установленные приложения» Windows.",
                                "Registered in Windows Installed Apps.",
                            ),
                        };
                        el.child(
                            div()
                                .flex_1()
                                .p(px(20.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.green_border)
                                .flex()
                                .flex_col()
                                .justify_center()
                                .gap(px(12.0))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(10.0))
                                        .child(
                                            div()
                                                .w(px(32.0))
                                                .h(px(32.0))
                                                .rounded(px(8.0))
                                                .bg(t.green_bg)
                                                .border_1()
                                                .border_color(t.green_border)
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .child(
                                                    svg()
                                                        .path("icons/check.svg")
                                                        .size(px(16.0))
                                                        .text_color(t.green),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(15.0))
                                                .font_weight(FontWeight::BOLD)
                                                .text_color(t.text)
                                                .child(self.tr(
                                                    "Установка успешно завершена",
                                                    "Installation Completed",
                                                )),
                                        ),
                                )
                                .child(
                                    div()
                                        .p(px(10.0))
                                        .rounded(px(8.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .text_size(px(11.5))
                                        .text_color(t.text_soft)
                                        .child(
                                            self.report
                                                .as_ref()
                                                .map(|r| r.installed_exe.to_string_lossy().to_string())
                                                .unwrap_or_default(),
                                        ),
                                )
                                .child(div().text_size(px(11.0)).text_color(t.text_dim).child(fw_note)),
                        )
                    })
                    .when_some(
                        match &self.stage {
                            InstallStage::Error(e) => Some(e.clone()),
                            _ => None,
                        },
                        |el, err_msg| {
                            el.child(
                                div()
                                    .flex_1()
                                    .p(px(20.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.red_border)
                                    .flex()
                                    .flex_col()
                                    .justify_center()
                                    .gap(px(10.0))
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.red)
                                            .child(self.tr("Ошибка установки", "Installation Failed")),
                                    )
                                    .child(
                                        div()
                                            .p(px(10.0))
                                            .rounded(px(8.0))
                                            .bg(t.red_bg)
                                            .border_1()
                                            .border_color(t.red_border)
                                            .text_size(px(11.5))
                                            .text_color(t.text)
                                            .child(err_msg),
                                    ),
                            )
                        },
                    ),
            )
            .child(
                div()
                    .h(px(56.0))
                    .w_full()
                    .px(px(16.0))
                    .bg(t.bg_card)
                    .border_t_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(10.5))
                            .text_color(t.text_mute)
                            .child("Tachyon Setup · Windows x86_64"),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .when(self.stage == InstallStage::Options, |el| {
                                el.child(
                                    div()
                                        .id("btn-inst-cancel")
                                        .px(px(14.0))
                                        .py(px(7.0))
                                        .rounded(px(8.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .hover(|s| s.bg(t.bg_hover))
                                        .cursor_pointer()
                                        .text_size(px(12.0))
                                        .text_color(t.text_soft)
                                        .on_click(|_, _, _| {
                                            std::process::exit(0);
                                        })
                                        .child(self.tr("Отмена", "Cancel")),
                                )
                                .child(
                                    div()
                                        .id("btn-inst-start")
                                        .px(px(18.0))
                                        .py(px(7.0))
                                        .rounded(px(8.0))
                                        .bg(t.accent)
                                        .hover(|s| s.bg(t.accent_2))
                                        .cursor_pointer()
                                        .text_size(px(12.0))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(gpui::rgb(0x0B0B0D))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.start_install(cx);
                                        }))
                                        .child(if self.existing.is_some() {
                                            self.tr("Обновить", "Update")
                                        } else {
                                            self.tr("Установить", "Install")
                                        }),
                                )
                            })
                            .when(matches!(self.stage, InstallStage::Error(_)), |el| {
                                el.child(
                                    div()
                                        .id("btn-inst-back")
                                        .px(px(14.0))
                                        .py(px(7.0))
                                        .rounded(px(8.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .hover(|s| s.bg(t.bg_hover))
                                        .cursor_pointer()
                                        .text_size(px(12.0))
                                        .text_color(t.text)
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.stage = InstallStage::Options;
                                            cx.notify();
                                        }))
                                        .child(self.tr("Назад", "Back")),
                                )
                                .child(
                                    div()
                                        .id("btn-inst-exit-err")
                                        .px(px(14.0))
                                        .py(px(7.0))
                                        .rounded(px(8.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .hover(|s| s.bg(t.bg_hover))
                                        .cursor_pointer()
                                        .text_size(px(12.0))
                                        .text_color(t.text_soft)
                                        .on_click(|_, _, _| {
                                            std::process::exit(1);
                                        })
                                        .child(self.tr("Закрыть", "Close")),
                                )
                            })
                            .when(self.stage == InstallStage::Done, |el| {
                                let installed_exe = self
                                    .report
                                    .as_ref()
                                    .map(|r| r.installed_exe.clone());
                                let should_launch = self.options.launch_after;
                                el.child(
                                    div()
                                        .id("btn-inst-close-only")
                                        .px(px(14.0))
                                        .py(px(7.0))
                                        .rounded(px(8.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .hover(|s| s.bg(t.bg_hover))
                                        .cursor_pointer()
                                        .text_size(px(12.0))
                                        .text_color(t.text_soft)
                                        .on_click(|_, _, _| {
                                            std::process::exit(0);
                                        })
                                        .child(self.tr("Закрыть", "Close")),
                                )
                                .when(installed_exe.is_some(), |row| {
                                    let exe = installed_exe.unwrap();
                                    row.child(
                                        div()
                                            .id("btn-inst-finish-launch")
                                            .px(px(18.0))
                                            .py(px(7.0))
                                            .rounded(px(8.0))
                                            .bg(t.green)
                                            .cursor_pointer()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(gpui::rgb(0x0B0B0D))
                                            .on_click(move |_, _, _| {
                                                let _ = Command::new(&exe).spawn();
                                                std::process::exit(0);
                                            })
                                            .child(if should_launch {
                                                self.tr("Запустить Tachyon", "Launch Tachyon")
                                            } else {
                                                self.tr("Запустить", "Launch")
                                            }),
                                    )
                                })
                            }),
                    ),
            )
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, PartialEq, Eq)]
enum UninstallStage {
    Confirm,
    Working,
    Done,
    Error(String),
}

#[cfg(target_os = "windows")]
struct TachyonUninstallerView {
    install_dir: PathBuf,
    purge_user_data: bool,
    light_theme: bool,
    is_en: bool,
    stage: UninstallStage,
    progress_pct: u8,
    progress_text: String,
    target: Option<UninstallTarget>,
    worker_state: Arc<Mutex<UninstallerWorkerState>>,
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct UninstallerWorkerState {
    pct: u8,
    step: String,
    result: Option<Result<UninstallTarget, String>>,
}

#[cfg(target_os = "windows")]
impl TachyonUninstallerView {
    fn new(cx: &mut Context<Self>) -> Self {
        let state = PersistedState::load();
        crate::theme::sync_kit_theme(state.light_theme, cx);
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("Tachyon.exe"));
        let install_dir = detect_existing_installation()
            .map(|i| i.install_dir)
            .or_else(|| exe_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(default_user_install_dir);
        let worker_state = Arc::new(Mutex::new(UninstallerWorkerState::default()));

        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                let keep = this
                    .update(cx, |view, cx| {
                        view.poll_worker(cx);
                    })
                    .is_ok();
                if !keep {
                    break;
                }
            }
        })
        .detach();

        Self {
            install_dir,
            purge_user_data: false,
            light_theme: state.light_theme,
            is_en: state.language.eq_ignore_ascii_case("en"),
            stage: UninstallStage::Confirm,
            progress_pct: 0,
            progress_text: String::new(),
            target: None,
            worker_state,
        }
    }

    fn tr(&self, ru: &'static str, en: &'static str) -> &'static str {
        if self.is_en { en } else { ru }
    }

    fn poll_worker(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        let mut finished: Option<Result<UninstallTarget, String>> = None;

        if self.stage == UninstallStage::Working {
            if let Ok(mut guard) = self.worker_state.lock() {
                if self.progress_pct != guard.pct || self.progress_text != guard.step {
                    self.progress_pct = guard.pct;
                    self.progress_text = guard.step.clone();
                    changed = true;
                }
                if guard.result.is_some() {
                    finished = guard.result.take();
                }
            }
        }

        if let Some(res) = finished {
            match res {
                Ok(target) => {
                    self.progress_pct = 100;
                    self.target = Some(target);
                    self.stage = UninstallStage::Done;
                }
                Err(err) => {
                    self.stage = UninstallStage::Error(err);
                }
            }
            changed = true;
        }

        if changed {
            cx.notify();
        }
    }

    fn start_uninstall(&mut self, cx: &mut Context<Self>) {
        if self.stage == UninstallStage::Working {
            return;
        }
        self.stage = UninstallStage::Working;
        self.progress_pct = 5;
        self.progress_text = self
            .tr("Подготовка к удалению...", "Preparing uninstallation...")
            .to_string();
        if let Ok(mut guard) = self.worker_state.lock() {
            guard.pct = 5;
            guard.step = self.progress_text.clone();
            guard.result = None;
        }

        let purge = self.purge_user_data;
        let dir = self.install_dir.clone();
        let ws = self.worker_state.clone();
        std::thread::spawn(move || {
            let res = perform_uninstall_internal(purge, Some(dir), false, true, &|pct, step| {
                if let Ok(mut g) = ws.lock() {
                    g.pct = pct;
                    g.step = step.to_string();
                }
            });
            if let Ok(mut g) = ws.lock() {
                g.result = Some(res);
            }
        });
        cx.notify();
    }

    fn finish_and_exit(&self) {
        if let Some(tgt) = &self.target {
            if tgt.needs_delayed_delete {
                let exe_path = std::env::current_exe().unwrap_or_default();
                let is_self_in_target = paths_equal_windows(&exe_path, &tgt.target_exe);
                if is_self_in_target && tgt.install_dir.exists() {
                    let probe = tgt.install_dir.join(".tachyon_uninst_probe");
                    match File::create(&probe) {
                        Ok(_) => {
                            let _ = fs::remove_file(&probe);
                            schedule_self_delete(&tgt.install_dir, &tgt.target_exe);
                        }
                        Err(err) if is_permission_denied(&err) => {
                            let _ = run_elevated_self(&[
                                "--uninstall".to_string(),
                                "--silent".to_string(),
                                "--elevated".to_string(),
                                "--dir".to_string(),
                                tgt.install_dir.to_string_lossy().to_string(),
                            ]);
                        }
                        Err(_) => {}
                    }
                } else {
                    schedule_self_delete(&tgt.install_dir, &tgt.target_exe);
                }
            }
        }
        std::process::exit(0);
    }
}

#[cfg(target_os = "windows")]
impl Render for TachyonUninstallerView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = Theme::for_mode(self.light_theme);
        let dir_text = self.install_dir.to_string_lossy().to_string();

        div()
            .w_full()
            .h_full()
            .bg(t.bg)
            .text_color(t.text)
            .border_1()
            .border_color(t.border)
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(
                div()
                    .h(px(44.0))
                    .w_full()
                    .bg(t.bg_card)
                    .border_b_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .id("uninst-titlebar-drag")
                            .flex_1()
                            .h_full()
                            .pl(px(16.0))
                            .pr(px(8.0))
                            .flex()
                            .items_center()
                            .gap(px(10.0))
                            .window_control_area(WindowControlArea::Drag)
                            .child(
                                div()
                                    .w(px(26.0))
                                    .h(px(26.0))
                                    .rounded(px(7.0))
                                    .bg(t.red_bg)
                                    .border_1()
                                    .border_color(t.red_border)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        svg()
                                            .path("icons/trash.svg")
                                            .size(px(14.0))
                                            .text_color(t.red),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr("Удаление Tachyon", "Uninstall Tachyon")),
                            ),
                    )
                    .child(
                        div()
                            .pr(px(12.0))
                            .h_full()
                            .occlude()
                            .flex()
                            .items_center()
                            .gap(px(4.0))
                            .child(
                                div()
                                    .id("uninst-lang-toggle")
                                    .h(px(26.0))
                                    .px(px(7.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .hover(|s| s.bg(t.bg_hover))
                                    .cursor_pointer()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .text_size(px(10.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.accent)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.is_en = !this.is_en;
                                        cx.notify();
                                    }))
                                    .child(if self.is_en { "EN" } else { "RU" }),
                            )
                            .child(
                                div()
                                    .id("uninst-win-close")
                                    .w(px(28.0))
                                    .h(px(26.0))
                                    .rounded(px(6.0))
                                    .hover(|s| s.bg(t.red_bg))
                                    .cursor_pointer()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .on_click(cx.listener(|this, _, _, _| {
                                        if this.stage == UninstallStage::Done {
                                            this.finish_and_exit();
                                        } else {
                                            std::process::exit(0);
                                        }
                                    }))
                                    .child(
                                        svg()
                                            .path("icons/close.svg")
                                            .size(px(12.0))
                                            .text_color(t.text_dim),
                                    ),
                            ),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .p(px(16.0))
                    .flex()
                    .flex_col()
                    .gap(px(12.0))
                    .when(self.stage == UninstallStage::Confirm, |el| {
                        el.child(
                            div()
                                .p(px(14.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .gap(px(8.0))
                                .child(
                                    div()
                                        .text_size(px(13.0))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(t.text)
                                        .child(self.tr(
                                            "Будут удалены программа, ярлыки и системная интеграция",
                                            "Application files, shortcuts and registry entries will be removed",
                                        )),
                                )
                                .child(
                                    div()
                                        .p(px(8.0))
                                        .rounded(px(6.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .text_size(px(11.0))
                                        .text_color(t.text_soft)
                                        .child(dir_text),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .text_color(t.text_dim)
                                        .child(self.tr(
                                            "Также будут сброшены системный прокси, автозапуск, правила брандмауэра и URI-схема tachyon://.",
                                            "System proxy, startup entry, firewall rules and tachyon:// handler will also be cleaned up.",
                                        )),
                                ),
                        )
                        .child(
                            div()
                                .id("uninst-purge-toggle")
                                .p(px(12.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(if self.purge_user_data {
                                    t.red_border
                                } else {
                                    t.border
                                })
                                .hover(|s| s.bg(t.bg_hover))
                                .cursor_pointer()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.purge_user_data = !this.purge_user_data;
                                    cx.notify();
                                }))
                                .flex()
                                .items_center()
                                .justify_between()
                                .gap(px(10.0))
                                .child(
                                    div()
                                        .flex_1()
                                        .flex()
                                        .flex_col()
                                        .gap(px(2.0))
                                        .child(
                                            div()
                                                .text_size(px(12.0))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(t.text)
                                                .child(self.tr(
                                                    "Удалить профили, подписки и настройки пользователя",
                                                    "Remove saved profiles, subscriptions and user settings",
                                                )),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(10.0))
                                                .text_color(t.text_dim)
                                                .child(self.tr(
                                                    "Очистить %LOCALAPPDATA%\\Tachyon и %APPDATA%\\tachyon",
                                                    "Purge %LOCALAPPDATA%\\Tachyon and %APPDATA%\\tachyon",
                                                )),
                                        ),
                                )
                                .child(
                                    div()
                                        .w(px(34.0))
                                        .h(px(18.0))
                                        .p(px(2.0))
                                        .rounded(px(9.0))
                                        .bg(if self.purge_user_data { t.red } else { t.bg_elev })
                                        .flex()
                                        .items_center()
                                        .justify_end()
                                        .when(!self.purge_user_data, |s| s.justify_start())
                                        .child(
                                            div()
                                                .w(px(14.0))
                                                .h(px(14.0))
                                                .rounded(px(7.0))
                                                .bg(if self.purge_user_data {
                                                    gpui::rgb(0xFFFFFF)
                                                } else {
                                                    t.text_dim
                                                }),
                                        ),
                                ),
                        )
                    })
                    .when(self.stage == UninstallStage::Working, |el| {
                        let pct = self.progress_pct.min(100) as f32 / 100.0;
                        el.child(
                            div()
                                .flex_1()
                                .p(px(18.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .justify_center()
                                .gap(px(12.0))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .child(
                                            div()
                                                .text_size(px(12.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(t.text)
                                                .child(self.progress_text.clone()),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(12.0))
                                                .font_weight(FontWeight::BOLD)
                                                .text_color(t.red)
                                                .child(format!("{}%", self.progress_pct)),
                                        ),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .h(px(8.0))
                                        .rounded(px(4.0))
                                        .bg(t.bg_elev)
                                        .border_1()
                                        .border_color(t.border)
                                        .overflow_hidden()
                                        .child(
                                            div()
                                                .h_full()
                                                .w(gpui::relative(pct))
                                                .rounded(px(4.0))
                                                .bg(t.red),
                                        ),
                                ),
                        )
                    })
                    .when(self.stage == UninstallStage::Done, |el| {
                        el.child(
                            div()
                                .flex_1()
                                .p(px(18.0))
                                .rounded(px(10.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.green_border)
                                .flex()
                                .flex_col()
                                .justify_center()
                                .gap(px(10.0))
                                .child(
                                    div()
                                        .text_size(px(14.0))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(t.green)
                                        .child(self.tr(
                                            "Tachyon удалён с компьютера",
                                            "Tachyon has been uninstalled",
                                        )),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .text_color(t.text_dim)
                                        .child(self.tr(
                                            "Все ярлыки, правила сети и записи реестра очищены. Исполняемый файл и каталог установки будут удалены сразу после закрытия окна.",
                                            "Shortcuts, network rules and registry entries were removed. Remaining application files will be deleted as soon as this window closes.",
                                        )),
                                ),
                        )
                    })
                    .when_some(
                        match &self.stage {
                            UninstallStage::Error(e) => Some(e.clone()),
                            _ => None,
                        },
                        |el, err_msg| {
                            el.child(
                                div()
                                    .flex_1()
                                    .p(px(18.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.red_border)
                                    .flex()
                                    .flex_col()
                                    .justify_center()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .text_size(px(13.5))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.red)
                                            .child(self.tr("Ошибка удаления", "Uninstallation Error")),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.5))
                                            .text_color(t.text)
                                            .child(err_msg),
                                    ),
                            )
                        },
                    ),
            )
            .child(
                div()
                    .h(px(54.0))
                    .w_full()
                    .px(px(16.0))
                    .bg(t.bg_card)
                    .border_t_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap(px(8.0))
                    .when(self.stage == UninstallStage::Confirm, |el| {
                        el.child(
                            div()
                                .id("btn-uninst-cancel")
                                .px(px(14.0))
                                .py(px(7.0))
                                .rounded(px(8.0))
                                .bg(t.bg_elev)
                                .border_1()
                                .border_color(t.border)
                                .hover(|s| s.bg(t.bg_hover))
                                .cursor_pointer()
                                .text_size(px(12.0))
                                .text_color(t.text_soft)
                                .on_click(|_, _, _| {
                                    std::process::exit(0);
                                })
                                .child(self.tr("Отмена", "Cancel")),
                        )
                        .child(
                            div()
                                .id("btn-uninst-run")
                                .px(px(16.0))
                                .py(px(7.0))
                                .rounded(px(8.0))
                                .bg(t.red)
                                .cursor_pointer()
                                .text_size(px(12.0))
                                .font_weight(FontWeight::BOLD)
                                .text_color(gpui::rgb(0xFFFFFF))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.start_uninstall(cx);
                                }))
                                .child(self.tr("Удалить", "Uninstall")),
                        )
                    })
                    .when(matches!(self.stage, UninstallStage::Error(_)), |el| {
                        el.child(
                            div()
                                .id("btn-uninst-close-err")
                                .px(px(16.0))
                                .py(px(7.0))
                                .rounded(px(8.0))
                                .bg(t.bg_elev)
                                .border_1()
                                .border_color(t.border)
                                .hover(|s| s.bg(t.bg_hover))
                                .cursor_pointer()
                                .text_size(px(12.0))
                                .text_color(t.text)
                                .on_click(|_, _, _| {
                                    std::process::exit(1);
                                })
                                .child(self.tr("Закрыть", "Close")),
                        )
                    })
                    .when(self.stage == UninstallStage::Done, |el| {
                        el.child(
                            div()
                                .id("btn-uninst-done")
                                .px(px(18.0))
                                .py(px(7.0))
                                .rounded(px(8.0))
                                .bg(t.accent)
                                .hover(|s| s.bg(t.accent_2))
                                .cursor_pointer()
                                .text_size(px(12.0))
                                .font_weight(FontWeight::BOLD)
                                .text_color(gpui::rgb(0x0B0B0D))
                                .on_click(cx.listener(|this, _, _, _| {
                                    this.finish_and_exit();
                                }))
                                .child(self.tr("Готово", "Finish")),
                        )
                    }),
            )
    }
}

#[cfg(target_os = "windows")]
fn run_install_gui() -> i32 {
    gpui_kit::application()
        .with_assets(TachyonAssetSource)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            let bounds = Bounds::centered(None, size(px(690.0), px(620.0)), cx);
            let opts = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Установка Tachyon".into()),
                    appears_transparent: true,
                    ..Default::default()
                }),
                window_decorations: Some(WindowDecorations::Client),
                app_owns_titlebar_drag: true,
                window_min_size: Some(size(px(640.0), px(570.0))),
                app_id: Some("io.tachyon.desktop.setup".to_string()),
                ..Default::default()
            };
            let _ = gpui_kit::open_window(opts, cx, |window, cx| {
                cx.new(|cx| TachyonInstallerView::new(window, cx))
            });
            cx.activate(true);
        });
    0
}

#[cfg(target_os = "windows")]
fn run_uninstall_gui() -> i32 {
    gpui_kit::application()
        .with_assets(TachyonAssetSource)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            let bounds = Bounds::centered(None, size(px(540.0), px(380.0)), cx);
            let opts = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Удаление Tachyon".into()),
                    appears_transparent: true,
                    ..Default::default()
                }),
                window_decorations: Some(WindowDecorations::Client),
                app_owns_titlebar_drag: true,
                window_min_size: Some(size(px(480.0), px(340.0))),
                app_id: Some("io.tachyon.desktop.uninstall".to_string()),
                ..Default::default()
            };
            let _ = gpui_kit::open_window(opts, cx, |_, cx| {
                cx.new(|cx| TachyonUninstallerView::new(cx))
            });
            cx.activate(true);
        });
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_installer_magic_trailer_detect_and_strip() {
        let tmp = std::env::temp_dir().join(format!(
            "tachyon_inst_trailer_test_{}.exe",
            std::process::id()
        ));
        let clean = b"MZ-payload-data-0123456789";
        let mut with_trailer = clean.to_vec();
        with_trailer.extend_from_slice(INSTALLER_MAGIC);

        fs::write(&tmp, &with_trailer).expect("write temp trailer file");
        assert!(has_installer_trailer(&tmp));
        assert_eq!(strip_installer_trailer(&with_trailer), clean);
        assert_eq!(strip_installer_trailer(clean), clean);

        fs::write(&tmp, clean).expect("write temp clean file");
        assert!(!has_installer_trailer(&tmp));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_detect_installer_mode_from_args_and_filenames() {
        let plain_exe = Path::new("Tachyon.exe");
        let setup_exe = Path::new("Tachyon-Setup-x86_64.exe");
        let uninst_exe = Path::new("Tachyon-Uninstall.exe");

        assert_eq!(
            detect_installer_mode(&["Tachyon.exe".into()], plain_exe),
            None
        );
        assert_eq!(
            detect_installer_mode(&["Tachyon-Setup-x86_64.exe".into()], setup_exe),
            Some(InstallerMode::InstallGui)
        );
        assert_eq!(
            detect_installer_mode(
                &["Tachyon-Setup-x86_64.exe".into(), "--version".into()],
                setup_exe
            ),
            None
        );
        assert_eq!(
            detect_installer_mode(&["Tachyon.exe".into(), "--install".into()], plain_exe),
            Some(InstallerMode::InstallGui)
        );
        assert_eq!(
            detect_installer_mode(
                &[
                    "Tachyon.exe".into(),
                    "--install-silent".into(),
                    "--dir".into(),
                    r"C:\Apps\Tachyon".into()
                ],
                plain_exe
            ),
            Some(InstallerMode::InstallSilent {
                dir: Some(PathBuf::from(r"C:\Apps\Tachyon"))
            })
        );
        assert_eq!(
            detect_installer_mode(
                &[
                    "Tachyon-Setup-x86_64.exe".into(),
                    "/S".into(),
                    r"/D=D:\Tachyon".into()
                ],
                setup_exe
            ),
            Some(InstallerMode::InstallSilent {
                dir: Some(PathBuf::from(r"D:\Tachyon"))
            })
        );
        assert_eq!(
            detect_installer_mode(&["Tachyon.exe".into(), "--uninstall".into()], plain_exe),
            Some(InstallerMode::UninstallGui)
        );
        assert_eq!(
            detect_installer_mode(
                &[
                    "Tachyon.exe".into(),
                    "--uninstall".into(),
                    "--silent".into(),
                    "--purge".into()
                ],
                plain_exe
            ),
            Some(InstallerMode::UninstallSilent { purge: true })
        );
        assert_eq!(
            detect_installer_mode(&["Tachyon-Uninstall.exe".into()], uninst_exe),
            Some(InstallerMode::UninstallGui)
        );
    }
}
