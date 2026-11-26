use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn extract_workspace_version(cargo_toml_path: &Path) -> Option<String> {
    let text = fs::read_to_string(cargo_toml_path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(val) = rest.strip_prefix('=') {
                let ver = val.trim().trim_matches('"').trim_matches('\'').trim();
                if !ver.is_empty() {
                    return Some(ver.to_string());
                }
            }
        }
    }
    None
}

fn clean_win_rc_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.replace('\\', "\\\\")
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let core_cargo_toml = manifest_dir
        .join("..")
        .join("..")
        .join("tachyon-core")
        .join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", core_cargo_toml.display());
    let core_ver =
        extract_workspace_version(&core_cargo_toml).unwrap_or_else(|| "0.6.7".to_string());
    println!("cargo:rustc-env=TACHYON_CORE_VERSION={core_ver}");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico_path = manifest_dir
            .join("..")
            .join("src")
            .join("app.ico")
            .canonicalize()
            .unwrap_or_else(|_| manifest_dir.join("../src/app.ico"));
        let mut rc_body = String::new();
        if ico_path.exists() {
            println!("cargo:rerun-if-changed={}", ico_path.display());
            rc_body.push_str(&format!("1 ICON \"{}\"\n", clean_win_rc_path(&ico_path)));
        }

        if !rc_body.is_empty() {
            let rc_path = out_dir.join("tachyon.rc");
            let res_path = out_dir.join("tachyon.res");
            if let Err(e) = fs::write(&rc_path, rc_body) {
                println!(
                    "cargo:warning=Не удалось записать {}: {e}",
                    rc_path.display()
                );
                return;
            }
            if let Some(rc_exe) = find_windows_rc_exe() {
                let status = std::process::Command::new(&rc_exe)
                    .args(["/nologo", "/fo"])
                    .arg(&res_path)
                    .arg(&rc_path)
                    .status();
                match status {
                    Ok(s) if s.success() && res_path.exists() => {
                        println!("cargo:rustc-link-arg-bins={}", res_path.display());
                    }
                    Ok(s) => {
                        println!(
                            "cargo:warning=rc.exe ({}) завершился со статусом {s}; ресурсы не встроены",
                            rc_exe.display()
                        );
                    }
                    Err(e) => {
                        println!(
                            "cargo:warning=Не удалось запустить rc.exe ({}): {e}",
                            rc_exe.display()
                        );
                    }
                }
            } else {
                println!("cargo:warning=rc.exe не найден; иконка и манифест Windows не встроены");
            }
        }
    }
}

fn find_windows_rc_exe() -> Option<PathBuf> {
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let cand = dir.join("rc.exe");
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let entries = fs::read_dir(kits_bin).ok()?;
    let mut versions: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path().join("x64").join("rc.exe"))
        .filter(|p| p.exists())
        .collect();
    versions.sort();
    versions.pop()
}
