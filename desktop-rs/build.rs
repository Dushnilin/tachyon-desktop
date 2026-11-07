use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn collect_files(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, out);
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(base) {
                let rel_str = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel_str, path));
            }
        }
    }
}

fn mime_for(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if lower.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if lower.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".ico") {
        "image/x-icon"
    } else if lower.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if lower.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

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

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let core_cargo_toml = manifest_dir
        .join("..")
        .join("..")
        .join("tachyon-core")
        .join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", core_cargo_toml.display());
    let core_ver = extract_workspace_version(&core_cargo_toml).unwrap_or_else(|| "0.4.0".to_string());
    println!("cargo:rustc-env=TACHYON_CORE_VERSION={core_ver}");

    let web_dir = manifest_dir
        .join("..")
        .join("src")
        .join("web")
        .canonicalize()
        .unwrap_or_else(|_| manifest_dir.join("../src/web"));

    println!("cargo:rerun-if-changed={}", web_dir.display());

    let mut files = Vec::new();
    collect_files(&web_dir, &web_dir, &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("web_assets.rs");
    let mut f = fs::File::create(&dest).unwrap();

    writeln!(
        f,
        "pub fn get_embedded_asset(path: &str) -> Option<(&'static [u8], &'static str)> {{"
    )
    .unwrap();
    writeln!(f, "    let clean = path.trim_start_matches('/');").unwrap();
    writeln!(
        f,
        "    let key = if clean.is_empty() {{ \"index.html\" }} else {{ clean }};"
    )
    .unwrap();
    writeln!(f, "    match key {{").unwrap();

    for (rel, abs) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
        let abs_escaped = abs.to_string_lossy().replace('\\', "/");
        let mime = mime_for(rel);
        writeln!(
            f,
            "        {:?} => Some((include_bytes!({:?}), {:?})),",
            rel, abs_escaped, mime
        )
        .unwrap();
    }

    writeln!(f, "        _ => None,").unwrap();
    writeln!(f, "    }}").unwrap();
    writeln!(f, "}}").unwrap();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico_path = manifest_dir
            .join("..")
            .join("src")
            .join("app.ico")
            .canonicalize()
            .unwrap_or_else(|_| manifest_dir.join("../src/app.ico"));
        if ico_path.exists() {
            println!("cargo:rerun-if-changed={}", ico_path.display());
            let rc_path = out_dir.join("tachyon.rc");
            let res_path = out_dir.join("tachyon.res");
            let ico_escaped = ico_path.to_string_lossy().replace('\\', "\\\\");
            let _ = fs::write(&rc_path, format!("1 ICON \"{ico_escaped}\"\n"));
            if let Some(rc_exe) = find_windows_rc_exe() {
                let status = std::process::Command::new(rc_exe)
                    .args(["/nologo", "/fo"])
                    .arg(&res_path)
                    .arg(&rc_path)
                    .status();
                if matches!(status, Ok(s) if s.success()) && res_path.exists() {
                    println!("cargo:rustc-link-arg-bins={}", res_path.display());
                }
            }
        }
    }
}

fn find_windows_rc_exe() -> Option<PathBuf> {
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
