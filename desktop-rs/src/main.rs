#![cfg_attr(windows, windows_subsystem = "windows")]

extern crate gpui_kit as gpui;

mod http;
mod icons;
mod state;
mod theme;
mod tray;
mod ui;
mod vpn;

use std::fs;
use std::process::Command;
use std::sync::{Arc, Mutex};

use gpui::{
    App, AppContext, Bounds, TitlebarOptions, WindowBounds, WindowDecorations, WindowOptions,
    point, px, size,
};

use crate::icons::TachyonAssetSource;
use crate::ui::TachyonApp;
use crate::vpn::{
    VpnManager, app_data_dir, cleanup_stale_state_on_startup, detect_passive_tun_error,
    flush_os_dns,
};

#[cfg(unix)]
fn raise_nofile_limit() {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return;
    }
    let max_allowed = if rl.rlim_max == libc::RLIM_INFINITY {
        65536
    } else {
        rl.rlim_max
    };
    for target in [65536u64, 32768, 16384, 10240, 4096] {
        let clamped = (target as libc::rlim_t).min(max_allowed);
        if clamped <= rl.rlim_cur {
            break;
        }
        let next = libc::rlimit {
            rlim_cur: clamped,
            rlim_max: rl.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } == 0 {
            break;
        }
    }
}

fn run_core_worker_mode(cfg_path: &str) -> i32 {
    let data_dir = std::path::Path::new(cfg_path)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(app_data_dir);
    let pid_file = data_dir.join("core.pid");
    let err_file = data_dir.join("core.err");
    let stop_file = data_dir.join("config.stop");
    let _ = fs::remove_file(&err_file);
    let _ = fs::write(&pid_file, std::process::id().to_string());

    let fail = |msg: String| -> i32 {
        eprintln!("run-core: {msg}");
        let _ = fs::write(&err_file, &msg);
        let _ = fs::remove_file(&pid_file);
        1
    };

    let Ok(raw) = fs::read_to_string(cfg_path) else {
        return fail(format!("failed to read {cfg_path}"));
    };
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return fail(format!("invalid JSON in {cfg_path}"));
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let stop_file_wait = stop_file.clone();
    let code = rt.block_on(async move {
        let mut bx = match core_runtime::start(&root).await {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("{e:#}");
                eprintln!("run-core: {msg}");
                let _ = fs::write(&err_file, &msg);
                return 1;
            }
        };

        if let Some(msg) = detect_passive_tun_error(&root) {
            eprintln!("run-core: {msg}");
            let _ = fs::write(&err_file, &msg);
            bx.shutdown_wait().await;
            return 1;
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                loop {
                    if stop_file_wait.exists() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            } => {}
        }
        bx.shutdown_wait().await;
        flush_os_dns();
        0
    });

    let _ = fs::remove_file(&stop_file);
    let _ = fs::remove_file(&pid_file);
    code
}

fn main() {
    #[cfg(unix)]
    raise_nofile_limit();

    std::panic::set_hook(Box::new(|info| {
        let msg = format!("PANIC: {info}\n");
        let _ = fs::write(app_data_dir().join("startup.log"), msg);
    }));

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--run-core" {
        std::process::exit(run_core_worker_mode(&args[2]));
    }
    #[cfg(target_os = "macos")]
    if args.len() >= 2 && args[1] == "--macos-helper" {
        std::process::exit(crate::vpn::run_macos_helper_daemon());
    }
    if args.len() >= 2 && (args[1] == "--version" || args[1] == "version" || args[1] == "-v") {
        println!(
            "tachyon-core {}",
            option_env!("TACHYON_CORE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        return;
    }

    if !crate::tray::acquire_single_instance_or_focus_existing() {
        return;
    }

    if let Ok(exe) = std::env::current_exe() {
        let _ = fs::remove_file(exe.with_extension("exe.old"));
        let _ = fs::remove_file(exe.with_extension("new"));
    }

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime"),
    );
    let _rt_guard = rt.enter();

    cleanup_stale_state_on_startup();

    let event_queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    crate::tray::init(event_queue.clone());
    let eq_cb = event_queue.clone();
    let vpn = Arc::new(VpnManager::new(Arc::new(move |msg: String| {
        if let Ok(mut guard) = eq_cb.lock() {
            guard.push(msg);
        }
    })));

    gpui_kit::application()
        .with_assets(TachyonAssetSource)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            let bounds = Bounds::centered(None, size(px(1120.0), px(760.0)), cx);
            let opts = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Tachyon".into()),
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(12.0), px(12.0))),
                }),
                window_decorations: Some(WindowDecorations::Client),
                app_owns_titlebar_drag: true,
                window_min_size: Some(size(px(460.0), px(500.0))),
                app_id: Some("io.tachyon.desktop".to_string()),
                ..Default::default()
            };

            let vpn_win = vpn.clone();
            let rt_win = rt.clone();
            let eq_win = event_queue.clone();

            let _ = gpui_kit::open_window(opts, cx, move |window, cx| {
                cx.new(|cx| TachyonApp::new(vpn_win, rt_win, eq_win, window, cx))
            });
            cx.activate(true);
        });
}

pub fn set_autostart_for_exe(exe: &std::path::Path, enable: bool) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let autostart_dir = std::path::PathBuf::from(home)
                .join(".config")
                .join("autostart");
            let _ = fs::create_dir_all(&autostart_dir);
            let desktop_file = autostart_dir.join("tachyon.desktop");
            if enable {
                let content = format!(
                    "[Desktop Entry]\nType=Application\nName=Tachyon\nExec=\"{}\"\nIcon=tachyon\nTerminal=false\nCategories=Network;VPN;\n",
                    exe.display()
                );
                let _ = fs::write(desktop_file, content);
            } else {
                let _ = fs::remove_file(desktop_file);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let agents_dir = std::path::PathBuf::from(home)
                .join("Library")
                .join("LaunchAgents");
            let _ = fs::create_dir_all(&agents_dir);
            let plist_file = agents_dir.join("io.tachyon.desktop.plist");
            if enable {
                let content = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.tachyon.desktop</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
                    exe.display()
                );
                let _ = fs::write(plist_file, content);
            } else {
                let _ = fs::remove_file(plist_file);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if enable {
            let val = format!("\"{}\"", exe.display());
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "Tachyon",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &val,
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        } else {
            let _ = Command::new("reg")
                .args([
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "Tachyon",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

pub fn set_autostart(enable: bool) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    set_autostart_for_exe(&exe, enable);
}
