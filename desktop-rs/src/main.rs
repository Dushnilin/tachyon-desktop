#![cfg_attr(windows, windows_subsystem = "windows")]

extern crate gpui_kit as gpui;

mod http;
mod icons;
mod state;
mod theme;
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
use crate::vpn::{VpnManager, app_data_dir, set_system_proxy};

fn run_core_worker_mode(cfg_path: &str) -> i32 {
    let Ok(raw) = fs::read_to_string(cfg_path) else {
        eprintln!("run-core: failed to read {cfg_path}");
        return 1;
    };
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&raw) else {
        eprintln!("run-core: invalid JSON in {cfg_path}");
        return 1;
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let mut bx = match core_runtime::start(&root).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("run-core: {e:#}");
                return 1;
            }
        };
        let stop_file = app_data_dir().join("config.stop");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                loop {
                    if stop_file.exists() {
                        let _ = fs::remove_file(&stop_file);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                }
            } => {}
        }
        bx.shutdown_wait().await;
        0
    })
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("PANIC: {info}\n");
        let _ = fs::write(app_data_dir().join("startup.log"), msg);
    }));

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--run-core" {
        std::process::exit(run_core_worker_mode(&args[2]));
    }
    if args.len() >= 2 && (args[1] == "--version" || args[1] == "version" || args[1] == "-v") {
        println!("tachyon-core {}", env!("CARGO_PKG_VERSION"));
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

    set_system_proxy(false);

    let event_queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
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
                window_min_size: Some(size(px(860.0), px(620.0))),
                app_id: Some("io.tachyon.desktop".to_string()),
                ..Default::default()
            };

            let vpn_win = vpn.clone();
            let rt_win = rt.clone();
            let eq_win = event_queue.clone();

            let _ = gpui_kit::open_window(opts, cx, move |_window, cx| {
                cx.new(|cx| TachyonApp::new(vpn_win, rt_win, eq_win, cx))
            });
            cx.activate(true);
        });
}

pub fn set_autostart(enable: bool) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

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
