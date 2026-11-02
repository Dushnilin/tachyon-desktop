#![cfg_attr(windows, windows_subsystem = "windows")]

mod http;
mod vpn;

use std::borrow::Cow;
use std::fs;
use std::process::Command;
use std::sync::Arc;

use serde_json::json;
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon, ResizeDirection, WindowBuilder};
use wry::{WebContext, WebViewBuilder};
use wry::http::{Request, Response, StatusCode};

use crate::vpn::{VpnManager, app_data_dir, enumerate_apps, set_system_proxy, tcp_connect_ms};

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

const APP_ICO_BYTES: &[u8] = include_bytes!("../../src/app.ico");

fn load_window_icon() -> Option<Icon> {
    // Entry 4 in src/app.ico is 64x64 32-bit BGRA DIB at offset 17574 (40-byte header + 16384 bytes BGRA)
    const DIB_OFFSET: usize = 17574 + 40;
    const W: usize = 64;
    const H: usize = 64;
    const PIXEL_BYTES: usize = W * H * 4;
    if APP_ICO_BYTES.len() < DIB_OFFSET + PIXEL_BYTES {
        return None;
    }
    let src = &APP_ICO_BYTES[DIB_OFFSET..DIB_OFFSET + PIXEL_BYTES];
    let mut rgba = vec![0u8; PIXEL_BYTES];
    for y in 0..H {
        let src_row = (H - 1 - y) * W * 4;
        let dst_row = y * W * 4;
        for x in 0..W {
            let si = src_row + x * 4;
            let di = dst_row + x * 4;
            rgba[di] = src[si + 2];     // R
            rgba[di + 1] = src[si + 1]; // G
            rgba[di + 2] = src[si];     // B
            rgba[di + 3] = src[si + 3]; // A
        }
    }
    Icon::from_rgba(rgba, W as u32, H as u32).ok()
}

#[derive(Debug, Clone)]
enum UserEvent {
    SendJs(String),
    IpcMessage(String),
}

const INIT_BRIDGE_JS: &str = r#"
(function() {
  if (!window.chrome) window.chrome = {};
  if (!window.chrome.webview) {
    window.chrome.webview = {
      postMessage: function(msg) {
        if (window.ipc && window.ipc.postMessage) {
          window.ipc.postMessage(typeof msg === 'string' ? msg : JSON.stringify(msg));
        }
      },
      addEventListener: function() {}
    };
  }
  const listeners = [];
  const origAdd = window.chrome.webview.addEventListener
    ? window.chrome.webview.addEventListener.bind(window.chrome.webview)
    : null;
  window.chrome.webview.addEventListener = function(type, fn) {
    if (type === 'message' && typeof fn === 'function') {
      listeners.push(fn);
    }
    if (origAdd) {
      try { origAdd(type, fn); } catch (e) {}
    }
  };
  window.chrome.webview.__dispatch = function(data) {
    const ev = { data: data };
    for (let i = 0; i < listeners.length; i++) {
      try { listeners[i](ev); } catch (e) {}
    }
  };

  // Borderless 6px edge resize support across Linux (X11/Wayland), macOS and Windows
  document.addEventListener('mousedown', function(e) {
    if (e.button !== 0) return;
    const g = 6;
    const w = window.innerWidth;
    const h = window.innerHeight;
    const x = e.clientX;
    const y = e.clientY;
    let dir = '';
    if (y < g && x < g) dir = 'nw';
    else if (y < g && x > w - g) dir = 'ne';
    else if (y > h - g && x < g) dir = 'sw';
    else if (y > h - g && x > w - g) dir = 'se';
    else if (x < g) dir = 'w';
    else if (x > w - g) dir = 'e';
    else if (y < g) dir = 'n';
    else if (y > h - g) dir = 's';
    if (dir && window.chrome && window.chrome.webview) {
      e.preventDefault();
      window.chrome.webview.postMessage('win:resize:' + dir);
    }
  }, true);
})();
"#;

fn current_platform_tag() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "unix"
    }
}

fn load_web_asset(uri_path: &str) -> Response<Cow<'static, [u8]>> {
    let clean = uri_path
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/');
    let rel = if clean.is_empty() {
        "index.html"
    } else {
        clean
    };

    // In dev mode, check ../src/web on disk first so UI edits reflect on reload
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().take(5) {
            let candidate = ancestor.join("src").join("web").join(rel);
            if candidate.is_file() {
                if let Ok(bytes) = fs::read(&candidate) {
                    let mime = get_embedded_asset(rel)
                        .map(|(_, m)| m)
                        .unwrap_or("application/octet-stream");
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", mime)
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Cow::Owned(bytes))
                        .unwrap();
                }
            }
        }
    }

    if let Some((bytes, mime)) = get_embedded_asset(rel) {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime)
            .header("Access-Control-Allow-Origin", "*")
            .body(Cow::Borrowed(bytes))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Cow::Borrowed(b"404 Not Found" as &[u8]))
            .unwrap()
    }
}

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

fn extract_legacy_state_json() -> Option<String> {
    let base = app_data_dir();
    let state_file = base.join("state.json");
    if let Ok(saved) = fs::read_to_string(&state_file) {
        if serde_json::from_str::<serde_json::Value>(&saved).is_ok() {
            return Some(saved);
        }
    }

    let leveldb_dir = base
        .join("WebView2")
        .join("EBWebView")
        .join("Default")
        .join("Local Storage")
        .join("leveldb");
    let entries = fs::read_dir(&leveldb_dir).ok()?;
    let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let ext = p.extension()?.to_str()?;
            if ext == "log" || ext == "ldb" {
                let mtime = e.metadata().ok()?.modified().ok()?;
                Some((mtime, p))
            } else {
                None
            }
        })
        .collect();
    // Sort newest first
    files.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, path) in files {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if let Some(found) = scan_bytes_for_tachyon_state(&bytes) {
            let _ = fs::write(&state_file, &found);
            return Some(found);
        }
    }
    None
}

fn scan_bytes_for_tachyon_state(bytes: &[u8]) -> Option<String> {
    // Chromium LevelDB stores strings with rich chars (Cyrillic) as UTF-16LE prefixed by 0x00
    // Scan from the end of the file to get the most recent record
    let marker_utf16: Vec<u8> = "{\"activeId\":"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    if bytes.len() > marker_utf16.len() {
        let mut pos = bytes.len() - marker_utf16.len();
        while pos > 0 {
            if bytes[pos..pos + marker_utf16.len()] == marker_utf16[..] {
                // Decode UTF-16LE until matching closing brace of the root JSON object
                let mut u16s = Vec::new();
                let mut depth = 0i32;
                let mut in_str = false;
                let mut esc = false;
                let mut idx = pos;
                while idx + 1 < bytes.len() {
                    let ch = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
                    idx += 2;
                    u16s.push(ch);
                    if esc {
                        esc = false;
                        continue;
                    }
                    if ch == b'\\' as u16 && in_str {
                        esc = true;
                        continue;
                    }
                    if ch == b'"' as u16 {
                        in_str = !in_str;
                        continue;
                    }
                    if !in_str {
                        if ch == b'{' as u16 {
                            depth += 1;
                        } else if ch == b'}' as u16 {
                            depth -= 1;
                            if depth == 0 {
                                if let Ok(s) = String::from_utf16(&u16s) {
                                    if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
                                        return Some(s);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            pos -= 1;
        }
    }
    None
}

fn prepare_webview_data_dir() -> std::path::PathBuf {
    let base = app_data_dir();
    let rs_dir = base.join("WebView2-rs");
    let old_leveldb = base
        .join("WebView2")
        .join("EBWebView")
        .join("Default")
        .join("Local Storage")
        .join("leveldb");
    let new_leveldb = rs_dir
        .join("EBWebView")
        .join("Default")
        .join("Local Storage")
        .join("leveldb");

    if !new_leveldb.exists() && old_leveldb.is_dir() {
        let _ = fs::create_dir_all(&new_leveldb);
        if let Ok(entries) = fs::read_dir(&old_leveldb) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Some(fname) = p.file_name() {
                        if fname != "LOCK" {
                            let _ = fs::copy(&p, new_leveldb.join(fname));
                        }
                    }
                }
            }
        }
    }
    let _ = fs::create_dir_all(&rs_dir);
    rs_dir
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

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy: EventLoopProxy<UserEvent> = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("Tachyon")
        .with_window_icon(load_window_icon())
        .with_decorations(false)
        .with_resizable(true)
        .with_inner_size(LogicalSize::new(1120.0, 760.0))
        .with_min_inner_size(LogicalSize::new(480.0, 620.0))
        .build(&event_loop)
        .expect("failed to create window");

    let send_proxy = proxy.clone();
    let vpn = Arc::new(VpnManager::new(Arc::new(move |msg: String| {
        let _ = send_proxy.send_event(UserEvent::SendJs(msg));
    })));

    let ipc_proxy = proxy.clone();
    let migrated_js = if let Some(state_json) = extract_legacy_state_json() {
        if let Ok(escaped) = serde_json::to_string(&state_json) {
            format!(
                "try {{ if (!localStorage.getItem('tachyon.v2')) {{ localStorage.setItem('tachyon.v2', {escaped}); }} }} catch(e) {{}}\n"
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let platform_init = format!(
        "window.__tachyonPlatform = {:?};\nwindow.__tachyonVersion = {:?};\n{}{}",
        current_platform_tag(),
        env!("CARGO_PKG_VERSION"),
        migrated_js,
        INIT_BRIDGE_JS
    );

    let mut web_context = WebContext::new(Some(prepare_webview_data_dir()));
    let initial_url = "tachyon://localhost/index.html";

    let webview = WebViewBuilder::with_web_context(&mut web_context)
        .with_background_color((8, 10, 15, 255))
        .with_custom_protocol("tachyon".into(), move |_webview_id, request: Request<Vec<u8>>| {
            load_web_asset(request.uri().path())
        })
        .with_initialization_script(&platform_init)
        .with_ipc_handler(move |req: Request<String>| {
            let _ = ipc_proxy.send_event(UserEvent::IpcMessage(req.body().clone()));
        })
        .with_url(initial_url)
        .build(&window)
        .expect("failed to build WebView");

    let rt_loop = rt.clone();
    let vpn_loop = vpn.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                let ver = env!("CARGO_PKG_VERSION");
                let _ = proxy.send_event(UserEvent::SendJs(format!("core:version:{ver}")));
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                let v = vpn_loop.clone();
                rt_loop.block_on(async move {
                    v.disconnect().await;
                });
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::SendJs(msg)) => {
                if let Ok(escaped) = serde_json::to_string(&msg) {
                    let js = format!(
                        "if(window.chrome&&window.chrome.webview&&window.chrome.webview.__dispatch){{window.chrome.webview.__dispatch({escaped});}}"
                    );
                    let _ = webview.evaluate_script(&js);
                }
            }
            Event::UserEvent(UserEvent::IpcMessage(msg)) => {
                handle_ipc_message(&window, &rt_loop, &vpn_loop, &proxy, msg);
            }
            _ => {}
        }
    });
}

fn handle_ipc_message(
    window: &tao::window::Window,
    rt: &Arc<tokio::runtime::Runtime>,
    vpn: &Arc<VpnManager>,
    proxy: &EventLoopProxy<UserEvent>,
    msg: String,
) {
    match msg.as_str() {
        "win:drag" => {
            let _ = window.drag_window();
        }
        "win:min" => {
            window.set_minimized(true);
        }
        "win:max" => {
            window.set_maximized(!window.is_maximized());
        }
        "win:close" => {
            let v = vpn.clone();
            rt.block_on(async move {
                v.disconnect().await;
            });
            std::process::exit(0);
        }
        "vpn:disconnect" => {
            let v = vpn.clone();
            rt.spawn(async move {
                v.disconnect().await;
            });
        }
        "core:version" => {
            let ver = env!("CARGO_PKG_VERSION");
            let _ = proxy.send_event(UserEvent::SendJs(format!("core:version:{ver}")));
        }
        "lists:refresh" => {
            let v = vpn.clone();
            rt.spawn(async move {
                v.refresh_rulesets(None).await;
            });
        }
        "conn:get" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let data = v.get_connections_json().await;
                let _ = p.send_event(UserEvent::SendJs(format!("conn:data:{data}")));
            });
        }
        "conn:close:all" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                v.close_connection(None).await;
                let data = v.get_connections_json().await;
                let _ = p.send_event(UserEvent::SendJs(format!("conn:data:{data}")));
            });
        }
        "log:tail" => {
            let tail = vpn.get_log_tail(120);
            let payload = json!({ "tail": tail }).to_string();
            let _ = proxy.send_event(UserEvent::SendJs(format!("log:tail:{payload}")));
        }
        "log:open" => {
            open_path_in_file_manager(vpn.log_path());
        }
        "apps:list" => {
            let p = proxy.clone();
            rt.spawn(async move {
                let apps = tokio::task::spawn_blocking(enumerate_apps)
                    .await
                    .unwrap_or_default();
                if let Ok(j) = serde_json::to_string(&apps) {
                    let _ = p.send_event(UserEvent::SendJs(format!("apps:list:{j}")));
                }
            });
        }
        "warp:create" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let res = v.provision_warp_awg().await;
                let _ = p.send_event(UserEvent::SendJs(format!("warp:result:{res}")));
            });
        }
        "exit:geo" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let res = v.check_exit_node_info().await;
                let _ = p.send_event(UserEvent::SendJs(format!("exit:geo:{res}")));
            });
        }
        "dns:bench" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let res = v.run_dns_benchmark().await;
                let _ = p.send_event(UserEvent::SendJs(format!("dns:bench:{res}")));
            });
        }
        "diag:matrix" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let res = v.run_diagnostics_matrix().await;
                let _ = p.send_event(UserEvent::SendJs(format!("diag:matrix:{res}")));
            });
        }
        "speedtest:run" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let res = v.run_speedtest(100, "auto").await;
                let _ = p.send_event(UserEvent::SendJs(format!("speedtest:result:{res}")));
            });
        }
        "speedtest:stop" => {
            vpn.cancel_speedtest();
        }
        "vpn:probe" => {
            let v = vpn.clone();
            let p = proxy.clone();
            rt.spawn(async move {
                let ms = v.probe_delay().await.map(|d| d as i64).unwrap_or(-1);
                let _ = p.send_event(UserEvent::SendJs(format!("probe:{ms}")));
            });
        }
        "ks:on" => vpn.set_kill_switch(true),
        "ks:off" => vpn.set_kill_switch(false),
        "autostart:on" => set_autostart(true),
        "autostart:off" => set_autostart(false),
        "update:check" | "core-update:check" => {
            let v = vpn.clone();
            rt.spawn(async move {
                v.check_github_update().await;
            });
        }
        "update:install" | "core-update:install" => {
            let v = vpn.clone();
            rt.spawn(async move {
                v.install_github_update().await;
            });
        }
        _ => {
            if let Some(dir) = msg.strip_prefix("win:resize:") {
                let resize_dir = match dir {
                    "n" => Some(ResizeDirection::North),
                    "s" => Some(ResizeDirection::South),
                    "e" => Some(ResizeDirection::East),
                    "w" => Some(ResizeDirection::West),
                    "ne" => Some(ResizeDirection::NorthEast),
                    "nw" => Some(ResizeDirection::NorthWest),
                    "se" => Some(ResizeDirection::SouthEast),
                    "sw" => Some(ResizeDirection::SouthWest),
                    _ => None,
                };
                if let Some(d) = resize_dir {
                    let _ = window.drag_resize_window(d);
                }
            } else if let Some(opts) = msg.strip_prefix("vpn:connect:") {
                let opts = opts.to_string();
                let v = vpn.clone();
                rt.spawn(async move {
                    v.connect(opts).await;
                });
            } else if let Some(sub) = msg.strip_prefix("vpn:sub:") {
                let sub = sub.to_string();
                let v = vpn.clone();
                rt.spawn(async move {
                    v.import_subscription(sub).await;
                });
            } else if let Some(rest) = msg.strip_prefix("speedtest:run:") {
                let parts: Vec<&str> = rest.split(':').collect();
                let size_mb = parts
                    .first()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(100);
                let prov = parts.get(1).copied().unwrap_or("auto").to_string();
                let v = vpn.clone();
                let p = proxy.clone();
                rt.spawn(async move {
                    let res = v.run_speedtest(size_mb, &prov).await;
                    let _ = p.send_event(UserEvent::SendJs(format!("speedtest:result:{res}")));
                });
            } else if let Some(rest) = msg.strip_prefix("tcping:") {
                let parts: Vec<&str> = rest.split(':').collect();
                if parts.len() >= 3 {
                    let id = parts[0].to_string();
                    let port = parts
                        .last()
                        .and_then(|s| s.parse::<u16>().ok())
                        .unwrap_or(443);
                    let host = parts[1..parts.len() - 1].join(":");
                    let p = proxy.clone();
                    rt.spawn(async move {
                        let ms = tcp_connect_ms(&host, port, 2500).await;
                        let _ = p.send_event(UserEvent::SendJs(format!("pong:{id}:{ms}")));
                    });
                }
            } else if let Some(rest) = msg.strip_prefix("ping:") {
                if let Some((id, host)) = rest.split_once(':') {
                    let id = id.to_string();
                    let host = host.to_string();
                    let p = proxy.clone();
                    rt.spawn(async move {
                        let ms = tcp_connect_ms(&host, 443, 2500).await;
                        let _ = p.send_event(UserEvent::SendJs(format!("pong:{id}:{ms}")));
                    });
                }
            } else if let Some(cid) = msg.strip_prefix("conn:close:") {
                let cid = cid.to_string();
                let v = vpn.clone();
                let p = proxy.clone();
                rt.spawn(async move {
                    v.close_connection(Some(&cid)).await;
                    let data = v.get_connections_json().await;
                    let _ = p.send_event(UserEvent::SendJs(format!("conn:data:{data}")));
                });
            } else if let Some(names) = msg.strip_prefix("lists:refresh:") {
                let names = names.to_string();
                let v = vpn.clone();
                rt.spawn(async move {
                    v.refresh_rulesets(Some(names)).await;
                });
            } else if let Some(url) = msg.strip_prefix("open:") {
                open_external_url(url);
            } else if msg.starts_with("selfcheck:") {
                let v = vpn.clone();
                rt.spawn(async move {
                    v.run_self_check().await;
                });
            }
        }
    }
}

fn open_external_url(url: &str) {
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("tg://")) {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

fn open_path_in_file_manager(path: &std::path::Path) {
    #[cfg(target_os = "linux")]
    {
        let dir = path.parent().unwrap_or(path);
        let _ = Command::new("xdg-open").arg(dir).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer.exe")
            .arg(format!("/select,\"{}\"", path.display()))
            .spawn();
    }
}

fn set_autostart(enable: bool) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let autostart_dir = std::path::PathBuf::from(home).join(".config").join("autostart");
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
            let agents_dir = std::path::PathBuf::from(home).join("Library").join("LaunchAgents");
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
