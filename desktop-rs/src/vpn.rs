use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use core_config::subscription::{
    extract_subscription_metadata, outbound_to_share_link, parse_share_uri,
    parse_subscription_payload, wireguard_node_to_endpoint,
};
use core_runtime::BoxInstance;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::http::{clash_api_request, fetch_url, run_speedtest_stream};

pub const API_PORT: u16 = 9090;
pub const PROXY_PORT: u16 = 7897;

const EMPTY_TRS_STUB: [u8; 96] = {
    let mut buf = [0u8; 96];
    buf[0] = b'T';
    buf[1] = b'S';
    buf[2] = b'R';
    buf[3] = b'S';
    buf[4] = 2; // version = 2 (u32 LE)
    buf
};
const TACHYON_LISTS_TRS_BASE: &str =
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/tachyon";
const TACHYON_LISTS_TRS_MIRROR: &str =
    "https://cdn.jsdelivr.net/gh/Dushnilin/tachyon-lists@main/release/tachyon";

#[derive(Debug, Clone)]
pub struct DesyncOptions {
    pub enabled: bool,
    pub auto_direct: bool,
    pub preset: String,
    pub mode: String,
    pub fooling: String,
    pub split_pos: String,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub repeats: u32,
    pub split_delay_ms: u32,
    pub udp_fake: bool,
    pub udp_repeats: u32,
    pub udp_fake_ttl: u32,
    pub auto_tune: bool,
    pub block_quic: bool,
}

impl Default for DesyncOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_direct: true,
            preset: "auto".to_string(),
            mode: "auto".to_string(),
            fooling: "md5".to_string(),
            split_pos: "midsld".to_string(),
            fake_ttl: 6,
            fake_sni: "www.google.com".to_string(),
            repeats: 2,
            split_delay_ms: 1,
            udp_fake: true,
            udp_repeats: 6,
            udp_fake_ttl: 6,
            auto_tune: true,
            block_quic: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommunityListRule {
    pub name: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct CustomRouteRule {
    pub rtype: String,
    pub value: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct ExtraNodeRef {
    pub tag: String,
    pub vless: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    All,
    Apps,
    AppsExclude,
    Selective,
    DesyncOnly,
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub vless: String,
    pub route: RouteMode,
    pub rules: Vec<String>,
    pub block_only: bool,
    pub proxy_mode: bool,
    pub dns: String,
    pub fake_ip: bool,
    pub dns_route_mode: String,
    pub dns_bootstrap: String,
    pub mtu: u32,
    pub allow_lan: bool,
    pub proxy_tls_fragment: bool,
    pub log_level: String,
    pub detour_vless: String,
    pub extra_nodes: Vec<ExtraNodeRef>,
    pub desync: DesyncOptions,
    pub community_lists: Vec<CommunityListRule>,
    pub custom_rules: Vec<CustomRouteRule>,
}

impl ConnectOptions {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.starts_with("vless://")
            || raw.starts_with("vmess://")
            || raw.starts_with("trojan://")
            || raw.starts_with("ss://")
            || raw.starts_with("hy2://")
            || raw.starts_with("hysteria2://")
            || raw.starts_with("amneziawg://")
            || raw.starts_with("awg://")
        {
            return Ok(Self {
                vless: raw.to_string(),
                route: RouteMode::All,
                rules: Vec::new(),
                block_only: false,
                proxy_mode: false,
                dns: "auto".to_string(),
                fake_ip: false,
                dns_route_mode: "split_ru".to_string(),
                dns_bootstrap: "77.88.8.8".to_string(),
                mtu: 1420,
                allow_lan: false,
                proxy_tls_fragment: true,
                log_level: "warn".to_string(),
                detour_vless: String::new(),
                extra_nodes: Vec::new(),
                desync: DesyncOptions::default(),
                community_lists: Vec::new(),
                custom_rules: Vec::new(),
            });
        }

        let root: Value = serde_json::from_str(raw).map_err(|e| format!("Invalid JSON: {e}"))?;
        let vless = root
            .get("vless")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();

        let route_str = root.get("route").and_then(Value::as_str).unwrap_or("all");
        let mut route = match route_str.to_ascii_lowercase().as_str() {
            "apps" => RouteMode::Apps,
            "apps-exclude" => RouteMode::AppsExclude,
            "selective" => RouteMode::Selective,
            "desync-only" => RouteMode::DesyncOnly,
            _ => RouteMode::All,
        };

        let mut rules = Vec::new();
        if let Some(arr) = root.get("rules").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.trim().is_empty() {
                        rules.push(s.trim().to_string());
                    }
                }
            }
        } else if let Some(arr) = root.get("apps").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.trim().is_empty() {
                        rules.push(format!("PROCESS-NAME,{},GLOBAL", s.trim()));
                    }
                }
            }
            if !rules.is_empty() {
                route = RouteMode::Apps;
            }
        }

        let mode_str = root.get("mode").and_then(Value::as_str).unwrap_or("tun");
        let block_only = mode_str.eq_ignore_ascii_case("block");
        let proxy_mode = !block_only && mode_str.eq_ignore_ascii_case("proxy");

        let dns = root
            .get("dns")
            .and_then(Value::as_str)
            .unwrap_or("auto")
            .trim()
            .to_string();
        let fake_ip = root.get("fakeIp").and_then(Value::as_bool).unwrap_or(false);
        let drm = root
            .get("dnsRouteMode")
            .and_then(Value::as_str)
            .unwrap_or("split_ru")
            .trim()
            .to_ascii_lowercase();
        let dns_route_mode = if drm == "proxy" || drm == "direct" {
            drm
        } else {
            "split_ru".to_string()
        };
        let dns_bootstrap = root
            .get("dnsBootstrap")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("77.88.8.8")
            .to_string();
        let mtu = root
            .get("mtu")
            .and_then(Value::as_u64)
            .map(|v| (v as u32).clamp(1280, 9000))
            .unwrap_or(1420);
        let allow_lan = root
            .get("allowLan")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let proxy_tls_fragment = root
            .get("proxyTlsFragment")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let ll = root
            .get("logLevel")
            .and_then(Value::as_str)
            .unwrap_or("warn")
            .trim()
            .to_ascii_lowercase();
        let log_level = if matches!(ll.as_str(), "error" | "info" | "debug") {
            ll
        } else {
            "warn".to_string()
        };
        let detour_vless = root
            .get("detourVless")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();

        let mut extra_nodes = Vec::new();
        if let Some(arr) = root.get("extraNodes").and_then(Value::as_array) {
            for item in arr {
                let tag = item
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let ev = item
                    .get("vless")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if tag.starts_with("NODE_") && !ev.is_empty() {
                    extra_nodes.push(ExtraNodeRef {
                        tag: tag.to_string(),
                        vless: ev.to_string(),
                    });
                }
            }
        }

        let mut desync = DesyncOptions::default();
        if let Some(d) = root.get("desync").and_then(Value::as_object) {
            if let Some(v) = d.get("enabled").and_then(Value::as_bool) {
                desync.enabled = v;
            }
            if let Some(v) = d.get("autoDirect").and_then(Value::as_bool) {
                desync.auto_direct = v;
            }
            if let Some(v) = d.get("preset").and_then(Value::as_str) {
                desync.preset = v.trim().to_string();
            }
            if let Some(v) = d.get("mode").and_then(Value::as_str) {
                desync.mode = v.trim().to_string();
            }
            if let Some(v) = d.get("fooling").and_then(Value::as_str) {
                desync.fooling = v.trim().to_string();
            }
            if let Some(v) = d.get("splitPos").and_then(Value::as_str) {
                desync.split_pos = v.trim().to_string();
            } else if let Some(v) = d.get("splitPos").and_then(Value::as_u64) {
                desync.split_pos = v.clamp(1, 1400).to_string();
            }
            if let Some(v) = d.get("fakeTtl").and_then(Value::as_u64) {
                desync.fake_ttl = (v as u32).clamp(1, 128);
            }
            if let Some(v) = d.get("fakeSni").and_then(Value::as_str) {
                if !v.trim().is_empty() {
                    desync.fake_sni = v.trim().to_string();
                }
            }
            if let Some(v) = d.get("repeats").and_then(Value::as_u64) {
                desync.repeats = (v as u32).clamp(1, 100);
            }
            if let Some(v) = d.get("splitDelayMs").and_then(Value::as_u64) {
                desync.split_delay_ms = (v as u32).clamp(0, 1000);
            }
            if let Some(v) = d.get("udpFake").and_then(Value::as_bool) {
                desync.udp_fake = v;
            }
            if let Some(v) = d.get("udpRepeats").and_then(Value::as_u64) {
                desync.udp_repeats = (v as u32).clamp(1, 50);
            }
            if let Some(v) = d.get("udpFakeTtl").and_then(Value::as_u64) {
                desync.udp_fake_ttl = (v as u32).clamp(1, 128);
            }
            if let Some(v) = d.get("autoTune").and_then(Value::as_bool) {
                desync.auto_tune = v;
            }
            if let Some(v) = d.get("blockQuic").and_then(Value::as_bool) {
                desync.block_quic = v;
            }
        }

        let mut community_lists = Vec::new();
        if let Some(arr) = root.get("communityLists").and_then(Value::as_array) {
            for item in arr {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let act_raw = item
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("vpn")
                    .trim();
                let action = if act_raw.to_ascii_uppercase().starts_with("NODE_") {
                    act_raw.to_ascii_uppercase()
                } else {
                    act_raw.to_ascii_lowercase()
                };
                if !name.is_empty() && action != "off" && action != "none" {
                    community_lists.push(CommunityListRule { name, action });
                }
            }
        }

        let mut custom_rules = Vec::new();
        if let Some(arr) = root.get("customRules").and_then(Value::as_array) {
            for item in arr {
                let rtype = item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("domain")
                    .trim()
                    .to_ascii_lowercase();
                let value = item
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let act_raw = item
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("vpn")
                    .trim();
                let action = if act_raw.to_ascii_uppercase().starts_with("NODE_") {
                    act_raw.to_ascii_uppercase()
                } else {
                    act_raw.to_ascii_lowercase()
                };
                if !value.is_empty() && action != "off" && action != "none" {
                    custom_rules.push(CustomRouteRule {
                        rtype,
                        value,
                        action,
                    });
                }
            }
        }

        let allow_without_node =
            block_only || route == RouteMode::DesyncOnly || desync.enabled;
        if !allow_without_node && vless.is_empty() {
            return Err("Не выбран сервер для подключения".to_string());
        }

        Ok(Self {
            vless,
            route,
            rules,
            block_only,
            proxy_mode,
            dns,
            fake_ip,
            dns_route_mode,
            dns_bootstrap,
            mtu,
            allow_lan,
            proxy_tls_fragment,
            log_level,
            detour_vless,
            extra_nodes,
            desync,
            community_lists,
            custom_rules,
        })
    }
}

pub fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(local).join("Tachyon");
            let _ = fs::create_dir_all(&p);
            return p;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Tachyon");
            let _ = fs::create_dir_all(&p);
            return p;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg).join("tachyon");
            let _ = fs::create_dir_all(&p);
            return p;
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("tachyon");
            let _ = fs::create_dir_all(&p);
            return p;
        }
    }
    let fallback = std::env::temp_dir().join("tachyon");
    let _ = fs::create_dir_all(&fallback);
    fallback
}

pub fn default_tun_device() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "tachyon0"
    }
    #[cfg(target_os = "macos")]
    {
        "utun"
    }
    #[cfg(target_os = "windows")]
    {
        "Tachyon"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "tun0"
    }
}

pub fn canonical_ruleset_name(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    let stripped = lowered
        .strip_suffix(".trs")
        .or_else(|| lowered.strip_suffix(".srs"))
        .unwrap_or(&lowered);
    let clean: String = stripped
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    match clean.as_str() {
        "geosite_ru" | "roscomvpn_ru" => "ru_domains".to_string(),
        "roscomvpn_whitelist" => "ru_whitelist".to_string(),
        "roscomvpn_geoblock" => "geoblock".to_string(),
        "roscomvpn_push" => "push".to_string(),
        "runetfreedom_blocked" => "ru_blocked".to_string(),
        "runetfreedom_blocked_all" => "ru_blocked_all".to_string(),
        "antifilter_community" => "antifilter".to_string(),
        "ru_available_only_inside" => "ru_only_inside".to_string(),
        _ => clean,
    }
}

fn is_priority_direct_ru_list(can: &str) -> bool {
    matches!(can, "russia_inside" | "ru_whitelist" | "ru_only_inside")
}

#[cfg(target_os = "windows")]
const WINTUN_DLL_BYTES: &[u8] = include_bytes!("../../src/core/wintun.dll");
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn ensure_wintun_dll() {
    #[cfg(target_os = "windows")]
    {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let dll_path = dir.join("wintun.dll");
                let needs_write = match fs::metadata(&dll_path) {
                    Ok(m) => m.len() != WINTUN_DLL_BYTES.len() as u64,
                    Err(_) => true,
                };
                if needs_write {
                    let _ = fs::write(&dll_path, WINTUN_DLL_BYTES);
                }
            }
        }
    }
}

struct RunningEngine {
    in_proc: Option<BoxInstance>,
    worker: Option<Child>,
    running_config: Value,
    proxy_mode: bool,
    block_only: bool,
    has_node: bool,
}

impl RunningEngine {
    async fn stop(&mut self) {
        if let Some(mut bx) = self.in_proc.take() {
            bx.shutdown_wait().await;
        }
        if let Some(mut child) = self.worker.take() {
            let stop_file = app_data_dir().join("config.stop");
            let _ = fs::write(&stop_file, b"1");
            for _ in 0..10 {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&stop_file);
        }
    }
}

pub struct VpnManager {
    data_dir: PathBuf,
    log_path: PathBuf,
    secret: String,
    engine: Arc<tokio::sync::Mutex<Option<RunningEngine>>>,
    stats_cancel: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    speedtest_cancel: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    last_connect_opts: Arc<Mutex<Option<String>>>,
    kill_switch: Arc<Mutex<bool>>,
    send_js: Arc<dyn Fn(String) + Send + Sync>,
}

impl VpnManager {
    pub fn new(send_js: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        ensure_wintun_dll();
        #[cfg(target_os = "windows")]
        refresh_cached_windows_phys_ifindex();
        let data_dir = app_data_dir();
        let log_path = data_dir.join("tachyon-core.log");
        let mut rnd = [0u8; 16];
        let _ = getrandom::fill(&mut rnd);
        let secret = rnd.iter().map(|b| format!("{b:02x}")).collect::<String>();

        Self {
            data_dir,
            log_path,
            secret,
            engine: Arc::new(tokio::sync::Mutex::new(None)),
            stats_cancel: Arc::new(Mutex::new(None)),
            speedtest_cancel: Arc::new(Mutex::new(None)),
            last_connect_opts: Arc::new(Mutex::new(None)),
            kill_switch: Arc::new(Mutex::new(false)),
            send_js,
        }
    }

    pub fn emit(&self, msg: impl Into<String>) {
        (self.send_js)(msg.into());
    }

    pub fn emit_vpn(&self, payload: Value) {
        self.emit(format!("vpn:{payload}"));
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub async fn is_running(&self) -> bool {
        let mut guard = self.engine.lock().await;
        if let Some(eng) = guard.as_mut() {
            if let Some(child) = eng.worker.as_mut() {
                if let Ok(Some(_)) = child.try_wait() {
                    *guard = None;
                    return false;
                }
            }
            return true;
        }
        false
    }

    fn ruleset_file_path(&self, canonical_name: &str) -> PathBuf {
        let dir = self.data_dir.join("rulesets");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("community-{canonical_name}.trs"))
    }

    fn is_valid_trs_file(path: &Path, require_populated: bool) -> bool {
        let Ok(meta) = fs::metadata(path) else {
            return false;
        };
        if meta.len() < 96 || (require_populated && meta.len() <= 96) {
            return false;
        };
        let Ok(bytes) = fs::read(path) else {
            return false;
        };
        bytes.len() >= 96 && &bytes[0..4] == b"TSRS"
    }

    fn ensure_trs_stub(&self, canonical_name: &str) {
        let path = self.ruleset_file_path(canonical_name);
        if Self::is_valid_trs_file(&path, false) {
            return;
        }
        let _ = fs::write(path, EMPTY_TRS_STUB);
    }

    async fn download_single_ruleset(&self, canonical_name: &str) -> bool {
        let path = self.ruleset_file_path(canonical_name);
        let urls = [
            format!("{TACHYON_LISTS_TRS_BASE}/{canonical_name}.trs"),
            format!("{TACHYON_LISTS_TRS_MIRROR}/{canonical_name}.trs"),
        ];
        for url in &urls {
            if let Ok(resp) = fetch_url(url, "GET", &[], None, None, Duration::from_secs(8)).await {
                if resp.status == 200
                    && resp.body.len() > 96
                    && &resp.body[0..4] == b"TSRS"
                {
                    let tmp = path.with_extension("trs.tmp");
                    if fs::write(&tmp, &resp.body).is_ok() {
                        let _ = fs::rename(&tmp, &path);
                        return true;
                    }
                }
            }
        }
        self.ensure_trs_stub(canonical_name);
        false
    }

    pub async fn ensure_community_rulesets(&self, opts: &ConnectOptions, force_refresh: bool) {
        let mut needed = HashSet::new();
        for item in &opts.community_lists {
            let can = canonical_ruleset_name(&item.name);
            if !can.is_empty() {
                needed.insert(can);
            }
        }
        if needed.is_empty() {
            return;
        }

        for can in needed {
            let path = self.ruleset_file_path(&can);
            let has_real = Self::is_valid_trs_file(&path, true);
            let expired = has_real
                && fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .map(|d| d > Duration::from_secs(86400))
                    .unwrap_or(true);
            if force_refresh || !has_real || expired {
                self.download_single_ruleset(&can).await;
            }
        }
    }

    pub async fn refresh_rulesets(&self, names_csv: Option<String>) {
        let mut target = HashSet::new();
        if let Some(csv) = names_csv {
            for part in csv.split([',', ';', ' ']) {
                let can = canonical_ruleset_name(part);
                if !can.is_empty() {
                    target.insert(can);
                }
            }
        }
        let dir = self.data_dir.join("rulesets");
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if let Some(rest) = fname.strip_prefix("community-") {
                    if let Some(stem) = rest.strip_suffix(".trs").or_else(|| rest.strip_suffix(".srs")) {
                        let can = canonical_ruleset_name(stem);
                        if !can.is_empty() {
                            target.insert(can);
                        }
                    }
                }
            }
        }
        if target.is_empty() {
            for def in [
                "ru_domains",
                "geoip_ru",
                "russia_inside",
                "youtube",
                "discord",
                "ru_blocked",
                "telegram",
                "ai_all",
                "ads_hagezi_pro",
            ] {
                target.insert(def.to_string());
            }
        }

        let total = target.len();
        self.emit(format!("lists-update:progress:0/{total}"));
        let mut done = 0usize;
        let mut ok_count = 0usize;
        for can in target {
            if self.download_single_ruleset(&can).await {
                ok_count += 1;
            }
            done += 1;
            self.emit(format!("lists-update:progress:{done}/{total}"));
        }
        self.emit(format!("lists-update:done:{ok_count}/{total}"));

        let last_opts = self.last_connect_opts.lock().unwrap().clone();
        if self.is_running().await {
            if let Some(opts_json) = last_opts {
                self.connect(opts_json).await;
            }
        }
    }

    fn build_desync_outbound(tag: &str, d: &DesyncOptions) -> Value {
        let preset = d.preset.trim().to_ascii_lowercase();
        let mapped_preset = match preset.as_str() {
            "youtube_discord" | "fake_split" | "fakesplit" => "fake_split",
            "fake_disorder" | "fakedisorder" | "aggressive" => "fake_disorder",
            "multi_split" | "multisplit" => "multi_split",
            "tlsrec" | "tls_rec" => "tlsrec",
            "split" => "split",
            "disorder" => "disorder",
            "fake" => "fake",
            "oob" => "oob",
            "custom" => "",
            _ => "auto",
        };

        let raw_mode = d.mode.trim().to_ascii_lowercase();
        let valid_mode = match raw_mode.as_str() {
            "auto" | "adaptive" | "smart" => "auto",
            "fake_split" | "fakesplit" => "fake_split",
            "fake_disorder" | "fakedisorder" => "fake_disorder",
            "multi_split" | "multisplit" => "multi_split",
            "tlsrec" | "tls_rec" => "tlsrec",
            "split" => "split",
            "disorder" => "disorder",
            "fake" => "fake",
            "oob" => "oob",
            _ => {
                if mapped_preset.is_empty() {
                    "fake_split"
                } else {
                    mapped_preset
                }
            }
        };

        let valid_fooling = match d.fooling.trim().to_ascii_lowercase().as_str() {
            "md5" | "md5sig" | "tcp_md5" | "wrong-md5" => "md5",
            "badseq" | "seq" | "wrong-sequence" => "badseq",
            "timestamp" | "ts" | "tcp_ts" | "wrong-timestamp" => "timestamp",
            "badsum" | "sum" | "wrong-checksum" => "badsum",
            "autottl" | "auto_ttl" | "ttl" | "low-ttl" => "autottl",
            _ => "md5",
        };

        let sp = d.split_pos.trim().to_ascii_lowercase();
        let split_pos_val: Value = if let Ok(n) = sp.parse::<u32>() {
            json!(n.clamp(1, 1400))
        } else if sp == "sni" || sp == "sniext" {
            json!("sni")
        } else {
            json!("midsld")
        };

        let mut obj = json!({
            "type": "desync",
            "tag": tag,
            "connect_timeout": "5s",
            "mode": valid_mode,
            "fooling": valid_fooling,
            "split_pos": split_pos_val,
            "fake_ttl": d.fake_ttl.clamp(1, 128),
            "fake_sni": if d.fake_sni.trim().is_empty() { "www.google.com" } else { d.fake_sni.trim() },
            "repeats": d.repeats.clamp(1, 100),
            "split_delay_ms": d.split_delay_ms.clamp(0, 1000),
            "auto_tune": if preset == "auto" { true } else { d.auto_tune },
            "udp_fake": d.udp_fake,
            "udp_repeats": d.udp_repeats.clamp(1, 50),
            "udp_fake_ttl": d.udp_fake_ttl.clamp(1, 128),
        });
        if !mapped_preset.is_empty() {
            obj["preset"] = json!(mapped_preset);
        }
        obj
    }

    fn prepare_parsed_node(
        raw_uri: &str,
        tag: &str,
        tls_fragment: bool,
        detour_tag: Option<&str>,
    ) -> Result<(bool, Value, Option<String>), String> {
        let mut node = parse_share_uri(raw_uri.trim())?;
        let server_host = node
            .get("server")
            .and_then(Value::as_str)
            .map(str::to_string);
        let ntype = node
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();

        if ntype == "wireguard" {
            if let Some(obj) = node.as_object_mut() {
                obj.insert("tag".to_string(), json!(tag));
            }
            let mut ep = wireguard_node_to_endpoint(&node);
            if let Some(obj) = ep.as_object_mut() {
                obj.insert("tag".to_string(), json!(tag));
            }
            return Ok((true, ep, server_host));
        }

        if let Some(obj) = node.as_object_mut() {
            obj.insert("tag".to_string(), json!(tag));
            obj.insert("connect_timeout".to_string(), json!("5s"));
            if let Some(dt) = detour_tag {
                obj.insert("detour".to_string(), json!(dt));
            }
            if tls_fragment
                && matches!(ntype.as_str(), "vless" | "vmess" | "trojan")
                && obj.get("tls").and_then(Value::as_object).is_some()
            {
                if let Some(tls_obj) = obj.get_mut("tls").and_then(Value::as_object_mut) {
                    tls_obj.insert("record_fragment".to_string(), json!(true));
                }
            }
        }
        Ok((false, node, server_host))
    }

    pub fn build_config(&self, opts: &ConnectOptions) -> Result<(Value, bool), String> {
        let has_main_node = !opts.block_only
            && opts.route != RouteMode::DesyncOnly
            && !opts.vless.trim().is_empty();

        let detour_parsed = if has_main_node && !opts.detour_vless.trim().is_empty() {
            Self::prepare_parsed_node(
                &opts.detour_vless,
                "detour-proxy",
                opts.proxy_tls_fragment,
                None,
            )
            .ok()
        } else {
            None
        };

        let main_detour_tag = detour_parsed.as_ref().map(|_| "detour-proxy");
        let main_parsed = if has_main_node {
            Some(Self::prepare_parsed_node(
                &opts.vless,
                "PROXY",
                opts.proxy_tls_fragment,
                main_detour_tag,
            )?)
        } else {
            None
        };

        let mut extra_parsed = Vec::new();
        if !opts.block_only && opts.route != RouteMode::DesyncOnly {
            for ex in &opts.extra_nodes {
                if let Ok(p) =
                    Self::prepare_parsed_node(&ex.vless, &ex.tag, opts.proxy_tls_fragment, None)
                {
                    extra_parsed.push((ex.tag.clone(), p));
                }
            }
        }

        let bootstrap_ip = opts
            .dns_bootstrap
            .trim()
            .parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "77.88.8.8".to_string());

        let mut dns_servers = vec![json!({
            "type": "udp",
            "tag": "dns_direct",
            "server": bootstrap_ip,
            "server_port": 53,
            "detour": "direct"
        })];

        let dns_detour = if main_parsed.is_some() {
            "GLOBAL"
        } else {
            "direct"
        };
        let dns_choice = opts.dns.trim().to_ascii_lowercase();
        let remote_dns = match dns_choice.as_str() {
            "adguard" => json!({
                "type": "https",
                "tag": "dns_remote",
                "server": "94.140.14.14",
                "server_port": 443,
                "path": "/dns-query",
                "detour": dns_detour
            }),
            "quad9" | "9.9.9.9" => json!({
                "type": "https",
                "tag": "dns_remote",
                "server": "9.9.9.9",
                "server_port": 443,
                "path": "/dns-query",
                "detour": dns_detour
            }),
            "google" | "8.8.8.8" => json!({
                "type": "https",
                "tag": "dns_remote",
                "server": "8.8.8.8",
                "server_port": 443,
                "path": "/dns-query",
                "detour": dns_detour
            }),
            "yandex" | "77.88.8.8" => json!({
                "type": "udp",
                "tag": "dns_remote",
                "server": "77.88.8.8",
                "server_port": 53,
                "detour": "direct"
            }),
            _ if dns_choice.parse::<IpAddr>().is_ok() => json!({
                "type": "udp",
                "tag": "dns_remote",
                "server": dns_choice,
                "server_port": 53,
                "detour": dns_detour
            }),
            _ => json!({
                "type": "https",
                "tag": "dns_remote",
                "server": "1.1.1.1",
                "server_port": 443,
                "path": "/dns-query",
                "detour": dns_detour
            }),
        };
        dns_servers.push(remote_dns);

        let fake_ip_enabled = opts.fake_ip && !opts.proxy_mode;
        if fake_ip_enabled {
            dns_servers.push(json!({
                "type": "fakeip",
                "tag": "dns-fakeip",
                "inet4_range": "198.18.0.0/15"
            }));
        }

        let mut dns_rules = vec![json!({
            "domain_suffix": [".lan", ".local", ".home.arpa", ".internal"],
            "server": "dns_direct"
        })];

        if opts.dns_route_mode == "split_ru" {
            dns_rules.push(json!({
                "domain_suffix": [".ru", ".su", ".рф", "xn--p1ai"],
                "server": "dns_direct"
            }));
            if fake_ip_enabled {
                dns_rules.push(json!({
                    "query_type": ["A", "AAAA"],
                    "server": "dns-fakeip",
                    "rewrite_ttl": 1
                }));
            }
        } else if opts.dns_route_mode == "proxy" && fake_ip_enabled {
            dns_rules.push(json!({
                "query_type": ["A", "AAAA"],
                "server": "dns-fakeip",
                "rewrite_ttl": 1
            }));
        }

        let final_dns_tag = if opts.dns_route_mode == "direct" || main_parsed.is_none() {
            "dns_direct"
        } else {
            "dns_remote"
        };

        let mut dns_obj = json!({
            "servers": dns_servers,
            "rules": dns_rules,
            "final": final_dns_tag,
            "strategy": "prefer_ipv4"
        });
        if fake_ip_enabled {
            dns_obj["fakeip"] = json!({
                "enabled": true,
                "inet4_range": "198.18.0.0/15"
            });
        }

        let mut inbounds = Vec::new();
        if !opts.proxy_mode {
            inbounds.push(json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": default_tun_device(),
                "address": ["172.19.0.1/30"],
                "mtu": opts.mtu.clamp(1280, 9000),
                "auto_route": true,
                "strict_route": true,
                "stack": "mixed",
                "route_exclude_address": [
                    "172.19.0.0/30",
                    "224.0.0.0/4",
                    "255.255.255.255/32",
                    "169.254.0.0/16",
                    "ff00::/8",
                    "fe80::/10"
                ]
            }));
        }
        inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": if opts.allow_lan { "0.0.0.0" } else { "127.0.0.1" },
            "listen_port": PROXY_PORT
        }));

        let mut endpoints = Vec::new();
        let mut outbounds = Vec::new();
        let mut server_hosts = HashSet::new();

        let need_desync = opts.desync.enabled
            || opts.route == RouteMode::DesyncOnly
            || main_parsed.is_none()
            || opts
                .community_lists
                .iter()
                .any(|x| x.action.eq_ignore_ascii_case("desync"))
            || opts
                .custom_rules
                .iter()
                .any(|x| x.action.eq_ignore_ascii_case("desync"));

        let mut selector_outbounds = Vec::new();
        if main_parsed.is_some() {
            selector_outbounds.push("PROXY".to_string());
        }
        for (tag, _) in &extra_parsed {
            selector_outbounds.push(tag.clone());
        }
        if need_desync {
            selector_outbounds.push("DESYNC".to_string());
        }
        selector_outbounds.push("direct".to_string());

        outbounds.push(json!({
            "type": "selector",
            "tag": "GLOBAL",
            "outbounds": selector_outbounds
        }));

        if let Some((is_ep, val, host)) = main_parsed.clone() {
            if let Some(h) = host {
                server_hosts.insert(h);
            }
            if is_ep {
                endpoints.push(val);
            } else {
                outbounds.push(val);
            }
        }
        if let Some((is_ep, val, host)) = detour_parsed {
            if let Some(h) = host {
                server_hosts.insert(h);
            }
            if is_ep {
                endpoints.push(val);
            } else {
                outbounds.push(val);
            }
        }
        for (_, (is_ep, val, host)) in &extra_parsed {
            if let Some(h) = host {
                server_hosts.insert(h.clone());
            }
            if *is_ep {
                endpoints.push(val.clone());
            } else {
                outbounds.push(val.clone());
            }
        }

        if need_desync {
            outbounds.push(Self::build_desync_outbound("DESYNC", &opts.desync));
        }
        outbounds.push(json!({
            "type": "direct",
            "tag": "direct",
            "connect_timeout": "5s"
        }));
        outbounds.push(json!({
            "type": "block",
            "tag": "block"
        }));

        let mut rules = vec![
            json!({ "action": "sniff" }),
            json!({ "protocol": "dns", "action": "hijack-dns" }),
            json!({ "process_name": ["tachyon", "tachyon-desktop", "tachyon-core", "tachyon-core.exe", "Tachyon.exe"], "outbound": "direct" }),
            json!({ "network": "udp", "port": [135, 137, 138, 139, 445, 1900, 3702, 5353, 5355], "action": "reject" }),
            json!({ "ip_is_private": true, "outbound": "direct" }),
            json!({ "ip_cidr": [format!("{bootstrap_ip}/32")], "outbound": "direct" }),
        ];

        let mut server_ips = Vec::new();
        let mut server_domains = Vec::new();
        for h in server_hosts {
            if h.parse::<IpAddr>().is_ok() {
                server_ips.push(format!("{h}/32"));
            } else if !h.is_empty() {
                server_domains.push(h);
            }
        }
        if !server_ips.is_empty() {
            rules.push(json!({ "ip_cidr": server_ips, "outbound": "direct" }));
        }
        if !server_domains.is_empty() {
            rules.push(json!({ "domain": server_domains, "outbound": "direct" }));
        }

        rules.push(json!({
            "domain_suffix": ["github.com", "githubusercontent.com", "github.io", "cdn.jsdelivr.net"],
            "outbound": "direct"
        }));

        let vpn_target_tag = if main_parsed.is_some() {
            "GLOBAL"
        } else {
            "DESYNC"
        };
        let valid_extra_tags: HashSet<String> =
            extra_parsed.iter().map(|(t, _)| t.clone()).collect();
        let mut rule_sets = Vec::new();
        let mut registered_rs = HashSet::new();

        self.append_custom_and_community_rules(
            opts,
            vpn_target_tag,
            &valid_extra_tags,
            &mut rules,
            &mut rule_sets,
            &mut registered_rs,
        );

        let mut app_procs = Vec::new();
        for r in &opts.rules {
            let rt = r.trim();
            if rt.to_ascii_uppercase().starts_with("PROCESS-NAME,") {
                let parts: Vec<&str> = rt.split(',').collect();
                if parts.len() >= 2 && !parts[1].trim().is_empty() {
                    app_procs.push(parts[1].trim().to_string());
                }
            } else if !rt.is_empty() {
                app_procs.push(rt.to_string());
            }
        }

        let direct_or_desync = if opts.desync.enabled && opts.desync.auto_direct {
            "DESYNC"
        } else {
            "direct"
        };

        let final_outbound = if opts.block_only {
            "direct"
        } else {
            match opts.route {
                RouteMode::Apps | RouteMode::Selective => {
                    if !app_procs.is_empty() {
                        rules.push(json!({ "process_name": app_procs, "outbound": vpn_target_tag }));
                    }
                    direct_or_desync
                }
                RouteMode::AppsExclude => {
                    if !app_procs.is_empty() {
                        rules.push(json!({ "process_name": app_procs, "outbound": direct_or_desync }));
                    }
                    vpn_target_tag
                }
                RouteMode::DesyncOnly => "DESYNC",
                RouteMode::All => vpn_target_tag,
            }
        };

        if final_outbound == "DESYNC" {
            rules.push(json!({
                "domain_suffix": [".ru", ".su", ".рф", "xn--p1ai"],
                "outbound": "direct"
            }));
            if opts.desync.block_quic {
                rules.push(json!({ "network": "udp", "port": 443, "action": "reject" }));
            }
        }

        let mut route_obj = json!({
            "default_domain_resolver": "dns_direct",
            "auto_detect_interface": true,
            "final": final_outbound,
            "rules": rules
        });
        if !rule_sets.is_empty() {
            route_obj["rule_set"] = Value::Array(rule_sets);
        }

        let experimental = json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{API_PORT}"),
                "secret": self.secret
            },
            "cache_file": {
                "enabled": true,
                "path": self.data_dir.join("cache.db").to_string_lossy(),
                "store_fakeip": fake_ip_enabled
            }
        });

        let mut root = json!({
            "log": {
                "level": opts.log_level,
                "output": self.log_path.to_string_lossy(),
                "timestamp": true
            },
            "dns": dns_obj,
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": route_obj,
            "experimental": experimental
        });
        if !endpoints.is_empty() {
            root["endpoints"] = Value::Array(endpoints);
        }

        Ok((root, main_parsed.is_some()))
    }

    fn append_custom_and_community_rules(
        &self,
        opts: &ConnectOptions,
        vpn_target_tag: &str,
        valid_extra_tags: &HashSet<String>,
        rules_list: &mut Vec<Value>,
        rule_sets_list: &mut Vec<Value>,
        registered_rs: &mut HashSet<String>,
    ) {
        let mut custom_groups = vec![
            "block".to_string(),
            "direct".to_string(),
            "desync".to_string(),
        ];
        for t in valid_extra_tags {
            custom_groups.push(t.clone());
        }
        custom_groups.push("vpn".to_string());

        let ip_re = Regex::new(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$").unwrap();

        for group in &custom_groups {
            let matching: Vec<&CustomRouteRule> = opts
                .custom_rules
                .iter()
                .filter(|r| r.action.eq_ignore_ascii_case(group))
                .collect();
            if matching.is_empty() {
                continue;
            }

            let mut dom_suffixes = Vec::new();
            let mut dom_keywords = Vec::new();
            let mut ip_cidrs = Vec::new();
            let mut procs = Vec::new();

            for cr in matching {
                let val = cr.value.trim();
                if val.is_empty() {
                    continue;
                }
                if cr.rtype == "process" || val.to_ascii_lowercase().ends_with(".exe") {
                    procs.push(val.to_string());
                } else if cr.rtype == "ip" || ip_re.is_match(val) {
                    if val.contains('/') {
                        ip_cidrs.push(val.to_string());
                    } else {
                        ip_cidrs.push(format!("{val}/32"));
                    }
                } else if let Some(kw) = val.strip_prefix("keyword:") {
                    if !kw.trim().is_empty() {
                        dom_keywords.push(kw.trim().to_string());
                    }
                } else {
                    let clean = val
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_start_matches("*.")
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_start_matches('.');
                    if !clean.is_empty() {
                        dom_suffixes.push(clean.to_string());
                    }
                }
            }

            let emit_matcher = |mut matcher: Map<String, Value>, rules_out: &mut Vec<Value>| {
                if group == "block" {
                    matcher.insert("action".to_string(), json!("reject"));
                    rules_out.push(Value::Object(matcher));
                } else if group == "direct" {
                    matcher.insert("outbound".to_string(), json!("direct"));
                    rules_out.push(Value::Object(matcher));
                } else if group == "desync" {
                    if opts.desync.block_quic {
                        let mut q = matcher.clone();
                        q.insert("network".to_string(), json!("udp"));
                        q.insert("port".to_string(), json!(443));
                        q.insert("action".to_string(), json!("reject"));
                        rules_out.push(Value::Object(q));
                    }
                    matcher.insert("outbound".to_string(), json!("DESYNC"));
                    rules_out.push(Value::Object(matcher));
                } else if valid_extra_tags.contains(group) {
                    matcher.insert("outbound".to_string(), json!(group));
                    rules_out.push(Value::Object(matcher));
                } else {
                    matcher.insert("outbound".to_string(), json!(vpn_target_tag));
                    rules_out.push(Value::Object(matcher));
                }
            };

            if !dom_suffixes.is_empty() {
                let mut m = Map::new();
                m.insert("domain_suffix".to_string(), json!(dom_suffixes));
                emit_matcher(m, rules_list);
            }
            if !dom_keywords.is_empty() {
                let mut m = Map::new();
                m.insert("domain_keyword".to_string(), json!(dom_keywords));
                emit_matcher(m, rules_list);
            }
            if !ip_cidrs.is_empty() {
                let mut m = Map::new();
                m.insert("ip_cidr".to_string(), json!(ip_cidrs));
                emit_matcher(m, rules_list);
            }
            if !procs.is_empty() {
                let mut m = Map::new();
                m.insert("process_name".to_string(), json!(procs));
                emit_matcher(m, rules_list);
            }
        }

        if opts.community_lists.is_empty() {
            return;
        }

        let mut block_rs = Vec::new();
        let mut prio_direct_rs = Vec::new();
        let mut desync_rs = Vec::new();
        let mut node_rs: HashMap<String, Vec<String>> = HashMap::new();
        let mut vpn_rs = Vec::new();
        let mut rest_direct_rs = Vec::new();

        for item in &opts.community_lists {
            let can = canonical_ruleset_name(&item.name);
            if can.is_empty() {
                continue;
            }
            let tag = format!("rs-{can}");
            if registered_rs.insert(tag.clone()) {
                self.ensure_trs_stub(&can);
                let path = self.ruleset_file_path(&can);
                rule_sets_list.push(json!({
                    "type": "local",
                    "tag": tag,
                    "format": "binary",
                    "path": path.to_string_lossy()
                }));
            }

            let act = item.action.trim();
            let act_low = act.to_ascii_lowercase();
            if act_low == "block" {
                block_rs.push(tag);
            } else if act_low == "desync" {
                desync_rs.push(tag);
            } else if valid_extra_tags.contains(act) {
                node_rs.entry(act.to_string()).or_default().push(tag);
            } else if act_low == "vpn" || act.to_ascii_uppercase().starts_with("NODE_") {
                vpn_rs.push(tag);
            } else if act_low == "direct" {
                if is_priority_direct_ru_list(&can) {
                    prio_direct_rs.push(tag);
                } else {
                    rest_direct_rs.push(tag);
                }
            }
        }

        if !block_rs.is_empty() {
            rules_list.push(json!({ "rule_set": block_rs, "action": "reject" }));
        }
        if !prio_direct_rs.is_empty() {
            rules_list.push(json!({ "rule_set": prio_direct_rs, "outbound": "direct" }));
        }
        if !desync_rs.is_empty() {
            if opts.desync.block_quic {
                rules_list.push(json!({
                    "rule_set": desync_rs.clone(),
                    "network": "udp",
                    "port": 443,
                    "action": "reject"
                }));
            }
            rules_list.push(json!({ "rule_set": desync_rs, "outbound": "DESYNC" }));
        }
        for (node_tag, tags) in node_rs {
            if !tags.is_empty() {
                rules_list.push(json!({ "rule_set": tags, "outbound": node_tag }));
            }
        }
        if !vpn_rs.is_empty() {
            rules_list.push(json!({ "rule_set": vpn_rs, "outbound": vpn_target_tag }));
        }
        if !rest_direct_rs.is_empty() {
            rules_list.push(json!({ "rule_set": rest_direct_rs, "outbound": "direct" }));
        }
    }

    pub async fn connect(&self, options_json: String) {
        let opts = match ConnectOptions::parse(&options_json) {
            Ok(o) => {
                *self.last_connect_opts.lock().unwrap() = Some(options_json.clone());
                o
            }
            Err(e) => {
                self.emit_vpn(json!({ "state": "error", "error": e }));
                return;
            }
        };

        self.ensure_community_rulesets(&opts, false).await;

        let (cfg_val, has_node) = match self.build_config(&opts) {
            Ok(res) => res,
            Err(e) => {
                self.emit_vpn(json!({ "state": "error", "error": e }));
                return;
            }
        };

        let cfg_path = self.data_dir.join("config.json");
        let cfg_text = serde_json::to_string_pretty(&cfg_val).unwrap_or_default();
        let _ = fs::write(&cfg_path, &cfg_text);

        // Try in-place hot reload if already running in the same mode
        {
            let mut guard = self.engine.lock().await;
            if let Some(eng) = guard.as_mut() {
                if eng.proxy_mode == opts.proxy_mode && !eng.block_only && !opts.block_only {
                    let mut reloaded = false;
                    if let Some(bx) = eng.in_proc.as_mut() {
                        if bx.reload_in_place(&cfg_val).await.is_ok() {
                            reloaded = true;
                        }
                    } else if eng.worker.is_some() {
                        let body = json!({ "path": cfg_path.to_string_lossy() }).to_string();
                        if let Ok((status, _)) = clash_api_request(
                            API_PORT,
                            &self.secret,
                            "PUT",
                            "/configs?force=true",
                            Some(&body),
                        )
                        .await
                        {
                            reloaded = (200..300).contains(&status);
                        }
                    }

                    if reloaded {
                        let _ = clash_api_request(
                            API_PORT,
                            &self.secret,
                            "DELETE",
                            "/connections",
                            None,
                        )
                        .await;
                        eng.running_config = cfg_val;
                        eng.has_node = has_node;
                        flush_os_dns();
                        self.emit_vpn(json!({ "state": "switched" }));
                        return;
                    }
                }
            }
        }

        self.emit_vpn(json!({ "state": "connecting" }));
        self.stop_stats_loop();

        {
            let mut guard = self.engine.lock().await;
            if let Some(mut old) = guard.take() {
                old.stop().await;
            }
        }

        #[cfg(target_os = "windows")]
        refresh_cached_windows_phys_ifindex();

        // Start in-process core-runtime first
        let mut started_in_proc: Option<BoxInstance> = None;
        let mut started_worker: Option<Child> = None;

        match core_runtime::start(&cfg_val).await {
            Ok(bx) => {
                started_in_proc = Some(bx);
            }
            Err(err) => {
                let err_str = format!("{err:#}");
                let need_elevation = !opts.proxy_mode
                    && (err_str.to_ascii_lowercase().contains("permission")
                        || err_str.to_ascii_lowercase().contains("operation not permitted")
                        || err_str.to_ascii_lowercase().contains("access is denied")
                        || err_str.to_ascii_lowercase().contains("eperm")
                        || err_str.to_ascii_lowercase().contains("eacces")
                        || err_str.to_ascii_lowercase().contains("tun"));

                if need_elevation {
                    match spawn_elevated_worker(&cfg_path, &self.secret).await {
                        Ok(child) => {
                            started_worker = Some(child);
                        }
                        Err(elev_err) => {
                            self.emit_vpn(json!({
                                "state": "error",
                                "error": format!("Не удалось поднять TUN-интерфейс ({elev_err}). Вы можете переключиться в режим «Системный прокси» или выдать права администратора."),
                                "details": err_str
                            }));
                            return;
                        }
                    }
                } else {
                    self.emit_vpn(json!({
                        "state": "error",
                        "error": format!("Ошибка запуска ядра: {err}"),
                        "details": err_str
                    }));
                    return;
                }
            }
        }

        {
            let mut guard = self.engine.lock().await;
            *guard = Some(RunningEngine {
                in_proc: started_in_proc,
                worker: started_worker,
                running_config: cfg_val,
                proxy_mode: opts.proxy_mode,
                block_only: opts.block_only,
                has_node,
            });
        }

        if opts.proxy_mode {
            set_system_proxy(true);
        } else {
            set_system_proxy(false);
        }
        flush_os_dns();

        if opts.block_only {
            self.emit_vpn(json!({ "state": "blocking" }));
        } else {
            self.start_stats_loop(has_node);
            self.emit_vpn(json!({
                "state": "connected",
                "mode": if opts.proxy_mode { "proxy" } else { "tun" },
                "proxyAddr": format!("127.0.0.1:{PROXY_PORT}"),
                "device": default_tun_device()
            }));
        }
    }

    pub async fn disconnect(&self) {
        self.stop_stats_loop();
        let mut was_proxy = false;
        {
            let mut guard = self.engine.lock().await;
            if let Some(mut eng) = guard.take() {
                was_proxy = eng.proxy_mode;
                eng.stop().await;
            }
        }
        if was_proxy {
            set_system_proxy(false);
        }
        if *self.kill_switch.lock().unwrap() {
            apply_kill_switch(false);
        }
        self.emit_vpn(json!({ "state": "off" }));
    }

    pub fn set_kill_switch(&self, on: bool) {
        *self.kill_switch.lock().unwrap() = on;
        apply_kill_switch(on);
    }

    fn stop_stats_loop(&self) {
        if let Some(tx) = self.stats_cancel.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }

    fn start_stats_loop(&self, has_node: bool) {
        self.stop_stats_loop();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        *self.stats_cancel.lock().unwrap() = Some(tx);

        let secret = self.secret.clone();
        let send_js = self.send_js.clone();
        let mut rx_delay = rx.clone();
        let secret_delay = secret.clone();
        let send_js_delay = send_js.clone();

        tokio::spawn(async move {
            let mut last_down = 0u64;
            let mut last_up = 0u64;
            let mut last_sample = Instant::now();

            loop {
                if *rx.borrow() {
                    break;
                }
                if let Ok((200, body)) =
                    clash_api_request(API_PORT, &secret, "GET", "/connections", None).await
                {
                    if let Ok(doc) = serde_json::from_str::<Value>(&body) {
                        let down_total = doc
                            .get("downloadTotal")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let up_total = doc.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0);
                        let dt = last_sample.elapsed().as_secs_f64().max(0.2);
                        let down_rate = if last_down == 0 {
                            0
                        } else {
                            ((down_total.saturating_sub(last_down)) as f64 / dt) as u64
                        };
                        let up_rate = if last_up == 0 {
                            0
                        } else {
                            ((up_total.saturating_sub(last_up)) as f64 / dt) as u64
                        };
                        last_down = down_total;
                        last_up = up_total;
                        last_sample = Instant::now();

                        let msg = json!({
                            "state": "connected",
                            "down": down_rate,
                            "up": up_rate,
                            "totalDown": down_total,
                            "totalUp": up_total
                        });
                        (send_js)(format!("vpn:{msg}"));
                    }
                }
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        });

        tokio::spawn(async move {
            loop {
                if *rx_delay.borrow() {
                    break;
                }
                let ping_opt = if has_node {
                    probe_proxy_delay(&secret_delay).await
                } else {
                    let ms = tcp_connect_ms("1.1.1.1", 443, 2500).await;
                    if ms > 0 { Some(ms as u64) } else { None }
                };
                if let Some(p) = ping_opt {
                    let msg = json!({ "state": "connected", "ping": p });
                    (send_js_delay)(format!("vpn:{msg}"));
                }
                tokio::select! {
                    _ = rx_delay.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(6)) => {}
                }
            }
        });
    }

    pub async fn probe_delay(&self) -> Option<u64> {
        probe_proxy_delay(&self.secret).await
    }

    pub async fn get_connections_json(&self) -> String {
        let Ok((200, body)) =
            clash_api_request(API_PORT, &self.secret, "GET", "/connections", None).await
        else {
            return "{\"conns\":[],\"down\":0,\"up\":0}".to_string();
        };
        let Ok(doc) = serde_json::from_str::<Value>(&body) else {
            return "{\"conns\":[],\"down\":0,\"up\":0}".to_string();
        };
        let down = doc
            .get("downloadTotal")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let up = doc.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0);
        let mut conns = Vec::new();
        if let Some(arr) = doc.get("connections").and_then(Value::as_array) {
            for item in arr {
                let id = item.get("id").and_then(Value::as_str).unwrap_or("");
                let meta = item.get("metadata");
                let host = meta
                    .and_then(|m| m.get("host"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let ip = meta
                    .and_then(|m| m.get("destinationIP"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let port = meta
                    .and_then(|m| m.get("destinationPort"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let net = meta
                    .and_then(|m| m.get("network"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let ctype = meta
                    .and_then(|m| m.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let proc_name = meta
                    .and_then(|m| m.get("process"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let mut direct = false;
                let mut desync = false;
                if let Some(chains) = item.get("chains").and_then(Value::as_array) {
                    for ch in chains {
                        if let Some(s) = ch.as_str() {
                            if s.eq_ignore_ascii_case("DIRECT") {
                                direct = true;
                            } else if s.eq_ignore_ascii_case("DESYNC") {
                                desync = true;
                            }
                        }
                    }
                }
                let cup = item.get("upload").and_then(Value::as_u64).unwrap_or(0);
                let cdown = item.get("download").and_then(Value::as_u64).unwrap_or(0);
                conns.push(json!({
                    "id": id,
                    "host": host,
                    "ip": ip,
                    "port": port,
                    "net": net,
                    "type": ctype,
                    "proc": proc_name,
                    "up": cup,
                    "down": cdown,
                    "direct": direct,
                    "desync": desync
                }));
            }
        }
        json!({
            "down": down,
            "up": up,
            "conns": conns
        })
        .to_string()
    }

    pub async fn close_connection(&self, cid: Option<&str>) {
        let path = match cid {
            Some(id) if !id.is_empty() && id != "all" => format!("/connections/{id}"),
            _ => "/connections".to_string(),
        };
        let _ = clash_api_request(API_PORT, &self.secret, "DELETE", &path, None).await;
    }

    pub fn get_log_tail(&self, max_lines: usize) -> String {
        if let Ok(content) = fs::read_to_string(&self.log_path) {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(max_lines);
            if !lines[start..].is_empty() {
                return lines[start..].join("\n");
            }
        }
        let ring = core_runtime::logging::recent(core_runtime::logging::Level::Trace);
        let start = ring.len().saturating_sub(max_lines);
        ring[start..].join("\n")
    }

    pub async fn import_subscription(&self, input: String) {
        let input = input.trim();
        if input.is_empty() {
            self.emit(format!("sub:{}", json!({ "error": "Пустая ссылка" })));
            return;
        }

        // Single share link
        if !input.starts_with("http://") && !input.starts_with("https://") {
            match parse_share_uri(input) {
                Ok(val) => {
                    let tag = val
                        .get("tag")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("Сервер");
                    let payload = json!({
                        "user": { "handle": tag },
                        "servers": [{
                            "id": "custom-1",
                            "name": tag,
                            "vless": input,
                            "country": detect_country_code(tag)
                        }]
                    });
                    self.emit(format!("sub:{payload}"));
                }
                Err(e) => {
                    self.emit(format!("sub:{}", json!({ "error": e })));
                }
            }
            return;
        }

        // Remote subscription URL
        let resp = match fetch_url(
            input,
            "GET",
            &[("User-Agent", "v2rayN/6.42"), ("Accept", "*/*")],
            None,
            None,
            Duration::from_secs(20),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                self.emit(format!("sub:{}", json!({ "error": e.to_string() })));
                return;
            }
        };

        if !(200..300).contains(&resp.status) {
            self.emit(format!(
                "sub:{}",
                json!({ "error": format!("Сервер вернул HTTP {}", resp.status) })
            ));
            return;
        }

        let body_text = resp.text();
        let meta = extract_subscription_metadata(
            &body_text,
            resp.header("subscription-userinfo"),
            resp.header("profile-title"),
        );
        let nodes = match parse_subscription_payload(&body_text) {
            Ok(n) => n,
            Err(e) => {
                self.emit(format!("sub:{}", json!({ "error": e })));
                return;
            }
        };

        let mut servers = Vec::new();
        for (idx, node) in nodes.iter().enumerate() {
            let Some(share_link) = outbound_to_share_link(node) else {
                continue;
            };
            let name = node
                .get("tag")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("Узел #{}", idx + 1));
            let country = detect_country_code(&name);
            servers.push(json!({
                "id": format!("sub-{}", idx + 1),
                "name": name,
                "vless": share_link,
                "country": country
            }));
        }

        if servers.is_empty() {
            self.emit(format!(
                "sub:{}",
                json!({ "error": "В ответе нет поддерживаемых узлов" })
            ));
            return;
        }

        let handle = meta
            .profile_title
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Подписка".to_string());
        let mut traffic_used = 0u64;
        let mut traffic_total = 0u64;
        if let Some(ref ui) = meta.user_info_raw {
            for part in ui.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if let Ok(num) = v.trim().parse::<u64>() {
                        match k.trim() {
                            "upload" | "download" => traffic_used += num,
                            "total" => traffic_total = num,
                            _ => {}
                        }
                    }
                }
            }
        }

        let result = json!({
            "user": { "handle": handle },
            "subscription": {
                "status": "active",
                "trafficUsed": traffic_used,
                "trafficTotal": traffic_total
            },
            "servers": servers
        });
        self.emit(format!("sub:{result}"));
    }

    pub async fn provision_warp_awg(&self) -> String {
        let mut priv_bytes = [0u8; 32];
        let _ = getrandom::fill(&mut priv_bytes);
        let secret = x25519_dalek::StaticSecret::from(priv_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);

        let priv_b64 = B64.encode(secret.to_bytes());
        let pub_b64 = B64.encode(public.as_bytes());

        let body_json = json!({
            "key": pub_b64,
            "install_id": "",
            "fcm_token": "",
            "tos": "2025-01-01T00:00:00.000Z",
            "model": "PC",
            "serial_number": &self.secret[..12],
            "locale": "en_US"
        })
        .to_string();

        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };

        let resp = match fetch_url(
            "https://api.cloudflareclient.com/v0a2158/reg",
            "POST",
            &[
                ("User-Agent", "okhttp/3.12.1"),
                ("CF-Client-Version", "a-6.11-2223"),
                ("Content-Type", "application/json"),
            ],
            Some(body_json.as_bytes()),
            proxy,
            Duration::from_secs(12),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return json!({ "ok": false, "error": e.to_string() }).to_string(),
        };

        if !(200..300).contains(&resp.status) {
            return json!({ "ok": false, "error": format!("HTTP {}", resp.status) }).to_string();
        }

        let Ok(doc) = serde_json::from_slice::<Value>(&resp.body) else {
            return json!({ "ok": false, "error": "Invalid JSON from Cloudflare" }).to_string();
        };
        let cfg = doc.get("config").unwrap_or(&doc);
        let v4 = cfg
            .get("interface")
            .and_then(|i| i.get("addresses"))
            .and_then(|a| a.get("v4"))
            .and_then(Value::as_str)
            .unwrap_or("172.16.0.2/32");
        let client_ip = if v4.contains('/') {
            v4.to_string()
        } else {
            format!("{v4}/32")
        };

        let peer_pub = cfg
            .get("peers")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|p| p.get("public_key"))
            .and_then(Value::as_str)
            .unwrap_or("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");

        let awg_uri = format!(
            "amneziawg://{}@162.159.192.1:2408?pub={}&ip={}&mtu=1280&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#Cloudflare%20WARP%20(AmneziaWG)",
            core_config::subscription::percent_encode_component(&priv_b64),
            core_config::subscription::percent_encode_component(peer_pub),
            core_config::subscription::percent_encode_component(&client_ip),
        );

        json!({
            "ok": true,
            "uri": awg_uri,
            "name": "Cloudflare WARP (AmneziaWG)",
            "ip": client_ip
        })
        .to_string()
    }

    pub async fn check_exit_node_info(&self) -> String {
        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let sw = Instant::now();
        if let Ok(resp) = fetch_url(
            "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,query&lang=ru",
            "GET",
            &[],
            None,
            proxy,
            Duration::from_secs(5),
        )
        .await
        {
            if let Ok(doc) = serde_json::from_slice::<Value>(&resp.body) {
                if doc.get("status").and_then(Value::as_str) == Some("success") {
                    let ip = doc.get("query").and_then(Value::as_str).unwrap_or("—");
                    let country = doc.get("country").and_then(Value::as_str).unwrap_or("");
                    let cc = doc.get("countryCode").and_then(Value::as_str).unwrap_or("");
                    let city = doc.get("city").and_then(Value::as_str).unwrap_or("");
                    let isp = doc
                        .get("isp")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .or_else(|| doc.get("org").and_then(Value::as_str))
                        .unwrap_or("");
                    return json!({
                        "ok": true,
                        "ip": ip,
                        "country": country,
                        "countryCode": cc,
                        "city": city,
                        "isp": isp,
                        "latencyMs": sw.elapsed().as_millis() as u64
                    })
                    .to_string();
                }
            }
        }

        let sw2 = Instant::now();
        if let Ok(resp) = fetch_url(
            "https://ipinfo.io/json",
            "GET",
            &[],
            None,
            proxy,
            Duration::from_secs(5),
        )
        .await
        {
            if let Ok(doc) = serde_json::from_slice::<Value>(&resp.body) {
                if let Some(ip) = doc.get("ip").and_then(Value::as_str) {
                    let cc = doc.get("country").and_then(Value::as_str).unwrap_or("");
                    let city = doc.get("city").and_then(Value::as_str).unwrap_or("");
                    let isp = doc.get("org").and_then(Value::as_str).unwrap_or("");
                    return json!({
                        "ok": true,
                        "ip": ip,
                        "country": cc,
                        "countryCode": cc,
                        "city": city,
                        "isp": isp,
                        "latencyMs": sw2.elapsed().as_millis() as u64
                    })
                    .to_string();
                }
            }
        }

        json!({ "ok": false, "error": "Нет ответа от гео-сервисов" }).to_string()
    }

    pub async fn run_dns_benchmark(&self) -> String {
        let targets = [
            ("yandex", "Яндекс DNS (77.88.8.8)", "77.88.8.8", 53u16, "UDP/TCP 53"),
            ("cloudflare", "Cloudflare (1.1.1.1)", "1.1.1.1", 443u16, "DoH / HTTPS"),
            ("google", "Google (8.8.8.8)", "8.8.8.8", 443u16, "DoH / HTTPS"),
            ("quad9", "Quad9 (9.9.9.9)", "9.9.9.9", 443u16, "DoH / HTTPS"),
            ("adguard", "AdGuard (94.140.14.14)", "94.140.14.14", 443u16, "DoH / HTTPS"),
        ];
        let mut results = Vec::new();
        for (id, name, host, port, proto) in targets {
            let ms = tcp_connect_ms(host, port, 3000).await;
            results.push(json!({
                "id": id,
                "name": name,
                "host": host,
                "proto": proto,
                "ms": ms
            }));
        }
        json!({ "results": results }).to_string()
    }

    pub async fn run_diagnostics_matrix(&self) -> String {
        let probes = [
            ("direct_ru", "Рунет (Яндекс)", "Проверка базового прямого канала", "https://ya.ru"),
            ("cloudflare", "Cloudflare Edge", "Зарубежный CDN и DoH-инфраструктура", "https://cp.cloudflare.com/generate_204"),
            ("youtube", "YouTube Web & Video", "Доступность видеоплатформы и манифестов", "https://www.youtube.com/generate_204"),
            ("discord", "Discord API & Gateway", "Голосовой и текстовый шлюз Discord", "https://discord.com/api/v9/experiments"),
            ("telegram", "Telegram Web", "Веб-шлюз и медиасерверы Telegram", "https://web.telegram.org/"),
        ];
        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let mut items = Vec::new();
        for (id, title, subtitle, url) in probes {
            let sw = Instant::now();
            match fetch_url(url, "GET", &[], None, proxy, Duration::from_secs(5)).await {
                Ok(resp) => {
                    let ok = (200..500).contains(&resp.status);
                    items.push(json!({
                        "id": id,
                        "title": title,
                        "subtitle": subtitle,
                        "ok": ok,
                        "status": format!("HTTP {}", resp.status),
                        "ms": sw.elapsed().as_millis() as i64
                    }));
                }
                Err(e) => {
                    items.push(json!({
                        "id": id,
                        "title": title,
                        "subtitle": subtitle,
                        "ok": false,
                        "status": e.kind().to_string(),
                        "ms": -1
                    }));
                }
            }
        }
        json!({ "items": items }).to_string()
    }

    pub fn cancel_speedtest(&self) {
        if let Some(tx) = self.speedtest_cancel.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }

    pub async fn run_speedtest(&self, size_mb: u32, provider: &str) -> String {
        self.cancel_speedtest();
        let (tx, rx) = tokio::sync::watch::channel(false);
        *self.speedtest_cancel.lock().unwrap() = Some(tx);

        let size_mb = size_mb.clamp(10, 1000);
        let target_bytes = (size_mb as u64) * 1024 * 1024;
        let ovh_url = if size_mb <= 100 {
            "https://proof.ovh.net/files/100Mb.dat"
        } else {
            "https://proof.ovh.net/files/1Gb.dat"
        };
        let cf_url = format!(
            "https://speed.cloudflare.com/__down?bytes={}",
            target_bytes.min(100 * 1024 * 1024)
        );
        let sel_url = if size_mb <= 100 {
            "https://speedtest.selectel.ru/100MB"
        } else {
            "https://speedtest.selectel.ru/1GB"
        };

        let candidates: Vec<(&str, &str)> = match provider.trim().to_ascii_lowercase().as_str() {
            "ovh" => vec![
                (ovh_url, "OVH Europe"),
                (&cf_url, "Cloudflare Edge"),
                (sel_url, "Selectel РФ"),
            ],
            "cloudflare" => vec![
                (&cf_url, "Cloudflare Edge"),
                (ovh_url, "OVH Europe"),
                (sel_url, "Selectel РФ"),
            ],
            "selectel" => vec![
                (sel_url, "Selectel РФ"),
                (ovh_url, "OVH Europe"),
                (&cf_url, "Cloudflare Edge"),
            ],
            _ => vec![
                (ovh_url, "OVH Europe"),
                (&cf_url, "Cloudflare Edge"),
                (sel_url, "Selectel РФ"),
            ],
        };

        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let send_js = self.send_js.clone();

        match run_speedtest_stream(&candidates, size_mb, proxy, rx, move |prog| {
            (send_js)(format!("speedtest:progress:{prog}"));
        })
        .await
        {
            Ok(out) => json!({
                "ok": true,
                "mbps": out.mbps,
                "mbs": out.mbs,
                "peakMbps": out.peak_mbps,
                "ttfbMs": out.ttfb_ms,
                "bytes": out.total_bytes,
                "downloadedMb": out.downloaded_mb,
                "targetMb": out.target_mb,
                "server": out.server,
                "stopped": out.stopped
            })
            .to_string(),
            Err(e) => json!({
                "ok": false,
                "error": e.to_string()
            })
            .to_string(),
        }
    }

    pub async fn run_self_check(&self) {
        let ver = env!("CARGO_PKG_VERSION");
        let step1 = json!({
            "id": "core",
            "name": "Ядро VPN",
            "status": "ok",
            "summary": format!("tachyon-core v{ver} (встроено)")
        });
        self.emit(format!("diag:step:{step1}"));

        let tun_step = json!({
            "id": "wintun",
            "name": "Драйвер TUN",
            "status": "ok",
            "summary": format!("Интерфейс {}", default_tun_device())
        });
        self.emit(format!("diag:step:{tun_step}"));

        let ping = tcp_connect_ms("1.1.1.1", 443, 3000).await;
        let net_step = if ping > 0 {
            json!({
                "id": "internet",
                "name": "Интернет",
                "status": "ok",
                "summary": format!("{ping} мс")
            })
        } else {
            json!({
                "id": "internet",
                "name": "Интернет",
                "status": "fail",
                "summary": "Нет доступа к 1.1.1.1:443"
            })
        };
        self.emit(format!("diag:step:{net_step}"));
        self.emit("diag:done");
    }

    pub async fn check_github_update(&self) {
        let current = env!("CARGO_PKG_VERSION").trim_start_matches('v').to_string();
        let pport = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };

        match fetch_latest_github_release(pport).await {
            Ok(rel) => {
                let has_update = is_newer_semver(&rel.version, &current);
                let payload = json!({
                    "current": current,
                    "latest": rel.version,
                    "size": rel.asset_size,
                    "asset": rel.asset_name,
                    "url": rel.html_url,
                    "hasUpdate": has_update
                });
                if has_update {
                    self.emit(format!("core-update:available:{payload}"));
                } else {
                    self.emit(format!("core-update:up-to-date:{payload}"));
                }
            }
            Err(e) => {
                self.emit(format!("core-update:error:{e}"));
            }
        }
    }

    pub async fn install_github_update(&self) {
        let current = env!("CARGO_PKG_VERSION").trim_start_matches('v').to_string();
        let pport = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };

        self.emit("core-update:progress:10");
        let rel = match fetch_latest_github_release(pport).await {
            Ok(r) => r,
            Err(e) => {
                self.emit(format!("core-update:error:{e}"));
                return;
            }
        };

        if !is_newer_semver(&rel.version, &current) && rel.download_url.is_empty() {
            let payload = json!({ "version": current });
            self.emit(format!("core-update:done:{payload}"));
            return;
        }

        if rel.download_url.is_empty() {
            self.emit("core-update:error:В релизе GitHub не найден бинарный файл для вашей ОС");
            return;
        }

        self.emit("core-update:progress:35");
        let mut headers = vec![
            ("Accept", "application/octet-stream"),
            ("User-Agent", "Tachyon-Desktop-Updater/1.0"),
        ];
        let token_hdr = std::env::var("TACHYON_GITHUB_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|t| format!("Bearer {}", t.trim()));
        if let Some(ref auth) = token_hdr {
            headers.push(("Authorization", auth.as_str()));
        }

        let dl_res = match fetch_url(
            &rel.download_url,
            "GET",
            &headers,
            None,
            pport,
            Duration::from_secs(180),
        )
        .await
        {
            Ok(r) if (200..300).contains(&r.status) => Ok(r.body),
            Ok(_) | Err(_) if pport.is_some() => fetch_url(
                &rel.download_url,
                "GET",
                &headers,
                None,
                None,
                Duration::from_secs(180),
            )
            .await
            .and_then(|r| {
                if (200..300).contains(&r.status) {
                    Ok(r.body)
                } else {
                    Err(std::io::Error::other(format!("HTTP {}", r.status)))
                }
            }),
            Ok(r) => Err(std::io::Error::other(format!("HTTP {}", r.status))),
            Err(e) => Err(e),
        };

        let bytes = match dl_res {
            Ok(b) => b,
            Err(e) => {
                self.emit(format!("core-update:error:Ошибка скачивания релиза: {e}"));
                return;
            }
        };

        if bytes.len() < 512 * 1024 {
            self.emit("core-update:error:Скачанный файл повреждён или слишком мал");
            return;
        }

        self.emit("core-update:progress:85");
        match apply_self_binary_update(&bytes, &rel.asset_name) {
            Ok(()) => {
                self.emit("core-update:progress:100");
                let payload = json!({ "version": rel.version });
                self.emit(format!("core-update:done:{payload}"));
            }
            Err(e) => {
                self.emit(format!("core-update:error:{e}"));
            }
        }
    }
}

struct GithubReleaseInfo {
    version: String,
    html_url: String,
    asset_name: String,
    asset_size: u64,
    download_url: String,
}

fn is_newer_semver(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let clean = s
            .trim()
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("0.0.0");
        let mut it = clean.split('.').filter_map(|p| p.parse::<u32>().ok());
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        )
    };
    parse(candidate) > parse(current)
}

async fn fetch_latest_github_release(proxy_port: Option<u16>) -> Result<GithubReleaseInfo, String> {
    let endpoints = [
        "https://api.github.com/repos/Dushnilin/tachyon-desktop/releases/latest",
        "https://api.github.com/repos/Dushnilin/tachyon-core/releases/latest",
    ];

    let mut headers = vec![
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "Tachyon-Desktop-Updater/1.0"),
    ];
    let token_hdr = std::env::var("TACHYON_GITHUB_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|t| format!("Bearer {}", t.trim()));
    if let Some(ref auth) = token_hdr {
        headers.push(("Authorization", auth.as_str()));
    }

    let mut last_err = String::from("Не удалось связаться с GitHub Releases");
    for api_url in endpoints {
        let resp = match fetch_url(
            api_url,
            "GET",
            &headers,
            None,
            proxy_port,
            Duration::from_secs(12),
        )
        .await
        {
            Ok(r) if (200..300).contains(&r.status) => Ok(r),
            Ok(_) | Err(_) if proxy_port.is_some() => fetch_url(
                api_url,
                "GET",
                &headers,
                None,
                None,
                Duration::from_secs(12),
            )
            .await,
            Err(e) => Err(e),
            Ok(r) => Ok(r),
        };

        let Ok(r) = resp else {
            continue;
        };
        if r.status == 404 {
            last_err = "Релизы в репозитории пока не опубликованы".to_string();
            continue;
        }
        if !(200..300).contains(&r.status) {
            last_err = format!("GitHub API вернул HTTP {}", r.status);
            continue;
        }

        let Ok(doc) = serde_json::from_slice::<Value>(&r.body) else {
            last_err = "Некорректный JSON от GitHub API".to_string();
            continue;
        };

        let tag = doc
            .get("tag_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .trim_start_matches('v')
            .to_string();
        if tag.is_empty() {
            continue;
        }

        let html_url = doc
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or("https://github.com/Dushnilin/tachyon-desktop/releases")
            .to_string();

        let mut best_name = String::new();
        let mut best_url = String::new();
        let mut best_size = 0u64;
        let mut best_score = 0i32;

        if let Some(assets) = doc.get("assets").and_then(Value::as_array) {
            for asset in assets {
                let name = asset.get("name").and_then(Value::as_str).unwrap_or("");
                let dl = asset
                    .get("browser_download_url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let size = asset.get("size").and_then(Value::as_u64).unwrap_or(0);
                let score = score_release_asset_for_current_os(name);
                if score > best_score && !dl.is_empty() {
                    best_score = score;
                    best_name = name.to_string();
                    best_url = dl.to_string();
                    best_size = size;
                }
            }
        }

        return Ok(GithubReleaseInfo {
            version: tag,
            html_url,
            asset_name: best_name,
            asset_size: best_size,
            download_url: best_url,
        });
    }

    Err(last_err)
}

fn score_release_asset_for_current_os(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".sha256") || lower.ends_with(".txt") || lower.ends_with(".sig") {
        return 0;
    }

    #[cfg(target_os = "windows")]
    {
        if lower.contains("windows") || lower.contains("win") {
            if lower.ends_with(".exe") {
                return 100;
            }
            if lower.ends_with(".zip") {
                return 60;
            }
        }
        if lower == "tachyon.exe" || lower == "tachyon-desktop.exe" {
            return 90;
        }
        0
    }

    #[cfg(target_os = "linux")]
    {
        if lower.contains("linux") {
            if !lower.ends_with(".deb")
                && !lower.ends_with(".tar.gz")
                && !lower.ends_with(".rpm")
                && !lower.ends_with(".zip")
            {
                return 100;
            }
            if lower.ends_with(".deb") {
                return 80;
            }
            if lower.ends_with(".tar.gz") {
                return 70;
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    {
        if lower.contains("macos") || lower.contains("darwin") || lower.contains("mac") {
            if !lower.ends_with(".dmg") && !lower.ends_with(".tar.gz") && !lower.ends_with(".zip") {
                return 100;
            }
            if lower.ends_with(".dmg") {
                return 85;
            }
            if lower.ends_with(".tar.gz") {
                return 75;
            }
        }
        0
    }
}

fn apply_self_binary_update(bytes: &[u8], asset_name: &str) -> Result<(), String> {
    let exe_path = std::env::current_exe().map_err(|e| format!("Не удалось определить путь: {e}"))?;
    let lower = asset_name.to_ascii_lowercase();

    #[cfg(target_os = "windows")]
    {
        if lower.ends_with(".exe") && bytes.starts_with(b"MZ") {
            let old_path = exe_path.with_extension("exe.old");
            let tmp_path = exe_path.with_extension("exe.new");
            let _ = fs::remove_file(&old_path);
            fs::write(&tmp_path, bytes)
                .map_err(|e| format!("Не удалось записать обновление: {e}"))?;
            fs::rename(&exe_path, &old_path)
                .map_err(|e| format!("Не удалось переименовать текущий исполняемый файл: {e}"))?;
            if let Err(e) = fs::rename(&tmp_path, &exe_path) {
                let _ = fs::rename(&old_path, &exe_path);
                return Err(format!("Не удалось заменить исполняемый файл: {e}"));
            }
            return Ok(());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if bytes.starts_with(b"\x7fELF") {
            use std::os::unix::fs::PermissionsExt;
            let tmp_path = exe_path.with_extension("new");
            if fs::write(&tmp_path, bytes).is_ok() {
                let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755));
                if fs::rename(&tmp_path, &exe_path).is_ok() {
                    return Ok(());
                }
                let _ = fs::remove_file(&tmp_path);
            }
            // Fallback for /usr/bin/tachyon requiring root via pkexec
            let staged = app_data_dir().join("tachyon.update.bin");
            fs::write(&staged, bytes).map_err(|e| format!("Не удалось сохранить обновление: {e}"))?;
            let _ = fs::set_permissions(&staged, fs::Permissions::from_mode(0o755));
            let status = Command::new("pkexec")
                .args([
                    "install",
                    "-m",
                    "755",
                    &staged.to_string_lossy(),
                    &exe_path.to_string_lossy(),
                ])
                .status()
                .map_err(|e| format!("Ошибка pkexec при обновлении: {e}"))?;
            let _ = fs::remove_file(&staged);
            if status.success() {
                return Ok(());
            }
            return Err("Не удалось обновить системный бинарный файл (отказ pkexec)".to_string());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let is_macho = bytes.len() > 4
            && matches!(
                &bytes[..4],
                [0xCF, 0xFA, 0xED, 0xFE]
                    | [0xFE, 0xED, 0xFA, 0xCF]
                    | [0xCA, 0xFE, 0xBA, 0xBE]
                    | [0xBE, 0xBA, 0xFE, 0xCA]
            );
        if is_macho {
            use std::os::unix::fs::PermissionsExt;
            let tmp_path = exe_path.with_extension("new");
            fs::write(&tmp_path, bytes)
                .map_err(|e| format!("Не удалось записать обновление: {e}"))?;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755));
            fs::rename(&tmp_path, &exe_path)
                .map_err(|e| format!("Не удалось обновить Tachyon.app: {e}"))?;
            return Ok(());
        }
    }

    // Fallback: save installer/archive to app_data_dir/updates and open it in file manager
    let updates_dir = app_data_dir().join("updates");
    let _ = fs::create_dir_all(&updates_dir);
    let safe_name = if asset_name.is_empty() {
        "tachyon-update.bin"
    } else {
        asset_name
    };
    let dest = updates_dir.join(safe_name);
    fs::write(&dest, bytes).map_err(|e| format!("Не удалось сохранить пакет обновления: {e}"))?;
    Ok(())
}

async fn probe_proxy_delay(secret: &str) -> Option<u64> {
    let urls = [
        "http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
        "http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204",
    ];
    for u in urls {
        let path = format!("/proxies/PROXY/delay?timeout=5000&url={u}");
        if let Ok((200, body)) = clash_api_request(API_PORT, secret, "GET", &path, None).await {
            if let Ok(doc) = serde_json::from_str::<Value>(&body) {
                if let Some(d) = doc.get("delay").and_then(Value::as_u64) {
                    if d > 0 {
                        return Some(d);
                    }
                }
            }
        }
    }
    None
}

async fn spawn_elevated_worker(cfg_path: &Path, secret: &str) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cfg_str = cfg_path.to_string_lossy().into_owned();
    let _ = fs::remove_file(app_data_dir().join("config.stop"));

    #[cfg(target_os = "linux")]
    let mut child = {
        // First try granting capabilities to the binary via pkexec so future starts don't even need a worker
        let _ = Command::new("pkexec")
            .args([
                "setcap",
                "cap_net_admin,cap_net_raw+eip",
                &exe.to_string_lossy(),
            ])
            .status();

        Command::new("pkexec")
            .arg(&exe)
            .arg("--run-core")
            .arg(&cfg_str)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("pkexec error: {e}"))?
    };

    #[cfg(target_os = "macos")]
    let mut child = {
        let script = format!(
            "do shell script \"'{}' --run-core '{}'\" with administrator privileges",
            exe.to_string_lossy().replace('\'', "'\\''"),
            cfg_str.replace('\'', "'\\''")
        );
        Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("osascript error: {e}"))?
    };

    #[cfg(target_os = "windows")]
    let mut child = {
        use std::os::windows::process::CommandExt;
        let ps_cmd = format!(
            "$p = Start-Process -FilePath '{}' -ArgumentList '--run-core','{}' -Verb RunAs -WindowStyle Hidden -PassThru; Wait-Process -Id $p.Id",
            exe.to_string_lossy().replace('\'', "''"),
            cfg_str.replace('\'', "''")
        );
        Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("UAC elevation error: {e}"))?
    };

    // Wait up to 15 seconds for Clash API to come up
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(Some(code)) = child.try_wait() {
            return Err(format!("Elevated worker exited with {code}"));
        }
        if let Ok((200, _)) = clash_api_request(API_PORT, secret, "GET", "/connections", None).await
        {
            return Ok(child);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let _ = child.kill();
    Err("Таймаут ожидания запуска привилегированного процесса".to_string())
}

pub async fn tcp_connect_ms(host: &str, port: u16, timeout_ms: u64) -> i64 {
    let host = host.trim().trim_matches(['[', ']']).to_string();
    let timeout = Duration::from_millis(timeout_ms);

    let addr_res = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| {
                it.find(|a| a.is_ipv4() && !is_fake_or_tun_ip(a.ip()))
                    .or_else(|| {
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .ok()?
                            .find(|a| !is_fake_or_tun_ip(a.ip()))
                    })
            })
    })
    .await
    .ok()
    .flatten();

    let Some(target_addr) = addr_res else {
        return -1;
    };

    let sw = Instant::now();
    match tokio::time::timeout(timeout, connect_bypassing_tun(target_addr)).await {
        Ok(Ok(_)) => {
            let ms = sw.elapsed().as_millis() as i64;
            if ms <= 1 && !target_addr.ip().is_loopback() {
                -1
            } else {
                ms.max(2)
            }
        }
        _ => -1,
    }
}

fn is_fake_or_tun_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 198 && (o[1] == 18 || o[1] == 19)) || (o[0] == 10 && o[1] == 255)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfdfe && s[1] == 0xdcba
        }
    }
}

async fn connect_bypassing_tun(addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if let Some(ifname) = default_linux_phys_interface() {
            let cstr = std::ffi::CString::new(ifname).unwrap_or_default();
            unsafe {
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    cstr.as_ptr() as *const libc::c_void,
                    cstr.as_bytes_with_nul().len() as libc::socklen_t,
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        if let Some(ifidx) = default_macos_phys_ifindex() {
            const IP_BOUND_IF: libc::c_int = 25;
            unsafe {
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    IP_BOUND_IF,
                    &ifidx as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        if !addr.ip().is_loopback() && addr.is_ipv4() {
            let if_idx = core_runtime::inbound::tun::active_win_outbound_if_index()
                .or_else(|| {
                    let cached = CACHED_WIN_PHYS_IFINDEX.load(std::sync::atomic::Ordering::Relaxed);
                    (cached != 0).then_some(cached)
                })
                .or_else(default_windows_phys_ifindex);
            if let Some(idx) = if_idx {
                #[link(name = "ws2_32")]
                unsafe extern "system" {
                    fn setsockopt(
                        s: usize,
                        level: i32,
                        optname: i32,
                        optval: *const u8,
                        optlen: i32,
                    ) -> i32;
                }
                let val = idx.to_be_bytes();
                unsafe {
                    let _ = setsockopt(
                        socket.as_raw_socket() as usize,
                        0,  // IPPROTO_IP
                        31, // IP_UNICAST_IF
                        val.as_ptr(),
                        val.len() as i32,
                    );
                }
            }
        }
    }

    socket.connect(addr).await
}

#[cfg(target_os = "windows")]
static CACHED_WIN_PHYS_IFINDEX: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

#[cfg(target_os = "windows")]
pub fn refresh_cached_windows_phys_ifindex() {
    if let Some(idx) = default_windows_phys_ifindex() {
        CACHED_WIN_PHYS_IFINDEX.store(idx, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_os = "windows")]
fn default_windows_phys_ifindex() -> Option<u32> {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetBestInterface(dwDestAddr: u32, pdwBestIfIndex: *mut u32) -> u32;
    }
    let mut best_if: u32 = 0;
    let rc = unsafe { GetBestInterface(0x0808_0808, &mut best_if) };
    if rc == 0 && best_if != 0 {
        Some(best_if)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn default_linux_phys_interface() -> Option<String> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 {
            let iface = cols[0];
            let dest = cols[1];
            let gw = cols[2];
            if dest == "00000000"
                && gw != "00000000"
                && !iface.starts_with("tachyon")
                && !iface.starts_with("tun")
                && !iface.starts_with("wg")
            {
                return Some(iface.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn default_macos_phys_ifindex() -> Option<libc::c_uint> {
    for candidate in ["en0", "en1", "en2"] {
        let cstr = std::ffi::CString::new(candidate).ok()?;
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx != 0 {
            return Some(idx);
        }
    }
    None
}

pub fn set_system_proxy(enable: bool) {
    #[cfg(target_os = "linux")]
    {
        if enable {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .status();
            for proto in ["http", "https", "socks"] {
                let schema = format!("org.gnome.system.proxy.{proto}");
                let _ = Command::new("gsettings")
                    .args(["set", &schema, "host", "127.0.0.1"])
                    .status();
                let _ = Command::new("gsettings")
                    .args(["set", &schema, "port", &PROXY_PORT.to_string()])
                    .status();
            }
        } else {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .status();
        }
    }

    #[cfg(target_os = "macos")]
    {
        for service in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
            if enable {
                let p = PROXY_PORT.to_string();
                let _ = Command::new("networksetup")
                    .args(["-setwebproxy", service, "127.0.0.1", &p])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsecurewebproxy", service, "127.0.0.1", &p])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsocksfirewallproxy", service, "127.0.0.1", &p])
                    .status();
            } else {
                let _ = Command::new("networksetup")
                    .args(["-setwebproxystate", service, "off"])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsecurewebproxystate", service, "off"])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsocksfirewallproxystate", service, "off"])
                    .status();
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let enable_val = if enable { "1" } else { "0" };
        let _ = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                enable_val,
                "/f",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        if enable {
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    "/v",
                    "ProxyServer",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &format!("127.0.0.1:{PROXY_PORT}"),
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

pub fn flush_os_dns() {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("resolvectl").arg("flush-caches").status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("dscacheutil").arg("-flushcache").status();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
}

pub fn apply_kill_switch(_enable: bool) {
    #[cfg(target_os = "linux")]
    {
        if !_enable {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", "tachyon_ks"])
                .status();
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        if !_enable {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    "name=Tachyon_KS_Block",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

fn detect_country_code(name: &str) -> String {
    let re = Regex::new(r"(?i)\b([A-Z]{2})\b").unwrap();
    if let Some(caps) = re.captures(name) {
        if let Some(m) = caps.get(1) {
            return m.as_str().to_ascii_lowercase();
        }
    }
    "auto".to_string()
}

#[derive(Serialize, Deserialize)]
pub struct RunningApp {
    pub binary: String,
    pub name: String,
    pub proc: String,
    pub icon: Option<String>,
    pub running: bool,
}

pub fn enumerate_apps() -> Vec<RunningApp> {
    let mut apps: Vec<RunningApp> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const SYSTEM_PROCS: &[&str] = &[
            "system",
            "system idle process",
            "registry",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "fontdrvhost.exe",
            "winlogon.exe",
            "dwm.exe",
            "conhost.exe",
            "sihost.exe",
            "taskhostw.exe",
            "explorer.exe",
            "runtimebroker.exe",
            "searchhost.exe",
            "startmenuexperiencehost.exe",
            "textinputhost.exe",
            "dllhost.exe",
            "ctfmon.exe",
            "spoolsv.exe",
            "wmiprvse.exe",
            "audiodg.exe",
            "securityhealthsystray.exe",
            "securityhealthservice.exe",
            "msedgewebview2.exe",
            "smartscreen.exe",
            "tasklist.exe",
            "tachyon.exe",
            "tachyon-core.exe",
        ];

        if let Ok(out) = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let Some(rest) = line.strip_prefix('"') else {
                    continue;
                };
                let Some((proc_name, _)) = rest.split_once('"') else {
                    continue;
                };
                let proc_trimmed = proc_name.trim();
                let lower = proc_trimmed.to_ascii_lowercase();
                if !lower.ends_with(".exe") || SYSTEM_PROCS.contains(&lower.as_str()) {
                    continue;
                }
                if seen.insert(lower) {
                    apps.push(RunningApp {
                        binary: proc_trimmed.to_string(),
                        name: friendly_windows_app_name(proc_trimmed),
                        proc: proc_trimmed.to_string(),
                        icon: None,
                        running: true,
                    });
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/usr/share/applications") {
            for entry in entries.flatten() {
                if let Ok(text) = fs::read_to_string(entry.path()) {
                    let mut name = String::new();
                    let mut exec = String::new();
                    let mut no_display = false;
                    for line in text.lines() {
                        if let Some(n) = line.strip_prefix("Name=") {
                            if name.is_empty() {
                                name = n.trim().to_string();
                            }
                        } else if let Some(e) = line.strip_prefix("Exec=") {
                            if exec.is_empty() {
                                exec = e
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .trim_matches('"')
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                            }
                        } else if line.trim() == "NoDisplay=true" {
                            no_display = true;
                        }
                    }
                    if !no_display && !name.is_empty() && !exec.is_empty() && seen.insert(exec.clone()) {
                        apps.push(RunningApp {
                            binary: exec.clone(),
                            name,
                            proc: exec,
                            icon: None,
                            running: false,
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(entries) = fs::read_dir("/Applications") {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if let Some(app_name) = fname.strip_suffix(".app") {
                    if seen.insert(app_name.to_string()) {
                        apps.push(RunningApp {
                            binary: app_name.to_string(),
                            name: app_name.to_string(),
                            proc: app_name.to_string(),
                            icon: None,
                            running: false,
                        });
                    }
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

#[cfg(target_os = "windows")]
fn friendly_windows_app_name(exe: &str) -> String {
    let lower = exe.trim().to_ascii_lowercase();
    match lower.as_str() {
        "chrome.exe" => "Google Chrome".to_string(),
        "msedge.exe" => "Microsoft Edge".to_string(),
        "firefox.exe" => "Mozilla Firefox".to_string(),
        "brave.exe" => "Brave Browser".to_string(),
        "opera.exe" => "Opera".to_string(),
        "yandex.exe" | "browser.exe" => "Яндекс Браузер".to_string(),
        "discord.exe" => "Discord".to_string(),
        "telegram.exe" => "Telegram Desktop".to_string(),
        "spotify.exe" => "Spotify".to_string(),
        "steam.exe" => "Steam".to_string(),
        "epicgameslauncher.exe" => "Epic Games".to_string(),
        "code.exe" => "Visual Studio Code".to_string(),
        "obs64.exe" => "OBS Studio".to_string(),
        "qbittorrent.exe" => "qBittorrent".to_string(),
        _ => {
            let stem = exe
                .strip_suffix(".exe")
                .or_else(|| exe.strip_suffix(".EXE"))
                .unwrap_or(exe);
            let mut chars = stem.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => exe.to_string(),
            }
        }
    }
}
