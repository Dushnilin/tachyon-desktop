use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use core_config::subscription::{
    extract_subscription_metadata, is_stub_or_dummy_outbound, outbound_to_share_link,
    parse_share_uri, parse_subscription_payload_with_hwid, resolve_subscription_input,
    wireguard_node_to_endpoint,
};
use core_runtime::BoxInstance;
use core_runtime::hardware::HardwareIdentity;
use core_runtime::subscription::fetch_url_standalone_with_options;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::http::{clash_api_request, fetch_url, fetch_url_with_progress, run_speedtest_stream};

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
    pub tlsrec_first: bool,
    pub seqovl: u32,
    pub syndata: bool,
    pub wsize: u32,
    pub wscale: Option<u8>,
    pub ipfrag: bool,
    pub udplen: u32,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub repeats: u32,
    pub split_delay_ms: u32,
    pub udp_fake: bool,
    pub quic_desync: bool,
    pub quic_repeats: u32,
    pub discord_udp_fake: bool,
    pub udp_repeats: u32,
    pub udp_fake_ttl: u32,
    pub host_fake: bool,
    pub fake_payload: String,
    pub udp_fake_payload: String,
    pub udp_out_range: String,
    pub udp_keep_socket: bool,
    pub auto_tune: bool,
    pub block_quic: bool,
    pub stun_fake: bool,
    pub anticheat_bypass: bool,
    pub lists_override_game_bypass: bool,
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
            tlsrec_first: true,
            seqovl: 0,
            syndata: false,
            wsize: 0,
            wscale: None,
            ipfrag: false,
            udplen: 0,
            fake_ttl: 6,
            fake_sni: "www.google.com".to_string(),
            repeats: 2,
            split_delay_ms: 1,
            udp_fake: true,
            quic_desync: true,
            quic_repeats: 6,
            discord_udp_fake: true,
            udp_repeats: 6,
            udp_fake_ttl: 6,
            host_fake: false,
            fake_payload: String::new(),
            udp_fake_payload: String::new(),
            udp_out_range: String::new(),
            udp_keep_socket: false,
            auto_tune: true,
            block_quic: true,
            stun_fake: true,
            anticheat_bypass: true,
            lists_override_game_bypass: true,
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
    pub time_window: String,
}

#[derive(Debug, Clone)]
pub struct ExtraNodeRef {
    pub tag: String,
    pub vless: String,
}

pub const BALANCER_URI_PREFIX: &str = "tachyon-balancer://";
pub const INLINE_NODE_URI_PREFIX: &str = "tachyon-node://";

pub fn encode_inline_node_uri(node: &Value) -> String {
    let json_bytes = serde_json::to_vec(node).unwrap_or_default();
    let b64 = B64.encode(&json_bytes);
    let tag = node
        .get("tag")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("Сервер");
    let frag = core_config::subscription::percent_encode_component(tag);
    format!("{INLINE_NODE_URI_PREFIX}{b64}#{frag}")
}

fn percent_decode_utf8(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn decode_inline_node_uri(raw: &str) -> Option<Value> {
    let rest = raw.trim().strip_prefix(INLINE_NODE_URI_PREFIX)?;
    let (b64_part, frag_part) = match rest.split_once('#') {
        Some((b, f)) => (b.trim(), Some(f.trim())),
        None => (rest.trim(), None),
    };
    let bytes = B64.decode(b64_part).ok()?;
    let mut node: Value = serde_json::from_slice(&bytes).ok()?;
    if let Some(obj) = node.as_object_mut() {
        let has_tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if !has_tag && let Some(f) = frag_part.filter(|s| !s.is_empty()) {
            obj.insert("tag".to_string(), json!(percent_decode_utf8(f)));
        }
    }
    Some(node)
}

pub fn node_to_share_link(node: &Value) -> Option<String> {
    if is_stub_or_dummy_outbound(node) {
        return None;
    }
    if let Some(link) = outbound_to_share_link(node) {
        return Some(link);
    }
    let ty = node
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        ty.as_str(),
        "" | "urltest" | "selector" | "direct" | "block" | "dns" | "desync" | "tlsspoof"
    ) {
        return None;
    }
    if node
        .get("server")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
    {
        return Some(encode_inline_node_uri(node));
    }
    None
}

pub fn parse_node_uri(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    if let Some(val) = decode_inline_node_uri(trimmed) {
        return Ok(val);
    }
    if let Ok(val) = parse_share_uri(trimmed) {
        return Ok(val);
    }
    if let Ok(mut nodes) = parse_subscription_payload_with_hwid(trimmed, None, None)
        && let Some(first) = nodes.drain(..).find(|n| !is_stub_or_dummy_outbound(n))
    {
        return Ok(first);
    }
    parse_share_uri(trimmed)
}

/// Проверяет, является ли ссылка MTProto-прокси (только TCP, не поддерживает UDP).
pub fn is_mtproto_uri(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    lower.starts_with("tg://proxy")
        || lower.starts_with("mtproto://")
        || lower.starts_with("https://t.me/proxy")
        || lower.starts_with("http://t.me/proxy")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerMember {
    pub name: String,
    pub vless: String,
    #[serde(default)]
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerPayload {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_balancer_mode")]
    pub mode: String,
    #[serde(default = "default_balancer_url")]
    pub url: String,
    #[serde(default = "default_balancer_interval")]
    pub interval: String,
    #[serde(default = "default_balancer_tolerance")]
    pub tolerance: u32,
    #[serde(default = "default_balancer_pool")]
    pub pool: u32,
    #[serde(default = "default_balancer_pool_tolerance")]
    pub pool_tolerance: u32,
    #[serde(default = "default_balancer_sticky_hash")]
    pub sticky_hash: Vec<String>,
    #[serde(default = "default_balancer_quota_mib")]
    pub quota_mib: u32,
    #[serde(default)]
    pub members: Vec<BalancerMember>,
}

fn default_balancer_mode() -> String {
    "stability".to_string()
}
fn default_balancer_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}
fn default_balancer_interval() -> String {
    "3m".to_string()
}
fn default_balancer_tolerance() -> u32 {
    50
}
fn default_balancer_pool() -> u32 {
    4
}
fn default_balancer_pool_tolerance() -> u32 {
    80
}
fn default_balancer_sticky_hash() -> Vec<String> {
    vec![
        "domain".to_string(),
        "dest_ip".to_string(),
        "process".to_string(),
    ]
}
fn default_balancer_quota_mib() -> u32 {
    256
}

pub fn normalize_balancer_mode(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "least_test" | "fastest" | "urltest" => "least_test",
        "failover" => "failover",
        "sticky" => "sticky",
        "least_load" => "least_load",
        "weighted" => "weighted",
        "passive" => "passive",
        "priority" => "priority",
        "hedged" => "hedged",
        "throughput" => "throughput",
        "quota" => "quota",
        "round_robin" => "round_robin",
        _ => "stability",
    }
}

pub fn encode_balancer_uri(payload: &BalancerPayload) -> String {
    let json_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let b64 = B64.encode(&json_bytes);
    let frag = core_config::subscription::percent_encode_component(&payload.name);
    format!("{BALANCER_URI_PREFIX}{b64}#{frag}")
}

pub fn decode_balancer_uri(raw: &str) -> Option<BalancerPayload> {
    let rest = raw.trim().strip_prefix(BALANCER_URI_PREFIX)?;
    let (b64_part, frag_part) = match rest.split_once('#') {
        Some((b, f)) => (b.trim(), Some(f.trim())),
        None => (rest.trim(), None),
    };
    let bytes = B64.decode(b64_part).ok()?;
    let mut payload: BalancerPayload = serde_json::from_slice(&bytes).ok()?;
    if payload.name.is_empty()
        && let Some(f) = frag_part
        && !f.is_empty()
    {
        payload.name = percent_decode_utf8(f);
    }
    payload.mode = normalize_balancer_mode(&payload.mode).to_string();
    Some(payload)
}

#[derive(Debug, Clone)]
pub struct BalancerOptions {
    pub mode_override: Option<String>,
    pub url: String,
    pub interval: String,
    pub tolerance: u32,
    pub pool: u32,
    pub pool_tolerance: u32,
    pub sticky_hash: Vec<String>,
    pub quota_mib: u32,
    /// `true`, если параметры пришли из глобальных настроек балансировщика клиента.
    /// Тогда они имеют приоритет над значениями, «замороженными» в `tachyon-balancer://`.
    pub from_prefs: bool,
    pub excluded_countries: Vec<String>,
    pub excluded_protocols: Vec<String>,
    pub include_regex: String,
    pub exclude_regex: String,
    /// Сервисы мульти-URL балансировщика (отдельный `urltest-svc-<id>` на каждый).
    pub multi_services: Vec<String>,
}

impl Default for BalancerOptions {
    fn default() -> Self {
        Self {
            mode_override: None,
            url: default_balancer_url(),
            interval: default_balancer_interval(),
            tolerance: default_balancer_tolerance(),
            pool: default_balancer_pool(),
            pool_tolerance: default_balancer_pool_tolerance(),
            sticky_hash: default_balancer_sticky_hash(),
            quota_mib: default_balancer_quota_mib(),
            from_prefs: false,
            excluded_countries: Vec::new(),
            excluded_protocols: Vec::new(),
            include_regex: String::new(),
            exclude_regex: String::new(),
            multi_services: Vec::new(),
        }
    }
}

/// Проверочные URL сервисов мульти-URL балансировщика (идентичны Android-версии).
/// `https` — общий пул, использует основной URL проверки.
pub fn balancer_service_probe_url(id: &str) -> Option<&'static str> {
    match id {
        "youtube" => Some("https://www.youtube.com/generate_204"),
        "telegram" => Some("https://core.telegram.org/favicon.ico"),
        "discord" => Some("https://discord.com/api/v9/experiments"),
        "instagram" => Some("https://www.instagram.com/robots.txt"),
        "openai" => Some("https://chatgpt.com/cdn-cgi/trace"),
        _ => None,
    }
}

/// Строит пару Unicode Regional Indicator (флаг страны) из 2-буквенного кода ISO.
fn regional_indicator_flag(code: &str) -> Option<String> {
    let bytes = code.trim().as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || !bytes[1].is_ascii_alphabetic() {
        return None;
    }
    let c0 = char::from_u32(0x1F1E6 + u32::from(bytes[0].to_ascii_uppercase() - b'A'))?;
    let c1 = char::from_u32(0x1F1E6 + u32::from(bytes[1].to_ascii_uppercase() - b'A'))?;
    let mut s = String::with_capacity(8);
    s.push(c0);
    s.push(c1);
    Some(s)
}

/// Страны для фильтра исключений: (код, название, алиасы).
const BALANCER_COUNTRY_FILTERS: &[(&str, &str, &[&str])] = &[
    (
        "RU",
        "Россия",
        &[
            "ru",
            "rus",
            "russia",
            "россия",
            "мск",
            "спб",
            "moscow",
            "spb",
        ],
    ),
    (
        "NL",
        "Нидерланды",
        &[
            "nl",
            "nld",
            "netherlands",
            "нидерланды",
            "голландия",
            "amsterdam",
            "амстердам",
        ],
    ),
    (
        "DE",
        "Германия",
        &[
            "de",
            "deu",
            "germany",
            "германия",
            "frankfurt",
            "франкфурт",
            "falkenstein",
        ],
    ),
    (
        "FI",
        "Финляндия",
        &["fi", "fin", "finland", "финляндия", "helsinki", "хельсинки"],
    ),
    (
        "US",
        "США",
        &[
            "us",
            "usa",
            "united states",
            "сша",
            "америка",
            "new york",
            "dallas",
            "miami",
        ],
    ),
    (
        "GB",
        "Великобритания",
        &[
            "gb",
            "uk",
            "united kingdom",
            "британия",
            "англия",
            "london",
            "лондон",
        ],
    ),
    (
        "FR",
        "Франция",
        &["fr", "fra", "france", "франция", "paris", "париж"],
    ),
    (
        "TR",
        "Турция",
        &[
            "tr",
            "tur",
            "turkey",
            "türkiye",
            "турция",
            "istanbul",
            "стамбул",
        ],
    ),
    (
        "KZ",
        "Казахстан",
        &["kz", "kaz", "kazakhstan", "казахстан", "алматы", "астана"],
    ),
    (
        "BY",
        "Беларусь",
        &["by", "blr", "belarus", "беларусь", "минск", "minsk"],
    ),
    (
        "SE",
        "Швеция",
        &["se", "swe", "sweden", "швеция", "stockholm", "стокгольм"],
    ),
    (
        "PL",
        "Польша",
        &["pl", "pol", "poland", "польша", "warsaw", "варшава"],
    ),
    (
        "LV",
        "Латвия",
        &["lv", "lva", "latvia", "латвия", "riga", "рига"],
    ),
    (
        "EE",
        "Эстония",
        &["ee", "est", "estonia", "эстония", "tallinn", "таллин"],
    ),
    ("SG", "Сингапур", &["sg", "sgp", "singapore", "сингапур"]),
    (
        "JP",
        "Япония",
        &["jp", "jpn", "japan", "япония", "tokyo", "токио"],
    ),
];

/// Быстрые варианты стран для UI: (код, название).
pub fn balancer_country_presets() -> impl Iterator<Item = (&'static str, &'static str)> {
    BALANCER_COUNTRY_FILTERS
        .iter()
        .map(|(code, title, _)| (*code, *title))
}

fn cached_regex(pattern: &str) -> Option<Regex> {
    static REGEX_CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = REGEX_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(found) = guard.get(pattern)
    {
        return found.clone();
    }
    let compiled = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .ok();
    if let Ok(mut guard) = cache.lock() {
        if guard.len() > 256 {
            guard.clear();
        }
        guard.insert(pattern.to_string(), compiled.clone());
    }
    compiled
}

fn balancer_regex_or_substring(haystack: &str, raw_pattern: &str) -> bool {
    let pattern = raw_pattern.trim();
    if pattern.is_empty() {
        return true;
    }
    match cached_regex(pattern) {
        Some(re) => re.is_match(haystack),
        // Некорректный RegExp не должен ломать подключение — откат к поиску подстроки.
        None => haystack.to_lowercase().contains(&pattern.to_lowercase()),
    }
}

fn balancer_word_boundary_hit(code_lower: &str, haystack: &str) -> bool {
    let pat = format!(
        "(^|[^a-zа-яё0-9]){}([^a-zа-яё0-9]|$)",
        regex::escape(code_lower)
    );
    cached_regex(&pat).is_some_and(|re| re.is_match(haystack))
}

fn balancer_protocol_excluded(p_type: &str, raw_proto: &str) -> bool {
    let proto = raw_proto.trim().to_ascii_lowercase();
    if proto.is_empty() {
        return false;
    }
    if p_type == proto {
        return true;
    }
    match proto.as_str() {
        "wireguard" | "awg" | "amneziawg" => matches!(p_type, "wireguard" | "amneziawg"),
        "socks" | "http" => matches!(p_type, "socks" | "http"),
        "ss" | "shadowsocks" => p_type == "shadowsocks",
        "hy2" | "hysteria2" | "hysteria" => matches!(p_type, "hysteria2" | "hysteria"),
        "wdtt" | "csqtt" | "qwdtt" => p_type == "wdtt",
        "openvpn" | "openvpn-client" => p_type == "openvpn-client",
        "mierus" => p_type == "mieru",
        "openconnect" | "anyconnect" => p_type == "openconnect",
        _ => false,
    }
}

fn balancer_country_excluded(name: &str, server: &str, raw_token: &str) -> bool {
    let token = raw_token.trim().to_lowercase();
    if token.is_empty() {
        return false;
    }
    let name_lower = name.to_lowercase();
    let server_lower = server.to_lowercase();
    let combined = format!("{name_lower} {server_lower}");

    let preset = BALANCER_COUNTRY_FILTERS.iter().find(|(code, title, _)| {
        code.to_lowercase() == token
            || regional_indicator_flag(code).as_deref() == Some(token.as_str())
            || title.to_lowercase() == token
    });
    if let Some((code, _, aliases)) = preset {
        let code_lower = code.to_lowercase();
        if let Some(flag) = regional_indicator_flag(code)
            && name.contains(&flag)
        {
            return true;
        }
        if server_lower.ends_with(&format!(".{code_lower}"))
            || server_lower.starts_with(&format!("{code_lower}."))
            || server_lower.starts_with(&format!("{code_lower}-"))
        {
            return true;
        }
        if balancer_word_boundary_hit(&code_lower, &name_lower) {
            return true;
        }
        for alias in aliases.iter() {
            if alias.encode_utf16().count() <= 2 {
                continue;
            }
            if combined.contains(alias) {
                return true;
            }
        }
        return false;
    }

    if token.chars().count() == 2 && token.chars().all(|c| c.is_ascii_lowercase()) {
        return regional_indicator_flag(&token).is_some_and(|flag| name.contains(&flag))
            || balancer_word_boundary_hit(&token, &name_lower)
            || server_lower.ends_with(&format!(".{token}"))
            || server_lower.starts_with(&format!("{token}."))
            || server_lower.starts_with(&format!("{token}-"));
    }
    combined.contains(&token)
}

/// Проходит ли узел фильтры балансировщика: включающий / исключающий RegExp,
/// исключённые протоколы и исключённые страны (порт `BalancerSettings.matchesFilter`
/// из Android-версии).
pub fn balancer_node_passes_filter(
    name: &str,
    server: &str,
    sni: &str,
    node_type: &str,
    opts: &BalancerOptions,
) -> bool {
    let p_type = node_type.trim().to_ascii_lowercase();
    let target = format!("{name} {server} {sni} {p_type}");
    if !balancer_regex_or_substring(&target, &opts.include_regex) {
        return false;
    }
    if !opts.exclude_regex.trim().is_empty()
        && balancer_regex_or_substring(&target, &opts.exclude_regex)
    {
        return false;
    }
    if opts
        .excluded_protocols
        .iter()
        .any(|proto| balancer_protocol_excluded(&p_type, proto))
    {
        return false;
    }
    if opts
        .excluded_countries
        .iter()
        .any(|tok| balancer_country_excluded(name, server, tok))
    {
        return false;
    }
    true
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
    pub bypass_lan: bool,
    pub proxy_tls_fragment: bool,
    pub log_level: String,
    pub detour_vless: String,
    pub extra_nodes: Vec<ExtraNodeRef>,
    pub desync: DesyncOptions,
    pub balancer: BalancerOptions,
    pub community_lists: Vec<CommunityListRule>,
    pub custom_rules: Vec<CustomRouteRule>,
    pub dns_strategy: String,
    pub dns_reverse_mapping: bool,
    pub route_find_process: bool,
    pub route_fullcone_nat: bool,
    pub route_smart_queue: bool,
    pub tun_stack: String,
    pub strict_route: bool,
    pub sniff: bool,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub ipv6_enabled: bool,
    pub dns_transport: String,
    pub ntp_enabled: bool,
    pub ntp_server: String,
}

impl ConnectOptions {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if !raw.starts_with('{')
            && (raw.starts_with(BALANCER_URI_PREFIX)
                || raw.starts_with(INLINE_NODE_URI_PREFIX)
                || parse_node_uri(raw).is_ok())
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
                bypass_lan: true,
                proxy_tls_fragment: true,
                log_level: "warn".to_string(),
                detour_vless: String::new(),
                extra_nodes: Vec::new(),
                desync: DesyncOptions::default(),
                balancer: BalancerOptions::default(),
                community_lists: Vec::new(),
                custom_rules: Vec::new(),
                dns_strategy: "prefer_ipv4".to_string(),
                dns_reverse_mapping: true,
                route_find_process: true,
                route_fullcone_nat: true,
                route_smart_queue: false,
                tun_stack: "mixed".to_string(),
                strict_route: true,
                sniff: true,
                tcp_fast_open: false,
                tcp_multi_path: false,
                ipv6_enabled: false,
                dns_transport: "https".to_string(),
                ntp_enabled: false,
                ntp_server: "time.cloudflare.com".to_string(),
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
                if let Some(s) = item.as_str()
                    && !s.trim().is_empty()
                {
                    rules.push(s.trim().to_string());
                }
            }
        } else if let Some(arr) = root.get("apps").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str()
                    && !s.trim().is_empty()
                {
                    rules.push(format!("PROCESS-NAME,{},GLOBAL", s.trim()));
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
        let bypass_lan = root
            .get("bypassLan")
            .and_then(Value::as_bool)
            .unwrap_or(true);
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
                let tag = item.get("tag").and_then(Value::as_str).unwrap_or("").trim();
                let ev = item
                    .get("vless")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if tag.to_ascii_uppercase().starts_with("NODE_") && !ev.is_empty() {
                    extra_nodes.push(ExtraNodeRef {
                        tag: tag.to_ascii_uppercase(),
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
            if let Some(v) = d.get("tlsrecFirst").and_then(Value::as_bool) {
                desync.tlsrec_first = v;
            }
            if let Some(v) = d.get("seqovl").and_then(Value::as_u64) {
                desync.seqovl = (v as u32).min(256);
            }
            if let Some(v) = d.get("syndata").and_then(Value::as_bool) {
                desync.syndata = v;
            }
            if let Some(v) = d.get("wsize").and_then(Value::as_u64) {
                desync.wsize = (v as u32).min(65535);
            }
            if let Some(v) = d
                .get("wscale")
                .or_else(|| d.get("scale"))
                .and_then(Value::as_u64)
            {
                desync.wscale = Some((v as u8).min(14));
            }
            if let Some(v) = d.get("ipfrag").and_then(Value::as_bool) {
                desync.ipfrag = v;
            }
            if let Some(v) = d.get("udplen").and_then(Value::as_u64) {
                desync.udplen = (v as u32).min(256);
            }
            if let Some(v) = d.get("fakeTtl").and_then(Value::as_u64) {
                desync.fake_ttl = (v as u32).clamp(1, 128);
            }
            if let Some(v) = d.get("fakeSni").and_then(Value::as_str)
                && !v.trim().is_empty()
            {
                desync.fake_sni = v.trim().to_string();
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
            if let Some(v) = d.get("quicDesync").and_then(Value::as_bool) {
                desync.quic_desync = v;
            }
            if let Some(v) = d.get("quicRepeats").and_then(Value::as_u64) {
                desync.quic_repeats = (v as u32).min(50);
            }
            if let Some(v) = d.get("discordUdpFake").and_then(Value::as_bool) {
                desync.discord_udp_fake = v;
            }
            if let Some(v) = d.get("udpRepeats").and_then(Value::as_u64) {
                desync.udp_repeats = (v as u32).clamp(1, 50);
            }
            if let Some(v) = d.get("udpFakeTtl").and_then(Value::as_u64) {
                desync.udp_fake_ttl = (v as u32).clamp(1, 128);
            }
            if let Some(v) = d.get("hostFake").and_then(Value::as_bool) {
                desync.host_fake = v;
            }
            if let Some(v) = d.get("fakePayload").and_then(Value::as_str) {
                desync.fake_payload = v.trim().to_string();
            }
            if let Some(v) = d.get("udpFakePayload").and_then(Value::as_str) {
                desync.udp_fake_payload = v.trim().to_string();
            }
            if let Some(v) = d.get("udpOutRange").and_then(Value::as_str) {
                desync.udp_out_range = v.trim().to_string();
            }
            if let Some(v) = d.get("udpKeepSocket").and_then(Value::as_bool) {
                desync.udp_keep_socket = v;
            }
            if let Some(v) = d.get("autoTune").and_then(Value::as_bool) {
                desync.auto_tune = v;
            }
            if let Some(v) = d.get("blockQuic").and_then(Value::as_bool) {
                desync.block_quic = v;
            }
            if let Some(v) = d.get("stunFake").and_then(Value::as_bool) {
                desync.stun_fake = v;
            }
            if let Some(v) = d.get("anticheatBypass").and_then(Value::as_bool) {
                desync.anticheat_bypass = v;
            }
            if let Some(v) = d.get("listsOverrideGameBypass").and_then(Value::as_bool) {
                desync.lists_override_game_bypass = v;
            }
        }

        let mut balancer = BalancerOptions::default();
        if let Some(m) = root
            .get("balancerMode")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
        {
            balancer.mode_override = Some(normalize_balancer_mode(m).to_string());
        }
        if let Some(b) = root.get("balancer").and_then(Value::as_object) {
            if let Some(m) = b
                .get("mode")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
            {
                balancer.mode_override = Some(normalize_balancer_mode(m).to_string());
            }
            if let Some(u) = b
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                balancer.url = u.to_string();
            }
            if let Some(iv) = b
                .get("interval")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                balancer.interval = iv.to_string();
            }
            if let Some(t) = b.get("tolerance").and_then(Value::as_u64) {
                balancer.tolerance = (t as u32).clamp(5, 2000);
            }
            if let Some(p) = b.get("pool").and_then(Value::as_u64) {
                balancer.pool = (p as u32).clamp(1, 32);
            }
            if let Some(pt) = b
                .get("poolTolerance")
                .or_else(|| b.get("pool_tolerance"))
                .and_then(Value::as_u64)
            {
                balancer.pool_tolerance = (pt as u32).clamp(10, 2000);
            }
            if let Some(q) = b
                .get("quotaMib")
                .or_else(|| b.get("quota_mib"))
                .and_then(Value::as_u64)
            {
                // 0 — квота выключена (в ядро `quota_mib` тогда не передаётся).
                balancer.quota_mib = (q as u32).clamp(0, 1_048_576);
            }
            balancer.from_prefs = true;
            let str_list = |key: &str| -> Vec<String> {
                b.get(key)
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            balancer.excluded_countries = str_list("excludedCountries");
            balancer.excluded_protocols = str_list("excludedProtocols")
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            balancer.include_regex = b
                .get("includeRegex")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            balancer.exclude_regex = b
                .get("excludeRegex")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            balancer.multi_services = str_list("multiServices")
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .filter(|s| balancer_service_probe_url(s).is_some())
                .collect();
            if let Some(arr) = b
                .get("stickyHash")
                .or_else(|| b.get("sticky_hash"))
                .and_then(Value::as_array)
            {
                let parsed: Vec<String> = arr
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| {
                        matches!(
                            s.as_str(),
                            "source_ip" | "domain" | "dest_ip" | "dest_port" | "process"
                        )
                    })
                    .collect();
                if !parsed.is_empty() {
                    balancer.sticky_hash = parsed;
                }
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
                let time_window = item
                    .get("timeWindow")
                    .or_else(|| item.get("time_window"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !value.is_empty() && action != "off" && action != "none" {
                    custom_rules.push(CustomRouteRule {
                        rtype,
                        value,
                        action,
                        time_window,
                    });
                }
            }
        }

        let dns_strategy = root
            .get("dnsStrategy")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| {
                matches!(
                    *s,
                    "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
                )
            })
            .unwrap_or("prefer_ipv4")
            .to_string();
        let dns_reverse_mapping = root
            .get("dnsReverseMapping")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let route_find_process = root
            .get("routeFindProcess")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let route_fullcone_nat = root
            .get("routeFullconeNat")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let route_smart_queue = root
            .get("routeSmartQueue")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let tun_stack = root
            .get("tunStack")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| matches!(*s, "mixed" | "system" | "gvisor"))
            .unwrap_or("mixed")
            .to_string();
        let strict_route = root
            .get("strictRoute")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let sniff = root.get("sniff").and_then(Value::as_bool).unwrap_or(true);
        let tcp_fast_open = root
            .get("tcpFastOpen")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let tcp_multi_path = root
            .get("tcpMultiPath")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ipv6_enabled = root
            .get("ipv6Enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let dns_transport = root
            .get("dnsTransport")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| matches!(s.as_str(), "https" | "h3" | "quic" | "tls" | "udp"))
            .unwrap_or_else(|| "https".to_string());
        let ntp_enabled = root
            .get("ntpEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ntp_server = root
            .get("ntpServer")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("time.cloudflare.com")
            .to_string();

        let allow_without_node = block_only || route == RouteMode::DesyncOnly || desync.enabled;
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
            bypass_lan,
            proxy_tls_fragment,
            log_level,
            detour_vless,
            extra_nodes,
            desync,
            balancer,
            community_lists,
            custom_rules,
            dns_strategy,
            dns_reverse_mapping,
            route_find_process,
            route_fullcone_nat,
            route_smart_queue,
            tun_stack,
            strict_route,
            sniff,
            tcp_fast_open,
            tcp_multi_path,
            ipv6_enabled,
            dns_transport,
            ntp_enabled,
            ntp_server,
        })
    }
}

fn ensure_private_dir(p: &Path) {
    let _ = fs::create_dir_all(p);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
    }
}

fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(local).join("Tachyon");
            ensure_private_dir(&p);
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
            ensure_private_dir(&p);
            return p;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg).join("tachyon");
            ensure_private_dir(&p);
            return p;
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("tachyon");
            ensure_private_dir(&p);
            return p;
        }
    }
    let fallback = std::env::temp_dir().join("tachyon");
    ensure_private_dir(&fallback);
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
    matches!(can, "ru_whitelist" | "ru_only_inside" | "russia_outside")
}

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct RunningEngine {
    in_proc: Option<BoxInstance>,
    worker: Option<Child>,
    worker_pid: Option<u32>,
    macos_helper: bool,
    running_config: Value,
    proxy_mode: bool,
    block_only: bool,
    has_node: bool,
    suppress_fake_ip: bool,
}

impl RunningEngine {
    async fn stop(&mut self) {
        if let Some(mut bx) = self.in_proc.take() {
            bx.shutdown_wait().await;
        }
        if self.macos_helper {
            self.macos_helper = false;
            self.worker_pid = None;
            #[cfg(target_os = "macos")]
            let _ = tokio::task::spawn_blocking(stop_macos_helper_tunnel).await;
            return;
        }
        let child_opt = self.worker.take();
        let pid_opt = self.worker_pid.take().or_else(read_core_pid_file);
        if child_opt.is_some() || pid_opt.is_some() {
            stop_worker_process(child_opt, pid_opt).await;
        }
    }
}

pub struct VpnManager {
    data_dir: PathBuf,
    log_path: PathBuf,
    secret: String,
    engine: Arc<tokio::sync::Mutex<Option<RunningEngine>>>,
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    stats_cancel: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    speedtest_cancel: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    last_connect_opts: Arc<Mutex<Option<String>>>,
    connect_gen: Arc<AtomicU64>,
    send_js: Arc<dyn Fn(String) + Send + Sync>,
}

impl VpnManager {
    pub fn new(send_js: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        #[cfg(target_os = "windows")]
        refresh_cached_windows_phys_ifindex();
        let data_dir = app_data_dir();
        let log_path = data_dir.join("tachyon-core.log");
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).expect("CSPRNG failure generating Clash API secret");
        let secret = rnd.iter().map(|b| format!("{b:02x}")).collect::<String>();

        Self {
            data_dir,
            log_path,
            secret,
            engine: Arc::new(tokio::sync::Mutex::new(None)),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            stats_cancel: Arc::new(Mutex::new(None)),
            speedtest_cancel: Arc::new(Mutex::new(None)),
            last_connect_opts: Arc::new(Mutex::new(None)),
            connect_gen: Arc::new(AtomicU64::new(0)),
            send_js,
        }
    }

    pub fn emit(&self, msg: impl Into<String>) {
        (self.send_js)(msg.into());
    }

    pub fn emit_vpn(&self, payload: Value) {
        self.emit(format!("vpn:{payload}"));
    }

    #[allow(dead_code)]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub async fn is_running(&self) -> bool {
        let mut guard = self.engine.lock().await;
        if let Some(eng) = guard.as_mut() {
            if let Some(child) = eng.worker.as_mut()
                && let Ok(Some(_)) = child.try_wait()
            {
                *guard = None;
                return false;
            }
            if let Some(pid) = eng.worker_pid
                && !is_pid_alive(pid)
            {
                *guard = None;
                return false;
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
        use std::io::Read;
        let Ok(meta) = fs::metadata(path) else {
            return false;
        };
        if meta.len() < 96 || (require_populated && meta.len() <= 96) {
            return false;
        }
        let Ok(mut f) = fs::File::open(path) else {
            return false;
        };
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).is_ok() && &magic == b"TSRS"
    }

    fn ensure_trs_stub(&self, canonical_name: &str) {
        let path = self.ruleset_file_path(canonical_name);
        if Self::is_valid_trs_file(&path, false) {
            return;
        }
        let _ = fs::write(path, EMPTY_TRS_STUB);
    }

    async fn download_single_ruleset_with_proxy(
        &self,
        canonical_name: &str,
        proxy_port: Option<u16>,
    ) -> bool {
        let path = self.ruleset_file_path(canonical_name);
        let urls = [
            format!("{TACHYON_LISTS_TRS_BASE}/{canonical_name}.trs"),
            format!("{TACHYON_LISTS_TRS_MIRROR}/{canonical_name}.trs"),
        ];
        for url in &urls {
            let res =
                match fetch_url(url, "GET", &[], None, proxy_port, Duration::from_secs(8)).await {
                    Ok(r) => Ok(r),
                    Err(_) if proxy_port.is_some() => {
                        fetch_url(url, "GET", &[], None, None, Duration::from_secs(8)).await
                    }
                    Err(e) => Err(e),
                };
            if let Ok(resp) = res
                && resp.status == 200
                && resp.body.len() > 96
                && &resp.body[0..4] == b"TSRS"
            {
                let tmp = path.with_extension("trs.tmp");
                if fs::write(&tmp, &resp.body).is_ok() {
                    if fs::rename(&tmp, &path).is_err() {
                        if fs::copy(&tmp, &path).is_err() {
                            let _ = fs::remove_file(&tmp);
                            continue;
                        }
                        let _ = fs::remove_file(&tmp);
                    }
                    return true;
                }
            }
        }
        self.ensure_trs_stub(canonical_name);
        false
    }

    async fn download_single_ruleset(&self, canonical_name: &str) -> bool {
        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        self.download_single_ruleset_with_proxy(canonical_name, proxy)
            .await
    }

    pub async fn ensure_community_rulesets(&self, opts: &ConnectOptions, force_refresh: bool) {
        let mut needed = HashSet::new();
        for item in &opts.community_lists {
            if opts.route == RouteMode::Selective
                && item.action.trim().eq_ignore_ascii_case("direct")
            {
                continue;
            }
            let can = canonical_ruleset_name(&item.name);
            if !can.is_empty() {
                needed.insert(can);
            }
        }
        if needed.is_empty() {
            return;
        }

        let to_fetch: Vec<String> = needed
            .into_iter()
            .filter(|can| {
                let path = self.ruleset_file_path(can);
                let has_real = Self::is_valid_trs_file(&path, true);
                let expired = has_real
                    && fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| SystemTime::now().duration_since(t).ok())
                        .map(|d| d > Duration::from_secs(86400))
                        .unwrap_or(true);
                force_refresh || !has_real || expired
            })
            .collect();

        if to_fetch.is_empty() {
            return;
        }

        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let sem = Arc::new(tokio::sync::Semaphore::new(6));
        let mut set = tokio::task::JoinSet::new();
        for can in to_fetch {
            let permit_fut = sem.clone();
            let this_data = self.data_dir.clone();
            set.spawn(async move {
                let _permit = permit_fut.acquire().await.ok();
                let dir = this_data.join("rulesets");
                let _ = fs::create_dir_all(&dir);
                let path = dir.join(format!("community-{can}.trs"));
                let urls = [
                    format!("{TACHYON_LISTS_TRS_BASE}/{can}.trs"),
                    format!("{TACHYON_LISTS_TRS_MIRROR}/{can}.trs"),
                ];
                for url in &urls {
                    let res = match fetch_url(url, "GET", &[], None, proxy, Duration::from_secs(8))
                        .await
                    {
                        Ok(r) => Ok(r),
                        Err(_) if proxy.is_some() => {
                            fetch_url(url, "GET", &[], None, None, Duration::from_secs(8)).await
                        }
                        Err(e) => Err(e),
                    };
                    if let Ok(resp) = res
                        && resp.status == 200
                        && resp.body.len() > 96
                        && &resp.body[0..4] == b"TSRS"
                    {
                        let tmp = path.with_extension("trs.tmp");
                        if fs::write(&tmp, &resp.body).is_ok() {
                            if fs::rename(&tmp, &path).is_err() {
                                let _ = fs::copy(&tmp, &path);
                                let _ = fs::remove_file(&tmp);
                            }
                            return;
                        }
                    }
                }
                if !VpnManager::is_valid_trs_file(&path, false) {
                    let _ = fs::write(path, EMPTY_TRS_STUB);
                }
            });
        }
        while set.join_next().await.is_some() {}
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
                if let Some(rest) = fname.strip_prefix("community-")
                    && let Some(stem) = rest
                        .strip_suffix(".trs")
                        .or_else(|| rest.strip_suffix(".srs"))
                {
                    let can = canonical_ruleset_name(stem);
                    if !can.is_empty() {
                        target.insert(can);
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

        let last_opts = self
            .last_connect_opts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if self.is_running().await
            && let Some(opts_json) = last_opts
        {
            self.connect(opts_json).await;
        }
    }

    fn build_desync_outbound(tag: &str, d: &DesyncOptions) -> Value {
        let preset = d.preset.trim().to_ascii_lowercase();
        let mapped_preset = match preset.as_str() {
            "youtube_discord" | "fake_split" | "fakesplit" => "fake_split",
            "fake_disorder" | "fakedisorder" | "aggressive" => "fake_disorder",
            "multi_disorder" | "multidisorder" | "multidisorder2" => "multi_disorder",
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
            "fake_split" | "fakesplit" | "fakedsplit" | "hostfakesplit" | "host_fake_split" => {
                "fake_split"
            }
            "fake_disorder" | "fakedisorder" | "fakeddisorder" | "faked_disorder" | "fad" => {
                "fake_disorder"
            }
            "multi_disorder" | "multidisorder" | "multidisorder2" => "multi_disorder",
            "multi_split" | "multisplit" | "multisplit2" => "multi_split",
            "tlsrec" | "tls_rec" => "tlsrec",
            "split" | "split2" => "split",
            "disorder" | "disorder2" => "disorder",
            "fake" | "syndata" => "fake",
            "oob" => "oob",
            "disoob" | "dis_oob" | "disorder_oob" => "disoob",
            _ => {
                if mapped_preset.is_empty() {
                    "fake_split"
                } else {
                    mapped_preset
                }
            }
        };

        let valid_fooling = match d.fooling.trim().to_ascii_lowercase().as_str() {
            "md5" | "md5sig" | "tcp_md5" | "tcp_md5sig" | "wrong-md5" | "wrong_md5" => "md5",
            "badseq" | "seq" | "wrong-sequence" | "wrong_sequence" => "badseq",
            "badack" | "ack" | "tcp_ack" | "wrong-ack" | "wrong_ack" => "badack",
            "timestamp" | "ts" | "tcp_ts" | "wrong-timestamp" | "wrong_timestamp" => "timestamp",
            "badsum" | "sum" | "wrong-checksum" | "wrong_checksum" => "badsum",
            "autottl" | "auto_ttl" | "ttl" | "low-ttl" | "low_ttl" => "autottl",
            "hopbyhop" | "hopbyhop2" | "ip6_hopbyhop" | "ip6_hopbyhop2" => "hopbyhop2",
            "destopt" | "ip6_destopt" | "destopt2" | "ip6_destopt2" => "destopt2",
            "ip6_ah" | "ah" => "ip6_ah",
            "badseq_badack_badsum" | "combo" | "badsum_combo" | "badseq,badsum" => {
                "badseq_badack_badsum"
            }
            "md5_badack" | "tcp_md5_badack" | "md5+badack" | "md5sig_badack" | "md5sig+badack"
            | "md5sig,badack" | "md5sig+badsum" | "md5+badsum" | "md5sig_badsum" | "md5_badsum"
            | "md5sig,badsum" => "md5_badack",
            "datanoack" | "data_no_ack" | "noack" => "datanoack",
            "fin" | "rst" | "finrst" | "fin_rst" => "finrst",
            _ => "md5",
        };

        let parse_single_split_pos = |token: &str| -> Value {
            let t = token.trim().to_ascii_lowercase();
            if let Ok(n) = t.parse::<u32>() {
                json!(n.clamp(1, 1400))
            } else {
                match t.as_str() {
                    "sni" | "sniext" => json!("sni"),
                    "sniext+1" | "sni+1" => json!("sniext+1"),
                    "host+1" => json!("host+1"),
                    "midsld-2" | "sld-2" => json!("midsld-2"),
                    "midsld" | "sld" | "host" => json!("midsld"),
                    "midsld+2" | "sld+2" => json!("midsld+2"),
                    "endhost-1" | "endsld-1" | "endhost" => json!("endhost-1"),
                    "extlen" => json!("extlen"),
                    _ => json!("midsld"),
                }
            }
        };

        let sp_raw = d.split_pos.trim();
        let split_pos_val: Value = if sp_raw.contains(',') {
            let arr: Vec<Value> = sp_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .take(8)
                .map(parse_single_split_pos)
                .collect();
            if arr.is_empty() {
                json!("midsld")
            } else {
                Value::Array(arr)
            }
        } else {
            parse_single_split_pos(sp_raw)
        };

        let snis: Vec<String> = d
            .fake_sni
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let primary_sni = snis
            .first()
            .cloned()
            .unwrap_or_else(|| "www.google.com".to_string());

        let is_auto_preset = mapped_preset == "auto";
        let mut obj = json!({
            "type": "desync",
            "tag": tag,
            "connect_timeout": "5s",
            "mode": valid_mode,
            "fooling": valid_fooling,
            "split_pos": split_pos_val,
            "tlsrec_first": if mapped_preset == "multi_disorder" || is_auto_preset { true } else { d.tlsrec_first },
            "fake_sni": primary_sni,
            "repeats": d.repeats.clamp(1, 100),
            "split_delay_ms": d.split_delay_ms.clamp(0, 1000),
            "auto_tune": if is_auto_preset { true } else { d.auto_tune },
            "udp_fake": d.udp_fake,
            "quic_desync": d.quic_desync,
            "udp_repeats": d.udp_repeats.clamp(1, 50),
            "udp_fake_ttl": d.udp_fake_ttl.clamp(1, 128),
        });
        if snis.len() > 1 {
            obj["sni_pool"] = json!(snis);
        }
        if d.quic_repeats > 0 {
            obj["quic_repeats"] = json!(d.quic_repeats.clamp(1, 50));
        }
        if d.host_fake {
            obj["host_fake"] = json!(true);
        }
        let fp = d.fake_payload.trim();
        if !fp.is_empty() {
            let valid_fp =
                if let Some(hex_s) = fp.strip_prefix("0x").or_else(|| fp.strip_prefix("0X")) {
                    !hex_s.is_empty()
                        && hex_s.len().is_multiple_of(2)
                        && hex_s.bytes().all(|b| b.is_ascii_hexdigit())
                } else {
                    true
                };
            if valid_fp {
                obj["fake_payload"] = json!(fp);
            }
        }
        let ufp = d.udp_fake_payload.trim();
        if !ufp.is_empty() && core_config::desync::parse_udp_fake_payload_hex(&json!(ufp)).is_ok() {
            obj["udp_fake_payload"] = json!(ufp);
        }
        let uor = d.udp_out_range.trim();
        if !uor.is_empty() && core_config::desync::UdpOutRange::from_json_value(&json!(uor)).is_ok()
        {
            obj["udp_out_range"] = json!(uor);
        }
        if d.udp_keep_socket {
            obj["udp_keep_socket"] = json!(true);
        }
        // Omit `fake_ttl` when running in `auto` mode with the default TTL=6 so `tachyon-core`
        // keeps `explicit_fake_ttl = false` and uses dynamic SYN+ACK hop-distance estimation.
        if !is_auto_preset || d.fake_ttl != 6 || valid_fooling == "autottl" {
            obj["fake_ttl"] = json!(d.fake_ttl.clamp(1, 128));
        }
        if d.seqovl > 0 {
            obj["seqovl"] = json!(d.seqovl.min(256));
        }
        if d.syndata {
            obj["syndata"] = json!(true);
        }
        if d.wsize > 0 {
            obj["wsize"] = json!(d.wsize.min(65535));
        }
        if let Some(ws) = d.wscale {
            obj["wscale"] = json!(ws.min(14));
        }
        if d.ipfrag {
            obj["ipfrag"] = json!(true);
        }
        if d.udplen > 0 {
            obj["udplen"] = json!(d.udplen.min(256));
        }
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
        let mut node = parse_node_uri(raw_uri.trim())?;
        let mut server_host = node
            .get("server")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .or_else(|| {
                node.pointer("/peers/0/address")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
            });
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
            if server_host.is_none() {
                server_host = ep
                    .pointer("/peers/0/address")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string);
            }
            if let Some(obj) = ep.as_object_mut() {
                obj.insert("tag".to_string(), json!(tag));
                if let Some(dt) = detour_tag {
                    obj.insert("detour".to_string(), json!(dt));
                }
            }
            return Ok((true, ep, server_host));
        }

        if matches!(ntype.as_str(), "tailscale" | "openvpn" | "openvpn-client") {
            if server_host.is_none() {
                server_host = node
                    .pointer("/servers/0/server")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        node.get("control_url")
                            .and_then(Value::as_str)
                            .and_then(|u| u.split("://").nth(1))
                            .and_then(|rest| rest.split('/').next())
                            .map(|hp| hp.split(':').next().unwrap_or("").trim().to_string())
                            .filter(|s| !s.is_empty())
                    });
            }
            if let Some(obj) = node.as_object_mut() {
                if ntype == "openvpn" {
                    obj.insert("type".to_string(), json!("openvpn-client"));
                }
                obj.insert("tag".to_string(), json!(tag));
                if let Some(dt) = detour_tag {
                    obj.insert("detour".to_string(), json!(dt));
                }
            }
            return Ok((true, node, server_host));
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
                && let Some(tls_obj) = obj.get_mut("tls").and_then(Value::as_object_mut)
            {
                tls_obj.insert("record_fragment".to_string(), json!(true));
            }
        }
        Ok((false, node, server_host))
    }

    fn alloc_unique_member_tag(
        base_name: &str,
        group_tag: &str,
        idx: usize,
        used_tags: &mut HashSet<String>,
    ) -> String {
        let trimmed = base_name.trim();
        let candidate_base = if trimmed.is_empty() {
            format!("{group_tag}-{}", idx + 1)
        } else {
            trimmed.to_string()
        };
        if !used_tags.contains(&candidate_base) {
            used_tags.insert(candidate_base.clone());
            return candidate_base;
        }
        let mut n = 2usize;
        loop {
            let next = format!("{candidate_base} #{n}");
            if !used_tags.contains(&next) {
                used_tags.insert(next.clone());
                return next;
            }
            n += 1;
        }
    }

    #[allow(clippy::type_complexity)]
    fn expand_parsed_target(
        raw_uri: &str,
        tag: &str,
        tls_fragment: bool,
        detour_tag: Option<&str>,
        balancer_opts: &BalancerOptions,
        used_tags: &mut HashSet<String>,
    ) -> Result<(Vec<Value>, Vec<Value>, Vec<String>), String> {
        let trimmed = raw_uri.trim();
        if let Some(bal) = decode_balancer_uri(trimmed) {
            let mut ep_list = Vec::new();
            let mut ob_list = Vec::new();
            let mut hosts = Vec::new();
            let mut member_tags = Vec::new();

            // 1. Разбираем всех участников, помечая тех, кто проходит фильтры
            //    (страны / протоколы / RegExp из настроек балансировщика).
            let mut candidates: Vec<(String, bool, Value, Option<String>, bool)> = Vec::new();
            let mut skipped_mtproto = false;
            for (idx, m) in bal.members.iter().enumerate() {
                let m_uri = m.vless.trim();
                if m_uri.is_empty() || m_uri.starts_with(BALANCER_URI_PREFIX) {
                    continue;
                }
                if is_mtproto_uri(m_uri) {
                    skipped_mtproto = true;
                    continue;
                }
                let m_tag = Self::alloc_unique_member_tag(&m.name, tag, idx, used_tags);
                if let Ok((is_ep, val, host)) =
                    Self::prepare_parsed_node(&m.vless, &m_tag, tls_fragment, detour_tag)
                {
                    let node_type = val.get("type").and_then(Value::as_str).unwrap_or("");
                    if node_type.eq_ignore_ascii_case("mtproto") {
                        skipped_mtproto = true;
                        used_tags.remove(&m_tag);
                        continue;
                    }
                    let sni = val
                        .pointer("/tls/server_name")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let passes = balancer_node_passes_filter(
                        &m.name,
                        host.as_deref().unwrap_or(""),
                        sni,
                        node_type,
                        balancer_opts,
                    );
                    candidates.push((m_tag, is_ep, val, host, passes));
                } else {
                    used_tags.remove(&m_tag);
                }
            }
            if candidates.is_empty() && skipped_mtproto {
                return Err(
                    "MTProto-узлы несовместимы с балансировщиком (только TCP без UDP). Выберите одиночный узел или добавьте в пул другие протоколы."
                        .to_string(),
                );
            }

            // Если фильтры отсекли все узлы — используем полный список (как в Android),
            // чтобы подключение не оставалось без рабочих узлов.
            let any_pass = candidates.iter().any(|c| c.4);
            for (m_tag, is_ep, val, host, passes) in candidates {
                if any_pass && !passes {
                    used_tags.remove(&m_tag);
                    continue;
                }
                if let Some(h) = host {
                    hosts.push(h);
                }
                if is_ep {
                    ep_list.push(val);
                } else {
                    ob_list.push(val);
                }
                member_tags.push(m_tag);
            }

            if member_tags.is_empty() {
                return Err("В балансировщике нет рабочих узлов".to_string());
            }

            let effective_mode = balancer_opts
                .mode_override
                .as_deref()
                .map(normalize_balancer_mode)
                .unwrap_or_else(|| normalize_balancer_mode(&bal.mode));

            // Глобальные настройки клиента имеют приоритет над значениями, сохранёнными в
            // самом балансировщике при его создании, поэтому изменения применяются сразу.
            let live = balancer_opts.from_prefs;
            let probe_url = if live && !balancer_opts.url.trim().is_empty() {
                balancer_opts.url.trim().to_string()
            } else if !bal.url.trim().is_empty() {
                bal.url.trim().to_string()
            } else {
                balancer_opts.url.clone()
            };
            let probe_interval = if live && !balancer_opts.interval.trim().is_empty() {
                balancer_opts.interval.trim().to_string()
            } else if !bal.interval.trim().is_empty() {
                bal.interval.trim().to_string()
            } else {
                balancer_opts.interval.clone()
            };
            let tolerance = if live {
                balancer_opts.tolerance
            } else if bal.tolerance > 0 {
                bal.tolerance.max(balancer_opts.tolerance)
            } else {
                balancer_opts.tolerance
            };
            let pool = if live {
                balancer_opts.pool
            } else if bal.pool > 0 {
                bal.pool
            } else {
                balancer_opts.pool
            };
            let pool_tol = if live {
                balancer_opts.pool_tolerance
            } else if bal.pool_tolerance > 0 {
                bal.pool_tolerance
            } else {
                balancer_opts.pool_tolerance
            };
            let quota_mib = if live {
                balancer_opts.quota_mib
            } else if bal.quota_mib > 0 {
                bal.quota_mib
            } else {
                balancer_opts.quota_mib
            };
            let sticky_hash = if live && !balancer_opts.sticky_hash.is_empty() {
                balancer_opts.sticky_hash.clone()
            } else if !bal.sticky_hash.is_empty() {
                bal.sticky_hash.clone()
            } else {
                balancer_opts.sticky_hash.clone()
            };

            let build_urltest = |group_tag: &str, url: &str| -> Value {
                let mut ob = json!({
                    "type": "urltest",
                    "tag": group_tag,
                    "outbounds": member_tags.clone(),
                    "url": url,
                    "interval": probe_interval.clone(),
                    "tolerance": tolerance,
                    "mode": effective_mode
                });
                if !matches!(effective_mode, "least_test" | "failover") {
                    let mut block = json!({
                        "pool": pool,
                        "pool_tolerance": pool_tol,
                        "sticky_hash": sticky_hash.clone()
                    });
                    if quota_mib > 0 {
                        block["quota_mib"] = json!(quota_mib);
                    }
                    ob["balancer"] = block;
                }
                ob
            };

            // Put urltest group first, followed by its member outbounds
            let mut final_obs = vec![build_urltest(tag, &probe_url)];

            // Мульти-URL: отдельный пул `urltest-svc-<id>` со своим проверочным URL
            // на каждый выбранный сервис (только для основного узла).
            if tag == "PROXY" {
                for svc in &balancer_opts.multi_services {
                    let Some(svc_url) = balancer_service_probe_url(svc) else {
                        continue;
                    };
                    let svc_tag = format!("urltest-svc-{svc}");
                    if !used_tags.insert(svc_tag.clone()) {
                        continue;
                    }
                    final_obs.push(build_urltest(&svc_tag, svc_url));
                }
            }
            final_obs.extend(ob_list);
            return Ok((ep_list, final_obs, hosts));
        }

        let (is_ep, val, host) = Self::prepare_parsed_node(trimmed, tag, tls_fragment, detour_tag)?;
        let mut ep_list = Vec::new();
        let mut ob_list = Vec::new();
        let mut hosts = Vec::new();
        if let Some(h) = host {
            hosts.push(h);
        }
        if is_ep {
            ep_list.push(val);
        } else {
            ob_list.push(val);
        }
        Ok((ep_list, ob_list, hosts))
    }

    fn build_remote_dns_server(dns_raw: &str, transport: &str, dns_detour: &str) -> Value {
        let make = |ty: &str, server: &str, port: Option<u16>, path: Option<&str>, detour: &str| {
            let t = ty.trim().to_ascii_lowercase();
            match t.as_str() {
                "h3" | "https" => json!({
                    "type": t,
                    "tag": "dns_remote",
                    "server": server,
                    "server_port": port.unwrap_or(443),
                    "path": path.unwrap_or("/dns-query"),
                    "detour": detour
                }),
                "quic" | "tls" => json!({
                    "type": t,
                    "tag": "dns_remote",
                    "server": server,
                    "server_port": port.unwrap_or(853),
                    "detour": detour
                }),
                _ => json!({
                    "type": "udp",
                    "tag": "dns_remote",
                    "server": server,
                    "server_port": port.unwrap_or(53),
                    "detour": detour
                }),
            }
        };

        let trimmed = dns_raw.trim();
        if let Some((scheme, rest)) = trimmed.split_once("://") {
            let low_scheme = scheme.trim().to_ascii_lowercase();
            if matches!(low_scheme.as_str(), "https" | "h3" | "quic" | "tls" | "udp") {
                let (authority, path_opt) = if let Some(idx) = rest.find('/') {
                    let p = &rest[idx..];
                    (&rest[..idx], if p.is_empty() { None } else { Some(p) })
                } else {
                    (rest, None)
                };
                let (host, port_opt) = if let Some(v6_tail) = authority.strip_prefix('[') {
                    if let Some((h, tail)) = v6_tail.split_once(']') {
                        let p = tail.strip_prefix(':').and_then(|s| s.parse::<u16>().ok());
                        (h.trim(), p)
                    } else {
                        (authority.trim(), None)
                    }
                } else if let Some((h, p_str)) = authority.rsplit_once(':') {
                    if let Ok(p) = p_str.parse::<u16>() {
                        (h.trim(), Some(p))
                    } else {
                        (authority.trim(), None)
                    }
                } else {
                    (authority.trim(), None)
                };
                if !host.is_empty() {
                    return make(&low_scheme, host, port_opt, path_opt, dns_detour);
                }
            }
        }

        let norm_tr = match transport.trim().to_ascii_lowercase().as_str() {
            "h3" | "quic" | "tls" | "udp" => transport.trim().to_ascii_lowercase(),
            _ => "https".to_string(),
        };
        let lower = trimmed.to_ascii_lowercase();
        match lower.as_str() {
            "cloudflare" | "1.1.1.1" => make(&norm_tr, "1.1.1.1", None, None, dns_detour),
            "adguard" | "94.140.14.14" => make(&norm_tr, "94.140.14.14", None, None, dns_detour),
            "quad9" | "9.9.9.9" => make(&norm_tr, "9.9.9.9", None, None, dns_detour),
            "google" | "8.8.8.8" => make(&norm_tr, "8.8.8.8", None, None, dns_detour),
            "yandex" | "77.88.8.8" => json!({
                "type": "udp",
                "tag": "dns_remote",
                "server": "77.88.8.8",
                "server_port": 53,
                "detour": "direct"
            }),
            _ if trimmed.parse::<IpAddr>().is_ok() => json!({
                "type": "udp",
                "tag": "dns_remote",
                "server": trimmed,
                "server_port": 53,
                "detour": dns_detour
            }),
            _ => make(&norm_tr, "1.1.1.1", None, None, dns_detour),
        }
    }

    #[allow(dead_code)]
    pub fn build_config(&self, opts: &ConnectOptions) -> Result<(Value, bool), String> {
        self.build_config_with_fakeip_override(opts, false)
    }

    fn build_config_with_fakeip_override(
        &self,
        opts: &ConnectOptions,
        suppress_fake_ip: bool,
    ) -> Result<(Value, bool), String> {
        let has_main_node = !opts.block_only
            && opts.route != RouteMode::DesyncOnly
            && !opts.vless.trim().is_empty();

        let mut used_tags: HashSet<String> = [
            "GLOBAL",
            "PROXY",
            "DESYNC",
            "direct",
            "block",
            "detour-proxy",
            "dns_direct",
            "dns_remote",
            "dns-fakeip",
            "tun-in",
            "mixed-in",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        for ex in &opts.extra_nodes {
            used_tags.insert(ex.tag.clone());
        }

        let detour_parsed = if has_main_node && !opts.detour_vless.trim().is_empty() {
            Self::expand_parsed_target(
                &opts.detour_vless,
                "detour-proxy",
                opts.proxy_tls_fragment,
                None,
                &opts.balancer,
                &mut used_tags,
            )
            .ok()
        } else {
            None
        };

        let main_detour_tag = detour_parsed.as_ref().map(|_| "detour-proxy");
        let main_parsed = if has_main_node {
            Some(Self::expand_parsed_target(
                &opts.vless,
                "PROXY",
                opts.proxy_tls_fragment,
                main_detour_tag,
                &opts.balancer,
                &mut used_tags,
            )?)
        } else {
            None
        };

        let mut extra_parsed = Vec::new();
        if !opts.block_only && opts.route != RouteMode::DesyncOnly {
            for ex in &opts.extra_nodes {
                if let Ok(p) = Self::expand_parsed_target(
                    &ex.vless,
                    &ex.tag,
                    opts.proxy_tls_fragment,
                    None,
                    &opts.balancer,
                    &mut used_tags,
                ) {
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
        let remote_dns = Self::build_remote_dns_server(&opts.dns, &opts.dns_transport, dns_detour);
        dns_servers.push(remote_dns);

        let fake_ip_enabled = opts.fake_ip && !opts.proxy_mode && !suppress_fake_ip;
        if fake_ip_enabled {
            let mut fip = json!({
                "type": "fakeip",
                "tag": "dns-fakeip",
                "inet4_range": "198.18.0.0/15"
            });
            if opts.ipv6_enabled {
                fip["inet6_range"] = json!("fc00::/18");
            }
            dns_servers.push(fip);
        }

        let mut dns_rules = Vec::new();
        if opts.bypass_lan {
            dns_rules.push(json!({
                "domain_suffix": [".lan", ".local", ".home.arpa", ".internal"],
                "server": "dns_direct"
            }));
        }

        if opts.dns_route_mode == "split_ru" || opts.dns_route_mode == "smart" {
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

        let dns_obj = json!({
            "servers": dns_servers,
            "rules": dns_rules,
            "final": final_dns_tag,
            "strategy": opts.dns_strategy,
            "reverse_mapping": opts.dns_reverse_mapping
        });

        let mut inbounds = Vec::new();
        if !opts.proxy_mode {
            let tun_addrs = if opts.ipv6_enabled {
                json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
            } else {
                json!(["172.19.0.1/30"])
            };
            let mut tun_excludes = vec![
                json!("172.19.0.1/32"),
                json!("127.0.0.0/8"),
                json!("224.0.0.0/4"),
                json!("255.255.255.255/32"),
                json!("169.254.0.0/16"),
                json!("::1/128"),
                json!("ff00::/8"),
                json!("fe80::/10"),
            ];
            if opts.bypass_lan {
                // Разбиваем 172.16.0.0/12 так, чтобы исключить подсеть TUN (172.19.0.0/24),
                // иначе на macOS/Windows системные таблицы маршрутизации могут конфликтовать с 172.19.0.1/30.
                tun_excludes.extend([
                    json!("10.0.0.0/8"),
                    json!("172.16.0.0/15"),
                    json!("172.18.0.0/16"),
                    json!("172.19.1.0/24"),
                    json!("172.19.2.0/23"),
                    json!("172.19.4.0/22"),
                    json!("172.19.8.0/21"),
                    json!("172.19.16.0/20"),
                    json!("172.19.32.0/19"),
                    json!("172.19.64.0/18"),
                    json!("172.19.128.0/17"),
                    json!("172.20.0.0/14"),
                    json!("172.24.0.0/13"),
                    json!("192.168.0.0/16"),
                    json!("100.64.0.0/10"),
                    json!("fc00::/7"),
                ]);
            }
            inbounds.push(json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": default_tun_device(),
                "address": tun_addrs,
                "mtu": opts.mtu.clamp(1280, 9000),
                "auto_route": true,
                "strict_route": opts.strict_route,
                "stack": opts.tun_stack,
                "route_exclude_address": tun_excludes
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
        let mut min_endpoint_mtu: Option<u32> = None;

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

        if let Some((eps, obs, hosts)) = main_parsed.clone() {
            for h in hosts {
                server_hosts.insert(h);
            }
            for ep in &eps {
                let ep_mtu = ep
                    .get("mtu")
                    .and_then(Value::as_u64)
                    .map(|m| (m as u32).clamp(1280, 9000))
                    .unwrap_or(1408);
                min_endpoint_mtu = Some(min_endpoint_mtu.map_or(ep_mtu, |cur| cur.min(ep_mtu)));
            }
            endpoints.extend(eps);
            outbounds.extend(obs);
        }
        if let Some((eps, obs, hosts)) = detour_parsed {
            for h in hosts {
                server_hosts.insert(h);
            }
            endpoints.extend(eps);
            outbounds.extend(obs);
        }
        for (_, (eps, obs, hosts)) in &extra_parsed {
            for h in hosts {
                server_hosts.insert(h.clone());
            }
            endpoints.extend(eps.clone());
            outbounds.extend(obs.clone());
        }

        if let Some(ep_mtu) = min_endpoint_mtu
            && let Some(tun_obj) = inbounds.first_mut().and_then(Value::as_object_mut)
            && tun_obj.get("type").and_then(Value::as_str) == Some("tun")
        {
            let cur_mtu = tun_obj
                .get("mtu")
                .and_then(Value::as_u64)
                .map(|m| m as u32)
                .unwrap_or(1420);
            if ep_mtu < cur_mtu {
                tun_obj.insert("mtu".to_string(), json!(ep_mtu));
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

        if opts.tcp_fast_open || opts.tcp_multi_path {
            for ob in &mut outbounds {
                if let Some(obj) = ob.as_object_mut() {
                    let ty = obj
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let tcp_dial = matches!(
                        ty.as_str(),
                        "direct"
                            | "desync"
                            | "vless"
                            | "vmess"
                            | "trojan"
                            | "shadowsocks"
                            | "socks"
                            | "http"
                            | "ssh"
                            | "shadowtls"
                            | "naive"
                            | "trusttunnel"
                    );
                    if tcp_dial {
                        if opts.tcp_fast_open {
                            obj.insert("tcp_fast_open".to_string(), json!(true));
                        }
                        if opts.tcp_multi_path {
                            obj.insert("tcp_multi_path".to_string(), json!(true));
                        }
                    }
                }
            }
        }

        let mut rules = Vec::new();
        if opts.sniff {
            rules.push(json!({ "action": "sniff" }));
        }
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
        let mut self_procs: Vec<String> = vec![
            "tachyon".to_string(),
            "tachyon-desktop".to_string(),
            "tachyon-core".to_string(),
            "tachyon-core.exe".to_string(),
            "Tachyon.exe".to_string(),
            "tachyon.exe".to_string(),
        ];
        if let Ok(exe) = std::env::current_exe()
            && let Some(fname) = exe.file_name().and_then(|s| s.to_str())
            && !self_procs.iter().any(|p| p == fname)
        {
            self_procs.push(fname.to_string());
        }
        if main_parsed.is_some() {
            rules.push(json!({
                "inbound": ["mixed-in"],
                "process_name": &self_procs,
                "outbound": "GLOBAL"
            }));
        }
        if !opts.proxy_mode {
            rules.push(json!({
                "inbound": ["tun-in"],
                "process_name": &self_procs,
                "outbound": "direct"
            }));
        }
        rules.push(json!({ "network": "udp", "port": [135, 137, 138, 139, 445, 1900, 3702, 5353, 5355], "action": "reject" }));
        if opts.bypass_lan {
            rules.extend([
                json!({ "ip_is_private": true, "outbound": "direct" }),
                json!({ "ip_cidr": ["100.64.0.0/10", "fc00::/7", "fe80::/10"], "outbound": "direct" }),
                json!({ "domain_suffix": [".local", ".lan", ".home.arpa", ".internal"], "outbound": "direct" }),
            ]);
        } else {
            rules.push(json!({ "ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct" }));
        }
        let bootstrap_cidr = if let Ok(ip) = bootstrap_ip.parse::<IpAddr>() {
            if ip.is_ipv6() {
                format!("{ip}/128")
            } else {
                format!("{ip}/32")
            }
        } else {
            format!("{bootstrap_ip}/32")
        };
        rules.push(json!({ "ip_cidr": [bootstrap_cidr], "outbound": "direct" }));

        let mut server_ips = Vec::new();
        let mut server_domains = Vec::new();
        for h in server_hosts {
            if let Ok(ip) = h.parse::<IpAddr>() {
                let cidr = if ip.is_ipv4() {
                    format!("{ip}/32")
                } else {
                    format!("{ip}/128")
                };
                server_ips.push(cidr);
            } else if !h.is_empty() {
                server_domains.push(h);
            }
        }
        if !opts.proxy_mode
            && !server_ips.is_empty()
            && let Some(tun_obj) = inbounds.first_mut().and_then(Value::as_object_mut)
            && let Some(Value::Array(excl)) = tun_obj.get_mut("route_exclude_address")
        {
            for cidr in &server_ips {
                excl.push(Value::String(cidr.clone()));
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

        const ANTICHEAT_PROCESSES: &[&str] = &[
            "cod.exe",
            "cod22-cod.exe",
            "cod23-cod.exe",
            "cod24-cod.exe",
            "sp22-cod.exe",
            "sp23-cod.exe",
            "sp24-cod.exe",
            "randgrid.exe",
            "battle.net.exe",
            "agent.exe",
            "easyanticheat.exe",
            "easyanticheat_eos.exe",
            "start_protected_game.exe",
            "beservice.exe",
            "beclient_x64.exe",
            "eaanticheat.gameservice.exe",
            "eaanticheat.gameservice.dll",
            "faceitclient.exe",
            "faceitservice.exe",
            "vgc.exe",
            "vgtray.exe",
            "valorant.exe",
            "valorant-win64-shipping.exe",
            "riotclientservices.exe",
            "cs2.exe",
            "dota2.exe",
            "r5apex.exe",
            "fortniteclient-win64-shipping.exe",
            "tslgame.exe",
            "rainbowsix.exe",
            "rainbowsix_be.exe",
            "escapefromtarkov.exe",
            "escapefromtarkov_be.exe",
            "rustclient.exe",
            "dayz_x64.exe",
            "deadbydaylight-win64-shipping.exe",
            "overwatch.exe",
            "destiny2.exe",
            "helldivers2.exe",
            "thefinals.exe",
            "bf2042.exe",
            "fc24.exe",
            "fc25.exe",
            "genshinimpact.exe",
            "starrail.exe",
        ];

        if opts.desync.anticheat_bypass {
            rules.push(json!({
                "domain_suffix": [
                    "demonware.net",
                    "callofduty.com",
                    "activision.com",
                    "battle.net",
                    "blizzard.com",
                    "bnet.com",
                    "easyanticheat.net",
                    "eac-cdn.com",
                    "battleye.com",
                    "faceit.com",
                    "pvp.net"
                ],
                "outbound": "direct"
            }));
            rules.push(json!({
                "process_name": ANTICHEAT_PROCESSES,
                "network": "udp",
                "outbound": "direct"
            }));
            if !opts.desync.lists_override_game_bypass {
                rules.push(json!({
                    "process_name": ANTICHEAT_PROCESSES,
                    "outbound": "direct"
                }));
            }
        }

        let vpn_target_tag = if main_parsed.is_some() {
            "GLOBAL"
        } else {
            "DESYNC"
        };
        let mut valid_extra_tags: HashSet<String> =
            extra_parsed.iter().map(|(t, _)| t.clone()).collect();
        // Пулы мульти-URL (`urltest-svc-<id>`) — допустимые цели правил маршрутизации.
        if let Some((_, obs, _)) = main_parsed.as_ref() {
            for ob in obs {
                if let Some(t) = ob.get("tag").and_then(Value::as_str)
                    && t.starts_with("urltest-svc-")
                {
                    valid_extra_tags.insert(t.to_string());
                }
            }
        }
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

        if opts.desync.anticheat_bypass && opts.desync.lists_override_game_bypass {
            rules.push(json!({
                "process_name": ANTICHEAT_PROCESSES,
                "outbound": "direct"
            }));
        }

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
                        rules
                            .push(json!({ "process_name": app_procs, "outbound": vpn_target_tag }));
                    }
                    direct_or_desync
                }
                RouteMode::AppsExclude => {
                    if !app_procs.is_empty() {
                        rules.push(
                            json!({ "process_name": app_procs, "outbound": direct_or_desync }),
                        );
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
            } else {
                rules.push(json!({ "network": "udp", "port": 443, "outbound": "DESYNC" }));
            }
            if opts.desync.discord_udp_fake {
                rules.push(json!({ "network": "udp", "port_range": ["19294:19344", "50000:50100"], "outbound": "DESYNC" }));
            } else {
                rules.push(json!({ "network": "udp", "port_range": ["50000:50100"], "outbound": "DESYNC" }));
            }
            if opts.desync.stun_fake {
                rules.push(
                    json!({ "network": "udp", "port": [3478, 3479, 5349], "outbound": "DESYNC" }),
                );
            }
            rules.push(json!({ "network": "udp", "outbound": "direct" }));
        }

        let mut route_obj = json!({
            "default_domain_resolver": "dns_direct",
            "auto_detect_interface": true,
            "find_process": opts.route_find_process,
            "fullcone": opts.route_fullcone_nat,
            "smart_queue": opts.route_smart_queue,
            "final": final_outbound,
            "rules": rules
        });
        #[cfg(target_os = "macos")]
        if !opts.proxy_mode
            && let Some(phys_iface) = detect_macos_phys_interface()
        {
            route_obj["default_interface"] = json!(phys_iface);
        }
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
        if opts.ntp_enabled {
            let ntp_srv = {
                let s = opts.ntp_server.trim();
                if s.is_empty() {
                    "time.cloudflare.com"
                } else {
                    s
                }
            };
            root["ntp"] = json!({
                "enabled": true,
                "server": ntp_srv,
                "server_port": 123,
                "interval": "30m",
                "write_to_system": false
            });
        }

        Ok((root, main_parsed.is_some()))
    }

    fn is_valid_time_window(raw: &str) -> bool {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return false;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let (days_tok, range_tok, tz_tok) = match tokens.as_slice() {
            [r] => (None, *r, None),
            [a, b] => {
                if a.contains(':') && a.contains('-') {
                    (None, *a, Some(*b))
                } else {
                    (Some(*a), *b, None)
                }
            }
            [d, r, tz] => (Some(*d), *r, Some(*tz)),
            _ => return false,
        };
        let valid_day = |s: &str| -> bool {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "mon"
                    | "monday"
                    | "1"
                    | "пн"
                    | "tue"
                    | "tues"
                    | "tuesday"
                    | "2"
                    | "вт"
                    | "wed"
                    | "wednesday"
                    | "3"
                    | "ср"
                    | "thu"
                    | "thur"
                    | "thurs"
                    | "thursday"
                    | "4"
                    | "чт"
                    | "fri"
                    | "friday"
                    | "5"
                    | "пт"
                    | "sat"
                    | "saturday"
                    | "6"
                    | "сб"
                    | "sun"
                    | "sunday"
                    | "7"
                    | "вс"
                    | "weekdays"
                    | "weekend"
            )
        };
        if let Some(d) = days_tok {
            for part in d.split(',') {
                for seg in part.split('-') {
                    if !valid_day(seg) {
                        return false;
                    }
                }
            }
        }
        let Some((s_t, e_t)) = range_tok.split_once('-') else {
            return false;
        };
        let valid_hm = |hm: &str| -> bool {
            let Some((hh, mm)) = hm.split_once(':') else {
                return false;
            };
            matches!((hh.parse::<u8>(), mm.parse::<u8>()), (Ok(h), Ok(m)) if h <= 23 && m <= 59)
        };
        if !valid_hm(s_t) || !valid_hm(e_t) {
            return false;
        }
        if let Some(tz) = tz_tok {
            let low = tz.to_ascii_lowercase();
            if low != "utc" && low != "local" && !low.starts_with('+') && !low.starts_with('-') {
                return false;
            }
        }
        true
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
        let is_selective = opts.route == RouteMode::Selective;
        let mut custom_groups = vec!["block".to_string()];
        if !is_selective {
            custom_groups.push("direct".to_string());
        }
        custom_groups.push("desync".to_string());
        for t in valid_extra_tags {
            custom_groups.push(t.clone());
        }
        custom_groups.push("vpn".to_string());

        static IP_RE: OnceLock<Regex> = OnceLock::new();
        let ip_re =
            IP_RE.get_or_init(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$").unwrap());

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
            let mut dom_regexes = Vec::new();
            let mut ip_cidrs = Vec::new();
            let mut procs = Vec::new();
            let mut proc_paths = Vec::new();
            let mut ports: Vec<u16> = Vec::new();
            let mut port_ranges: Vec<String> = Vec::new();

            let emit_matcher =
                |mut matcher: Map<String, Value>, tw: Option<&str>, rules_out: &mut Vec<Value>| {
                    if let Some(window_str) = tw {
                        matcher.insert("time_window".to_string(), json!(window_str));
                    }
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

            let mut windowed: Vec<(String, Map<String, Value>)> = Vec::new();

            for cr in matching {
                let val = cr.value.trim();
                if val.is_empty() {
                    continue;
                }
                let tw = {
                    let t = cr.time_window.trim();
                    if !t.is_empty() && Self::is_valid_time_window(t) {
                        Some(t.to_string())
                    } else {
                        None
                    }
                };

                if cr.rtype == "process_path"
                    || (cr.rtype == "process" && (val.contains('/') || val.contains('\\')))
                {
                    if let Some(w) = tw {
                        let mut m = Map::new();
                        m.insert("process_path".to_string(), json!([val]));
                        windowed.push((w, m));
                    } else {
                        proc_paths.push(val.to_string());
                    }
                } else if cr.rtype == "process" || val.to_ascii_lowercase().ends_with(".exe") {
                    if let Some(w) = tw {
                        let mut m = Map::new();
                        m.insert("process_name".to_string(), json!([val]));
                        windowed.push((w, m));
                    } else {
                        procs.push(val.to_string());
                    }
                } else if cr.rtype == "domain_regex" {
                    if Regex::new(val).is_ok() {
                        if let Some(w) = tw {
                            let mut m = Map::new();
                            m.insert("domain_regex".to_string(), json!([val]));
                            windowed.push((w, m));
                        } else {
                            dom_regexes.push(val.to_string());
                        }
                    }
                } else if cr.rtype == "port" || cr.rtype == "port_range" {
                    let norm = val.replace('-', ":");
                    if let Some((a, b)) = norm.split_once(':') {
                        if a.trim().parse::<u16>().is_ok() && b.trim().parse::<u16>().is_ok() {
                            let pr = format!("{}:{}", a.trim(), b.trim());
                            if let Some(w) = tw {
                                let mut m = Map::new();
                                m.insert("port_range".to_string(), json!([pr]));
                                windowed.push((w, m));
                            } else {
                                port_ranges.push(pr);
                            }
                        }
                    } else if let Ok(p) = val.parse::<u16>()
                        && p > 0
                    {
                        if let Some(w) = tw {
                            let mut m = Map::new();
                            m.insert("port".to_string(), json!([p]));
                            windowed.push((w, m));
                        } else {
                            ports.push(p);
                        }
                    }
                } else if cr.rtype == "ip"
                    || cr.rtype == "cidr"
                    || ip_re.is_match(val)
                    || val.parse::<IpAddr>().is_ok()
                {
                    let parsed_cidr = if let Some((addr_part, prefix_part)) = val.split_once('/') {
                        if let (Ok(ip), Ok(p)) = (
                            addr_part.trim().parse::<IpAddr>(),
                            prefix_part.trim().parse::<u8>(),
                        ) {
                            let max_p = if ip.is_ipv6() { 128 } else { 32 };
                            (p <= max_p).then(|| format!("{ip}/{p}"))
                        } else {
                            None
                        }
                    } else if let Ok(ip) = val.parse::<IpAddr>() {
                        Some(if ip.is_ipv6() {
                            format!("{ip}/128")
                        } else {
                            format!("{ip}/32")
                        })
                    } else {
                        None
                    };
                    if let Some(cidr) = parsed_cidr {
                        if let Some(w) = tw {
                            let mut m = Map::new();
                            m.insert("ip_cidr".to_string(), json!([cidr]));
                            windowed.push((w, m));
                        } else {
                            ip_cidrs.push(cidr);
                        }
                    }
                } else if let Some(kw) = val.strip_prefix("keyword:") {
                    let kwt = kw.trim();
                    if !kwt.is_empty() {
                        if let Some(w) = tw {
                            let mut m = Map::new();
                            m.insert("domain_keyword".to_string(), json!([kwt]));
                            windowed.push((w, m));
                        } else {
                            dom_keywords.push(kwt.to_string());
                        }
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
                        if let Some(w) = tw {
                            let mut m = Map::new();
                            m.insert("domain_suffix".to_string(), json!([clean]));
                            windowed.push((w, m));
                        } else {
                            dom_suffixes.push(clean.to_string());
                        }
                    }
                }
            }

            if !dom_suffixes.is_empty() {
                let mut m = Map::new();
                m.insert("domain_suffix".to_string(), json!(dom_suffixes));
                emit_matcher(m, None, rules_list);
            }
            if !dom_keywords.is_empty() {
                let mut m = Map::new();
                m.insert("domain_keyword".to_string(), json!(dom_keywords));
                emit_matcher(m, None, rules_list);
            }
            if !dom_regexes.is_empty() {
                let mut m = Map::new();
                m.insert("domain_regex".to_string(), json!(dom_regexes));
                emit_matcher(m, None, rules_list);
            }
            if !ip_cidrs.is_empty() {
                let mut m = Map::new();
                m.insert("ip_cidr".to_string(), json!(ip_cidrs));
                emit_matcher(m, None, rules_list);
            }
            if !procs.is_empty() {
                let mut m = Map::new();
                m.insert("process_name".to_string(), json!(procs));
                emit_matcher(m, None, rules_list);
            }
            if !proc_paths.is_empty() {
                let mut m = Map::new();
                m.insert("process_path".to_string(), json!(proc_paths));
                emit_matcher(m, None, rules_list);
            }
            if !ports.is_empty() {
                let mut m = Map::new();
                m.insert("port".to_string(), json!(ports));
                emit_matcher(m, None, rules_list);
            }
            if !port_ranges.is_empty() {
                let mut m = Map::new();
                m.insert("port_range".to_string(), json!(port_ranges));
                emit_matcher(m, None, rules_list);
            }
            for (tw, m) in windowed {
                emit_matcher(m, Some(&tw), rules_list);
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
            let act = item.action.trim();
            let act_low = act.to_ascii_lowercase();
            let act_upper = act.to_ascii_uppercase();
            if is_selective && act_low == "direct" {
                continue;
            }
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

            if act_low == "block" {
                block_rs.push(tag);
            } else if act_low == "desync" {
                desync_rs.push(tag);
            } else if valid_extra_tags.contains(&act_upper) {
                node_rs.entry(act_upper).or_default().push(tag);
            } else if valid_extra_tags.contains(act) {
                node_rs.entry(act.to_string()).or_default().push(tag);
            } else if act_low == "vpn" || act_upper.starts_with("NODE_") {
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

    fn rotate_log_if_oversized(&self) {
        const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
        if let Ok(meta) = fs::metadata(&self.log_path)
            && meta.len() > MAX_LOG_BYTES
        {
            let prev = self.log_path.with_extension("log.prev");
            let _ = fs::remove_file(&prev);
            if fs::rename(&self.log_path, &prev).is_err() {
                let _ = fs::write(&self.log_path, b"");
            }
        }
    }

    pub async fn connect(&self, options_json: String) {
        let my_gen = self.connect_gen.fetch_add(1, Ordering::AcqRel) + 1;
        let opts = match ConnectOptions::parse(&options_json) {
            Ok(o) => {
                *self
                    .last_connect_opts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(options_json.clone());
                o
            }
            Err(e) => {
                self.emit_vpn(json!({ "state": "error", "error": e }));
                return;
            }
        };

        let cfg_path = self.data_dir.join("config.json");

        // Try fast in-place hot reload if already running in the same mode and rulesets exist
        let can_hot_reload = {
            let guard = self.engine.lock().await;
            guard.as_ref().is_some_and(|e| {
                e.proxy_mode == opts.proxy_mode && !e.block_only && !opts.block_only
            })
        };
        if can_hot_reload {
            self.ensure_community_rulesets(&opts, false).await;
            if self.connect_gen.load(Ordering::Acquire) != my_gen {
                return;
            }
            let _life = self.lifecycle_lock.lock().await;
            if self.connect_gen.load(Ordering::Acquire) != my_gen {
                return;
            }
            let mut guard = self.engine.lock().await;
            if let Some(eng) = guard.as_mut()
                && eng.proxy_mode == opts.proxy_mode
                && !eng.block_only
                && !opts.block_only
            {
                let suppress_fake_ip = eng.suppress_fake_ip;
                let (cfg_val, has_node) =
                    match self.build_config_with_fakeip_override(&opts, suppress_fake_ip) {
                        Ok(res) => res,
                        Err(e) => {
                            self.emit_vpn(json!({ "state": "error", "error": e }));
                            return;
                        }
                    };
                let cfg_text = serde_json::to_string_pretty(&cfg_val).unwrap_or_default();
                let _ = write_private_file(&cfg_path, cfg_text.as_bytes());

                let mut reloaded = false;
                if let Some(bx) = eng.in_proc.as_mut() {
                    if bx.reload_in_place(&cfg_val).await.is_ok() {
                        reloaded = true;
                    }
                } else if eng.worker.is_some() || eng.worker_pid.is_some() || eng.macos_helper {
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
                    let _ =
                        clash_api_request(API_PORT, &self.secret, "DELETE", "/connections", None)
                            .await;
                    let prev_has_node = eng.has_node;
                    eng.running_config = cfg_val;
                    eng.has_node = has_node;
                    flush_os_dns();
                    if prev_has_node != has_node {
                        self.start_stats_loop(has_node);
                    }
                    self.emit_vpn(json!({ "state": "switched" }));
                    return;
                }
            }
        }

        self.emit_vpn(json!({ "state": "connecting", "stage": "rulesets" }));
        self.stop_stats_loop();
        self.ensure_community_rulesets(&opts, false).await;

        if self.connect_gen.load(Ordering::Acquire) != my_gen {
            return;
        }

        let _life = self.lifecycle_lock.lock().await;
        if self.connect_gen.load(Ordering::Acquire) != my_gen {
            return;
        }

        {
            let mut guard = self.engine.lock().await;
            if let Some(mut old) = guard.take() {
                let was_proxy = old.proxy_mode;
                old.stop().await;
                if was_proxy || proxy_points_to_us() {
                    set_system_proxy(false);
                }
            }
        }

        if self.connect_gen.load(Ordering::Acquire) != my_gen {
            return;
        }

        self.emit_vpn(json!({ "state": "connecting", "stage": "config" }));
        self.rotate_log_if_oversized();

        // Определяем, активен ли в текущей сети шлюз с тем же FakeIP-пулом (198.18.0.0/15),
        // строго до поднятия локального TUN, чтобы избежать конфликта таблиц FakeIP.
        let suppress_fake_ip = if opts.fake_ip && !opts.proxy_mode {
            detect_upstream_fakeip().await
        } else {
            false
        };
        if suppress_fake_ip {
            flush_os_dns();
        }

        let (cfg_val, has_node) =
            match self.build_config_with_fakeip_override(&opts, suppress_fake_ip) {
                Ok(res) => res,
                Err(e) => {
                    self.emit_vpn(json!({ "state": "error", "error": e }));
                    return;
                }
            };
        let cfg_text = serde_json::to_string_pretty(&cfg_val).unwrap_or_default();
        let _ = write_private_file(&cfg_path, cfg_text.as_bytes());

        #[cfg(target_os = "windows")]
        refresh_cached_windows_phys_ifindex();

        self.emit_vpn(json!({
            "state": "connecting",
            "stage": if opts.proxy_mode || opts.block_only { "core" } else { "tun" }
        }));

        let mut started_in_proc: Option<BoxInstance> = None;
        let mut started_worker: Option<Child> = None;
        let mut started_worker_pid: Option<u32> = None;
        let mut started_macos_helper = false;

        // On Windows/macOS/Linux, opening a TUN adapter (Wintun / utun / /dev/net/tun)
        // requires administrator/root privileges. Note that `core_runtime::inbound::tun::Tun::bind`
        // logs a warning and falls back to `PlatformTun::Passive` instead of returning `Err`
        // when the process is not elevated! Therefore, if `opts.proxy_mode == false` and the
        // current process is not elevated (or TUN fell back to passive after `start()`),
        // we must spawn the elevated worker / helper so TUN actually routes traffic.
        let try_in_proc_first = opts.proxy_mode || opts.block_only || is_current_process_elevated();

        if try_in_proc_first {
            self.emit_vpn(json!({ "state": "connecting", "stage": "core" }));
            match core_runtime::start(&cfg_val).await {
                Ok(mut bx) => {
                    let tun_failed_passively = !opts.proxy_mode
                        && !opts.block_only
                        && detect_passive_tun_error(&cfg_val).is_some();

                    if tun_failed_passively {
                        bx.shutdown_wait().await;
                        self.emit_vpn(json!({ "state": "connecting", "stage": "tun" }));
                        match spawn_elevated_worker(&cfg_path, &self.secret).await {
                            Ok(w) => {
                                started_worker = w.child;
                                started_worker_pid = w.pid;
                                started_macos_helper = w.macos_helper;
                            }
                            Err(elev_err) => {
                                self.emit_vpn(json!({
                                    "state": "error",
                                    "error": format!("Не удалось поднять TUN-интерфейс ({elev_err}). Вы можете переключиться в режим «Системный прокси» или выдать права администратора.")
                                }));
                                return;
                            }
                        }
                    } else {
                        started_in_proc = Some(bx);
                    }
                }
                Err(err) => {
                    let err_str = format!("{err:#}");
                    let need_elevation = !opts.proxy_mode
                        && (err_str.to_ascii_lowercase().contains("permission")
                            || err_str
                                .to_ascii_lowercase()
                                .contains("operation not permitted")
                            || err_str.to_ascii_lowercase().contains("access is denied")
                            || err_str.to_ascii_lowercase().contains("eperm")
                            || err_str.to_ascii_lowercase().contains("eacces")
                            || err_str.to_ascii_lowercase().contains("tun"));

                    if need_elevation {
                        self.emit_vpn(json!({ "state": "connecting", "stage": "tun" }));
                        match spawn_elevated_worker(&cfg_path, &self.secret).await {
                            Ok(w) => {
                                started_worker = w.child;
                                started_worker_pid = w.pid;
                                started_macos_helper = w.macos_helper;
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
        } else {
            self.emit_vpn(json!({ "state": "connecting", "stage": "tun" }));
            match spawn_elevated_worker(&cfg_path, &self.secret).await {
                Ok(w) => {
                    started_worker = w.child;
                    started_worker_pid = w.pid;
                    started_macos_helper = w.macos_helper;
                }
                Err(elev_err) => {
                    self.emit_vpn(json!({
                        "state": "error",
                        "error": format!("Не удалось поднять TUN-интерфейс ({elev_err}). Вы можете переключиться в режим «Системный прокси» или выдать права администратора.")
                    }));
                    return;
                }
            }
        }

        if self.connect_gen.load(Ordering::Acquire) != my_gen {
            let mut aborted = RunningEngine {
                in_proc: started_in_proc,
                worker: started_worker,
                worker_pid: started_worker_pid,
                macos_helper: started_macos_helper,
                running_config: cfg_val,
                proxy_mode: opts.proxy_mode,
                block_only: opts.block_only,
                has_node,
                suppress_fake_ip,
            };
            aborted.stop().await;
            cleanup_orphaned_wintun_routes();
            cleanup_orphaned_macos_routes();
            flush_os_dns();
            return;
        }

        {
            let mut guard = self.engine.lock().await;
            *guard = Some(RunningEngine {
                in_proc: started_in_proc,
                worker: started_worker,
                worker_pid: started_worker_pid,
                macos_helper: started_macos_helper,
                running_config: cfg_val,
                proxy_mode: opts.proxy_mode,
                block_only: opts.block_only,
                has_node,
                suppress_fake_ip,
            });
        }

        if opts.proxy_mode {
            set_system_proxy(true);
        } else if proxy_points_to_us() {
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
        self.connect_gen.fetch_add(1, Ordering::AcqRel);
        self.stop_stats_loop();
        let _life = self.lifecycle_lock.lock().await;
        let mut was_proxy = false;
        {
            let mut guard = self.engine.lock().await;
            if let Some(mut eng) = guard.take() {
                was_proxy = eng.proxy_mode;
                eng.stop().await;
            }
        }
        if was_proxy || proxy_points_to_us() {
            set_system_proxy(false);
        }
        apply_kill_switch(false);
        cleanup_orphaned_wintun_routes();
        cleanup_orphaned_macos_routes();
        flush_os_dns();
        self.emit_vpn(json!({ "state": "off" }));
    }

    fn stop_stats_loop(&self) {
        if let Some(tx) = self
            .stats_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(true);
        }
    }

    fn start_stats_loop(&self, has_node: bool) {
        self.stop_stats_loop();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        *self.stats_cancel.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);

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
                let conn_res = tokio::select! {
                    _ = rx.changed() => break,
                    r = clash_api_request(API_PORT, &secret, "GET", "/connections", None) => r,
                };
                if *rx.borrow() {
                    break;
                }
                if let Ok((200, body)) = conn_res
                    && let Ok(doc) = serde_json::from_str::<Value>(&body)
                {
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

                    let mut msg = json!({
                        "state": "connected",
                        "down": down_rate,
                        "up": up_rate,
                        "totalDown": down_total,
                        "totalUp": up_total
                    });
                    let proxy_res = tokio::select! {
                        _ = rx.changed() => break,
                        r = clash_api_request(API_PORT, &secret, "GET", "/proxies/PROXY", None) => r,
                    };
                    if let Ok((200, pbody)) = proxy_res
                        && let Ok(pdoc) = serde_json::from_str::<Value>(&pbody)
                        && (pdoc.get("type").and_then(Value::as_str) == Some("URLTest")
                            || pdoc.get("telemetry").is_some())
                    {
                        let now_tag = pdoc
                            .get("now")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let mode_str = pdoc
                            .get("mode")
                            .and_then(Value::as_str)
                            .unwrap_or("stability")
                            .to_string();
                        let telemetry = pdoc.get("telemetry").cloned().unwrap_or_else(|| json!({}));
                        let all = pdoc.get("all").cloned().unwrap_or_else(|| json!([]));
                        if let Some(active_rtt) = telemetry
                            .get(&now_tag)
                            .and_then(|t| t.get("rtt_ms"))
                            .and_then(Value::as_u64)
                            .filter(|&ms| ms > 0)
                        {
                            msg["ping"] = json!(active_rtt);
                        }
                        msg["balancer"] = json!({
                            "tag": "PROXY",
                            "now": now_tag,
                            "mode": mode_str,
                            "all": all,
                            "telemetry": telemetry
                        });
                    }
                    if *rx.borrow() {
                        break;
                    }
                    (send_js)(format!("vpn:{msg}"));
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
                    tokio::select! {
                        _ = rx_delay.changed() => break,
                        p = probe_proxy_delay(&secret_delay) => p,
                    }
                } else {
                    tokio::select! {
                        _ = rx_delay.changed() => break,
                        ms = tcp_connect_ms("1.1.1.1", 443, 2500) => if ms > 0 { Some(ms as u64) } else { None },
                    }
                };
                if *rx_delay.borrow() {
                    break;
                }
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

    #[allow(dead_code)]
    pub async fn probe_delay(&self) -> Option<u64> {
        probe_proxy_delay(&self.secret).await
    }

    pub async fn test_https_via_tunnel(&self) -> String {
        if !self.is_running().await {
            return json!({
                "ok": false,
                "error": "Туннель не запущен"
            })
            .to_string();
        }
        let clash_urls = [
            (
                "https://www.gstatic.com/generate_204",
                "https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
            ),
            (
                "https://cp.cloudflare.com/generate_204",
                "https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204",
            ),
        ];
        for (plain, enc) in clash_urls {
            let path = format!("/proxies/PROXY/delay?timeout=5000&url={enc}");
            if let Ok((200, body)) =
                clash_api_request(API_PORT, &self.secret, "GET", &path, None).await
                && let Ok(doc) = serde_json::from_str::<Value>(&body)
                && let Some(d) = doc.get("delay").and_then(Value::as_u64)
                && d > 0
            {
                return json!({
                    "ok": true,
                    "delay_ms": d,
                    "url": plain,
                    "via": "clash"
                })
                .to_string();
            }
        }

        let sw = Instant::now();
        match fetch_url(
            "https://www.gstatic.com/generate_204",
            "GET",
            &[],
            None,
            Some(PROXY_PORT),
            Duration::from_secs(5),
        )
        .await
        {
            Ok(resp) if (200..400).contains(&resp.status) => json!({
                "ok": true,
                "delay_ms": (sw.elapsed().as_millis() as u64).max(1),
                "status": resp.status,
                "url": "https://www.gstatic.com/generate_204",
                "via": "http_proxy"
            })
            .to_string(),
            Ok(resp) => json!({
                "ok": false,
                "error": format!("HTTP {}", resp.status)
            })
            .to_string(),
            Err(e) => json!({
                "ok": false,
                "error": e.to_string()
            })
            .to_string(),
        }
    }

    pub async fn self_repair_network(&self) -> String {
        let mut steps: Vec<Value> = Vec::new();
        self.disconnect().await;

        let mut stale_killed = false;
        if let Some(pid) = read_core_pid_file()
            && is_pid_alive(pid)
        {
            terminate_pid(pid);
            stale_killed = true;
        }
        let _ = fs::remove_file(app_data_dir().join("config.stop"));
        let _ = fs::remove_file(core_pid_path());
        let _ = fs::remove_file(core_err_path());
        steps.push(json!({
            "id": "repair-proc",
            "name": "Очистка фоновых процессов",
            "ok": true,
            "status": "ok",
            "detail": if stale_killed { "Завершён зависший процесс ядра" } else { "Зависшие процессы не обнаружены" }
        }));

        let proxy_cleared = if proxy_points_to_us() {
            set_system_proxy(false);
            true
        } else {
            false
        };
        steps.push(json!({
            "id": "repair-proxy",
            "name": "Системный прокси",
            "ok": true,
            "status": "ok",
            "detail": if proxy_cleared { "Сброшен прокси 127.0.0.1:7897" } else { "Не требовал сброса" }
        }));

        cleanup_orphaned_wintun_routes();
        cleanup_orphaned_macos_routes();
        steps.push(json!({
            "id": "repair-routes",
            "name": "Таблица маршрутов TUN",
            "ok": true,
            "status": "ok",
            "detail": "Осиротевшие маршруты очищены"
        }));

        flush_os_dns();
        steps.push(json!({
            "id": "repair-dns",
            "name": "Кэш DNS системы",
            "ok": true,
            "status": "ok",
            "detail": "Сброс выполнен"
        }));

        #[cfg(target_os = "windows")]
        {
            refresh_cached_windows_phys_ifindex();
            let phys_idx = default_windows_phys_ifindex();
            let ok = phys_idx.is_some();
            steps.push(json!({
                "id": "repair-iface",
                "name": "Физический интерфейс",
                "ok": ok,
                "status": if ok { "ok" } else { "warn" },
                "detail": phys_idx
                    .map(|idx| format!("ifIndex={idx}"))
                    .unwrap_or_else(|| "Не найден маршрут по умолчанию".to_string())
            }));
        }
        #[cfg(target_os = "macos")]
        {
            let phys = detect_macos_phys_interface();
            let (helper_alive, helper_ver) = macos_helper_status();
            let detail = match (&phys, helper_alive) {
                (Some(p), true) => format!(
                    "NIC: {p}, helper: {}",
                    helper_ver.as_deref().unwrap_or("active")
                ),
                (Some(p), false) => format!("NIC: {p}, helper не активен"),
                (None, _) => "Не определён основной интерфейс (route/netstat/scutil)".to_string(),
            };
            steps.push(json!({
                "id": "repair-iface",
                "name": "Физический интерфейс и служба macOS",
                "ok": phys.is_some(),
                "status": if phys.is_some() { "ok" } else { "warn" },
                "detail": detail
            }));
        }
        #[cfg(target_os = "linux")]
        {
            let phys = default_linux_phys_interface();
            steps.push(json!({
                "id": "repair-iface",
                "name": "Физический интерфейс",
                "ok": phys.is_some(),
                "status": if phys.is_some() { "ok" } else { "warn" },
                "detail": phys.unwrap_or_else(|| "Не найден маршрут по умолчанию".to_string())
            }));
        }

        let all_ok = steps
            .iter()
            .all(|s| s.get("ok").and_then(Value::as_bool) == Some(true));
        json!({
            "ok": all_ok,
            "steps": steps
        })
        .to_string()
    }

    pub async fn select_balancer_member(&self, member: &str) -> bool {
        let member = member.trim();
        if member.is_empty() {
            return false;
        }
        let has_in_proc_res = {
            let guard = self.engine.lock().await;
            if let Some(eng) = guard.as_ref() {
                if let Some(bx) = eng.in_proc.as_ref() {
                    let inner = bx.router().inner();
                    let mut found = false;
                    for (_, tag, outbound) in inner.outbound_table() {
                        if tag == "PROXY"
                            && let core_runtime::route::Outbound::Urltest(u) = outbound
                        {
                            found = u.select(member);
                            break;
                        }
                    }
                    Some(found)
                } else {
                    None
                }
            } else {
                return false;
            }
        };
        if let Some(res) = has_in_proc_res {
            return res;
        }
        let body = json!({ "name": member }).to_string();
        matches!(
            clash_api_request(API_PORT, &self.secret, "PUT", "/proxies/PROXY", Some(&body)).await,
            Ok((200..=299, _))
        )
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

    #[allow(dead_code)]
    pub fn get_log_tail(&self, max_lines: usize) -> String {
        self.get_log_tail_filtered(max_lines, "all")
    }

    pub fn get_log_tail_filtered(&self, max_lines: usize, min_level: &str) -> String {
        use std::io::{Read, Seek, SeekFrom};
        const MAX_TAIL_BYTES: u64 = 256 * 1024;
        if let Ok(mut file) = fs::File::open(&self.log_path) {
            let len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if len > 0 {
                if len > MAX_TAIL_BYTES {
                    let _ = file.seek(SeekFrom::Start(len - MAX_TAIL_BYTES));
                }
                let mut buf = Vec::new();
                if file.read_to_end(&mut buf).is_ok() {
                    let text = String::from_utf8_lossy(&buf);
                    let trimmed = if len > MAX_TAIL_BYTES {
                        text.split_once('\n').map(|(_, rest)| rest).unwrap_or(&text)
                    } else {
                        &text
                    };
                    let lines: Vec<&str> = trimmed.lines().collect();
                    if !lines.is_empty() {
                        return filter_log_lines(&lines, max_lines, min_level);
                    }
                }
            }
        }
        let ring = core_runtime::logging::recent(core_runtime::logging::Level::Trace);
        let refs: Vec<&str> = ring.iter().map(String::as_str).collect();
        filter_log_lines(&refs, max_lines, min_level)
    }

    pub fn clear_log_file(&self) {
        let _ = fs::write(&self.log_path, b"");
    }

    pub async fn set_live_log_level(&self, level: &str) -> bool {
        let body = json!({ "log-level": level }).to_string();
        matches!(
            clash_api_request(API_PORT, &self.secret, "PATCH", "/configs", Some(&body)).await,
            Ok((200..=299, _))
        )
    }

    pub async fn import_subscription(&self, input: String) {
        let raw_trimmed = input.trim();
        let (actual_input, custom_handle_opt) = if raw_trimmed.starts_with('{')
            && let Ok(doc) = serde_json::from_str::<Value>(raw_trimmed)
            && let Some(u) = doc.get("url").and_then(Value::as_str)
        {
            let h = doc
                .get("handle")
                .or_else(|| doc.get("name"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            (u.trim().to_string(), h)
        } else {
            (raw_trimmed.to_string(), None)
        };
        let input = actual_input.as_str();
        if input.is_empty() {
            self.emit(format!("sub:{}", json!({ "error": "Пустая ссылка" })));
            return;
        }

        let hwid = HardwareIdentity::detect();
        let resolved = resolve_subscription_input(input, Some(&hwid.hwid), None)
            .unwrap_or_else(|_| input.to_string());
        let resolved = resolved.trim();

        // Single share link, balancer URI, inline node, or offline container/bundle
        if !resolved.starts_with("http://") && !resolved.starts_with("https://") {
            if let Some(bal) = decode_balancer_uri(resolved) {
                let name = if let Some(h) = &custom_handle_opt {
                    h.clone()
                } else if bal.name.trim().is_empty() {
                    "Балансировщик".to_string()
                } else {
                    bal.name.clone()
                };
                let payload = json!({
                    "handle": name,
                    "url": input,
                    "user": { "handle": name },
                    "servers": [{
                        "id": "custom-bal-1",
                        "name": name,
                        "vless": resolved,
                        "country": detect_country_code(&name),
                        "isBalancer": true,
                        "balancerMode": bal.mode,
                        "memberCount": bal.members.len()
                    }]
                });
                self.emit(format!("sub:{payload}"));
                return;
            }
            if let Some(val) = decode_inline_node_uri(resolved) {
                let raw_tag = custom_handle_opt
                    .as_deref()
                    .or_else(|| {
                        val.get("tag")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                    })
                    .unwrap_or("Сервер");
                let country = detect_country_code(raw_tag);
                let tag = crate::state::clean_node_display_name(raw_tag);
                let payload = json!({
                    "handle": tag,
                    "url": input,
                    "user": { "handle": tag },
                    "servers": [{
                        "id": "custom-1",
                        "name": tag,
                        "vless": resolved,
                        "country": country
                    }]
                });
                self.emit(format!("sub:{payload}"));
                return;
            }
            if let Ok(nodes) =
                parse_subscription_payload_with_hwid(resolved, Some(&hwid.hwid), None)
            {
                let real_nodes: Vec<Value> = nodes
                    .into_iter()
                    .filter(|n| !is_stub_or_dummy_outbound(n))
                    .collect();
                let is_container = input.starts_with("happ://")
                    || input.starts_with("v2raytun://")
                    || input.starts_with("incy://")
                    || input.starts_with("fptn:")
                    || input.starts_with("fptnb:");
                if real_nodes.len() >= 2 || (is_container && !real_nodes.is_empty()) {
                    let meta = extract_subscription_metadata(resolved, None, None);
                    let handle = custom_handle_opt
                        .clone()
                        .or(meta.profile_title.filter(|s| !s.is_empty()))
                        .unwrap_or_else(|| "Подписка".to_string());
                    let servers = build_subscription_servers_list(&real_nodes, &handle);
                    if !servers.is_empty() {
                        let result = json!({
                            "handle": handle,
                            "url": input,
                            "user": { "handle": handle },
                            "subscription": {
                                "status": "active",
                                "trafficUsed": 0,
                                "trafficTotal": 0
                            },
                            "servers": servers
                        });
                        self.emit(format!("sub:{result}"));
                        return;
                    }
                } else if real_nodes.len() == 1 {
                    let node = &real_nodes[0];
                    let raw_tag = custom_handle_opt
                        .as_deref()
                        .or_else(|| {
                            node.get("tag")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                        })
                        .unwrap_or("Сервер");
                    let country = detect_country_code(raw_tag);
                    let tag = crate::state::clean_node_display_name(raw_tag);
                    let uri = node_to_share_link(node).unwrap_or_else(|| resolved.to_string());
                    let payload = json!({
                        "handle": tag,
                        "url": input,
                        "user": { "handle": tag },
                        "servers": [{
                            "id": "custom-1",
                            "name": tag,
                            "vless": uri,
                            "country": country
                        }]
                    });
                    self.emit(format!("sub:{payload}"));
                    return;
                }
            }
            match parse_share_uri(resolved) {
                Ok(val) => {
                    let raw_tag = custom_handle_opt
                        .as_deref()
                        .or_else(|| {
                            val.get("tag")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                        })
                        .unwrap_or("Сервер");
                    let country = detect_country_code(raw_tag);
                    let tag = crate::state::clean_node_display_name(raw_tag);
                    let payload = json!({
                        "handle": tag,
                        "url": input,
                        "user": { "handle": tag },
                        "servers": [{
                            "id": "custom-1",
                            "name": tag,
                            "vless": resolved,
                            "country": country
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

        // Remote subscription URL: delegate to tachyon-core 0.4.0 adaptive fetcher
        // (UA cascade, X-HWID headers, Encrypt-Tag AES-GCM decryption, WireGuard peer synthesis)
        let proxy_url = if self.is_running().await {
            Some(format!("socks5://127.0.0.1:{PROXY_PORT}"))
        } else {
            None
        };

        let fetched_res = if let Some(ref px) = proxy_url {
            match fetch_url_standalone_with_options(
                input,
                None,
                true,
                Some(&hwid.hwid),
                false,
                Some(px.as_str()),
                &[],
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(_) => {
                    fetch_url_standalone_with_options(
                        input,
                        None,
                        true,
                        Some(&hwid.hwid),
                        false,
                        None,
                        &[],
                    )
                    .await
                }
            }
        } else {
            fetch_url_standalone_with_options(input, None, true, Some(&hwid.hwid), false, None, &[])
                .await
        };

        let fetched = match fetched_res {
            Ok(f) => f,
            Err(e) => {
                self.emit(format!("sub:{}", json!({ "error": e })));
                return;
            }
        };

        let meta = fetched.metadata;
        let handle = custom_handle_opt
            .or(meta.profile_title)
            .or(meta.file_name)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Подписка".to_string());

        let servers = build_subscription_servers_list(&fetched.nodes, &handle);

        if servers.is_empty() {
            self.emit(format!(
                "sub:{}",
                json!({ "error": "В ответе нет поддерживаемых узлов" })
            ));
            return;
        }
        let (traffic_used, traffic_total, expire_unix) = if let Some(ui) = fetched.user_info {
            (
                ui.upload.saturating_add(ui.download),
                ui.total,
                if ui.expire > 0 { Some(ui.expire) } else { None },
            )
        } else {
            let mut u = 0u64;
            let mut t = 0u64;
            let mut ex = None;
            if let Some(ref ui_raw) = meta.user_info_raw {
                for part in ui_raw.split(';') {
                    if let Some((k, v)) = part.trim().split_once('=')
                        && let Ok(num) = v.trim().parse::<u64>()
                    {
                        match k.trim() {
                            "upload" | "download" => u = u.saturating_add(num),
                            "total" => t = num,
                            "expire" if num > 0 => ex = Some(num),
                            _ => {}
                        }
                    }
                }
            }
            (u, t, ex)
        };

        let result = json!({
            "handle": handle,
            "url": input,
            "user": { "handle": handle },
            "meta": {
                "title": handle,
                "usedBytes": traffic_used,
                "totalBytes": traffic_total,
                "expireUnix": expire_unix,
                "supportUrl": meta.support_url,
                "webPageUrl": meta.web_page_url,
                "announce": meta.announce
            },
            "subscription": {
                "status": "active",
                "trafficUsed": traffic_used,
                "trafficTotal": traffic_total,
                "expireUnix": expire_unix
            },
            "servers": servers
        });
        self.emit(format!("sub:{result}"));
    }

    pub async fn provision_warp_awg(&self) -> String {
        if self.is_running().await
            && let Ok((200, body)) = clash_api_request(
                API_PORT,
                &self.secret,
                "POST",
                "/tachyon/warp/register",
                Some(r#"{"tag":"Cloudflare WARP"}"#),
            )
            .await
            && let Ok(doc) = serde_json::from_str::<Value>(&body)
            && let Some(acct) = doc.get("account")
        {
            let priv_b64 = acct
                .get("private_key")
                .and_then(Value::as_str)
                .unwrap_or("");
            let peer_pub = acct
                .get("peer_public_key")
                .and_then(Value::as_str)
                .unwrap_or("");
            let inet4 = acct
                .get("inet4")
                .and_then(Value::as_str)
                .unwrap_or("172.16.0.2/32");
            let endpoint = acct
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or("162.159.192.1:2408");
            let reserved_param = acct
                .get("reserved")
                .and_then(Value::as_array)
                .filter(|a| a.len() >= 3)
                .map(|a| {
                    format!(
                        "&reserved={},{},{}",
                        a[0].as_u64().unwrap_or(0),
                        a[1].as_u64().unwrap_or(0),
                        a[2].as_u64().unwrap_or(0),
                    )
                })
                .unwrap_or_default();
            if !priv_b64.is_empty() && !peer_pub.is_empty() {
                let awg_uri = format!(
                    "awg://{}@{}?publickey={}&address={}{}&mtu=1280&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#Cloudflare%20WARP%20(AmneziaWG)",
                    core_config::subscription::percent_encode_component(priv_b64),
                    endpoint,
                    core_config::subscription::percent_encode_component(peer_pub),
                    core_config::subscription::percent_encode_component(inet4),
                    reserved_param,
                );
                let masque_uri = doc
                    .get("masque_outbound")
                    .cloned()
                    .map(|mut ob| {
                        if let Some(m) = ob.as_object_mut() {
                            m.insert("tag".to_string(), json!("Cloudflare WARP (MASQUE)"));
                        }
                        encode_inline_node_uri(&ob)
                    })
                    .unwrap_or_default();
                return json!({
                    "ok": true,
                    "uri": awg_uri,
                    "masque_uri": masque_uri,
                    "name": "Cloudflare WARP (AmneziaWG)",
                    "ip": inet4
                })
                .to_string();
            }
        }

        let mut priv_bytes = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut priv_bytes) {
            return json!({ "ok": false, "error": format!("Ошибка ГПСЧ: {e}") }).to_string();
        }
        let secret = x25519_dalek::StaticSecret::from(priv_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);

        let priv_b64 = B64.encode(secret.to_bytes());
        let pub_b64 = B64.encode(public.as_bytes());
        let mut serial_bytes = [0u8; 6];
        let _ = getrandom::fill(&mut serial_bytes);
        let serial_number: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();

        let body_json = json!({
            "key": pub_b64,
            "install_id": "",
            "fcm_token": "",
            "tos": "2025-01-01T00:00:00.000Z",
            "model": "PC",
            "serial_number": serial_number,
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

        let peer_endpoint = cfg
            .pointer("/peers/0/endpoint/v4")
            .and_then(Value::as_str)
            .or_else(|| {
                cfg.pointer("/peers/0/endpoint/host")
                    .and_then(Value::as_str)
            })
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let st = s.trim();
                if let Some((h, p)) = st.rsplit_once(':') {
                    let port_num = p.trim().parse::<u16>().unwrap_or(0);
                    if port_num == 0 {
                        format!("{}:2408", h.trim())
                    } else {
                        st.to_string()
                    }
                } else {
                    format!("{st}:2408")
                }
            })
            .unwrap_or_else(|| "188.114.96.1:2408".to_string());

        let reserved_param = cfg
            .get("client_id")
            .and_then(Value::as_str)
            .and_then(|cid| B64.decode(cid.trim()).ok())
            .filter(|b| b.len() >= 3)
            .map(|b| format!("&reserved={},{},{}", b[0], b[1], b[2]))
            .unwrap_or_default();

        let awg_uri = format!(
            "awg://{}@{}?publickey={}&address={}{}&mtu=1280&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#Cloudflare%20WARP%20(AmneziaWG)",
            core_config::subscription::percent_encode_component(&priv_b64),
            peer_endpoint,
            core_config::subscription::percent_encode_component(peer_pub),
            core_config::subscription::percent_encode_component(&client_ip),
            reserved_param,
        );

        json!({
            "ok": true,
            "uri": awg_uri,
            "name": "Cloudflare WARP (AmneziaWG)",
            "ip": client_ip
        })
        .to_string()
    }

    async fn clash_json(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<String, String> {
        if !self.is_running().await {
            return Err("Подключите туннель для обращения к API ядра".to_string());
        }
        let body_str = body.map(|v| v.to_string());
        let (status, resp) =
            clash_api_request(API_PORT, &self.secret, method, path, body_str.as_deref())
                .await
                .map_err(|e| format!("API error: {e}"))?;
        if (200..300).contains(&status) {
            Ok(resp)
        } else {
            let msg = serde_json::from_str::<Value>(&resp)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| format!("HTTP {status}"));
            Err(msg)
        }
    }

    /// Проверяет маршрут и опционально выполняет живую пробу через `/tachyon/route-check`.
    pub async fn route_check(&self, target: &str, probe: bool) -> Result<String, String> {
        let tgt = target.trim();
        if tgt.is_empty() {
            return Err("Укажите домен, URL или IP".to_string());
        }
        self.clash_json(
            "POST",
            "/tachyon/route-check",
            Some(json!({ "target": tgt, "probe": probe })),
        )
        .await
    }

    /// Проверяет состояние DNS-резолвера ядра и UDP/53 через `/tachyon/dns-check`.
    pub async fn dns_check(&self, domain: &str) -> Result<String, String> {
        let host = if domain.trim().is_empty() {
            "example.com"
        } else {
            domain.trim()
        };
        self.clash_json(
            "POST",
            "/tachyon/dns-check",
            Some(json!({ "domain": host })),
        )
        .await
    }

    /// Запрашивает аудит маршрутов IPv4/IPv6/WebRTC/DNS через `/tachyon/leak`.
    pub async fn leak_audit(&self) -> Result<String, String> {
        self.clash_json("GET", "/tachyon/leak", None).await
    }

    /// Возвращает телеметрию памяти ядра через `/tachyon/memory`.
    pub async fn memory_stats(&self) -> Result<String, String> {
        self.clash_json("GET", "/tachyon/memory", None).await
    }

    /// Освобождает кэши ядра при повышенной нагрузке через `/tachyon/memory/trim`.
    pub async fn memory_trim(&self) -> Result<String, String> {
        self.clash_json("POST", "/tachyon/memory/trim", Some(json!({})))
            .await
    }

    /// Читает недавние записи журнала соединений из `/tachyon/flight`.
    pub async fn get_flight_recorder(&self) -> Result<String, String> {
        self.clash_json("GET", "/tachyon/flight", None).await
    }

    /// Очищает буфер журнала соединений через `DELETE /tachyon/flight`.
    pub async fn clear_flight_recorder(&self) -> Result<String, String> {
        self.clash_json("DELETE", "/tachyon/flight", None).await
    }

    /// Строит `DesyncConfig` из текущих UI-настроек для активных проб.
    pub fn build_desync_config_for_probe(
        d: &DesyncOptions,
    ) -> core_runtime::outbound::desync::DesyncConfig {
        let val = Self::build_desync_outbound("DESYNC", d);
        if let Some(obj) = val.as_object()
            && let Ok(cfg) = core_runtime::outbound::desync::DesyncConfig::from_json(obj)
        {
            return cfg;
        }
        core_runtime::outbound::desync::DesyncConfig::default()
    }

    async fn resolve_probe_target(raw: &str) -> Result<(String, SocketAddr), String> {
        let cleaned = raw
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim();
        let host = if cleaned.is_empty() {
            "www.youtube.com".to_string()
        } else if let Some((h, _)) = cleaned.rsplit_once(':')
            && !cleaned.starts_with('[')
        {
            h.trim().to_string()
        } else {
            cleaned.trim_matches(&['[', ']'][..]).to_string()
        };
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 443u16))
            .await
            .map_err(|e| format!("DNS error: {e}"))?
            .collect();
        let chosen = addrs
            .iter()
            .find(|sa| sa.is_ipv4() && !is_fake_or_tun_ip(sa.ip()))
            .or_else(|| addrs.iter().find(|sa| !is_fake_or_tun_ip(sa.ip())))
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| "Не удалось определить IP-адрес цели".to_string())?;
        Ok((host, chosen))
    }

    /// Выполняет потоковую HTTPS-пробу текущей конфигурации фрагментации/десинхронизации.
    pub async fn run_desync_probe(
        &self,
        domain: &str,
        d: &DesyncOptions,
    ) -> Result<String, String> {
        let (host, addr) = Self::resolve_probe_target(domain).await?;
        let cfg = Self::build_desync_config_for_probe(d);
        let outcome = core_runtime::outbound::desync::probe_desync_https_stream(
            addr,
            &host,
            None,
            &cfg,
            Duration::from_secs(6),
        )
        .await;
        Ok(json!({
            "host": host,
            "ip": addr.ip().to_string(),
            "ok": outcome.ok,
            "verified_32k": outcome.verified_32k,
            "status": format!("{:?}", outcome.status),
            "block_reason": outcome.block_reason,
            "detail": outcome.detail,
            "rtt_ms": outcome.rtt_ms,
            "rx_wire_bytes": outcome.rx_wire_bytes,
            "rx_app_bytes": outcome.rx_app_bytes,
        })
        .to_string())
    }

    /// Калибрует оптимальный TTL на маршруте до узла через `calibrate_ttl_hops`.
    pub async fn run_desync_ttl_calibration(
        &self,
        domain: &str,
        d: &DesyncOptions,
    ) -> Result<String, String> {
        let (host, addr) = Self::resolve_probe_target(domain).await?;
        let cfg = Self::build_desync_config_for_probe(d);
        let report = core_runtime::outbound::desync::calibrate_ttl_hops(
            addr,
            &host,
            &cfg,
            Duration::from_secs(4),
        )
        .await;
        Ok(json!({
            "domain": report.domain,
            "resolved_ip": report.resolved_ip,
            "optimal_ttl": report.optimal_ttl,
            "min_working_ttl": report.min_working_ttl,
            "max_working_ttl": report.max_working_ttl,
            "summary": report.summary,
        })
        .to_string())
    }

    pub async fn check_exit_node_info(&self) -> String {
        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let no_cache = &[("Cache-Control", "no-cache")];
        let sw = Instant::now();
        if let Ok(resp) = fetch_url(
            "https://ipinfo.io/json",
            "GET",
            no_cache,
            None,
            proxy,
            Duration::from_secs(5),
        )
        .await
            && let Ok(doc) = serde_json::from_slice::<Value>(&resp.body)
            && let Some(ip) = doc.get("ip").and_then(Value::as_str)
        {
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
                "latencyMs": sw.elapsed().as_millis() as u64
            })
            .to_string();
        }

        let sw2 = Instant::now();
        if let Ok(resp) = fetch_url(
            "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,query&lang=ru",
            "GET",
            no_cache,
            None,
            proxy,
            Duration::from_secs(5),
        )
        .await
            && let Ok(doc) = serde_json::from_slice::<Value>(&resp.body)
            && doc.get("status").and_then(Value::as_str) == Some("success")
        {
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
                "latencyMs": sw2.elapsed().as_millis() as u64
            })
            .to_string();
        }

        let sw3 = Instant::now();
        if let Ok(resp) = fetch_url(
            "https://api.ipify.org?format=json",
            "GET",
            no_cache,
            None,
            proxy,
            Duration::from_secs(5),
        )
        .await
            && let Ok(doc) = serde_json::from_slice::<Value>(&resp.body)
            && let Some(ip) = doc.get("ip").and_then(Value::as_str)
        {
            return json!({
                "ok": true,
                "ip": ip,
                "country": "",
                "countryCode": "",
                "city": "",
                "isp": "",
                "latencyMs": sw3.elapsed().as_millis() as u64
            })
            .to_string();
        }

        json!({ "ok": false, "error": "Нет ответа от гео-сервисов" }).to_string()
    }

    pub async fn run_dns_benchmark(&self) -> String {
        let targets = [
            (
                "yandex",
                "Яндекс DNS (77.88.8.8)",
                "77.88.8.8",
                53u16,
                "UDP/TCP 53",
            ),
            (
                "cloudflare",
                "Cloudflare (1.1.1.1)",
                "1.1.1.1",
                443u16,
                "DoH / HTTPS",
            ),
            (
                "google",
                "Google (8.8.8.8)",
                "8.8.8.8",
                443u16,
                "DoH / HTTPS",
            ),
            ("quad9", "Quad9 (9.9.9.9)", "9.9.9.9", 443u16, "DoH / HTTPS"),
            (
                "adguard",
                "AdGuard (94.140.14.14)",
                "94.140.14.14",
                443u16,
                "DoH / HTTPS",
            ),
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
            (
                "direct_ru",
                "Рунет (Яндекс)",
                "Проверка базового прямого канала",
                "https://ya.ru",
            ),
            (
                "cloudflare",
                "Cloudflare Edge",
                "Зарубежный CDN и DoH-инфраструктура",
                "https://cp.cloudflare.com/generate_204",
            ),
            (
                "youtube",
                "YouTube Web & Video",
                "Доступность видеоплатформы и манифестов",
                "https://www.youtube.com/generate_204",
            ),
            (
                "discord",
                "Discord API & Gateway",
                "Голосовой и текстовый шлюз Discord",
                "https://discord.com/api/v9/experiments",
            ),
            (
                "telegram",
                "Telegram Web",
                "Веб-шлюз и медиасерверы Telegram",
                "https://web.telegram.org/",
            ),
        ];
        let proxy = if self.is_running().await {
            Some(PROXY_PORT)
        } else {
            None
        };
        let mut items = Vec::new();
        for (id, title, subtitle, url) in probes {
            let sw = Instant::now();
            let probe_proxy = if id == "direct_ru" { None } else { proxy };
            match fetch_url(url, "GET", &[], None, probe_proxy, Duration::from_secs(5)).await {
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
        if let Some(tx) = self
            .speedtest_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(true);
        }
    }

    pub async fn run_speedtest(&self, size_mb: u32, provider: &str) -> String {
        self.cancel_speedtest();
        let (tx, rx) = tokio::sync::watch::channel(false);
        *self
            .speedtest_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);

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
        let ver = option_env!("TACHYON_CORE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
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

    pub async fn check_github_update(&self, silent: bool) {
        let current = env!("CARGO_PKG_VERSION")
            .trim_start_matches('v')
            .to_string();
        let core_ver = option_env!("TACHYON_CORE_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .trim_start_matches('v')
            .to_string();
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
                    "coreVersion": core_ver,
                    "latest": rel.version,
                    "size": rel.asset_size,
                    "asset": rel.asset_name,
                    "url": rel.html_url,
                    "hasUpdate": has_update,
                    "silent": silent
                });
                if has_update {
                    self.emit(format!("core-update:available:{payload}"));
                } else if !silent {
                    self.emit(format!("core-update:up-to-date:{payload}"));
                }
            }
            Err(e) => {
                if !silent {
                    self.emit(format!("core-update:error:{e}"));
                }
            }
        }
    }

    pub async fn install_github_update(&self) {
        let current = env!("CARGO_PKG_VERSION")
            .trim_start_matches('v')
            .to_string();
        let core_ver = option_env!("TACHYON_CORE_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .trim_start_matches('v')
            .to_string();
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

        if !is_newer_semver(&rel.version, &current) {
            let payload = json!({ "version": current, "coreVersion": core_ver, "upToDate": true });
            self.emit(format!("core-update:up-to-date:{payload}"));
            return;
        }

        if rel.download_url.is_empty() {
            self.emit("core-update:error:В релизе GitHub не найден бинарный файл для вашей ОС");
            return;
        }

        let Some(ref sums_url) = rel.sha256_url else {
            self.emit("core-update:error:В релизе GitHub отсутствует файл контрольных сумм SHA256SUMS.txt");
            return;
        };

        let target_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                self.emit(format!("core-update:error:Не удалось определить путь: {e}"));
                return;
            }
        };

        self.emit("core-update:progress:15");
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

        let expected_size = rel.asset_size as usize;
        let send_prog = self.send_js.clone();
        let report_dl = move |got: usize, total_opt: Option<usize>| {
            let total = total_opt.unwrap_or(expected_size);
            if let Some(scaled) = got.saturating_mul(70).checked_div(total) {
                let pct = 15 + scaled.min(70);
                (send_prog)(format!("core-update:progress:{pct}"));
            }
        };

        let dl_res = match fetch_url_with_progress(
            &rel.download_url,
            "GET",
            &headers,
            None,
            pport,
            Duration::from_secs(180),
            &report_dl,
        )
        .await
        {
            Ok(r) if (200..300).contains(&r.status) => Ok(r.body),
            Ok(_) | Err(_) if pport.is_some() => fetch_url_with_progress(
                &rel.download_url,
                "GET",
                &headers,
                None,
                None,
                Duration::from_secs(180),
                &report_dl,
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

        self.emit("core-update:progress:88");
        let sums_res = match fetch_url(
            sums_url,
            "GET",
            &headers,
            None,
            pport,
            Duration::from_secs(15),
        )
        .await
        {
            Ok(r) if (200..300).contains(&r.status) => Ok(r),
            Ok(_) | Err(_) if pport.is_some() => {
                fetch_url(
                    sums_url,
                    "GET",
                    &headers,
                    None,
                    None,
                    Duration::from_secs(15),
                )
                .await
            }
            other => other,
        };
        let sums_resp = match sums_res {
            Ok(r) if (200..300).contains(&r.status) => r,
            Ok(r) => {
                self.emit(format!(
                    "core-update:error:Не удалось загрузить SHA256SUMS.txt (HTTP {})",
                    r.status
                ));
                return;
            }
            Err(e) => {
                self.emit(format!(
                    "core-update:error:Не удалось загрузить SHA256SUMS.txt: {e}"
                ));
                return;
            }
        };
        let sums_text = String::from_utf8_lossy(&sums_resp.body);
        if let Err(err_msg) = verify_asset_sha256(&bytes, &rel.asset_name, &sums_text) {
            self.emit(format!("core-update:error:{err_msg}"));
            return;
        }

        self.emit("core-update:progress:92");
        self.disconnect().await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        match apply_self_binary_update(&target_exe, &bytes, &rel.asset_name) {
            Ok(replaced_in_place) => {
                self.emit("core-update:progress:100");
                let payload = json!({
                    "version": rel.version,
                    "coreVersion": rel.version,
                    "restarting": replaced_in_place
                });
                self.emit(format!("core-update:done:{payload}"));
                if replaced_in_place {
                    tokio::time::sleep(Duration::from_millis(750)).await;
                    schedule_relaunch_and_exit(&target_exe);
                }
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
    sha256_url: Option<String>,
}

fn verify_asset_sha256(bytes: &[u8], asset_name: &str, sums_text: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let target_name = Path::new(asset_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if target_name.is_empty() {
        return Err("Не указано имя файла обновления для проверки SHA-256".to_string());
    }
    for line in sums_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(expected_hex) = parts.next() else {
            continue;
        };
        let Some(raw_file) = parts.next() else {
            continue;
        };
        let clean_file = raw_file.trim_start_matches('*').trim_start_matches("./");
        if clean_file.eq_ignore_ascii_case(target_name) {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let actual_hex = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if actual_hex.eq_ignore_ascii_case(expected_hex) {
                return Ok(());
            } else {
                return Err(format!(
                    "Ошибка проверки SHA-256 для {target_name} (ожидался {expected_hex}, получен {actual_hex})"
                ));
            }
        }
    }
    Err(format!(
        "В SHA256SUMS.txt не найдена контрольная сумма для {target_name}"
    ))
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
    let endpoints = ["https://api.github.com/repos/Dushnilin/tachyon-desktop/releases/latest"];

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
            Ok(_) | Err(_) if proxy_port.is_some() => {
                fetch_url(
                    api_url,
                    "GET",
                    &headers,
                    None,
                    None,
                    Duration::from_secs(12),
                )
                .await
            }
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
        let mut sha256_url = None;

        if let Some(assets) = doc.get("assets").and_then(Value::as_array) {
            for asset in assets {
                let name = asset.get("name").and_then(Value::as_str).unwrap_or("");
                let dl = asset
                    .get("browser_download_url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let size = asset.get("size").and_then(Value::as_u64).unwrap_or(0);
                if name.eq_ignore_ascii_case("SHA256SUMS.txt") && !dl.is_empty() {
                    sha256_url = Some(dl.to_string());
                }
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
            sha256_url,
        });
    }

    Err(last_err)
}

#[cfg(target_os = "windows")]
fn is_windows_msi_install() -> bool {
    if let Ok(exe) = std::env::current_exe() {
        let low = exe.to_string_lossy().to_ascii_lowercase();
        if low.contains(r"\program files\") || low.contains(r"\program files (x86)\") {
            return true;
        }
    }
    false
}

fn score_release_asset_for_current_os(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".sha256") || lower.ends_with(".txt") || lower.ends_with(".sig") {
        return 0;
    }

    let arch_bonus = if cfg!(target_arch = "aarch64") {
        if lower.contains("arm64") || lower.contains("aarch64") {
            20
        } else if lower.contains("x86_64") || lower.contains("amd64") || lower.contains("x64") {
            -40
        } else {
            0
        }
    } else if cfg!(target_arch = "x86_64") {
        if lower.contains("x86_64") || lower.contains("amd64") || lower.contains("x64") {
            20
        } else if lower.contains("arm64") || lower.contains("aarch64") {
            -40
        } else {
            0
        }
    } else {
        0
    };

    #[cfg(target_os = "windows")]
    {
        if lower.contains("darwin") || lower.contains("macos") || lower.contains("linux") {
            return 0;
        }
        let msi_preferred = is_windows_msi_install();
        if lower.ends_with(".msi")
            && (lower.contains("tachyon")
                || lower.contains("windows")
                || lower.contains("x86_64")
                || lower.contains("x64"))
        {
            return (if msi_preferred { 120 } else { 75 }) + arch_bonus;
        }
        if lower.contains("windows")
            || lower.contains("win64")
            || lower.contains("win-")
            || lower.ends_with("-win.exe")
            || lower.contains("setup")
            || lower.contains("install")
        {
            if lower.ends_with(".exe") {
                if lower.contains("setup") || lower.contains("install") {
                    return 70 + arch_bonus;
                }
                return 100 + arch_bonus;
            }
            if lower.ends_with(".zip") {
                return 60 + arch_bonus;
            }
        }
        if lower == "tachyon.exe" || lower == "tachyon-desktop.exe" {
            return 90 + arch_bonus;
        }
        0
    }

    #[cfg(target_os = "linux")]
    {
        if lower.contains("windows") || lower.contains("darwin") || lower.contains("macos") {
            return 0;
        }
        if lower.contains("linux") {
            if !lower.ends_with(".deb")
                && !lower.ends_with(".tar.gz")
                && !lower.ends_with(".rpm")
                && !lower.ends_with(".zip")
            {
                return (100 + arch_bonus).max(1);
            }
            if lower.ends_with(".deb") {
                return (80 + arch_bonus).max(1);
            }
            if lower.ends_with(".tar.gz") {
                return (70 + arch_bonus).max(1);
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    {
        if lower.contains("windows") || lower.contains("linux") {
            return 0;
        }
        let univ_bonus = if lower.contains("universal") {
            15
        } else {
            arch_bonus
        };
        if lower.contains("macos") || lower.contains("darwin") || lower.contains("mac") {
            if !lower.ends_with(".dmg") && !lower.ends_with(".tar.gz") && !lower.ends_with(".zip") {
                return (100 + univ_bonus).max(1);
            }
            if lower.ends_with(".dmg") {
                return (85 + univ_bonus).max(1);
            }
            if lower.ends_with(".tar.gz") {
                return (75 + univ_bonus).max(1);
            }
        }
        0
    }
}

fn apply_self_binary_update(
    exe_path: &Path,
    bytes: &[u8],
    asset_name: &str,
) -> Result<bool, String> {
    let clean_name = Path::new(asset_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let lower = clean_name.to_ascii_lowercase();
    let _ = &lower;

    #[cfg(target_os = "windows")]
    {
        if lower.ends_with(".exe") && bytes.starts_with(b"MZ") {
            let old_path = PathBuf::from(format!("{}.old", exe_path.display()));
            let tmp_path = PathBuf::from(format!("{}.new", exe_path.display()));
            let _ = fs::remove_file(&old_path);
            let _ = fs::remove_file(&tmp_path);
            if fs::write(&tmp_path, bytes).is_ok() && fs::rename(exe_path, &old_path).is_ok() {
                if fs::rename(&tmp_path, exe_path).is_ok() {
                    return Ok(true);
                }
                let _ = fs::rename(&old_path, exe_path);
            }
            let _ = fs::remove_file(&tmp_path);

            let staged = app_data_dir().join("tachyon.update.exe");
            fs::write(&staged, bytes)
                .map_err(|e| format!("Не удалось записать обновление во временный каталог: {e}"))?;
            use std::os::windows::process::CommandExt;
            let exe_q = exe_path.to_string_lossy().replace('\'', "''");
            let old_q = old_path.to_string_lossy().replace('\'', "''");
            let staged_q = staged.to_string_lossy().replace('\'', "''");
            let inner_cmd = format!(
                "$ErrorActionPreference='Stop'; \
                try {{ \
                    Move-Item -LiteralPath '{exe_q}' -Destination '{old_q}' -Force; \
                    Move-Item -LiteralPath '{staged_q}' -Destination '{exe_q}' -Force \
                }} catch {{ \
                    if (-not (Test-Path -LiteralPath '{exe_q}') -and (Test-Path -LiteralPath '{old_q}')) {{ \
                        Move-Item -LiteralPath '{old_q}' -Destination '{exe_q}' -Force \
                    }}; \
                    exit 1 \
                }}"
            );
            let utf16: Vec<u8> = inner_cmd
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let encoded = B64.encode(utf16);
            let outer_ps = format!(
                "$p = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-WindowStyle','Hidden','-EncodedCommand','{encoded}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode"
            );
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    &outer_ps,
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|e| format!("Ошибка запроса прав администратора для обновления: {e}"))?;
            let _ = fs::remove_file(&staged);
            if status.success() && exe_path.exists() {
                return Ok(true);
            }
            return Err(
                "Не удалось заменить исполняемый файл (отказ UAC или файл заблокирован)"
                    .to_string(),
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        if bytes.starts_with(b"\x7fELF") {
            use std::os::unix::fs::PermissionsExt;
            let tmp_path = PathBuf::from(format!("{}.new", exe_path.display()));
            if fs::write(&tmp_path, bytes).is_ok() {
                let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755));
                if fs::rename(&tmp_path, exe_path).is_ok() {
                    return Ok(true);
                }
                let _ = fs::remove_file(&tmp_path);
            }
            let staged = app_data_dir().join("tachyon.update.bin");
            fs::write(&staged, bytes)
                .map_err(|e| format!("Не удалось сохранить обновление: {e}"))?;
            let _ = fs::set_permissions(&staged, fs::Permissions::from_mode(0o755));
            let staged_q = staged.to_string_lossy().replace('\'', "'\\''");
            let exe_q = exe_path.to_string_lossy().replace('\'', "'\\''");
            let sh_cmd = format!(
                "install -m 755 '{staged_q}' '{exe_q}' && (command -v setcap >/dev/null 2>&1 && setcap cap_net_admin,cap_net_raw+eip '{exe_q}' || true)"
            );
            let status = Command::new("pkexec")
                .args(["sh", "-c", &sh_cmd])
                .status()
                .map_err(|e| format!("Ошибка pkexec при обновлении: {e}"))?;
            let _ = fs::remove_file(&staged);
            if status.success() {
                return Ok(true);
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
            let tmp_path = PathBuf::from(format!("{}.new", exe_path.display()));
            fs::write(&tmp_path, bytes)
                .map_err(|e| format!("Не удалось записать обновление: {e}"))?;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755));
            fs::rename(&tmp_path, exe_path)
                .map_err(|e| format!("Не удалось обновить Tachyon.app: {e}"))?;
            let sign_target = exe_path
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("app"))
                .unwrap_or(exe_path);
            let sign_status = Command::new("/usr/bin/codesign")
                .args(["--force", "--deep", "--sign", "-"])
                .arg(sign_target)
                .status();
            if !matches!(sign_status, Ok(s) if s.success()) {
                return Err("Не удалось подписать обновлённое приложение (codesign)".to_string());
            }
            return Ok(true);
        }
    }

    let updates_dir = app_data_dir().join("updates");
    let _ = fs::create_dir_all(&updates_dir);
    let safe_name = if clean_name.is_empty() {
        "tachyon-update.bin"
    } else {
        clean_name
    };
    let dest = updates_dir.join(safe_name);
    fs::write(&dest, bytes).map_err(|e| format!("Не удалось сохранить пакет обновления: {e}"))?;
    #[cfg(target_os = "windows")]
    if lower.ends_with(".msi") {
        let _ = Command::new("msiexec")
            .arg("/i")
            .arg(&dest)
            .arg("/passive")
            .spawn();
    }
    #[cfg(target_os = "macos")]
    if lower.ends_with(".dmg") {
        let _ = Command::new("/usr/bin/open").arg(&dest).spawn();
    }
    Ok(false)
}

fn schedule_relaunch_and_exit(target_exe: &Path) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let escaped_ps = target_exe.to_string_lossy().replace('\'', "''");
        let ps_cmd =
            format!("Start-Sleep -Milliseconds 900; Start-Process -FilePath '{escaped_ps}'");
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let escaped = target_exe.to_string_lossy().replace('\'', "'\\''");
        let _ = Command::new("sh")
            .args(["-c", &format!("sleep 1 && exec '{escaped}'")])
            .spawn();
    }

    std::process::exit(0);
}

async fn probe_proxy_delay(secret: &str) -> Option<u64> {
    let urls = [
        "https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
        "https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204",
        "http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
    ];
    for u in urls {
        let path = format!("/proxies/PROXY/delay?timeout=5000&url={u}");
        if let Ok((200, body)) = clash_api_request(API_PORT, secret, "GET", &path, None).await
            && let Ok(doc) = serde_json::from_str::<Value>(&body)
            && let Some(d) = doc.get("delay").and_then(Value::as_u64)
            && d > 0
        {
            return Some(d);
        }
    }
    None
}

fn is_current_process_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() == 0 } {
            return true;
        }
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex) = line.strip_prefix("CapEff:")
                    && let Ok(mask) = u64::from_str_radix(hex.trim(), 16)
                {
                    // bit 12 = CAP_NET_ADMIN
                    return (mask & (1u64 << 12)) != 0;
                }
            }
        }
        false
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

fn core_pid_path() -> PathBuf {
    app_data_dir().join("core.pid")
}

fn core_err_path() -> PathBuf {
    app_data_dir().join("core.err")
}

fn read_core_pid_file() -> Option<u32> {
    fs::read_to_string(core_pid_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&pid| pid != 0 && pid != std::process::id())
}

fn read_core_err_file() -> Option<String> {
    fs::read_to_string(core_err_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        const STILL_ACTIVE_CODE: u32 = 259;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
        }
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe {
            CloseHandle(handle);
        }
        ok != 0 && exit_code == STILL_ACTIVE_CODE
    }
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            true
        } else {
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    }
}

fn terminate_pid(pid: u32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if !handle.is_null() {
            unsafe {
                let _ = TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
    }
    #[cfg(unix)]
    {
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

fn cleanup_orphaned_wintun_routes() {
    #[cfg(target_os = "windows")]
    {
        if read_core_pid_file().is_some_and(is_pid_alive) {
            return;
        }
        use std::os::windows::process::CommandExt;
        for prefix in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let _ = Command::new("route")
                .args(["delete", prefix.0, "mask", prefix.1, "172.19.0.1"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

fn cleanup_orphaned_macos_routes() {
    #[cfg(target_os = "macos")]
    {
        if read_core_pid_file().is_some_and(is_pid_alive) {
            return;
        }
        if let Ok(out) = Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let has_utun_split = text.lines().any(|line| {
                let cols: Vec<&str> = line.split_whitespace().collect();
                cols.len() >= 4
                    && (cols[0] == "0/1" || cols[0] == "128.0/1")
                    && cols.iter().any(|c| c.starts_with("utun"))
            });
            if has_utun_split {
                if macos_helper::status().0 {
                    macos_helper::stop_tunnel();
                } else {
                    for net in ["0.0.0.0/1", "128.0.0.0/1", "198.18.0.0/15"] {
                        let _ = Command::new("/sbin/route")
                            .args(["-n", "delete", "-net", net])
                            .status();
                    }
                }
            }
        }
    }
}

async fn stop_worker_process(mut child_opt: Option<Child>, pid_opt: Option<u32>) {
    let stop_file = app_data_dir().join("config.stop");
    let _ = fs::write(&stop_file, b"1");

    // Ждём штатного завершения `--run-core` (`bx.shutdown_wait` с watchdog до 20 с).
    // Файл `config.stop` не удаляется, пока процесс не завершится.
    let mut exited = false;
    for _ in 0..220 {
        let child_done = match child_opt.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
            None => true,
        };
        let pid_done = match pid_opt {
            Some(pid) => !is_pid_alive(pid),
            None => true,
        };
        if child_done && pid_done {
            exited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if !exited {
        if let Some(pid) = pid_opt {
            terminate_pid(pid);
        }
        if let Some(mut c) = child_opt.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for _ in 0..20 {
            if pid_opt.is_none_or(|p| !is_pid_alive(p)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    } else if let Some(mut c) = child_opt.take() {
        let _ = c.wait();
    }

    let still_alive = pid_opt.is_some_and(is_pid_alive);
    if !still_alive {
        let _ = fs::remove_file(&stop_file);
        let _ = fs::remove_file(core_pid_path());
    }
}

fn is_fakeip_pool_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 198 && (o[1] == 18 || o[1] == 19)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xffc0) == 0xfc00
        }
    }
}

async fn detect_upstream_fakeip() -> bool {
    for host in ["cloudflare.com", "google.com"] {
        if let Ok(Ok(addrs)) = tokio::time::timeout(
            Duration::from_millis(350),
            tokio::net::lookup_host((host, 443)),
        )
        .await
            && addrs.into_iter().any(|sa| is_fakeip_pool_addr(sa.ip()))
        {
            return true;
        }
    }
    false
}

pub fn parse_log_level_rank(level: &str) -> u8 {
    match level.trim().to_ascii_lowercase().as_str() {
        "all" | "trace" => 0,
        "debug" => 1,
        "info" => 2,
        "warn" | "warning" => 3,
        "error" | "err" => 4,
        "fatal" | "panic" => 5,
        _ => 2,
    }
}

pub fn extract_log_line_rank(line: &str) -> Option<u8> {
    for (tag, rank) in [
        ("[TRACE]", 0u8),
        ("[DEBUG]", 1u8),
        ("[INFO]", 2u8),
        ("[WARN]", 3u8),
        ("[ERROR]", 4u8),
        ("[FATAL]", 5u8),
    ] {
        if line.contains(tag) {
            return Some(rank);
        }
    }
    None
}

pub fn filter_log_lines(lines: &[&str], max_lines: usize, min_level: &str) -> String {
    let min_rank = parse_log_level_rank(min_level);
    if min_rank == 0 {
        let start = lines.len().saturating_sub(max_lines);
        return lines[start..].join("\n");
    }
    let mut kept = Vec::new();
    let mut last_rank: Option<u8> = None;
    for &line in lines {
        if let Some(r) = extract_log_line_rank(line) {
            last_rank = Some(r);
            if r >= min_rank {
                kept.push(line);
            }
        } else if last_rank.is_none_or(|r| r >= min_rank) {
            kept.push(line);
        }
    }
    let start = kept.len().saturating_sub(max_lines);
    kept[start..].join("\n")
}

pub fn detect_passive_tun_error(root: &Value) -> Option<String> {
    let has_tun = root
        .get("inbounds")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|ib| ib.get("type").and_then(Value::as_str) == Some("tun"))
        });
    if !has_tun {
        return None;
    }

    #[cfg(target_os = "windows")]
    if core_runtime::inbound::tun::active_win_outbound_if_index().is_none() {
        return Some(
            "Не удалось открыть виртуальный адаптер Wintun (ошибка драйвера или прав)".to_string(),
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        let recent_warns = core_runtime::logging::recent(core_runtime::logging::Level::Warn);
        for line in recent_warns.iter().rev().take(24) {
            let lower = line.to_ascii_lowercase();
            if lower.contains("failed to open utun")
                || lower.contains("failed to open tun")
                || lower.contains("failed to register utun")
                || lower.contains("continuing in passive mode")
            {
                return Some(format!(
                    "Нет прав на создание виртуального TUN-интерфейса ({line}). Выдайте права администратора / установите службу или переключитесь в режим «Системный прокси»."
                ));
            }
        }
    }

    None
}

struct SpawnedWorker {
    child: Option<Child>,
    pid: Option<u32>,
    macos_helper: bool,
}

#[cfg(target_os = "macos")]
mod macos_helper {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use core_runtime::BoxInstance;
    use serde_json::{Value, json};
    use tokio::io::{AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::UnixListener;

    pub const HELPER_BIN: &str = "/Library/PrivilegedHelperTools/io.tachyon.desktop.helper";
    pub const HELPER_PLIST: &str = "/Library/LaunchDaemons/io.tachyon.desktop.helper.plist";
    pub const HELPER_SOCK: &str = "/var/run/tachyon-helper.sock";
    pub const HELPER_LABEL: &str = "io.tachyon.desktop.helper";

    fn helper_request(req: &Value, timeout: Duration) -> Result<Value, String> {
        let mut stream = UnixStream::connect(HELPER_SOCK)
            .map_err(|e| format!("Служба macOS не отвечает ({e})"))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let line = format!("{req}\n");
        stream
            .write_all(line.as_bytes())
            .map_err(|e| format!("Ошибка записи в сокет службы: {e}"))?;
        let _ = stream.flush();

        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader
            .by_ref()
            .take(64 * 1024)
            .read_line(&mut resp_line)
            .map_err(|e| format!("Таймаут ответа службы macOS: {e}"))?;
        serde_json::from_str::<Value>(resp_line.trim())
            .map_err(|e| format!("Некорректный ответ службы macOS: {e}"))
    }

    pub fn status() -> (bool, Option<String>) {
        match helper_request(&json!({ "cmd": "ping" }), Duration::from_millis(800)) {
            Ok(doc) if doc.get("ok").and_then(Value::as_bool) == Some(true) => {
                let ver = doc
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                (true, ver)
            }
            _ => (false, None),
        }
    }

    pub fn stop_tunnel() {
        let _ = helper_request(&json!({ "cmd": "stop" }), Duration::from_secs(12));
    }

    pub fn sysproxy(enable: bool, port: u16) -> bool {
        matches!(
            helper_request(
                &json!({ "cmd": "sysproxy", "enable": enable, "port": port }),
                Duration::from_secs(6)
            ),
            Ok(doc) if doc.get("ok").and_then(Value::as_bool) == Some(true)
        )
    }

    pub fn start_tunnel(cfg_path: &Path) -> Result<Option<u32>, String> {
        let resp = helper_request(
            &json!({
                "cmd": "start",
                "config_path": cfg_path.to_string_lossy()
            }),
            Duration::from_secs(20),
        )?;
        if resp.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(resp.get("pid").and_then(Value::as_u64).map(|p| p as u32))
        } else {
            let err = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Неизвестная ошибка службы macOS");
            Err(err.to_string())
        }
    }

    pub fn install() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{HELPER_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{HELPER_BIN}</string>
        <string>--macos-helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
"#
        );
        let tmp_plist = super::app_data_dir().join(format!("{HELPER_LABEL}.plist.tmp"));
        super::write_private_file(&tmp_plist, plist_content.as_bytes())
            .map_err(|e| format!("Не удалось записать временный plist: {e}"))?;

        let exe_q = exe.to_string_lossy().replace('\'', "'\\''");
        let tmp_q = tmp_plist.to_string_lossy().replace('\'', "'\\''");
        let shell_cmd = format!(
            "mkdir -p /Library/PrivilegedHelperTools /Library/LaunchDaemons && \
cp -f '{exe_q}' '{HELPER_BIN}' && \
chown root:wheel '{HELPER_BIN}' && \
chmod 755 '{HELPER_BIN}' && \
(codesign -v '{HELPER_BIN}' >/dev/null 2>&1 || codesign --force --sign - '{HELPER_BIN}' >/dev/null 2>&1 || true) && \
cp -f '{tmp_q}' '{HELPER_PLIST}' && \
chown root:wheel '{HELPER_PLIST}' && \
chmod 644 '{HELPER_PLIST}' && \
launchctl bootout system/{HELPER_LABEL} >/dev/null 2>&1 || true; \
launchctl unload -w '{HELPER_PLIST}' >/dev/null 2>&1 || true; \
launchctl bootstrap system '{HELPER_PLIST}' || launchctl load -w '{HELPER_PLIST}'"
        );
        let osa_script = format!(
            "do shell script \"{}\" with administrator privileges",
            shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let osa_status = Command::new("osascript")
            .args(["-e", &osa_script])
            .status()
            .map_err(|e| format!("osascript error: {e}"))?;
        let _ = fs::remove_file(&tmp_plist);

        if !osa_status.success() {
            return Err("Установка службы macOS отменена или завершилась с ошибкой".to_string());
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let (alive, ver) = status();
            if alive && ver.as_deref() == Some(env!("CARGO_PKG_VERSION")) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        Err("Служба macOS установлена, но не ответила на проверочный запрос".to_string())
    }

    pub fn uninstall() -> Result<(), String> {
        let _ = helper_request(&json!({ "cmd": "uninstall" }), Duration::from_secs(6));
        let shell_cmd = format!(
            "launchctl bootout system/{HELPER_LABEL} >/dev/null 2>&1 || true; \
launchctl unload -w '{HELPER_PLIST}' >/dev/null 2>&1 || true; \
rm -f '{HELPER_PLIST}' '{HELPER_BIN}' '{HELPER_SOCK}'"
        );
        let osa_script = format!(
            "do shell script \"{}\" with administrator privileges",
            shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let status = Command::new("osascript")
            .args(["-e", &osa_script])
            .status()
            .map_err(|e| format!("osascript error: {e}"))?;
        if !status.success() {
            return Err("Удаление службы macOS отменено или завершилось с ошибкой".to_string());
        }
        Ok(())
    }

    pub fn run_daemon() -> i32 {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for macOS helper");

        rt.block_on(async move {
            let _ = fs::remove_file(HELPER_SOCK);
            let listener = match UnixListener::bind(HELPER_SOCK) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("macos-helper: bind {HELPER_SOCK} failed: {e}");
                    return 1;
                }
            };
            if let Ok(c_sock) = std::ffi::CString::new(HELPER_SOCK) {
                unsafe {
                    let _ = libc::chmod(c_sock.as_ptr(), 0o666);
                }
            }
            let engine: Arc<tokio::sync::Mutex<Option<BoxInstance>>> =
                Arc::new(tokio::sync::Mutex::new(None));
            let op_lock: Arc<tokio::sync::Mutex<()>> = Arc::new(tokio::sync::Mutex::new(()));
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

            loop {
                tokio::select! {
                    _ = async {
                        if let Some(ref mut s) = sigterm {
                            let _ = s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        let _op = op_lock.lock().await;
                        let prev = engine.lock().await.take();
                        if let Some(mut bx) = prev {
                            bx.shutdown_wait().await;
                        }
                        super::flush_os_dns();
                        let _ = fs::remove_file(HELPER_SOCK);
                        return 0;
                    }
                    accept_res = listener.accept() => {
                        let (stream, _) = match accept_res {
                            Ok(pair) => pair,
                            Err(_) => continue,
                        };
                        let eng = Arc::clone(&engine);
                        let op = Arc::clone(&op_lock);
                        tokio::spawn(async move {
                            let exit_now = handle_client(stream, eng, op).await;
                            if exit_now {
                                std::process::exit(0);
                            }
                        });
                    }
                }
            }
        })
    }

    fn verify_peer_identity(fd: std::os::unix::io::RawFd) -> Result<libc::uid_t, String> {
        let mut peer_uid: libc::uid_t = u32::MAX;
        let mut peer_gid: libc::gid_t = u32::MAX;
        if unsafe { libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) } != 0 {
            return Err("getpeereid failed".to_string());
        }
        let _ = peer_gid;

        if peer_uid != 0 {
            if let Ok(console_meta) = fs::metadata("/dev/console") {
                let console_uid = console_meta.uid();
                if console_uid != 0 && peer_uid != console_uid {
                    return Err("peer uid does not match console user".to_string());
                }
            } else if peer_uid < 500 {
                return Err("peer uid not authorized".to_string());
            }
        }

        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 2;
        let mut peer_pid: libc::pid_t = 0;
        let mut pid_len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut peer_pid as *mut _ as *mut libc::c_void,
                &mut pid_len,
            )
        } != 0
            || peer_pid <= 0
        {
            return Err("LOCAL_PEERPID unavailable".to_string());
        }

        unsafe extern "C" {
            fn proc_pidpath(
                pid: libc::c_int,
                buffer: *mut libc::c_void,
                buffersize: u32,
            ) -> libc::c_int;
        }
        let mut path_buf = [0u8; 4096];
        let rc = unsafe {
            proc_pidpath(
                peer_pid,
                path_buf.as_mut_ptr() as *mut libc::c_void,
                path_buf.len() as u32,
            )
        };
        if rc <= 0 {
            return Err("proc_pidpath failed".to_string());
        }
        let peer_path = String::from_utf8_lossy(&path_buf[..rc as usize]);
        let allowed_path = peer_path == HELPER_BIN
            || peer_path.ends_with("/Contents/MacOS/tachyon")
            || peer_path.ends_with("/tachyon");
        if !allowed_path {
            return Err("peer executable is not Tachyon".to_string());
        }
        Ok(peer_uid)
    }

    async fn handle_client(
        stream: tokio::net::UnixStream,
        engine: Arc<tokio::sync::Mutex<Option<BoxInstance>>>,
        op_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        let peer_auth = verify_peer_identity(stream.as_raw_fd());

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = TokioBufReader::new(read_half);
        let mut line = String::new();
        let read_res = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = Vec::with_capacity(512);
            loop {
                let mut byte = [0u8; 1];
                let n = tokio::io::AsyncReadExt::read(&mut reader, &mut byte).await?;
                if n == 0 || byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() > 8192 {
                    return Err(std::io::Error::other("request too large"));
                }
            }
            line = String::from_utf8_lossy(&buf).into_owned();
            Ok::<(), std::io::Error>(())
        })
        .await;

        let Ok(Ok(())) = read_res else {
            return false;
        };
        let Ok(req) = serde_json::from_str::<Value>(line.trim()) else {
            let _ = write_half
                .write_all(b"{\"ok\":false,\"error\":\"invalid json\"}\n")
                .await;
            return false;
        };
        let cmd = req.get("cmd").and_then(Value::as_str).unwrap_or("");
        let mut exit_after = false;

        let reply = match cmd {
            "ping" => {
                let running = engine.lock().await.is_some();
                json!({
                    "ok": true,
                    "version": env!("CARGO_PKG_VERSION"),
                    "running": running,
                    "pid": std::process::id()
                })
            }
            "start" => match peer_auth {
                Err(e) => json!({ "ok": false, "error": e }),
                Ok(peer_uid) => {
                    if let Some(cfg_str) = req.get("config_path").and_then(Value::as_str) {
                        let _op = op_lock.lock().await;
                        match start_from_path(cfg_str, peer_uid, &engine).await {
                            Ok(()) => json!({ "ok": true, "pid": std::process::id() }),
                            Err(err) => json!({ "ok": false, "error": err }),
                        }
                    } else {
                        json!({ "ok": false, "error": "missing config_path" })
                    }
                }
            },
            "stop" => match peer_auth {
                Err(e) => json!({ "ok": false, "error": e }),
                Ok(_) => {
                    let _op = op_lock.lock().await;
                    let prev = engine.lock().await.take();
                    if let Some(mut bx) = prev {
                        bx.shutdown_wait().await;
                    }
                    super::flush_os_dns();
                    json!({ "ok": true })
                }
            },
            "sysproxy" => match peer_auth {
                Err(e) => json!({ "ok": false, "error": e }),
                Ok(_) => {
                    let enable = req.get("enable").and_then(Value::as_bool).unwrap_or(false);
                    let port = req.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
                    if !(1024..=65535).contains(&port) {
                        json!({ "ok": false, "error": "invalid proxy port" })
                    } else if super::apply_macos_system_proxy_direct(enable, port) {
                        json!({ "ok": true })
                    } else {
                        json!({ "ok": false, "error": "networksetup failed" })
                    }
                }
            },
            "uninstall" => match peer_auth {
                Err(e) => json!({ "ok": false, "error": e }),
                Ok(_) => {
                    let _op = op_lock.lock().await;
                    let prev = engine.lock().await.take();
                    if let Some(mut bx) = prev {
                        bx.shutdown_wait().await;
                    }
                    super::flush_os_dns();
                    let _ = fs::remove_file(HELPER_PLIST);
                    let _ = fs::remove_file(HELPER_BIN);
                    let _ = fs::remove_file(HELPER_SOCK);
                    exit_after = true;
                    json!({ "ok": true })
                }
            },
            _ => json!({ "ok": false, "error": "unknown command" }),
        };

        let _ = write_half.write_all(format!("{reply}\n").as_bytes()).await;
        let _ = write_half.flush().await;
        exit_after
    }

    fn sanitize_root_config(root: &mut Value, base_dir: &Path) -> Result<(), String> {
        let base_str = base_dir.to_string_lossy();
        let is_under_base = |raw: &str| -> bool {
            let p = Path::new(raw);
            if p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return false;
            }
            p.starts_with(base_dir)
        };
        if let Some(log_obj) = root.get_mut("log").and_then(Value::as_object_mut) {
            let safe_log = base_dir.join("tachyon-core.log");
            let keep = log_obj
                .get("output")
                .and_then(Value::as_str)
                .is_some_and(is_under_base);
            if !keep {
                log_obj.insert("output".to_string(), json!(safe_log.to_string_lossy()));
            }
        }
        if let Some(exp) = root.get_mut("experimental").and_then(Value::as_object_mut) {
            if let Some(ca) = exp.get_mut("clash_api").and_then(Value::as_object_mut) {
                let port = ca
                    .get("external_controller")
                    .and_then(Value::as_str)
                    .and_then(|s| s.rsplit_once(':'))
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .filter(|&p| p >= 1024)
                    .unwrap_or(super::API_PORT);
                ca.insert(
                    "external_controller".to_string(),
                    json!(format!("127.0.0.1:{port}")),
                );
            }
            if let Some(cf) = exp.get_mut("cache_file").and_then(Value::as_object_mut) {
                let keep = cf
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(is_under_base);
                if !keep {
                    cf.insert("path".to_string(), json!(format!("{base_str}/cache.db")));
                }
            }
        }
        if let Some(inbounds) = root.get_mut("inbounds").and_then(Value::as_array_mut) {
            for ib in inbounds {
                if let Some(obj) = ib.as_object_mut()
                    && obj.get("type").and_then(Value::as_str) != Some("tun")
                {
                    let port = obj.get("listen_port").and_then(Value::as_u64).unwrap_or(0);
                    if port < 1024 || port > 65535 {
                        return Err("Недопустимый порт прослушивания в конфиге".to_string());
                    }
                    let listen = obj
                        .get("listen")
                        .and_then(Value::as_str)
                        .unwrap_or("127.0.0.1");
                    if listen != "127.0.0.1" && listen != "0.0.0.0" {
                        obj.insert("listen".to_string(), json!("127.0.0.1"));
                    }
                }
            }
        }
        Ok(())
    }

    async fn start_from_path(
        cfg_str: &str,
        peer_uid: u32,
        engine: &Arc<tokio::sync::Mutex<Option<BoxInstance>>>,
    ) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let canon = fs::canonicalize(cfg_str)
            .map_err(|e| format!("Не найден файл конфигурации {cfg_str}: {e}"))?;
        if canon.file_name() != Some(OsStr::new("config.json")) {
            return Err("Недопустимое имя файла конфигурации".to_string());
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&canon)
            .map_err(|e| format!("Не удалось открыть файл конфигурации: {e}"))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("Не удалось прочитать метаданные конфига: {e}"))?;
        if !meta.is_file() || meta.len() > 2 * 1024 * 1024 {
            return Err("Некорректный размер файла конфигурации".to_string());
        }
        if peer_uid != 0 && meta.uid() != peer_uid {
            return Err("Доступ к файлу конфигурации запрещён".to_string());
        }
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|e| format!("Ошибка чтения конфигурации: {e}"))?;
        core_config::check_str(&raw).map_err(|e| format!("Ошибка валидации конфигурации: {e}"))?;
        let mut root: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("Ошибка разбора JSON конфигурации: {e}"))?;
        let base_dir = canon
            .parent()
            .ok_or_else(|| "Некорректный каталог конфигурации".to_string())?;
        sanitize_root_config(&mut root, base_dir)?;
        let sanitized = serde_json::to_string(&root)
            .map_err(|e| format!("Ошибка сериализации конфигурации: {e}"))?;
        core_config::check_str(&sanitized)
            .map_err(|e| format!("Ошибка валидации конфигурации: {e}"))?;

        let prev = engine.lock().await.take();
        if let Some(mut old) = prev {
            old.shutdown_wait().await;
        }

        let mut bx = core_runtime::start(&root)
            .await
            .map_err(|e| format!("{e:#}"))?;
        if let Some(msg) = super::detect_passive_tun_error(&root) {
            bx.shutdown_wait().await;
            return Err(msg);
        }
        *engine.lock().await = Some(bx);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub fn run_macos_helper_daemon() -> i32 {
    macos_helper::run_daemon()
}

#[cfg(target_os = "macos")]
pub fn macos_helper_status() -> (bool, Option<String>) {
    macos_helper::status()
}

#[cfg(target_os = "macos")]
pub fn install_macos_helper() -> Result<(), String> {
    macos_helper::install()
}

#[cfg(target_os = "macos")]
pub fn uninstall_macos_helper() -> Result<(), String> {
    macos_helper::uninstall()
}

#[cfg(target_os = "macos")]
fn stop_macos_helper_tunnel() {
    macos_helper::stop_tunnel();
}

pub fn cleanup_stale_state_on_startup() {
    #[cfg(target_os = "macos")]
    {
        if macos_helper::status().0 {
            macos_helper::stop_tunnel();
        }
    }
    if let Some(stale_pid) = read_core_pid_file()
        && is_pid_alive(stale_pid)
    {
        let stop_file = app_data_dir().join("config.stop");
        let _ = fs::write(&stop_file, b"1");
        for _ in 0..60 {
            if !is_pid_alive(stale_pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if is_pid_alive(stale_pid) {
            terminate_pid(stale_pid);
        }
    }
    let _ = fs::remove_file(app_data_dir().join("config.stop"));
    let _ = fs::remove_file(core_pid_path());
    let _ = fs::remove_file(core_err_path());
    cleanup_orphaned_wintun_routes();
    cleanup_orphaned_macos_routes();
    if proxy_points_to_us() {
        set_system_proxy(false);
    }
    apply_kill_switch(false);
    flush_os_dns();
}

pub fn emergency_cleanup_on_panic() {
    let stop_file = app_data_dir().join("config.stop");
    let _ = fs::write(&stop_file, b"1");
    if proxy_points_to_us() {
        set_system_proxy(false);
    }
    apply_kill_switch(false);
    flush_os_dns();
}

async fn spawn_elevated_worker(cfg_path: &Path, secret: &str) -> Result<SpawnedWorker, String> {
    #[cfg(target_os = "macos")]
    {
        let cfg_owned = cfg_path.to_path_buf();
        let pid = tokio::task::spawn_blocking(move || -> Result<Option<u32>, String> {
            let (alive, ver) = macos_helper::status();
            if !alive || ver.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
                macos_helper::install()?;
            }
            macos_helper::start_tunnel(&cfg_owned)
        })
        .await
        .map_err(|e| format!("Ошибка задачи службы macOS: {e}"))??;

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok((200, _)) =
                clash_api_request(API_PORT, secret, "GET", "/connections", None).await
            {
                return Ok(SpawnedWorker {
                    child: None,
                    pid,
                    macos_helper: true,
                });
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let _ = tokio::task::spawn_blocking(macos_helper::stop_tunnel).await;
        return Err("Таймаут запуска ядра через службу macOS".to_string());
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(stale_pid) = read_core_pid_file()
            && is_pid_alive(stale_pid)
        {
            stop_worker_process(None, Some(stale_pid)).await;
        }
        let _ = fs::remove_file(app_data_dir().join("config.stop"));
        let _ = fs::remove_file(core_pid_path());
        let _ = fs::remove_file(core_err_path());

        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let cfg_str = cfg_path.to_string_lossy().into_owned();
        let parent_pid = std::process::id().to_string();

        #[cfg(target_os = "linux")]
        let (mut child_opt, mut worker_pid): (Option<Child>, Option<u32>) = {
            let exe_c = exe.clone();
            let cfg_c = cfg_str.clone();
            let ppid_c = parent_pid.clone();
            let ch = tokio::task::spawn_blocking(move || {
                Command::new("pkexec")
                    .arg(&exe_c)
                    .arg("--run-core")
                    .arg(&cfg_c)
                    .arg("--parent-pid")
                    .arg(&ppid_c)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("pkexec error: {e}"))
            })
            .await
            .map_err(|e| format!("pkexec task error: {e}"))??;
            let pid = Some(ch.id());
            (Some(ch), pid)
        };

        #[cfg(target_os = "windows")]
        let (mut child_opt, mut worker_pid): (Option<Child>, Option<u32>) = {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND};
            use windows_sys::Win32::System::Threading::GetProcessId;
            use windows_sys::Win32::UI::Shell::SEE_MASK_NOCLOSEPROCESS;
            use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

            #[cfg_attr(target_arch = "x86", repr(C, packed(1)))]
            #[cfg_attr(not(target_arch = "x86"), repr(C))]
            struct ShellExecuteInfoW {
                cb_size: u32,
                f_mask: u32,
                hwnd: HWND,
                lp_verb: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show: i32,
                h_inst_app: HINSTANCE,
                lp_id_list: *mut std::ffi::c_void,
                lp_class: *const u16,
                hkey_class: *mut std::ffi::c_void,
                dw_hot_key: u32,
                h_icon_or_monitor: HANDLE,
                h_process: HANDLE,
            }

            #[link(name = "shell32")]
            unsafe extern "system" {
                fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> i32;
            }

            let exe_c = exe.clone();
            let cfg_c = cfg_str.clone();
            let ppid_c = parent_pid.clone();

            let pid = tokio::task::spawn_blocking(move || -> Result<Option<u32>, String> {
                let to_wide =
                    |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
                let verb_w = to_wide("runas");
                let file_w = to_wide(&exe_c.to_string_lossy());
                let params_str = format!("--run-core \"{cfg_c}\" --parent-pid {ppid_c}");
                let params_w = to_wide(&params_str);

                let mut sei: ShellExecuteInfoW = unsafe { std::mem::zeroed() };
                sei.cb_size = std::mem::size_of::<ShellExecuteInfoW>() as u32;
                sei.f_mask = SEE_MASK_NOCLOSEPROCESS;
                sei.lp_verb = verb_w.as_ptr();
                sei.lp_file = file_w.as_ptr();
                sei.lp_parameters = params_w.as_ptr();
                sei.n_show = SW_HIDE;

                let ok = unsafe { ShellExecuteExW(&mut sei) };
                if ok == 0 {
                    return Err("Запрос прав администратора отклонён".to_string());
                }
                let spawned_pid = if !sei.h_process.is_null() {
                    let p = unsafe { GetProcessId(sei.h_process) };
                    unsafe {
                        let _ = CloseHandle(sei.h_process);
                    }
                    (p != 0).then_some(p)
                } else {
                    None
                };
                Ok(spawned_pid.or_else(read_core_pid_file))
            })
            .await
            .map_err(|e| format!("UAC task error: {e}"))??;
            (None, pid)
        };

        // Wait up to 15 seconds for Clash API to come up
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if worker_pid.is_none() {
                worker_pid = read_core_pid_file();
            }
            if let Some(err_msg) = read_core_err_file() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = fs::remove_file(core_pid_path());
                return Err(err_msg);
            }
            if let Some(c) = child_opt.as_mut() {
                if let Ok(Some(code)) = c.try_wait() {
                    let err_msg = read_core_err_file()
                        .unwrap_or_else(|| format!("Elevated worker exited with {code}"));
                    return Err(err_msg);
                }
            } else if let Some(pid) = worker_pid
                && !is_pid_alive(pid)
            {
                let err_msg = read_core_err_file()
                    .unwrap_or_else(|| format!("Привилегированный процесс {pid} завершился"));
                let _ = fs::remove_file(core_pid_path());
                return Err(err_msg);
            }
            if let Ok((200, _)) =
                clash_api_request(API_PORT, secret, "GET", "/connections", None).await
            {
                if worker_pid.is_none() {
                    worker_pid = read_core_pid_file();
                }
                return Ok(SpawnedWorker {
                    child: child_opt,
                    pid: worker_pid,
                    macos_helper: false,
                });
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        stop_worker_process(child_opt, worker_pid.or_else(read_core_pid_file)).await;
        cleanup_orphaned_wintun_routes();
        Err(read_core_err_file()
            .unwrap_or_else(|| "Таймаут ожидания запуска привилегированного процесса".to_string()))
    }
}

pub fn median_ping_samples(samples: &[i64]) -> i64 {
    let mut valid: Vec<i64> = samples.iter().copied().filter(|&v| v > 0).collect();
    if valid.is_empty() {
        return -1;
    }
    valid.sort_unstable();
    let n = valid.len();
    if n % 2 == 1 {
        valid[n / 2]
    } else {
        (valid[n / 2 - 1] + valid[n / 2]) / 2
    }
}

pub async fn probe_endpoint_median_ms(host: &str, port: u16, is_udp_proto: bool) -> i64 {
    let first = if is_udp_proto {
        icmp_ping_ms(host, 1800).await
    } else {
        tcp_connect_ms(host, port, 1800).await
    };
    let mut samples = Vec::with_capacity(3);
    if first > 0 {
        samples.push(first);
    } else {
        let retry = if is_udp_proto {
            icmp_ping_ms(host, 1200).await
        } else {
            tcp_connect_ms(host, port, 1200).await
        };
        if retry <= 0 {
            return -1;
        }
        samples.push(retry);
    }
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(35)).await;
        let next = if is_udp_proto {
            icmp_ping_ms(host, 1500).await
        } else {
            tcp_connect_ms(host, port, 1500).await
        };
        if next > 0 {
            samples.push(next);
        }
    }
    median_ping_samples(&samples)
}

pub async fn icmp_ping_ms(host: &str, timeout_ms: u64) -> i64 {
    let host_owned = host.trim().trim_matches(['[', ']']).to_string();
    #[cfg(target_os = "windows")]
    {
        let h = host_owned.clone();
        if let Some(ms) = tokio::task::spawn_blocking(move || windows_icmp_ping_ms(&h, timeout_ms))
            .await
            .ok()
            .flatten()
        {
            return ms;
        }
    }
    #[cfg(unix)]
    {
        let h = host_owned;
        if let Some(ms) = tokio::task::spawn_blocking(move || unix_icmp_ping_ms(&h, timeout_ms))
            .await
            .ok()
            .flatten()
        {
            return ms;
        }
    }
    -1
}

fn bind_std_udp_bypassing_tun(sock: &std::net::UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if let Some(ifname) = default_linux_phys_interface()
            && let Ok(cstr) = std::ffi::CString::new(ifname)
        {
            unsafe {
                let _ = libc::setsockopt(
                    sock.as_raw_fd(),
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
        if let Some(ifidx) = core_runtime::inbound::tun::active_macos_outbound_if_index()
            .or_else(default_macos_phys_ifindex)
        {
            const IP_BOUND_IF: libc::c_int = 25;
            unsafe {
                let _ = libc::setsockopt(
                    sock.as_raw_fd(),
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
                    sock.as_raw_socket() as usize,
                    0,  // IPPROTO_IP
                    31, // IP_UNICAST_IF
                    val.as_ptr(),
                    val.len() as i32,
                );
            }
        }
    }
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0u8;
    while offset < packet.len() {
        let len = packet[offset];
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            return Some(offset + 2);
        }
        if len == 0 {
            return Some(offset + 1);
        }
        if len > 63 || jumps > 32 {
            return None;
        }
        jumps += 1;
        offset = offset.checked_add(1 + usize::from(len))?;
    }
    None
}

fn resolve_ipv4_bypassing_tun(host: &str, timeout_ms: u64) -> Option<std::net::Ipv4Addr> {
    let clean = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    if clean.is_empty() {
        return None;
    }
    if let Ok(ip) = clean.parse::<std::net::Ipv4Addr>() {
        return (!is_fake_or_tun_ip(IpAddr::V4(ip))).then_some(ip);
    }
    if let Ok(addrs) = (clean, 0u16).to_socket_addrs() {
        for addr in addrs {
            if let IpAddr::V4(v4) = addr.ip()
                && !is_fake_or_tun_ip(IpAddr::V4(v4))
            {
                return Some(v4);
            }
        }
    }

    let mut txid = [0u8; 2];
    let _ = getrandom::fill(&mut txid);
    if txid == [0, 0] {
        txid = [0x54, 0x41];
    }
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[
        txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        req.push(label.len() as u8);
        req.extend_from_slice(label.as_bytes());
    }
    req.push(0);
    req.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let timeout = Duration::from_millis(timeout_ms.clamp(300, 1500));
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    bind_std_udp_bypassing_tun(&sock);

    let mut buf = [0u8; 512];
    for dns_srv in ["1.1.1.1:53", "8.8.8.8:53"] {
        let Ok(expected_addr) = dns_srv.parse::<SocketAddr>() else {
            continue;
        };
        if sock.send_to(&req, expected_addr).is_err() {
            continue;
        }
        let Ok((n, from_addr)) = sock.recv_from(&mut buf) else {
            continue;
        };
        if from_addr != expected_addr {
            continue;
        }
        let pkt = &buf[..n];
        if pkt.len() < 12 || pkt[0..2] != req[0..2] || (pkt[2] & 0x80) == 0 || (pkt[3] & 0x0F) != 0
        {
            continue;
        }
        let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
        let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
        let mut off = 12usize;
        for _ in 0..qdcount {
            off = skip_dns_name(pkt, off)?;
            off = off.checked_add(4)?;
            if off > pkt.len() {
                return None;
            }
        }
        for _ in 0..ancount {
            let Some(next) = skip_dns_name(pkt, off) else {
                break;
            };
            off = next;
            if off + 10 > pkt.len() {
                break;
            }
            let rtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let rclass = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
            off += 10;
            if off + rdlen > pkt.len() {
                break;
            }
            if rtype == 1 && rclass == 1 && rdlen == 4 {
                let ip =
                    std::net::Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
                if !is_fake_or_tun_ip(IpAddr::V4(ip)) {
                    return Some(ip);
                }
            }
            off += rdlen;
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_phys_ipv4() -> Option<u32> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibIpAddrRow {
        dw_addr: u32,
        dw_index: u32,
        dw_mask: u32,
        dw_bcast_addr: u32,
        dw_reasm_size: u32,
        unused1: u16,
        w_type: u16,
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetIpAddrTable(p_ip_addr_table: *mut u8, pdw_size: *mut u32, border: i32) -> u32;
    }

    let if_idx = core_runtime::inbound::tun::active_win_outbound_if_index()
        .or_else(|| {
            let cached = CACHED_WIN_PHYS_IFINDEX.load(std::sync::atomic::Ordering::Relaxed);
            (cached != 0).then_some(cached)
        })
        .or_else(default_windows_phys_ifindex)?;

    let mut size: u32 = 0;
    let _ = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if !(4..=1024 * 1024).contains(&size) {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr(), &mut size, 0) };
    if rc != 0 || buf.len() < 4 {
        return None;
    }
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<MibIpAddrRow>();
    let max_rows = (buf.len() - 4) / row_size;
    for i in 0..count.min(max_rows) {
        let row = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(4 + i * row_size) as *const MibIpAddrRow)
        };
        if row.dw_index == if_idx && row.dw_addr != 0 {
            let ip = std::net::Ipv4Addr::from(row.dw_addr.to_ne_bytes());
            if !ip.is_loopback() && !ip.is_unspecified() && !is_fake_or_tun_ip(IpAddr::V4(ip)) {
                return Some(row.dw_addr);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_icmp_ping_ms(host: &str, timeout_ms: u64) -> Option<i64> {
    use std::ffi::c_void;
    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }
    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut c_void,
        options: IpOptionInformation,
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(icmp_handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            icmp_handle: *mut c_void,
            destination_address: u32,
            request_data: *const u8,
            request_size: u16,
            request_options: *const IpOptionInformation,
            reply_buffer: *mut u8,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn IcmpSendEcho2Ex(
            icmp_handle: *mut c_void,
            event: *mut c_void,
            apc_routine: *mut c_void,
            apc_context: *mut c_void,
            source_address: u32,
            destination_address: u32,
            request_data: *const u8,
            request_size: u16,
            request_options: *const IpOptionInformation,
            reply_buffer: *mut u8,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    let ipv4 = resolve_ipv4_bypassing_tun(host, timeout_ms.min(1200))?;
    let dest_in_addr = u32::from_ne_bytes(ipv4.octets());
    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() || handle == (-1isize as *mut c_void) {
        return None;
    }
    let payload = b"tachyon";
    let mut reply_buf = vec![0u8; std::mem::size_of::<IcmpEchoReply>() + payload.len() + 64];
    let timeout_clamped = timeout_ms.clamp(200, 5000) as u32;
    let src_in_addr = windows_phys_ipv4();
    let sw = Instant::now();
    let count = unsafe {
        if let Some(src) = src_in_addr {
            IcmpSendEcho2Ex(
                handle,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                src,
                dest_in_addr,
                payload.as_ptr(),
                payload.len() as u16,
                std::ptr::null(),
                reply_buf.as_mut_ptr(),
                reply_buf.len() as u32,
                timeout_clamped,
            )
        } else {
            IcmpSendEcho(
                handle,
                dest_in_addr,
                payload.as_ptr(),
                payload.len() as u16,
                std::ptr::null(),
                reply_buf.as_mut_ptr(),
                reply_buf.len() as u32,
                timeout_clamped,
            )
        }
    };
    let elapsed_ms = sw.elapsed().as_millis() as i64;
    unsafe {
        IcmpCloseHandle(handle);
    }
    if count > 0 {
        let reply = unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const IcmpEchoReply) };
        if reply.status == 0 && reply.address == dest_in_addr {
            let rtt = (reply.round_trip_time as i64).max(elapsed_ms).max(1);
            return Some(rtt);
        }
    }
    None
}

#[cfg(unix)]
fn unix_icmp_ping_ms(host: &str, timeout_ms: u64) -> Option<i64> {
    struct FdGuard(libc::c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    let ipv4 = resolve_ipv4_bypassing_tun(host, timeout_ms.min(1200))?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return None;
    }
    let _guard = FdGuard(fd);

    #[cfg(target_os = "linux")]
    if let Some(ifname) = default_linux_phys_interface()
        && let Ok(cstr) = std::ffi::CString::new(ifname)
    {
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                cstr.as_ptr() as *const libc::c_void,
                cstr.as_bytes_with_nul().len() as libc::socklen_t,
            );
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(ifidx) = core_runtime::inbound::tun::active_macos_outbound_if_index()
        .or_else(default_macos_phys_ifindex)
    {
        const IP_BOUND_IF: libc::c_int = 25;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                IP_BOUND_IF,
                &ifidx as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
        }
    }

    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as libc::time_t,
        tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
    };
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut pkt = [0u8; 16];
    pkt[0] = 8; // Echo Request
    pkt[1] = 0;
    let pid = (std::process::id() & 0xFFFF) as u16;
    pkt[4..6].copy_from_slice(&pid.to_be_bytes());
    pkt[6..8].copy_from_slice(&1u16.to_be_bytes());
    pkt[8..16].copy_from_slice(b"tachyon!");
    let mut sum = 0u32;
    for chunk in pkt.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt[2..4].copy_from_slice(&csum.to_be_bytes());

    let dest = libc::sockaddr_in {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ipv4.octets()),
        },
        sin_zero: [0; 8],
    };

    let sw = Instant::now();
    let sent = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dest as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return None;
    }

    let mut recv_buf = [0u8; 256];
    let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.clamp(200, 5000));
    while Instant::now() < deadline {
        let n = unsafe {
            libc::recvfrom(
                fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
                &mut from as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        let elapsed_ms = sw.elapsed().as_millis() as i64;
        let len = n as usize;
        if len < 8 {
            continue;
        }
        let from_ip = std::net::Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes());
        if from_ip != ipv4 {
            continue;
        }
        let icmp = if (recv_buf[0] >> 4) == 4 {
            let ihl = ((recv_buf[0] & 0x0F) * 4) as usize;
            if len >= ihl + 8 {
                &recv_buf[ihl..len]
            } else {
                continue;
            }
        } else {
            &recv_buf[..len]
        };
        if icmp[0] == 0 && icmp[1] == 0 {
            return Some(elapsed_ms.max(1));
        }
    }
    None
}

pub async fn tcp_connect_ms(host: &str, port: u16, timeout_ms: u64) -> i64 {
    let host = host.trim().trim_matches(['[', ']']).to_string();
    let timeout = Duration::from_millis(timeout_ms);

    let addr_res = tokio::task::spawn_blocking(move || {
        if let Ok(resolved) = (host.as_str(), port).to_socket_addrs() {
            let addrs: Vec<SocketAddr> = resolved.filter(|a| !is_fake_or_tun_ip(a.ip())).collect();
            if let Some(v4) = addrs.iter().copied().find(|a| a.is_ipv4()) {
                return Some(v4);
            }
            if let Some(any) = addrs.into_iter().next() {
                return Some(any);
            }
        }
        resolve_ipv4_bypassing_tun(&host, 1200).map(|v4| SocketAddr::new(IpAddr::V4(v4), port))
    })
    .await
    .ok()
    .flatten();

    let Some(target_addr) = addr_res else {
        return -1;
    };

    let sw = Instant::now();
    match tokio::time::timeout(timeout, connect_bypassing_tun(target_addr)).await {
        Ok(Ok(_)) => (sw.elapsed().as_millis() as i64).max(1),
        _ => -1,
    }
}

fn is_fake_or_tun_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 10 && o[1] == 255)
                || (o[0] == 172 && o[1] == 19 && o[2] == 0)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfdfe && s[1] == 0xdcba
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn is_virtual_or_tun_adapter_name(desc: &str) -> bool {
    let lower = desc.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    const MARKERS: [&str; 13] = [
        "wintun",
        "wireguard",
        "amneziawg",
        "tachyon",
        "tap-windows",
        "tap-",
        "openvpn",
        "loopback",
        "utun",
        "tailscale",
        "zerotier",
        "vethernet (wsl)",
        "sing-box",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_virtual_macos_iface(iface: &str) -> bool {
    let name = iface.trim();
    if name.is_empty() {
        return true;
    }
    name == "lo"
        || name.starts_with("lo0")
        || name.starts_with("lo1")
        || name.starts_with("utun")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("gif")
        || name.starts_with("stf")
        || name.starts_with("awdl")
        || name.starts_with("llw")
        || name.starts_with("anpi")
        || name.starts_with("bridge")
        || name.starts_with("tailscale")
        || name.starts_with("wg")
        || name.starts_with("tachyon")
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_macos_route_default(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("interface:") {
            let iface = rest.trim();
            if !is_virtual_macos_iface(iface) {
                return Some(iface.to_string());
            }
        }
    }
    None
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_macos_netstat_default(output: &str) -> Option<String> {
    let mut fallback: Option<String> = None;
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "default" {
            let iface = cols[3];
            if !is_virtual_macos_iface(iface) {
                if iface.starts_with("en") {
                    return Some(iface.to_string());
                }
                if fallback.is_none() {
                    fallback = Some(iface.to_string());
                }
            }
        }
    }
    fallback
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_macos_scutil_nwi(output: &str) -> Option<String> {
    let mut in_ipv4 = false;
    let mut fallback: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("IPv4 network interface information") {
            in_ipv4 = true;
            continue;
        }
        if trimmed.starts_with("IPv6 network interface information") {
            in_ipv4 = false;
            continue;
        }
        if !in_ipv4 && output.contains("IPv4 network interface information") {
            continue;
        }
        if let Some((left, right)) = trimmed.split_once(':') {
            let cand = left.trim();
            if !cand.contains(' ') && right.contains("flags") && !is_virtual_macos_iface(cand) {
                if cand.starts_with("en") {
                    return Some(cand.to_string());
                }
                if fallback.is_none() {
                    fallback = Some(cand.to_string());
                }
            }
        }
    }
    fallback
}

#[cfg(target_os = "macos")]
fn detect_macos_phys_interface() -> Option<String> {
    if let Ok(out) = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        && let Some(iface) = parse_macos_route_default(&String::from_utf8_lossy(&out.stdout))
    {
        return Some(iface);
    }
    if let Ok(out) = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        && let Some(iface) = parse_macos_netstat_default(&String::from_utf8_lossy(&out.stdout))
    {
        return Some(iface);
    }
    if let Ok(out) = Command::new("/usr/sbin/scutil").args(["--nwi"]).output()
        && let Some(iface) = parse_macos_scutil_nwi(&String::from_utf8_lossy(&out.stdout))
    {
        return Some(iface);
    }
    None
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
        if let Some(ifidx) = core_runtime::inbound::tun::active_macos_outbound_if_index()
            .or_else(default_macos_phys_ifindex)
        {
            const IP_BOUND_IF: libc::c_int = 25;
            const IPV6_BOUND_IF: libc::c_int = 125;
            unsafe {
                let (level, opt) = if addr.is_ipv6() {
                    (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
                } else {
                    (libc::IPPROTO_IP, IP_BOUND_IF)
                };
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    level,
                    opt,
                    &ifidx as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        if !addr.ip().is_loopback() {
            let active_tun_if = core_runtime::inbound::tun::active_win_outbound_if_index();
            let cached_phys = CACHED_WIN_PHYS_IFINDEX.load(std::sync::atomic::Ordering::Relaxed);
            let if_idx = active_tun_if
                .filter(|&idx| windows_if_is_eligible_phys(idx))
                .or_else(|| {
                    (cached_phys != 0 && windows_if_is_eligible_phys(cached_phys))
                        .then_some(cached_phys)
                })
                .or_else(default_windows_phys_ifindex);
            let worker_alive = read_core_pid_file().is_some_and(is_pid_alive);
            if if_idx.is_none() && (worker_alive || active_tun_if.is_some()) {
                return Err(std::io::Error::other(
                    "physical outbound interface unavailable while TUN is active",
                ));
            }
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
                if addr.is_ipv4() {
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
                } else {
                    let val = idx.to_ne_bytes();
                    unsafe {
                        let _ = setsockopt(
                            socket.as_raw_socket() as usize,
                            41, // IPPROTO_IPV6
                            31, // IPV6_UNICAST_IF
                            val.as_ptr(),
                            val.len() as i32,
                        );
                    }
                }
            }
        }
    }

    let res = socket.connect(addr).await;
    #[cfg(target_os = "windows")]
    if res.is_err() {
        refresh_cached_windows_phys_ifindex();
    }
    res
}

#[cfg(target_os = "windows")]
static CACHED_WIN_PHYS_IFINDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(target_os = "windows")]
pub fn refresh_cached_windows_phys_ifindex() {
    if let Some(idx) = default_windows_phys_ifindex()
        && windows_if_is_eligible_phys(idx)
    {
        CACHED_WIN_PHYS_IFINDEX.store(idx, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_os = "windows")]
fn windows_if_has_valid_phys_ipv4(if_idx: u32) -> bool {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibIpAddrRow {
        dw_addr: u32,
        dw_index: u32,
        dw_mask: u32,
        dw_bcast_addr: u32,
        dw_reasm_size: u32,
        unused1: u16,
        w_type: u16,
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetIpAddrTable(p_ip_addr_table: *mut u8, pdw_size: *mut u32, border: i32) -> u32;
    }

    let mut size: u32 = 0;
    let _ = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if !(4..=1024 * 1024).contains(&size) {
        return false;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr(), &mut size, 0) };
    if rc != 0 || buf.len() < 4 {
        return false;
    }
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<MibIpAddrRow>();
    let max_rows = (buf.len() - 4) / row_size;
    for i in 0..count.min(max_rows) {
        let row = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(4 + i * row_size) as *const MibIpAddrRow)
        };
        if row.dw_index == if_idx && row.dw_addr != 0 {
            let ip = std::net::Ipv4Addr::from(row.dw_addr.to_ne_bytes());
            let o = ip.octets();
            if !ip.is_loopback()
                && !ip.is_unspecified()
                && !(o[0] == 169 && o[1] == 254)
                && !is_fake_or_tun_ip(IpAddr::V4(ip))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MibIfRow {
    wsz_name: [u16; 256],
    dw_index: u32,
    dw_type: u32,
    dw_mtu: u32,
    dw_speed: u32,
    dw_phys_addr_len: u32,
    b_phys_addr: [u8; 8],
    dw_admin_status: u32,
    dw_oper_status: u32,
    dw_last_change: u32,
    dw_in_octets: u32,
    dw_in_ucast_pkts: u32,
    dw_in_nucast_pkts: u32,
    dw_in_discards: u32,
    dw_in_errors: u32,
    dw_in_unknown_protos: u32,
    dw_out_octets: u32,
    dw_out_ucast_pkts: u32,
    dw_out_nucast_pkts: u32,
    dw_out_discards: u32,
    dw_out_errors: u32,
    dw_out_qlen: u32,
    dw_descr_len: u32,
    b_descr: [u8; 256],
}

#[cfg(target_os = "windows")]
fn windows_if_is_non_virtual(if_idx: u32) -> bool {
    const MIB_IF_TYPE_LOOPBACK: u32 = 24;
    const IF_OPER_STATUS_CONNECTED: u32 = 4;
    const IF_OPER_STATUS_OPERATIONAL: u32 = 5;
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetIfEntry(p_if_row: *mut MibIfRow) -> u32;
    }
    if if_idx == 0 {
        return false;
    }
    let mut row: MibIfRow = unsafe { std::mem::zeroed() };
    row.dw_index = if_idx;
    if unsafe { GetIfEntry(&mut row) } != 0 {
        return false;
    }
    if row.dw_type == MIB_IF_TYPE_LOOPBACK {
        return false;
    }
    if row.dw_oper_status != IF_OPER_STATUS_CONNECTED
        && row.dw_oper_status != IF_OPER_STATUS_OPERATIONAL
    {
        return false;
    }
    let len = (row.dw_descr_len as usize).min(row.b_descr.len());
    let descr = String::from_utf8_lossy(&row.b_descr[..len]);
    !is_virtual_or_tun_adapter_name(&descr)
}

#[cfg(target_os = "windows")]
fn windows_if_is_eligible_phys(if_idx: u32) -> bool {
    if_idx != 0 && windows_if_has_valid_phys_ipv4(if_idx) && windows_if_is_non_virtual(if_idx)
}

#[cfg(target_os = "windows")]
fn default_windows_phys_ifindex() -> Option<u32> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibIpForwardRow {
        dw_forward_dest: u32,
        dw_forward_mask: u32,
        dw_forward_policy: u32,
        dw_forward_next_hop: u32,
        dw_forward_if_index: u32,
        dw_forward_type: u32,
        dw_forward_proto: u32,
        dw_forward_age: u32,
        dw_forward_next_hop_as: u32,
        dw_forward_metric1: u32,
        dw_forward_metric2: u32,
        dw_forward_metric3: u32,
        dw_forward_metric4: u32,
        dw_forward_metric5: u32,
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetIpForwardTable(p_ip_forward_table: *mut u8, pdw_size: *mut u32, b_order: i32) -> u32;
        fn GetBestInterface(dw_dest_addr: u32, pdw_best_if_index: *mut u32) -> u32;
    }

    if let Some(core_idx) = core_runtime::inbound::tun::active_win_outbound_if_index()
        && windows_if_is_eligible_phys(core_idx)
    {
        return Some(core_idx);
    }

    let mut size: u32 = 0;
    let _ = unsafe { GetIpForwardTable(std::ptr::null_mut(), &mut size, 1) };
    if (4..=2 * 1024 * 1024).contains(&size) {
        let mut buf = vec![0u8; size as usize];
        if unsafe { GetIpForwardTable(buf.as_mut_ptr(), &mut size, 1) } == 0 && buf.len() >= 4 {
            let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let row_size = std::mem::size_of::<MibIpForwardRow>();
            let max_rows = (buf.len() - 4) / row_size;
            let mut candidates: Vec<(u32, u32)> = Vec::new();
            for i in 0..count.min(max_rows) {
                let row = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr().add(4 + i * row_size) as *const MibIpForwardRow
                    )
                };
                if row.dw_forward_dest == 0
                    && row.dw_forward_mask == 0
                    && row.dw_forward_if_index != 0
                {
                    candidates.push((row.dw_forward_metric1, row.dw_forward_if_index));
                }
            }
            candidates.sort_by_key(|c| c.0);
            for (_, idx) in candidates {
                if windows_if_is_eligible_phys(idx) {
                    return Some(idx);
                }
            }
        }
    }

    let mut best_if: u32 = 0;
    let rc = unsafe { GetBestInterface(0x0808_0808, &mut best_if) };
    if rc == 0 && windows_if_is_eligible_phys(best_if) {
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
    if let Some(iface) = detect_macos_phys_interface()
        && let Ok(cstr) = std::ffi::CString::new(iface)
    {
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx != 0 {
            return Some(idx);
        }
    }
    for idx_num in 0..=9 {
        let candidate = format!("en{idx_num}");
        if let Ok(cstr) = std::ffi::CString::new(candidate) {
            let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
            if idx != 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn proxy_points_to_us() -> bool {
    let our_host = "127.0.0.1";
    let our_port = PROXY_PORT.to_string();
    let our_addr = format!("{our_host}:{our_port}");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let enabled = Command::new("reg")
            .args(["query", REG_PATH, "/v", "ProxyEnable"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()
            .is_some_and(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.contains("0x1") || s.trim().ends_with(" 1")
            });
        if !enabled {
            return false;
        }
        if let Ok(out) = Command::new("reg")
            .args(["query", REG_PATH, "/v", "ProxyServer"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            return text.contains(&our_addr);
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        for service in list_macos_network_services() {
            if let Ok(out) = Command::new("/usr/sbin/networksetup")
                .args(["-getwebproxy", &service])
                .output()
            {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("Enabled: Yes")
                    && text.contains(our_host)
                    && text.contains(&our_port)
                {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    {
        let _ = our_addr;
        if let Ok(mode_out) = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
            && String::from_utf8_lossy(&mode_out.stdout).contains("manual")
            && let Ok(host_out) = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy.http", "host"])
                .output()
            && String::from_utf8_lossy(&host_out.stdout).contains(our_host)
            && let Ok(port_out) = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy.http", "port"])
                .output()
            && String::from_utf8_lossy(&port_out.stdout).contains(&our_port)
        {
            return true;
        }
        for kread in ["kreadconfig6", "kreadconfig5"] {
            if let Ok(pt) = Command::new(kread)
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                ])
                .output()
                && pt.status.success()
                && String::from_utf8_lossy(&pt.stdout).trim() == "1"
                && let Ok(hp) = Command::new(kread)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "httpProxy",
                    ])
                    .output()
                && String::from_utf8_lossy(&hp.stdout).contains(&our_addr)
            {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (our_host, our_port, our_addr);
        false
    }
}

#[cfg(target_os = "windows")]
fn notify_wininet_proxy_changed() {
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    #[link(name = "wininet")]
    unsafe extern "system" {
        fn InternetSetOptionW(
            h_internet: *mut std::ffi::c_void,
            dw_option: u32,
            lp_buffer: *const std::ffi::c_void,
            dw_buffer_length: u32,
        ) -> i32;
    }
    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> Vec<String> {
    let Ok(out) = Command::new("/usr/sbin/networksetup")
        .arg("-listallnetworkservices")
        .output()
    else {
        return vec![
            "Wi-Fi".to_string(),
            "Ethernet".to_string(),
            "USB 10/100/1000 LAN".to_string(),
        ];
    };
    let services: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect();
    if services.is_empty() {
        vec![
            "Wi-Fi".to_string(),
            "Ethernet".to_string(),
            "USB 10/100/1000 LAN".to_string(),
        ]
    } else {
        services
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_system_proxy_direct(enable: bool, port: u16) -> bool {
    let p = port.to_string();
    let mut any_ok = false;
    let mut all_ok = true;
    for service in list_macos_network_services() {
        if enable {
            let s1 = Command::new("/usr/sbin/networksetup")
                .args(["-setwebproxy", &service, "127.0.0.1", &p])
                .status()
                .is_ok_and(|s| s.success());
            let s2 = Command::new("/usr/sbin/networksetup")
                .args(["-setwebproxystate", &service, "on"])
                .status()
                .is_ok_and(|s| s.success());
            let s3 = Command::new("/usr/sbin/networksetup")
                .args(["-setsecurewebproxy", &service, "127.0.0.1", &p])
                .status()
                .is_ok_and(|s| s.success());
            let s4 = Command::new("/usr/sbin/networksetup")
                .args(["-setsecurewebproxystate", &service, "on"])
                .status()
                .is_ok_and(|s| s.success());
            let s5 = Command::new("/usr/sbin/networksetup")
                .args(["-setsocksfirewallproxy", &service, "127.0.0.1", &p])
                .status()
                .is_ok_and(|s| s.success());
            let s6 = Command::new("/usr/sbin/networksetup")
                .args(["-setsocksfirewallproxystate", &service, "on"])
                .status()
                .is_ok_and(|s| s.success());
            let _ = Command::new("/usr/sbin/networksetup")
                .args([
                    "-setproxybypassdomains",
                    &service,
                    "127.0.0.1",
                    "localhost",
                    "*.local",
                ])
                .status();
            if s1 && s2 && s3 && s4 && s5 && s6 {
                any_ok = true;
            } else {
                all_ok = false;
            }
        } else {
            let s1 = Command::new("/usr/sbin/networksetup")
                .args(["-setwebproxystate", &service, "off"])
                .status()
                .is_ok_and(|s| s.success());
            let s2 = Command::new("/usr/sbin/networksetup")
                .args(["-setsecurewebproxystate", &service, "off"])
                .status()
                .is_ok_and(|s| s.success());
            let s3 = Command::new("/usr/sbin/networksetup")
                .args(["-setsocksfirewallproxystate", &service, "off"])
                .status()
                .is_ok_and(|s| s.success());
            if s1 && s2 && s3 {
                any_ok = true;
            } else {
                all_ok = false;
            }
        }
    }
    any_ok && all_ok
}

#[cfg(target_os = "windows")]
fn query_reg_sz_or_dword(reg_path: &str, name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new("reg")
        .args(["query", reg_path, "/v", name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(name) {
            let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
            if parts.len() >= 3 {
                return Some(parts[2].trim().to_string());
            }
            if let Some((_, val)) = trimmed
                .rsplit_once("REG_SZ")
                .or_else(|| trimmed.rsplit_once("REG_DWORD"))
            {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

pub fn set_system_proxy(enable: bool) {
    #[cfg(target_os = "linux")]
    {
        let p_str = PROXY_PORT.to_string();
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
                    .args(["set", &schema, "port", &p_str])
                    .status();
            }
            for kwrite in ["kwriteconfig6", "kwriteconfig5"] {
                if Command::new(kwrite)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "1",
                    ])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    let http_val = format!("http://127.0.0.1:{p_str}");
                    let socks_val = format!("socks://127.0.0.1:{p_str}");
                    let _ = Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "httpProxy",
                            &http_val,
                        ])
                        .status();
                    let _ = Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "httpsProxy",
                            &http_val,
                        ])
                        .status();
                    let _ = Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "socksProxy",
                            &socks_val,
                        ])
                        .status();
                    break;
                }
            }
        } else {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .status();
            for kwrite in ["kwriteconfig6", "kwriteconfig5"] {
                if Command::new(kwrite)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "0",
                    ])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if !apply_macos_system_proxy_direct(enable, PROXY_PORT) && macos_helper::status().0 {
            let _ = macos_helper::sysproxy(enable, PROXY_PORT);
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        const PROXY_BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";
        let backup_path = app_data_dir().join("prev_proxy.json");

        if enable {
            if !proxy_points_to_us() && !backup_path.exists() {
                let prev_enable =
                    query_reg_sz_or_dword(REG_PATH, "ProxyEnable").unwrap_or_default();
                let prev_server =
                    query_reg_sz_or_dword(REG_PATH, "ProxyServer").unwrap_or_default();
                let prev_override =
                    query_reg_sz_or_dword(REG_PATH, "ProxyOverride").unwrap_or_default();
                if !prev_server.is_empty() || prev_enable == "0x1" || prev_enable == "1" {
                    let snap = json!({
                        "enable": prev_enable,
                        "server": prev_server,
                        "override": prev_override,
                    });
                    let _ = write_private_file(&backup_path, snap.to_string().as_bytes());
                }
            }
            let _ = Command::new("reg")
                .args([
                    "add",
                    REG_PATH,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = Command::new("reg")
                .args([
                    "add",
                    REG_PATH,
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
            let _ = Command::new("reg")
                .args([
                    "add",
                    REG_PATH,
                    "/v",
                    "ProxyOverride",
                    "/t",
                    "REG_SZ",
                    "/d",
                    PROXY_BYPASS,
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        } else {
            let restored = if let Ok(raw) = fs::read_to_string(&backup_path)
                && let Ok(doc) = serde_json::from_str::<Value>(&raw)
            {
                let _ = fs::remove_file(&backup_path);
                let prev_en = doc.get("enable").and_then(Value::as_str).unwrap_or("0");
                let prev_en_num = if prev_en == "0x1" || prev_en == "1" {
                    "1"
                } else {
                    "0"
                };
                let _ = Command::new("reg")
                    .args([
                        "add",
                        REG_PATH,
                        "/v",
                        "ProxyEnable",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        prev_en_num,
                        "/f",
                    ])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
                if let Some(srv) = doc
                    .get("server")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    let _ = Command::new("reg")
                        .args([
                            "add",
                            REG_PATH,
                            "/v",
                            "ProxyServer",
                            "/t",
                            "REG_SZ",
                            "/d",
                            srv,
                            "/f",
                        ])
                        .creation_flags(CREATE_NO_WINDOW)
                        .status();
                } else {
                    let _ = Command::new("reg")
                        .args(["delete", REG_PATH, "/v", "ProxyServer", "/f"])
                        .creation_flags(CREATE_NO_WINDOW)
                        .status();
                }
                if let Some(ov) = doc
                    .get("override")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    let _ = Command::new("reg")
                        .args([
                            "add",
                            REG_PATH,
                            "/v",
                            "ProxyOverride",
                            "/t",
                            "REG_SZ",
                            "/d",
                            ov,
                            "/f",
                        ])
                        .creation_flags(CREATE_NO_WINDOW)
                        .status();
                }
                true
            } else {
                false
            };

            if !restored {
                let _ = Command::new("reg")
                    .args([
                        "add",
                        REG_PATH,
                        "/v",
                        "ProxyEnable",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        "0",
                        "/f",
                    ])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
                if proxy_points_to_us() {
                    let _ = Command::new("reg")
                        .args(["delete", REG_PATH, "/v", "ProxyServer", "/f"])
                        .creation_flags(CREATE_NO_WINDOW)
                        .status();
                }
            }
        }
        notify_wininet_proxy_changed();
    }
}

pub fn flush_os_dns() {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("resolvectl").arg("flush-caches").status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .status();
        let _ = Command::new("/usr/bin/killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
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
    crate::state::detect_country_code(name)
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
                    if !no_display
                        && !name.is_empty()
                        && !exec.is_empty()
                        && seen.insert(exec.clone())
                    {
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

    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

pub fn build_subscription_servers_list(nodes: &[Value], handle: &str) -> Vec<Value> {
    let mut leaf_by_tag: HashMap<String, BalancerMember> = HashMap::new();
    let mut leaf_entries: Vec<(String, String, String, bool, String)> = Vec::new();

    for (idx, node) in nodes.iter().enumerate() {
        let ty = node
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if ty == "urltest" || is_stub_or_dummy_outbound(node) {
            continue;
        }
        let Some(share_link) = node_to_share_link(node) else {
            continue;
        };
        let raw_name = node
            .get("tag")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("Узел #{}", idx + 1));
        let country = detect_country_code(&raw_name);
        let name = crate::state::clean_node_display_name(&raw_name);
        let is_hidden = node
            .get("__tachyon_hidden")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let server_host = node
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        leaf_by_tag.insert(
            raw_name.clone(),
            BalancerMember {
                name: name.clone(),
                vless: share_link.clone(),
                country: country.clone(),
            },
        );
        leaf_by_tag.insert(
            name.clone(),
            BalancerMember {
                name: name.clone(),
                vless: share_link.clone(),
                country: country.clone(),
            },
        );
        leaf_entries.push((name, share_link, country, is_hidden, server_host));
    }

    let mut servers = Vec::new();
    let mut explicit_balancer_count = 0usize;

    for node in nodes {
        let ty = node
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if ty != "urltest" {
            continue;
        }
        let Some(member_tags) = node.get("outbounds").and_then(Value::as_array) else {
            continue;
        };
        let mut members = Vec::new();
        for mt in member_tags {
            if let Some(t_str) = mt.as_str()
                && let Some(m) = leaf_by_tag.get(t_str)
                && !is_mtproto_uri(&m.vless)
            {
                members.push(m.clone());
            }
        }
        if members.is_empty() {
            continue;
        }
        explicit_balancer_count += 1;
        let group_name = node
            .get("remark")
            .or_else(|| node.get("tag"))
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("Балансировщик #{explicit_balancer_count}"));
        let mode = node
            .get("mode")
            .and_then(Value::as_str)
            .map(normalize_balancer_mode)
            .unwrap_or("stability")
            .to_string();
        let url = node
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(default_balancer_url);
        let interval = node
            .get("interval")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(default_balancer_interval);
        let tolerance = node
            .get("tolerance")
            .and_then(Value::as_u64)
            .map(|v| v as u32)
            .unwrap_or_else(default_balancer_tolerance);

        let mut group_country = detect_country_code(&group_name);
        if group_country == "xx" {
            let first_cc = members[0].country.as_str();
            if first_cc != "xx" && members.iter().all(|m| m.country == first_cc) {
                group_country = first_cc.to_string();
            }
        }

        let payload = BalancerPayload {
            name: group_name.clone(),
            mode: mode.clone(),
            url,
            interval,
            tolerance,
            pool: default_balancer_pool(),
            pool_tolerance: default_balancer_pool_tolerance(),
            sticky_hash: default_balancer_sticky_hash(),
            quota_mib: default_balancer_quota_mib(),
            members: members.clone(),
        };
        let bal_uri = encode_balancer_uri(&payload);
        servers.push(json!({
            "id": format!("sub-bal-{explicit_balancer_count}"),
            "name": group_name,
            "vless": bal_uri,
            "country": group_country,
            "isBalancer": true,
            "balancerMode": mode,
            "memberCount": members.len()
        }));
    }

    if explicit_balancer_count == 0 && leaf_entries.len() >= 2 {
        let valid_members: Vec<BalancerMember> = leaf_entries
            .iter()
            .filter(|(_, vless, _, _, host)| {
                let h = host.trim();
                !is_mtproto_uri(vless)
                    && !h.is_empty()
                    && h != "0.0.0.0"
                    && h != "127.0.0.1"
                    && !h.eq_ignore_ascii_case("localhost")
                    && !h.starts_with("127.")
            })
            .map(|(name, vless, country, _, _)| BalancerMember {
                name: name.clone(),
                vless: vless.clone(),
                country: country.clone(),
            })
            .collect();

        if valid_members.len() >= 2 {
            let auto_name = if handle.trim().is_empty() || handle.trim() == "Подписка" {
                "Автобалансировщик".to_string()
            } else {
                format!("Автобалансировщик · {}", handle.trim())
            };
            let payload = BalancerPayload {
                name: auto_name.clone(),
                mode: "stability".to_string(),
                url: default_balancer_url(),
                interval: default_balancer_interval(),
                tolerance: default_balancer_tolerance(),
                pool: default_balancer_pool(),
                pool_tolerance: default_balancer_pool_tolerance(),
                sticky_hash: default_balancer_sticky_hash(),
                quota_mib: default_balancer_quota_mib(),
                members: valid_members.clone(),
            };
            let bal_uri = encode_balancer_uri(&payload);
            servers.push(json!({
                "id": "sub-bal-auto",
                "name": auto_name,
                "vless": bal_uri,
                "country": "xx",
                "isBalancer": true,
                "balancerMode": "stability",
                "memberCount": valid_members.len()
            }));
        }
    }

    for (idx, (name, share_link, country, is_hidden, _)) in leaf_entries.into_iter().enumerate() {
        if explicit_balancer_count > 0 && is_hidden {
            continue;
        }
        servers.push(json!({
            "id": format!("sub-{}", idx + 1),
            "name": name,
            "vless": share_link,
            "country": country
        }));
    }

    servers
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balancer_uri_round_trip_and_config_generation() {
        let m1 = BalancerMember {
            name: "NL-1 Amsterdam".to_string(),
            vless: "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls&type=tcp&sni=nl1.example.com#NL-1".to_string(),
            country: "nl".to_string(),
        };
        let m2 = BalancerMember {
            name: "DE-1 Frankfurt".to_string(),
            vless: "vless://22222222-2222-2222-2222-222222222222@198.51.100.20:443?security=tls&type=tcp&sni=de1.example.com#DE-1".to_string(),
            country: "de".to_string(),
        };
        let payload = BalancerPayload {
            name: "EU Smart Balancer".to_string(),
            mode: "stability".to_string(),
            url: default_balancer_url(),
            interval: default_balancer_interval(),
            tolerance: 50,
            pool: 4,
            pool_tolerance: 80,
            sticky_hash: default_balancer_sticky_hash(),
            quota_mib: 256,
            members: vec![m1, m2],
        };
        let uri = encode_balancer_uri(&payload);
        assert!(uri.starts_with(BALANCER_URI_PREFIX));

        let decoded = decode_balancer_uri(&uri).expect("decode balancer uri");
        assert_eq!(decoded.name, "EU Smart Balancer");
        assert_eq!(decoded.members.len(), 2);

        let mgr = VpnManager::new(Arc::new(|_| {}));
        for mode in [
            "stability",
            "least_test",
            "sticky",
            "least_load",
            "weighted",
            "passive",
            "priority",
            "hedged",
            "throughput",
            "quota",
            "failover",
            "round_robin",
        ] {
            let req = json!({
                "vless": uri,
                "mode": "proxy",
                "route": "all",
                "balancerMode": mode,
                "balancer": {
                    "pool": 4,
                    "poolTolerance": 80,
                    "stickyHash": ["domain", "dest_ip", "process"],
                    "quotaMib": 512
                }
            });
            let opts = ConnectOptions::parse(&req.to_string()).expect("parse options");
            let (cfg, has_node) = mgr.build_config(&opts).expect("build config");
            assert!(has_node);
            let cfg_str = serde_json::to_string(&cfg).expect("serialize config");
            core_config::check_str(&cfg_str)
                .unwrap_or_else(|e| panic!("core_config::check_str failed for mode {mode}: {e}"));
        }
    }

    #[test]
    fn subscription_balancers_hide_internal_members_and_auto_synthesize() {
        let raw_two_nodes = "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls&type=tcp#NL-1\nvless://22222222-2222-2222-2222-222222222222@198.51.100.20:443?security=tls&type=tcp#DE-1";
        let parsed = parse_subscription_payload_with_hwid(raw_two_nodes, None, None)
            .expect("parse two nodes");
        let list = build_subscription_servers_list(&parsed, "TestSub");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["isBalancer"], json!(true));
        assert_eq!(list[0]["memberCount"], json!(2));
    }

    #[test]
    fn github_updater_semver_scoring_and_sha256_verification() {
        assert!(is_newer_semver("v0.3.4", "0.3.3"));
        assert!(is_newer_semver("0.4.0", "0.3.9"));
        assert!(!is_newer_semver("0.3.3", "0.3.3"));
        assert!(!is_newer_semver("0.3.2", "0.3.3"));

        #[cfg(target_os = "windows")]
        {
            assert!(score_release_asset_for_current_os("Tachyon-windows-x86_64.exe") >= 100);
            assert!(score_release_asset_for_current_os("Tachyon-0.4.0-x86_64.msi") >= 75);
            assert!(
                score_release_asset_for_current_os("Tachyon-0.4.0-x86_64.msi")
                    > score_release_asset_for_current_os("Tachyon-windows-x86_64.zip")
            );
            assert!(
                score_release_asset_for_current_os("Tachyon-windows-x86_64.exe")
                    > score_release_asset_for_current_os("Tachyon-windows-x86_64.zip")
            );
            #[cfg(target_arch = "x86_64")]
            assert!(
                score_release_asset_for_current_os("Tachyon-windows-x86_64.exe")
                    > score_release_asset_for_current_os("Tachyon-windows-arm64.exe")
            );
            assert_eq!(score_release_asset_for_current_os("SHA256SUMS.txt"), 0);
        }

        use sha2::{Digest, Sha256};
        let payload = b"MZ-tachyon-test-binary";
        let expected_hex = Sha256::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let sums = format!("{expected_hex}  Tachyon-windows-x86_64.exe\n");
        assert!(verify_asset_sha256(payload, "Tachyon-windows-x86_64.exe", &sums).is_ok());

        let bad_sums = "0000000000000000000000000000000000000000000000000000000000000000  Tachyon-windows-x86_64.exe\n";
        assert!(verify_asset_sha256(payload, "Tachyon-windows-x86_64.exe", bad_sums).is_err());
    }

    #[test]
    fn tachyon_core_0_4_0_protocols_and_containers_roundtrip() {
        let mgr = VpnManager::new(Arc::new(|_| {}));

        // 1. Test new 0.4.0 share links (wdtt, tewfai, mieru, tuic, anytls, naive)
        let uris = [
            "wdtt://mywdttpass@198.51.100.10:56000?mode=wg&obfs=audio&hashes=0123456789abcdef#WDTT-1",
            "tewfai://secretpass@198.51.100.11:443?sni=example.com&pqc=true&fec=true#Tewfai-PQC",
            "mieru://alice:pa55@198.51.100.12:8443?transport=TCP&multiplexing=MULTIPLEXING_HIGH#Mieru-1",
            "tuic://11111111-1111-1111-1111-111111111111:secret@198.51.100.13:443?congestion_control=bbr&sni=example.com#TUIC-1",
            "anytls://secret@198.51.100.14:443?sni=example.com#AnyTLS-1",
            "naive+https://user:pass@198.51.100.15:443#Naive-1",
        ];

        for uri in uris {
            let opts =
                ConnectOptions::parse(uri).expect("ConnectOptions::parse should accept 0.4.0 URI");
            let (cfg, has_node) = mgr.build_config(&opts).expect("build_config for 0.4.0 URI");
            assert!(has_node);
            let cfg_str = serde_json::to_string(&cfg).expect("serialize config");
            core_config::check_str(&cfg_str)
                .unwrap_or_else(|e| panic!("core_config::check_str failed for {uri}: {e}"));
        }

        // 2. Test inline node URI fallback (fptn / sudoku / ssh)
        let fptn_node = json!({
            "type": "fptn",
            "tag": "FPTN-NL",
            "server": "198.51.100.50",
            "server_port": 443,
            "sni": "fptn.example.com",
            "md5_fingerprint": "0123456789abcdef0123456789abcdef"
        });
        let inline_link = node_to_share_link(&fptn_node).expect("node_to_share_link for fptn");
        assert!(inline_link.starts_with(INLINE_NODE_URI_PREFIX));
        let parsed_back = parse_node_uri(&inline_link).expect("parse_node_uri for inline fptn");
        assert_eq!(parsed_back["type"], json!("fptn"));
        assert_eq!(parsed_back["server"], json!("198.51.100.50"));

        // 3. Test happ://add redirect resolution & stub filtering
        let resolved = resolve_subscription_input(
            "happ://add/https://example.com/sub",
            Some("0123456789abcdef"),
            None,
        )
        .expect("resolve happ://add");
        assert_eq!(resolved, "https://example.com/sub");

        let stub_and_real = vec![
            json!({
                "type": "vless",
                "tag": "⏳ Тариф закончился",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000"
            }),
            fptn_node,
        ];
        let srv_list = build_subscription_servers_list(&stub_and_real, "Test040");
        assert_eq!(srv_list.len(), 1);
        assert_eq!(srv_list[0]["name"], json!("FPTN-NL"));
    }

    #[test]
    fn test_awg_all_versions_and_formats() {
        use base64::Engine as _;
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write as _;

        let mgr = VpnManager::new(Arc::new(|_| {}));
        let priv_k = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let pub_k = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
        let hpk = "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8td28=";

        // 1. AWG 1.0 / 1.5 / 2.0 / 3.x full .conf (multiline)
        let awg2_conf = format!(
            "[Interface]\n\
             PrivateKey = {priv_k}\n\
             Address = 10.8.1.2/32\n\
             MTU = 1360\n\
             Jc = 5\n\
             Jmin = 50\n\
             Jmax = 1000\n\
             S1 = 24\n\
             S2 = 32\n\
             S3 = 16\n\
             S4 = 20\n\
             H1 = 100-200\n\
             H2 = 300-400\n\
             H3 = 500-600\n\
             H4 = 700-800\n\
             I1 = <b 0xc000000001><rc 8>\n\
             ID = example.com\n\
             IP = quic\n\
             HeaderProtectionKey = {hpk}\n\
             ContentPaddingAddition = 0-64\n\
             RandomTrailers = true\n\
             DisableCookies = 1\n\
             \n\
             [Peer]\n\
             PublicKey = {pub_k}\n\
             Endpoint = 198.51.100.77:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25\n"
        );

        let nodes =
            parse_subscription_payload_with_hwid(&awg2_conf, None, None).expect("parse awg2 conf");
        assert_eq!(nodes.len(), 1);
        let share_link = node_to_share_link(&nodes[0]).expect("awg2 node_to_share_link");
        assert!(
            share_link.starts_with("awg://"),
            "expected awg:// scheme, got {share_link}"
        );

        let opts = ConnectOptions::parse(&share_link).expect("ConnectOptions::parse awg2 link");
        let (cfg, _) = mgr.build_config(&opts).expect("build_config awg2 link");
        core_config::check_str(&cfg.to_string()).expect("core_config::check_str awg2");

        // 2. Single-line pasted .conf (when browser <input> strips newlines)
        let single_line_conf = awg2_conf.replace('\n', " ");
        let sl_nodes = parse_subscription_payload_with_hwid(&single_line_conf, None, None)
            .expect("parse single-line pasted .conf");
        assert_eq!(sl_nodes.len(), 1);
        let sl_link = node_to_share_link(&sl_nodes[0]).expect("sl_link");
        assert!(sl_link.starts_with("awg://"));

        // 3. Direct ConnectOptions::parse with raw .conf
        let raw_conf_opts =
            ConnectOptions::parse(&awg2_conf).expect("ConnectOptions::parse raw .conf");
        let (raw_conf_cfg, _) = mgr
            .build_config(&raw_conf_opts)
            .expect("build_config raw .conf");
        core_config::check_str(&raw_conf_cfg.to_string()).expect("check_str raw .conf");

        // 4. Amnezia `vpn://` Qt qCompress container with `amnezia-awg2`
        let amnezia_json = json!({
            "containers": [{
                "container": "amnezia-awg2",
                "awg": {
                    "last_config": awg2_conf
                }
            }],
            "defaultContainer": "amnezia-awg2",
            "description": "Amnezia AWG 2.0 Server",
            "hostName": "198.51.100.77"
        })
        .to_string();
        let raw_bytes = amnezia_json.as_bytes();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw_bytes).unwrap();
        let compressed = enc.finish().unwrap();
        let mut qcompress_buf = Vec::with_capacity(4 + compressed.len());
        qcompress_buf.extend_from_slice(&(raw_bytes.len() as u32).to_be_bytes());
        qcompress_buf.extend_from_slice(&compressed);
        let vpn_uri = format!(
            "vpn://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&qcompress_buf)
        );

        let vpn_nodes =
            parse_subscription_payload_with_hwid(&vpn_uri, None, None).expect("parse vpn://");
        assert_eq!(vpn_nodes.len(), 1);
        let vpn_link = node_to_share_link(&vpn_nodes[0]).expect("vpn:// node_to_share_link");
        assert!(vpn_link.starts_with("awg://"));
        let vpn_opts = ConnectOptions::parse(&vpn_link).expect("ConnectOptions vpn_link");
        let (vpn_cfg, _) = mgr.build_config(&vpn_opts).expect("build_config vpn_link");
        core_config::check_str(&vpn_cfg.to_string()).expect("check_str vpn_link");

        // 5. Legacy `amneziawg://...?pub=...&ip=172.16.0.2/32` URI (must not collide with AWG masque `ip`)
        let legacy_warp_uri = format!(
            "amneziawg://{}@162.159.192.1:2408?pub={}&ip=172.16.0.2/32&mtu=1280&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#WARP",
            core_config::subscription::percent_encode_component(priv_k),
            core_config::subscription::percent_encode_component(pub_k),
        );
        let warp_opts =
            ConnectOptions::parse(&legacy_warp_uri).expect("ConnectOptions legacy_warp_uri");
        let (warp_cfg, _) = mgr
            .build_config(&warp_opts)
            .expect("build_config legacy_warp_uri");
        core_config::check_str(&warp_cfg.to_string()).expect("check_str legacy_warp_uri");
        assert!(warp_cfg["endpoints"][0].get("ip").is_none());

        // 6. End-to-end integration test: PersistedState::build_connect_payload -> ConnectOptions::parse -> build_config
        let mut st = crate::state::PersistedState::default();
        st.servers.push(crate::state::ServerNode {
            id: "node-awg-1".to_string(),
            name: "Cloudflare WARP (AWG)".to_string(),
            vless: share_link.clone(),
            country: "us".to_string(),
            sub_id: None,
            is_balancer: false,
            balancer_mode: None,
            member_count: None,
            ping_ms: Some(18),
            ping_at: None,
            alive: Some(true),
        });
        st.active_id = "node-awg-1".to_string();
        st.vpn_prefs.mode = "tun".to_string();
        st.vpn_prefs.route = "all".to_string();
        st.desync_prefs.enabled = true;
        st.desync_prefs.preset = "auto".to_string();
        let json_payload = st.build_connect_payload(None);
        let parsed_opts =
            ConnectOptions::parse(&json_payload).expect("ConnectOptions from PersistedState");
        assert!(!parsed_opts.proxy_mode && !parsed_opts.block_only);
        assert_eq!(parsed_opts.route, RouteMode::All);
        assert!(parsed_opts.desync.enabled);
        let (state_cfg, _) = mgr
            .build_config(&parsed_opts)
            .expect("build_config from PersistedState");
        core_config::check_str(&state_cfg.to_string()).expect("check_str from PersistedState");
        assert_eq!(state_cfg["endpoints"][0]["type"], "wireguard");
        // Verify TUN MTU is clamped down to the AWG endpoint MTU (1360)
        assert_eq!(state_cfg["inbounds"][0]["mtu"], 1360);

        // 7. Desync-only mode WITHOUT any subscription or server nodes
        let empty_st = crate::state::PersistedState::default();
        assert!(empty_st.servers.is_empty());
        assert!(empty_st.subscriptions.is_empty());
        let desync_only_payload = empty_st.build_connect_payload(None);
        let desync_only_opts = ConnectOptions::parse(&desync_only_payload)
            .expect("ConnectOptions for desync-only without servers");
        assert_eq!(desync_only_opts.route, RouteMode::DesyncOnly);
        assert!(desync_only_opts.vless.is_empty());
        assert!(desync_only_opts.desync.enabled);
        let (desync_only_cfg, has_main_node) = mgr
            .build_config(&desync_only_opts)
            .expect("build_config for desync-only without servers");
        assert!(!has_main_node);
        core_config::check_str(&desync_only_cfg.to_string())
            .expect("check_str for desync-only without servers");
        assert_eq!(desync_only_cfg["route"]["final"], "DESYNC");
        assert!(
            desync_only_cfg["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["tag"] == "DESYNC")
        );
    }

    #[test]
    fn test_tachyon_core_0_5_3_desync_wscale_anticheat_order_and_csqtt_v2() {
        let mgr = VpnManager::new(Arc::new(|_| {}));

        // 1. wsize=1, wscale=1 и lists_override_game_bypass=true (по умолчанию)
        let mut st = crate::state::PersistedState::default();
        st.desync_prefs.enabled = true;
        st.desync_prefs.wsize = 1;
        st.desync_prefs.wscale = Some(1);
        st.desync_prefs.anticheat_bypass = true;
        st.desync_prefs.lists_override_game_bypass = true;
        st.custom_rules.push(crate::state::CustomRule {
            id: "r-cdn".to_string(),
            rule_type: "domain".to_string(),
            value: "cloudfront.net".to_string(),
            action: "desync".to_string(),
            time_window: String::new(),
        });

        let payload_on = st.build_connect_payload(None);
        let opts_on = ConnectOptions::parse(&payload_on).expect("parse opts lists_override=true");
        assert_eq!(opts_on.desync.wsize, 1);
        assert_eq!(opts_on.desync.wscale, Some(1));
        assert!(opts_on.desync.lists_override_game_bypass);

        let (cfg_on, _) = mgr
            .build_config(&opts_on)
            .expect("build_config lists_override=true");
        core_config::check_str(&cfg_on.to_string()).expect("check_str lists_override=true");

        let desync_ob = cfg_on["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "DESYNC")
            .expect("DESYNC outbound");
        assert_eq!(desync_ob["wsize"], json!(1));
        assert_eq!(desync_ob["wscale"], json!(1));

        let rules_on = cfg_on["route"]["rules"].as_array().unwrap();
        let idx_auth_domain = rules_on
            .iter()
            .position(|r| {
                r.get("domain_suffix")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|x| x == "demonware.net"))
            })
            .expect("anticheat auth domain rule");
        let idx_ac_udp = rules_on
            .iter()
            .position(|r| {
                r.get("network") == Some(&json!("udp"))
                    && r.get("process_name").is_some()
                    && r.get("outbound") == Some(&json!("direct"))
            })
            .expect("anticheat UDP rule");
        let idx_custom_cdn = rules_on
            .iter()
            .position(|r| {
                r.get("outbound") == Some(&json!("DESYNC"))
                    && r.get("domain_suffix")
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| a.iter().any(|x| x == "cloudfront.net"))
            })
            .expect("custom cloudfront desync rule");
        let idx_ac_full = rules_on
            .iter()
            .position(|r| {
                r.get("network").is_none()
                    && r.get("process_name")
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| a.iter().any(|x| x == "cod.exe"))
            })
            .expect("full anticheat process rule");

        assert!(idx_auth_domain < idx_custom_cdn);
        assert!(idx_ac_udp < idx_custom_cdn);
        assert!(idx_custom_cdn < idx_ac_full);

        // Discord Voice UDP range 19294:19344 включён в DESYNC
        assert!(rules_on.iter().any(|r| {
            r.get("network") == Some(&json!("udp"))
                && r.get("outbound") == Some(&json!("DESYNC"))
                && r.get("port_range")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|x| x == "19294:19344"))
        }));

        // 2. lists_override_game_bypass = false: полное правило античита идёт ДО списков
        st.desync_prefs.lists_override_game_bypass = false;
        let payload_off = st.build_connect_payload(None);
        let opts_off =
            ConnectOptions::parse(&payload_off).expect("parse opts lists_override=false");
        let (cfg_off, _) = mgr
            .build_config(&opts_off)
            .expect("build_config lists_override=false");
        core_config::check_str(&cfg_off.to_string()).expect("check_str lists_override=false");
        let rules_off = cfg_off["route"]["rules"].as_array().unwrap();
        let idx_ac_full_off = rules_off
            .iter()
            .position(|r| {
                r.get("network").is_none()
                    && r.get("process_name")
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| a.iter().any(|x| x == "cod.exe"))
            })
            .expect("full anticheat process rule when override=false");
        let idx_custom_cdn_off = rules_off
            .iter()
            .position(|r| {
                r.get("outbound") == Some(&json!("DESYNC"))
                    && r.get("domain_suffix")
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| a.iter().any(|x| x == "cloudfront.net"))
            })
            .expect("custom cloudfront desync rule when override=false");
        assert!(idx_ac_full_off < idx_custom_cdn_off);

        // 3. csqtt:// v2 (AES-256-GCM) из tachyon-core 0.5.3
        let csqtt_v2_uri = "csqtt://GNANVH0fhD6MisDFiWP_P0Bm_FHr-frawgfwur3Zx4ipjJx8gk-M6ZZbnDr_2clwPmzO-QS8AkiHLaMXyYO1RHyPeehXPqTc6jJi_iw72fRQJ9AR918ne5XsBRg#V2Vec";
        assert_eq!(crate::state::detect_protocol_badge(csqtt_v2_uri), "CSQTT");
        let parsed_csqtt = parse_node_uri(csqtt_v2_uri).expect("parse csqtt v2");
        assert_eq!(parsed_csqtt["type"], json!("wdtt"));
        assert_eq!(parsed_csqtt["mode"], json!("csqtt"));
        assert_eq!(parsed_csqtt["workers"], json!(36));
        let reexported = node_to_share_link(&parsed_csqtt).expect("re-export csqtt v2");
        assert!(reexported.starts_with("csqtt://"));
        let opts_csqtt = ConnectOptions::parse(&reexported).expect("ConnectOptions csqtt v2");
        let (cfg_csqtt, has_node) = mgr
            .build_config(&opts_csqtt)
            .expect("build_config csqtt v2");
        assert!(has_node);
        core_config::check_str(&cfg_csqtt.to_string()).expect("check_str csqtt v2");
    }

    #[test]
    fn desync_advanced_fields_and_sni_pool_validate() {
        let mgr = VpnManager::new(Arc::new(|_| {}));

        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "desync".to_string();
        st.desync_prefs.preset = "custom".to_string();
        st.desync_prefs.mode = "fake_split".to_string();
        st.desync_prefs.fake_sni = "www.google.com, ya.ru, vk.com".to_string();
        st.desync_prefs.host_fake = true;
        st.desync_prefs.fake_payload = "0x1603010005".to_string();
        st.desync_prefs.udp_fake_payload = "0x000100002112a442".to_string();
        st.desync_prefs.udp_out_range = "1-3".to_string();
        st.desync_prefs.udp_keep_socket = true;
        st.desync_prefs.quic_fake = true;
        st.desync_prefs.quic_repeats = 5;

        let payload = st.build_connect_payload(None);
        let opts = ConnectOptions::parse(&payload).expect("parse adv desync");
        let (cfg, has_node) = mgr.build_config(&opts).expect("build adv desync config");
        assert!(!has_node);
        core_config::check_str(&cfg.to_string()).expect("check_str adv desync");

        let desync_ob = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "DESYNC")
            .expect("DESYNC outbound");
        assert_eq!(desync_ob["fake_sni"], json!("www.google.com"));
        assert_eq!(
            desync_ob["sni_pool"],
            json!(["www.google.com", "ya.ru", "vk.com"])
        );
        assert_eq!(desync_ob["host_fake"], json!(true));
        assert_eq!(desync_ob["udp_out_range"], json!("1-3"));
        assert_eq!(desync_ob["udp_keep_socket"], json!(true));
        assert_eq!(desync_ob["quic_desync"], json!(true));
        assert_eq!(desync_ob["quic_repeats"], json!(5));
    }

    #[test]
    fn endpoint_vs_outbound_routing_for_wg_ts_ovpn_and_openconnect() {
        let wg_node = json!({
            "type": "wireguard",
            "address": ["10.0.0.2/32"],
            "private_key": "cO0+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY=",
            "peers": [{
                "address": "198.51.100.1",
                "port": 51820,
                "public_key": "dO0+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY=",
                "allowed_ips": ["0.0.0.0/0"]
            }]
        });
        let (wg_ep, wg_val, _) =
            VpnManager::prepare_parsed_node(&encode_inline_node_uri(&wg_node), "WG", false, None)
                .expect("wg node");
        assert!(wg_ep);
        assert_eq!(wg_val["type"], json!("wireguard"));

        let ts_node = json!({
            "type": "tailscale",
            "control_url": "https://controlplane.tailscale.com",
            "auth_key": "tskey-auth-dummy"
        });
        let (ts_ep, ts_val, host) =
            VpnManager::prepare_parsed_node(&encode_inline_node_uri(&ts_node), "TS", false, None)
                .expect("ts node");
        assert!(ts_ep);
        assert_eq!(ts_val["type"], json!("tailscale"));
        assert_eq!(host.as_deref(), Some("controlplane.tailscale.com"));

        let ovpn_node = json!({
            "type": "openvpn",
            "server": "198.51.100.5",
            "server_port": 1194,
            "tls": { "enabled": true }
        });
        let (ovpn_ep, ovpn_val, _) = VpnManager::prepare_parsed_node(
            &encode_inline_node_uri(&ovpn_node),
            "OVPN",
            false,
            None,
        )
        .expect("ovpn node");
        assert!(ovpn_ep);
        assert_eq!(ovpn_val["type"], json!("openvpn-client"));

        let oc_node = json!({
            "type": "openconnect",
            "server": "198.51.100.6",
            "server_port": 443,
            "cookie": "webvpn=1"
        });
        let (oc_ep, oc_val, _) =
            VpnManager::prepare_parsed_node(&encode_inline_node_uri(&oc_node), "OC", false, None)
                .expect("openconnect node");
        assert!(!oc_ep);
        assert_eq!(oc_val["type"], json!("openconnect"));
    }

    #[test]
    fn config_transports_ipv6_ntp_sniff_dialer_and_rules_validate() {
        let mgr = VpnManager::new(Arc::new(|_| {}));

        let vless_uri = "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls&type=tcp&sni=example.com#Node";
        for transport in ["https", "h3", "quic", "tls", "udp"] {
            let mut st = crate::state::PersistedState::default();
            st.servers.push(crate::state::ServerNode {
                id: "n1".to_string(),
                name: "Node".to_string(),
                country: "nl".to_string(),
                vless: vless_uri.to_string(),
                sub_id: None,
                is_balancer: false,
                balancer_mode: None,
                member_count: None,
                ping_ms: None,
                ping_at: None,
                alive: None,
            });
            st.active_id = "n1".to_string();
            st.vpn_prefs.dns = "cloudflare".to_string();
            st.vpn_prefs.dns_transport = transport.to_string();
            st.vpn_prefs.ipv6_enabled = true;
            st.vpn_prefs.ntp_enabled = true;
            st.vpn_prefs.ntp_server = "time.cloudflare.com".to_string();
            st.vpn_prefs.sniff = false;
            st.vpn_prefs.tcp_fast_open = true;
            st.vpn_prefs.tcp_multi_path = true;
            st.custom_rules = vec![
                crate::state::CustomRule {
                    id: "r1".to_string(),
                    rule_type: "domain_regex".to_string(),
                    value: "^.*\\.internal\\.example$".to_string(),
                    action: "direct".to_string(),
                    time_window: "mon-fri 09:00-18:00".to_string(),
                },
                crate::state::CustomRule {
                    id: "r2".to_string(),
                    rule_type: "port".to_string(),
                    value: "8000-8080".to_string(),
                    action: "vpn".to_string(),
                    time_window: String::new(),
                },
                crate::state::CustomRule {
                    id: "r3".to_string(),
                    rule_type: "process".to_string(),
                    value: r"C:\Apps\tool.exe".to_string(),
                    action: "direct".to_string(),
                    time_window: String::new(),
                },
            ];

            let payload = st.build_connect_payload(None);
            let opts = ConnectOptions::parse(&payload).expect("parse opts");
            let (cfg, has_node) = mgr.build_config(&opts).expect("build_config");
            assert!(has_node);
            core_config::check_str(&cfg.to_string())
                .unwrap_or_else(|e| panic!("transport {transport} failed check_str: {e}"));

            let remote_dns = cfg["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["tag"] == "dns_remote")
                .unwrap();
            assert_eq!(remote_dns["type"], json!(transport));
            assert_eq!(
                cfg["inbounds"][0]["address"],
                json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
            );
            let fakeip_srv = cfg["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["tag"] == "dns-fakeip")
                .unwrap();
            assert_eq!(fakeip_srv["inet6_range"], json!("fc00::/18"));
            assert_eq!(cfg["ntp"]["enabled"], json!(true));
            assert_eq!(cfg["ntp"]["server"], json!("time.cloudflare.com"));
            let rules_arr = cfg["route"]["rules"].as_array().unwrap();
            assert!(
                !rules_arr
                    .iter()
                    .any(|r| r.get("action") == Some(&json!("sniff")))
            );
            assert!(rules_arr.iter().any(|r| r.get("domain_regex").is_some()
                && r.get("time_window") == Some(&json!("mon-fri 09:00-18:00"))));
            assert!(
                rules_arr
                    .iter()
                    .any(|r| r.get("port_range") == Some(&json!(["8000:8080"])))
            );
            assert!(
                rules_arr
                    .iter()
                    .any(|r| r.get("process_path") == Some(&json!([r"C:\Apps\tool.exe"])))
            );
        }

        // anytls must NOT get tcp_fast_open
        let anytls_ob = json!({
            "type": "anytls",
            "server": "198.51.100.30",
            "server_port": 443,
            "password": "secret",
            "tls": { "enabled": true, "server_name": "any.example.com" }
        });
        let mut st_any = crate::state::PersistedState::default();
        st_any.servers.push(crate::state::ServerNode {
            id: "any1".to_string(),
            name: "AnyTLS".to_string(),
            country: "nl".to_string(),
            vless: encode_inline_node_uri(&anytls_ob),
            sub_id: None,
            is_balancer: false,
            balancer_mode: None,
            member_count: None,
            ping_ms: None,
            ping_at: None,
            alive: None,
        });
        st_any.active_id = "any1".to_string();
        st_any.vpn_prefs.tcp_fast_open = true;
        let opts_any = ConnectOptions::parse(&st_any.build_connect_payload(None)).unwrap();
        let (cfg_any, _) = mgr.build_config(&opts_any).unwrap();
        core_config::check_str(&cfg_any.to_string()).expect("anytls with tfo global pref");
        let proxy_ob = cfg_any["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "PROXY")
            .unwrap();
        assert!(proxy_ob.get("tcp_fast_open").is_none());
    }

    #[test]
    fn upstream_fakeip_detection_and_override_disables_local_fakeip() {
        assert!(is_fakeip_pool_addr("198.18.0.69".parse().unwrap()));
        assert!(is_fakeip_pool_addr("198.19.255.1".parse().unwrap()));
        assert!(is_fakeip_pool_addr("fc00::1".parse().unwrap()));
        assert!(!is_fakeip_pool_addr("1.1.1.1".parse().unwrap()));
        assert!(!is_fakeip_pool_addr("10.255.0.1".parse().unwrap()));

        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.mode = "tun".to_string();
        st.vpn_prefs.route = "desync".to_string();
        st.vpn_prefs.fake_ip = true;
        st.desync_prefs.enabled = true;

        let mgr = VpnManager::new(Arc::new(|_| {}));
        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).expect("parse opts");

        let (cfg_normal, _) = mgr
            .build_config_with_fakeip_override(&opts, false)
            .expect("normal build");
        assert!(
            cfg_normal["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["tag"] == "dns-fakeip")
        );
        assert_eq!(
            cfg_normal["experimental"]["cache_file"]["store_fakeip"],
            json!(true)
        );

        let (cfg_suppressed, _) = mgr
            .build_config_with_fakeip_override(&opts, true)
            .expect("suppressed build");
        assert!(
            !cfg_suppressed["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["tag"] == "dns-fakeip")
        );
        assert_eq!(
            cfg_suppressed["experimental"]["cache_file"]["store_fakeip"],
            json!(false)
        );
        core_config::check_str(&cfg_suppressed.to_string()).expect("check_str suppressed fakeip");
    }
    #[test]
    fn balancer_filter_excludes_countries_protocols_and_regex() {
        let o = BalancerOptions {
            excluded_countries: vec!["RU".to_string()],
            ..Default::default()
        };
        let ru_flag = regional_indicator_flag("RU").unwrap();
        let nl_flag = regional_indicator_flag("NL").unwrap();
        assert!(!balancer_node_passes_filter(
            &format!("{ru_flag} Moscow"),
            "1.2.3.4",
            "",
            "vless",
            &o
        ));
        assert!(balancer_node_passes_filter(
            &format!("{nl_flag} Amsterdam"),
            "5.6.7.8",
            "",
            "vless",
            &o
        ));

        let o = BalancerOptions {
            excluded_protocols: vec!["ss".to_string()],
            ..Default::default()
        };
        assert!(!balancer_node_passes_filter(
            "n",
            "h",
            "",
            "shadowsocks",
            &o
        ));
        assert!(balancer_node_passes_filter("n", "h", "", "vless", &o));

        let o = BalancerOptions {
            include_regex: "LTE|Whitelist".to_string(),
            exclude_regex: "expired".to_string(),
            ..Default::default()
        };
        assert!(balancer_node_passes_filter(
            "LTE node", "h", "", "vless", &o
        ));
        assert!(!balancer_node_passes_filter(
            "LTE expired",
            "h",
            "",
            "vless",
            &o
        ));
        assert!(!balancer_node_passes_filter("plain", "h", "", "vless", &o));

        // Некорректный RegExp откатывается к поиску подстроки
        let o = BalancerOptions {
            exclude_regex: "([".to_string(),
            ..Default::default()
        };
        assert!(balancer_node_passes_filter("n", "h", "", "vless", &o));
    }

    #[test]
    fn balancer_service_probe_urls_cover_multi_url_catalog() {
        for id in ["youtube", "telegram", "discord", "instagram", "openai"] {
            assert!(balancer_service_probe_url(id).is_some(), "{id}");
        }
        assert!(balancer_service_probe_url("https").is_none());
    }

    #[test]
    fn balancer_prefs_override_and_multi_url_pass_core_config_check() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let payload = BalancerPayload {
            name: "AutoPool".to_string(),
            mode: "stability".to_string(),
            url: "https://frozen.example/204".to_string(),
            interval: "10m".to_string(),
            tolerance: 150,
            pool: 2,
            pool_tolerance: 90,
            sticky_hash: vec!["domain".to_string()],
            quota_mib: 512,
            members: vec![
                BalancerMember {
                    name: "NL-1".to_string(),
                    vless: "vless://11111111-1111-1111-1111-111111111111@198.51.100.11:443?security=tls&type=tcp&sni=nl1.example#NL1".to_string(),
                    country: "nl".to_string(),
                },
                BalancerMember {
                    name: "DE-2".to_string(),
                    vless: "vless://22222222-2222-2222-2222-222222222222@198.51.100.12:443?security=tls&type=tcp&sni=de2.example#DE2".to_string(),
                    country: "de".to_string(),
                },
            ],
        };
        let bal_uri = encode_balancer_uri(&payload);
        let mut st = crate::state::PersistedState::default();
        st.servers.push(crate::state::ServerNode {
            id: "bal-1".to_string(),
            name: "AutoPool".to_string(),
            country: "xx".to_string(),
            vless: bal_uri,
            sub_id: None,
            is_balancer: true,
            balancer_mode: Some("stability".to_string()),
            member_count: Some(2),
            ping_ms: None,
            ping_at: None,
            alive: Some(true),
        });
        st.active_id = "bal-1".to_string();
        st.vpn_prefs.balancer_mode = "least_test".to_string();
        st.vpn_prefs.balancer_tolerance = 30;
        st.vpn_prefs.balancer_quota_mib = 0;
        st.vpn_prefs.balancer_interval = "2m".to_string();
        st.vpn_prefs.balancer_url = "https://www.gstatic.com/generate_204".to_string();
        st.vpn_prefs.balancer_multi_service = true;
        st.vpn_prefs.balancer_multi_services = vec!["youtube".to_string(), "telegram".to_string()];
        st.list_modes
            .insert("youtube".to_string(), "vpn".to_string());
        st.list_modes
            .insert("telegram".to_string(), "vpn".to_string());

        let opts = ConnectOptions::parse(&st.build_connect_payload(None))
            .expect("ConnectOptions from balancer prefs");
        assert!(opts.balancer.from_prefs);
        let (cfg, _) = mgr.build_config(&opts).expect("build_config balancer");
        core_config::check_str(&cfg.to_string()).expect("check_str balancer multi-url");

        let outbounds = cfg["outbounds"].as_array().unwrap();
        let proxy = outbounds.iter().find(|o| o["tag"] == "PROXY").unwrap();
        assert_eq!(proxy["type"], "urltest");
        assert_eq!(proxy["tolerance"], 30);
        assert_eq!(proxy["interval"], "2m");
        assert!(proxy.get("quota_mib").is_none());
        assert!(outbounds.iter().any(|o| o["tag"] == "urltest-svc-youtube"));
        assert!(outbounds.iter().any(|o| o["tag"] == "urltest-svc-telegram"));
    }

    #[test]
    fn build_config_inbound_self_rules_pass_core_config_check() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.servers.push(crate::state::ServerNode {
            id: "s1".to_string(),
            name: "DE".to_string(),
            country: "de".to_string(),
            vless: "vless://11111111-1111-1111-1111-111111111111@198.51.100.20:443?security=tls&type=tcp&sni=de.example#DE".to_string(),
            sub_id: None,
            is_balancer: false,
            balancer_mode: None,
            member_count: None,
            ping_ms: None,
            ping_at: None,
            alive: None,
        });
        st.active_id = "s1".to_string();
        st.vpn_prefs.mode = "tun".to_string();
        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg, _) = mgr
            .build_config(&opts)
            .expect("build_config tun self rules");
        core_config::check_str(&cfg.to_string()).expect("check_str tun self rules");

        let rules = cfg["route"]["rules"].as_array().unwrap();
        let has_mixed_global = rules.iter().any(|r| {
            r["inbound"] == json!(["mixed-in"])
                && r["outbound"] == "GLOBAL"
                && r["process_name"].as_array().is_some_and(|a| !a.is_empty())
        });
        let has_tun_direct = rules.iter().any(|r| {
            r["inbound"] == json!(["tun-in"])
                && r["outbound"] == "direct"
                && r["process_name"].as_array().is_some_and(|a| !a.is_empty())
        });
        assert!(has_mixed_global, "missing mixed-in -> GLOBAL self rule");
        assert!(has_tun_direct, "missing tun-in -> direct self rule");
    }

    #[test]
    fn filter_log_lines_respects_levels() {
        let lines = [
            "12:00:00 [DEBUG] trace packet",
            "12:00:01 [INFO] core started",
            "12:00:02 [WARN] urltest degraded",
            "12:00:03 [ERROR] handshake failed",
        ];
        let err_only = filter_log_lines(&lines, 50, "error");
        assert!(!err_only.contains("[WARN]"));
        assert!(!err_only.contains("[INFO]"));
        assert!(err_only.contains("[ERROR] handshake failed"));

        let warn_up = filter_log_lines(&lines, 50, "warn");
        assert!(!warn_up.contains("[INFO]"));
        assert!(warn_up.contains("[WARN] urltest degraded"));
        assert!(warn_up.contains("[ERROR] handshake failed"));

        let all = filter_log_lines(&lines, 2, "all");
        assert!(!all.contains("[INFO]"));
        assert!(all.contains("[WARN]"));
        assert!(all.contains("[ERROR]"));
    }

    #[test]
    fn median_and_dns_wire_helpers() {
        assert_eq!(median_ping_samples(&[]), -1);
        assert_eq!(median_ping_samples(&[-1, 0]), -1);
        assert_eq!(median_ping_samples(&[90, 20, 45]), 45);
        assert_eq!(median_ping_samples(&[80, 20, -1, 40]), 40);
        assert_eq!(median_ping_samples(&[10, 30, 50, 70]), 40);

        let mut pkt = vec![
            7u8, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1,
        ];
        assert_eq!(skip_dns_name(&pkt, 0), Some(13));
        pkt[0] = 0xC0;
        pkt[1] = 0x0C;
        assert_eq!(skip_dns_name(&pkt[..2], 0), Some(2));
        assert_eq!(skip_dns_name(&[0xC0], 0), None);
        assert_eq!(skip_dns_name(&[10, b'a'], 0), None);
    }

    #[test]
    fn remote_dns_preserves_transport_for_cloudflare_and_adguard_ips() {
        let cf = VpnManager::build_remote_dns_server("1.1.1.1", "https", "GLOBAL");
        assert_eq!(cf["type"], "https");
        assert_eq!(cf["server"], "1.1.1.1");
        assert_eq!(cf["server_port"], 443);

        let ag = VpnManager::build_remote_dns_server("94.140.14.14", "quic", "GLOBAL");
        assert_eq!(ag["type"], "quic");
        assert_eq!(ag["server"], "94.140.14.14");
        assert_eq!(ag["server_port"], 853);
    }

    #[test]
    fn bypass_lan_toggle_controls_private_routes_and_tun_excludes() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "desync".to_string();
        st.vpn_prefs.mode = "tun".to_string();

        st.vpn_prefs.bypass_lan = true;
        let opts_on = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg_on, _) = mgr.build_config(&opts_on).expect("build_config lan on");
        core_config::check_str(&cfg_on.to_string()).expect("check_str lan on");
        let excl_on = cfg_on["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap();
        assert!(excl_on.iter().any(|v| v == "192.168.0.0/16"));
        assert!(excl_on.iter().any(|v| v == "100.64.0.0/10"));
        assert!(
            cfg_on["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.get("ip_is_private") == Some(&json!(true)))
        );

        st.vpn_prefs.bypass_lan = false;
        let opts_off = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg_off, _) = mgr.build_config(&opts_off).expect("build_config lan off");
        core_config::check_str(&cfg_off.to_string()).expect("check_str lan off");
        let excl_off = cfg_off["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap();
        assert!(!excl_off.iter().any(|v| v == "192.168.0.0/16"));
        assert!(excl_off.iter().any(|v| v == "127.0.0.0/8"));
        assert!(
            !cfg_off["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.get("ip_is_private") == Some(&json!(true)))
        );
    }

    #[test]
    fn desync_outbound_maps_compound_fooling_and_fad_mode_and_validates() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "desync".to_string();
        st.desync_prefs.preset = "custom".to_string();
        st.desync_prefs.mode = "fad".to_string();
        st.desync_prefs.fooling = "md5sig+badsum".to_string();
        st.desync_prefs.stun_fake = true;

        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg, _) = mgr.build_config(&opts).expect("build_config desync fad");
        core_config::check_str(&cfg.to_string()).expect("check_str desync fad");
        let desync = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "DESYNC")
            .unwrap();
        assert_eq!(desync["mode"], "fake_disorder");
        assert_eq!(desync["fooling"], "md5_badack");
    }

    #[test]
    fn custom_ipv6_cidr_and_semver_helpers() {
        assert!(is_newer_semver("0.4.2", "0.4.1"));
        assert!(!is_newer_semver("0.4.1", "0.4.1"));
        assert!(!is_newer_semver("0.4.0", "0.4.1"));

        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "desync".to_string();
        st.custom_rules.push(crate::state::CustomRule {
            id: "r1".to_string(),
            rule_type: "cidr".to_string(),
            value: "2001:db8::1".to_string(),
            action: "direct".to_string(),
            time_window: String::new(),
        });
        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg, _) = mgr.build_config(&opts).expect("build_config ipv6 cidr");
        core_config::check_str(&cfg.to_string()).expect("check_str ipv6 cidr");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|r| r["ip_cidr"] == json!(["2001:db8::1/128"]))
        );
    }

    #[test]
    fn tun_ip_and_virtual_adapter_filters() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1))));
        assert!(is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2))));
        assert!(!is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1))));
        assert!(is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))));
        assert!(!is_fake_or_tun_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));

        assert!(is_virtual_or_tun_adapter_name("Wintun Userspace Tunnel"));
        assert!(is_virtual_or_tun_adapter_name("WireGuard Tunnel"));
        assert!(is_virtual_or_tun_adapter_name(
            "Software Loopback Interface 1"
        ));
        assert!(!is_virtual_or_tun_adapter_name(
            "Intel(R) Wi-Fi 6 AX201 160MHz"
        ));
        assert!(!is_virtual_or_tun_adapter_name(
            "Realtek PCIe GbE Family Controller"
        ));

        #[cfg(target_os = "windows")]
        {
            // Проверяем, что структура MIB_IFROW имеет точный размер Win32 (860 байт),
            // а поиск физического интерфейса на хосте не возвращает ошибку/панику.
            assert_eq!(std::mem::size_of::<MibIfRow>(), 860);
            let _ = default_windows_phys_ifindex();
        }
    }

    #[test]
    fn macos_phys_interface_parsers_skip_utun() {
        let route_utun_first = "   route to: default\n destination: default\n   interface: utun4\n";
        assert_eq!(parse_macos_route_default(route_utun_first), None);

        let route_en0 = "   route to: default\n destination: default\n   gateway: 192.168.1.1\n   interface: en0\n";
        assert_eq!(parse_macos_route_default(route_en0).as_deref(), Some("en0"));

        let netstat_out = "\
Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
0/1                link#22            UCSg                utun4\n\
default            192.168.1.1        UGScg                 en0\n";
        assert_eq!(
            parse_macos_netstat_default(netstat_out).as_deref(),
            Some("en0")
        );

        let scutil_out = "\
IPv4 network interface information\n\
   en0 : flags      : 0x7 (IPv4,IPv6,DNS)\n\
   utun4 : flags    : 0x5 (IPv4,DNS)\n";
        assert_eq!(parse_macos_scutil_nwi(scutil_out).as_deref(), Some("en0"));
    }

    #[test]
    fn bypass_lan_splits_172_16_without_overlapping_tun_subnet() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "desync".to_string();
        st.vpn_prefs.mode = "tun".to_string();
        st.vpn_prefs.bypass_lan = true;
        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg, _) = mgr.build_config(&opts).expect("build_config");
        let excl = cfg["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap();
        assert!(!excl.iter().any(|v| v == "172.16.0.0/12"));
        assert!(excl.iter().any(|v| v == "172.16.0.0/15"));
        assert!(excl.iter().any(|v| v == "172.19.1.0/24"));
        assert!(excl.iter().any(|v| v == "172.20.0.0/14"));
    }

    #[test]
    fn mtproto_excluded_from_auto_and_explicit_balancers() {
        assert!(is_mtproto_uri(
            "tg://proxy?server=1.2.3.4&port=443&secret=dd1122"
        ));
        assert!(is_mtproto_uri(
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=00"
        ));
        assert!(!is_mtproto_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#NL"
        ));

        let nodes = vec![
            json!({
                "type": "socks",
                "tag": "SOCKS #1",
                "server": "198.51.100.1",
                "server_port": 1080
            }),
            json!({
                "type": "mtproto",
                "tag": "MTProto #1",
                "server": "198.51.100.2",
                "server_port": 443,
                "secret": "00112233445566778899aabbccddeeff"
            }),
            json!({
                "type": "vless",
                "tag": "VLESS #1",
                "server": "198.51.100.3",
                "server_port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111"
            }),
        ];
        let srvs = build_subscription_servers_list(&nodes, "TestSub");
        let bal_uri = srvs[0]["vless"].as_str().unwrap();
        let bal = decode_balancer_uri(bal_uri).unwrap();
        assert!(!bal.members.iter().any(|m| is_mtproto_uri(&m.vless)));

        let poisoned = encode_balancer_uri(&BalancerPayload {
            name: "Mixed".to_string(),
            mode: "stability".to_string(),
            url: default_balancer_url(),
            interval: default_balancer_interval(),
            tolerance: 50,
            pool: 4,
            pool_tolerance: 80,
            sticky_hash: default_balancer_sticky_hash(),
            quota_mib: 0,
            members: vec![
                BalancerMember {
                    name: "TG".to_string(),
                    vless: "tg://proxy?server=198.51.100.2&port=443&secret=00112233445566778899aabbccddeeff".to_string(),
                    country: "xx".to_string(),
                },
                BalancerMember {
                    name: "VLESS".to_string(),
                    vless: "vless://11111111-1111-1111-1111-111111111111@198.51.100.3:443#NL".to_string(),
                    country: "nl".to_string(),
                },
            ],
        });
        let mut used = HashSet::new();
        let (_, obs, _) = VpnManager::expand_parsed_target(
            &poisoned,
            "PROXY",
            false,
            None,
            &BalancerOptions::default(),
            &mut used,
        )
        .expect("expand_parsed_target filters mtproto");
        assert!(!obs.iter().any(|o| o["type"] == "mtproto"));
    }

    #[test]
    fn per_service_and_custom_rule_node_action_builds_valid_config() {
        let mgr = VpnManager::new(Arc::new(|_| {}));
        let mut st = crate::state::PersistedState::default();
        st.vpn_prefs.route = "selective".to_string();
        st.servers.push(crate::state::ServerNode {
            id: "srv-main".to_string(),
            name: "Main NL".to_string(),
            vless: "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls&sni=example.com#Main".to_string(),
            country: "nl".to_string(),
            sub_id: None,
            is_balancer: false,
            balancer_mode: None,
            member_count: None,
            ping_ms: None,
            ping_at: None,
            alive: None,
        });
        st.servers.push(crate::state::ServerNode {
            id: "srv-de".to_string(),
            name: "Special DE".to_string(),
            vless: "vless://22222222-2222-2222-2222-222222222222@198.51.100.20:443?security=tls&sni=de.example.com#DE".to_string(),
            country: "de".to_string(),
            sub_id: None,
            is_balancer: false,
            balancer_mode: None,
            member_count: None,
            ping_ms: None,
            ping_at: None,
            alive: None,
        });
        st.active_id = "srv-main".to_string();
        st.list_modes
            .insert("youtube".to_string(), "NODE_srv-de".to_string());
        st.custom_rules.push(crate::state::CustomRule {
            id: "r-node".to_string(),
            rule_type: "domain".to_string(),
            value: "custom-site.org".to_string(),
            action: "NODE_srv-de".to_string(),
            time_window: String::new(),
        });

        let opts = ConnectOptions::parse(&st.build_connect_payload(None)).unwrap();
        let (cfg, _) = mgr.build_config(&opts).expect("build_config NODE_<id>");
        core_config::check_str(&cfg.to_string()).expect("check_str NODE_<id>");
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert!(outbounds.iter().any(|o| o["tag"] == "NODE_SRV-DE"));
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| {
            r["domain_suffix"] == json!(["custom-site.org"]) && r["outbound"] == "NODE_SRV-DE"
        }));
        assert!(rules.iter().any(|r| {
            r["outbound"] == "NODE_SRV-DE"
                && r["rule_set"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v == "rs-youtube"))
        }));
    }
}
