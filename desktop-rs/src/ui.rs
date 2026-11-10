use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpui::prelude::*;
use gpui::{
    AnyElement, App, ClipboardItem, Context, FontWeight, KeyDownEvent, MouseButton, MouseDownEvent,
    Render, SharedString, Window, div, img, px, svg,
};
use serde_json::{Value, json};

use crate::icons::flag_image;
use crate::state::{
    CustomRule, PersistedState, ROUTE_CATALOG, ServerNode, SubscriptionItem, SubscriptionMeta,
    country_title_ru, detect_protocol_badge, extract_host_port_from_uri,
};
use crate::theme::Theme;
use crate::vpn::{RunningApp, VpnManager, enumerate_apps, icmp_or_tcp_ping_ms, tcp_connect_ms};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Tunnel,
    Desync,
    Routes,
    Nodes,
    Traffic,
    Options,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteSubTab {
    Catalog,
    Custom,
    Apps,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActiveField {
    None,
    ServerSearch,
    NodeUriInput,
    NodeNameInput,
    SubUrlInput,
    SubHandleInput,
    RouteSearch,
    CustomRuleValue,
    CustomDns,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModalKind {
    None,
    Subscriptions,
    KernelLog,
}

#[derive(Clone, Debug, Default)]
pub struct ExitNodeInfo {
    pub loading: bool,
    pub ok: bool,
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
    pub latency_ms: u64,
    pub error: String,
}

#[derive(Clone, Debug)]
pub struct DiagProbeItem {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub ok: bool,
    pub status: String,
    pub ms: i64,
}

#[derive(Clone, Debug)]
pub struct DnsBenchItem {
    pub id: String,
    pub name: String,
    pub host: String,
    pub proto: String,
    pub ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct SpeedtestStatus {
    pub running: bool,
    pub mbps: f64,
    pub mbs: f64,
    pub peak_mbps: f64,
    pub ttfb_ms: u64,
    pub progress: u32,
    pub server: String,
    pub error: String,
}

#[derive(Clone, Debug)]
pub struct ActiveConnectionRow {
    pub id: String,
    pub net: String,
    pub host: String,
    pub process: String,
    pub chain: String,
    pub rule: String,
    pub dl: u64,
    pub ul: u64,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateBanner {
    pub available: bool,
    pub tag: String,
    pub notes: String,
    pub downloading: bool,
    pub progress_pct: u32,
}

pub struct TachyonApp {
    pub state: PersistedState,
    pub tab: Tab,
    pub route_subtab: RouteSubTab,
    pub active_field: ActiveField,
    pub modal: ModalKind,
    pub vpn: Arc<VpnManager>,
    pub rt: Arc<tokio::runtime::Runtime>,
    pub event_queue: Arc<Mutex<Vec<String>>>,

    // Live runtime telemetry
    pub vpn_status: String, // "disconnected" | "connecting" | "connected" | "error"
    pub last_error: String,
    pub connected_since: Option<Instant>,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
    pub exit_info: ExitNodeInfo,
    pub live_balancer: Option<Value>,
    pub self_check_items: Vec<Value>,

    // Inputs & filters
    pub server_search: String,
    pub node_filter: String,
    pub hide_ru_by: bool,
    pub conn_filter: String,
    pub speedtest_size_mb: u32,
    pub speedtest_provider: String,
    pub node_uri_input: String,
    pub node_name_input: String,
    pub sub_url_input: String,
    pub sub_handle_input: String,
    pub route_search: String,
    pub custom_rule_type: String,
    pub custom_rule_value: String,
    pub custom_rule_action: String,
    pub collapsed_countries: HashSet<String>,

    // Diagnostics & Tools
    pub connections: Vec<ActiveConnectionRow>,
    pub running_apps: Vec<RunningApp>,
    pub diag_items: Vec<DiagProbeItem>,
    pub diag_running: bool,
    pub dns_bench: Vec<DnsBenchItem>,
    pub dns_running: bool,
    pub speedtest: SpeedtestStatus,
    pub log_tail: String,
    pub toast: Option<(String, Instant)>,
    pub update_banner: UpdateBanner,
}

impl TachyonApp {
    pub fn new(
        vpn: Arc<VpnManager>,
        rt: Arc<tokio::runtime::Runtime>,
        event_queue: Arc<Mutex<Vec<String>>>,
        cx: &mut Context<Self>,
    ) -> Self {
        let state = PersistedState::load();
        let mut app = Self {
            state,
            tab: Tab::Tunnel,
            route_subtab: RouteSubTab::Catalog,
            active_field: ActiveField::None,
            modal: ModalKind::None,
            vpn,
            rt,
            event_queue,
            vpn_status: "disconnected".to_string(),
            last_error: String::new(),
            connected_since: None,
            rx_bps: 0,
            tx_bps: 0,
            rx_total: 0,
            tx_total: 0,
            rx_history: vec![0; 48],
            tx_history: vec![0; 48],
            exit_info: ExitNodeInfo::default(),
            live_balancer: None,
            self_check_items: Vec::new(),
            server_search: String::new(),
            node_filter: "all".to_string(),
            hide_ru_by: false,
            conn_filter: "all".to_string(),
            speedtest_size_mb: 100,
            speedtest_provider: "auto".to_string(),
            node_uri_input: String::new(),
            node_name_input: String::new(),
            sub_url_input: String::new(),
            sub_handle_input: String::new(),
            route_search: String::new(),
            custom_rule_type: "domain".to_string(),
            custom_rule_value: String::new(),
            custom_rule_action: "vpn".to_string(),
            collapsed_countries: HashSet::new(),
            connections: Vec::new(),
            running_apps: Vec::new(),
            diag_items: Vec::new(),
            diag_running: false,
            dns_bench: Vec::new(),
            dns_running: false,
            speedtest: SpeedtestStatus::default(),
            log_tail: String::new(),
            toast: None,
            update_banner: UpdateBanner::default(),
        };

        // Initial background tasks
        app.ping_all_nodes();
        if app.state.vpn_prefs.auto_connect && app.state.active_server().is_some() {
            app.toggle_connection();
        }
        let v_upd = app.vpn.clone();
        app.rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            v_upd.check_github_update(true).await;
        });

        // 150ms UI tick for event queue draining, speed history & timers
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let keep_going = this
                    .update(cx, |app, cx| {
                        app.drain_backend_events(cx);
                    })
                    .is_ok();
                if !keep_going {
                    break;
                }
            }
        })
        .detach();

        app
    }

    pub fn show_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    pub fn drain_backend_events(&mut self, cx: &mut Context<Self>) {
        let mut drained = Vec::new();
        if let Ok(mut guard) = self.event_queue.lock() {
            if !guard.is_empty() {
                std::mem::swap(&mut drained, &mut *guard);
            }
        }

        let mut needs_notify = false;
        if let Some((_, ts)) = &self.toast {
            if ts.elapsed() > Duration::from_secs(4) {
                self.toast = None;
                needs_notify = true;
            }
        }
        if self.vpn_status == "connected" {
            needs_notify = true;
        }

        for msg in drained {
            needs_notify = true;
            if let Some(vpn_str) = msg.strip_prefix("vpn:") {
                if let Ok(doc) = serde_json::from_str::<Value>(vpn_str) {
                    if let Some(st) = doc.get("state").and_then(Value::as_str) {
                        let prev = self.vpn_status.clone();
                        match st {
                            "connected" | "switched" | "blocking" => {
                                self.vpn_status = "connected".to_string();
                                if prev != "connected" {
                                    self.connected_since = Some(Instant::now());
                                    self.last_error.clear();
                                    self.refresh_exit_info();
                                } else if st == "switched" {
                                    self.refresh_exit_info();
                                }
                            }
                            "connecting" => {
                                self.vpn_status = "connecting".to_string();
                            }
                            "off" | "disconnected" | "dropped" => {
                                self.vpn_status = "disconnected".to_string();
                                self.connected_since = None;
                                self.rx_bps = 0;
                                self.tx_bps = 0;
                                self.live_balancer = None;
                            }
                            "error" => {
                                self.vpn_status = "disconnected".to_string();
                                self.connected_since = None;
                                self.rx_bps = 0;
                                self.tx_bps = 0;
                                let err = doc
                                    .get("error")
                                    .and_then(Value::as_str)
                                    .unwrap_or("Ошибка запуска туннеля");
                                self.last_error = err.to_string();
                                self.show_toast(err.to_string());
                            }
                            _ => {}
                        }
                    }
                    if let Some(rx) = doc.get("down").and_then(Value::as_u64) {
                        let tx = doc.get("up").and_then(Value::as_u64).unwrap_or(0);
                        let rxt = doc
                            .get("totalDown")
                            .and_then(Value::as_u64)
                            .unwrap_or(self.rx_total);
                        let txt = doc
                            .get("totalUp")
                            .and_then(Value::as_u64)
                            .unwrap_or(self.tx_total);
                        self.rx_bps = rx;
                        self.tx_bps = tx;
                        self.rx_total = rxt;
                        self.tx_total = txt;
                        self.rx_history.push(rx);
                        if self.rx_history.len() > 48 {
                            self.rx_history.remove(0);
                        }
                        self.tx_history.push(tx);
                        if self.tx_history.len() > 48 {
                            self.tx_history.remove(0);
                        }
                    }
                    if let Some(ping) = doc.get("ping").and_then(Value::as_i64) {
                        if ping > 0 {
                            let aid = self.state.active_id.clone();
                            if let Some(srv) =
                                self.state.servers.iter_mut().find(|s| s.id == aid)
                            {
                                srv.ping_ms = Some(ping);
                                srv.alive = Some(true);
                            }
                        }
                    }
                    if let Some(bal) = doc.get("balancer") {
                        self.live_balancer = Some(bal.clone());
                    }
                }
            } else if let Some(status) = msg.strip_prefix("status:") {
                let prev = self.vpn_status.clone();
                self.vpn_status = status.to_string();
                if status == "connected" && prev != "connected" {
                    self.connected_since = Some(Instant::now());
                    self.last_error.clear();
                    self.refresh_exit_info();
                } else if status == "disconnected" {
                    self.connected_since = None;
                    self.rx_bps = 0;
                    self.tx_bps = 0;
                    self.live_balancer = None;
                }
            } else if let Some(err) = msg.strip_prefix("error:") {
                self.last_error = err.to_string();
                self.show_toast(format!("Ошибка: {err}"));
            } else if let Some(sp) = msg.strip_prefix("speed:") {
                let parts: Vec<&str> = sp.split('|').collect();
                if parts.len() >= 4 {
                    let rx = parts[0].parse::<u64>().unwrap_or(0);
                    let tx = parts[1].parse::<u64>().unwrap_or(0);
                    let rxt = parts[2].parse::<u64>().unwrap_or(0);
                    let txt = parts[3].parse::<u64>().unwrap_or(0);
                    self.rx_bps = rx;
                    self.tx_bps = tx;
                    self.rx_total = rxt;
                    self.tx_total = txt;
                    self.rx_history.push(rx);
                    if self.rx_history.len() > 48 {
                        self.rx_history.remove(0);
                    }
                    self.tx_history.push(tx);
                    if self.tx_history.len() > 48 {
                        self.tx_history.remove(0);
                    }
                }
            } else if let Some(pong) = msg.strip_prefix("pong:") {
                let mut it = pong.splitn(2, ':');
                if let (Some(id), Some(ms_str)) = (it.next(), it.next()) {
                    let ms = ms_str.parse::<i64>().unwrap_or(-1);
                    if let Some(srv) = self.state.servers.iter_mut().find(|s| s.id == id) {
                        srv.ping_ms = Some(ms);
                        srv.alive = Some(ms > 0);
                    }
                }
            } else if let Some(done_str) = msg.strip_prefix("ping:batch:done:") {
                self.state.save();
                if let Ok(doc) = serde_json::from_str::<Value>(done_str) {
                    let reach = doc.get("reachable").and_then(Value::as_u64).unwrap_or(0);
                    let total = doc.get("total").and_then(Value::as_u64).unwrap_or(0);
                    self.show_toast(format!(
                        "Замер задержки завершён: {reach} из {total} доступно"
                    ));
                }
            } else if let Some(sub_str) = msg
                .strip_prefix("sub:result:")
                .or_else(|| msg.strip_prefix("sub:"))
            {
                self.handle_subscription_result(sub_str);
            } else if let Some(warp_str) = msg.strip_prefix("warp:result:") {
                if let Ok(doc) = serde_json::from_str::<Value>(warp_str) {
                    if doc.get("ok").and_then(Value::as_bool) == Some(true) {
                        if let Some(uri) = doc.get("uri").and_then(Value::as_str) {
                            let name = doc
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("Cloudflare WARP (AmneziaWG)");
                            self.add_single_server_uri(uri, Some(name));
                            self.show_toast("Профиль Cloudflare WARP (AWG) создан и выбран");
                        }
                    } else {
                        let e = doc
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Не удалось зарегистрировать WARP");
                        self.show_toast(format!("WARP: {e}"));
                    }
                }
            } else if let Some(geo_str) = msg.strip_prefix("exit:geo:") {
                self.exit_info.loading = false;
                if let Ok(doc) = serde_json::from_str::<Value>(geo_str) {
                    if doc.get("ok").and_then(Value::as_bool) == Some(true) {
                        self.exit_info.ok = true;
                        self.exit_info.ip = doc
                            .get("ip")
                            .and_then(Value::as_str)
                            .unwrap_or("—")
                            .to_string();
                        self.exit_info.country = doc
                            .get("country")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        self.exit_info.country_code = doc
                            .get("countryCode")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        self.exit_info.city = doc
                            .get("city")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        self.exit_info.isp = doc
                            .get("isp")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        self.exit_info.latency_ms =
                            doc.get("latencyMs").and_then(Value::as_u64).unwrap_or(0);
                        self.exit_info.error.clear();
                    } else {
                        self.exit_info.ok = false;
                        self.exit_info.error = doc
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Нет ответа")
                            .to_string();
                    }
                }
            } else if let Some(conn_str) = msg.strip_prefix("conn:data:") {
                if let Ok(doc) = serde_json::from_str::<Value>(conn_str) {
                    if let Some(arr) = doc
                        .get("conns")
                        .or_else(|| doc.get("connections"))
                        .and_then(Value::as_array)
                    {
                        let mut rows = Vec::with_capacity(arr.len());
                        for item in arr {
                            let id = item
                                .get("id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let dl = item
                                .get("down")
                                .or_else(|| item.get("download"))
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let ul = item
                                .get("up")
                                .or_else(|| item.get("upload"))
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let direct = item
                                .get("direct")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let desync = item
                                .get("desync")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let chain = if direct {
                                "DIRECT".to_string()
                            } else if desync {
                                "DESYNC".to_string()
                            } else {
                                item.get("chains")
                                    .and_then(Value::as_array)
                                    .and_then(|a| a.first())
                                    .and_then(Value::as_str)
                                    .unwrap_or("PROXY")
                                    .to_string()
                            };
                            let rule = item
                                .get("type")
                                .or_else(|| item.get("rule"))
                                .and_then(Value::as_str)
                                .unwrap_or("match")
                                .to_string();
                            let net = item
                                .get("net")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .or_else(|| {
                                    item.get("metadata")
                                        .and_then(|m| m.get("network"))
                                        .and_then(Value::as_str)
                                })
                                .unwrap_or("tcp")
                                .to_ascii_uppercase();
                            let host_raw = item
                                .get("host")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .or_else(|| item.get("ip").and_then(Value::as_str).filter(|s| !s.is_empty()))
                                .or_else(|| {
                                    item.get("metadata").and_then(|m| {
                                        m.get("host")
                                            .and_then(Value::as_str)
                                            .filter(|s| !s.is_empty())
                                            .or_else(|| {
                                                m.get("destinationIP").and_then(Value::as_str)
                                            })
                                    })
                                })
                                .unwrap_or("—");
                            let port_str = item
                                .get("port")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let host = if !port_str.is_empty() && !host_raw.contains(':') {
                                format!("{host_raw}:{port_str}")
                            } else {
                                host_raw.to_string()
                            };
                            let process = item
                                .get("proc")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .or_else(|| {
                                    item.get("metadata").and_then(|m| {
                                        m.get("processPath").or_else(|| m.get("process")).and_then(Value::as_str)
                                    })
                                })
                                .unwrap_or("system")
                                .rsplit(['/', '\\'])
                                .next()
                                .unwrap_or("system")
                                .to_string();
                            rows.push(ActiveConnectionRow {
                                id,
                                net,
                                host,
                                process,
                                chain,
                                rule,
                                dl,
                                ul,
                            });
                        }
                        self.connections = rows;
                    }
                }
            } else if let Some(diag_str) = msg.strip_prefix("diag:matrix:") {
                self.diag_running = false;
                if let Ok(doc) = serde_json::from_str::<Value>(diag_str) {
                    if let Some(arr) = doc.get("items").and_then(Value::as_array) {
                        self.diag_items = arr
                            .iter()
                            .map(|v| DiagProbeItem {
                                id: v
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                title: v
                                    .get("title")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                subtitle: v
                                    .get("subtitle")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                ok: v.get("ok").and_then(Value::as_bool).unwrap_or(false),
                                status: v
                                    .get("status")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                ms: v.get("ms").and_then(Value::as_i64).unwrap_or(-1),
                            })
                            .collect();
                    }
                }
            } else if let Some(step_str) = msg.strip_prefix("diag:step:") {
                if let Ok(doc) = serde_json::from_str::<Value>(step_str) {
                    let id = doc.get("id").and_then(Value::as_str).unwrap_or("");
                    self.self_check_items
                        .retain(|x| x.get("id").and_then(Value::as_str) != Some(id));
                    self.self_check_items.push(doc);
                }
            } else if msg == "diag:done" {
                self.show_toast("Самодиагностика стека завершена");
            } else if let Some(dns_str) = msg.strip_prefix("dns:bench:") {
                self.dns_running = false;
                if let Ok(doc) = serde_json::from_str::<Value>(dns_str) {
                    if let Some(arr) = doc.get("results").and_then(Value::as_array) {
                        self.dns_bench = arr
                            .iter()
                            .map(|v| DnsBenchItem {
                                id: v
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                name: v
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                host: v
                                    .get("host")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                proto: v
                                    .get("proto")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                ms: v.get("ms").and_then(Value::as_i64).unwrap_or(-1),
                            })
                            .collect();
                    }
                }
            } else if let Some(prog_str) = msg.strip_prefix("speedtest:progress:") {
                if let Ok(doc) = serde_json::from_str::<Value>(prog_str) {
                    self.speedtest.running = true;
                    self.speedtest.mbps = doc.get("mbps").and_then(Value::as_f64).unwrap_or(0.0);
                    self.speedtest.mbs = doc.get("mbs").and_then(Value::as_f64).unwrap_or(0.0);
                    self.speedtest.peak_mbps =
                        doc.get("peakMbps").and_then(Value::as_f64).unwrap_or(0.0);
                    self.speedtest.ttfb_ms = doc.get("ttfbMs").and_then(Value::as_u64).unwrap_or(0);
                    self.speedtest.progress =
                        doc.get("progress").and_then(Value::as_u64).unwrap_or(0) as u32;
                    self.speedtest.server = doc
                        .get("server")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                }
            } else if let Some(res_str) = msg.strip_prefix("speedtest:result:") {
                self.speedtest.running = false;
                if let Ok(doc) = serde_json::from_str::<Value>(res_str) {
                    if doc.get("ok").and_then(Value::as_bool) == Some(true) {
                        self.speedtest.mbps =
                            doc.get("mbps").and_then(Value::as_f64).unwrap_or(0.0);
                        self.speedtest.mbs = doc.get("mbs").and_then(Value::as_f64).unwrap_or(0.0);
                        self.speedtest.peak_mbps =
                            doc.get("peakMbps").and_then(Value::as_f64).unwrap_or(0.0);
                        self.speedtest.ttfb_ms =
                            doc.get("ttfbMs").and_then(Value::as_u64).unwrap_or(0);
                        self.speedtest.progress = 100;
                        self.speedtest.error.clear();
                    } else {
                        self.speedtest.error = doc
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Ошибка замера")
                            .to_string();
                    }
                }
            } else if let Some(avail_str) = msg.strip_prefix("core-update:available:") {
                if let Ok(doc) = serde_json::from_str::<Value>(avail_str) {
                    self.update_banner.available = true;
                    self.update_banner.tag = doc
                        .get("latest")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    self.show_toast(format!(
                        "Доступно обновление Tachyon v{}",
                        self.update_banner.tag
                    ));
                }
            } else if msg.starts_with("core-update:up-to-date:") {
                self.show_toast("Установлена актуальная версия Tachyon");
            } else if let Some(pct_str) = msg.strip_prefix("core-update:progress:") {
                self.update_banner.downloading = true;
                self.update_banner.progress_pct = pct_str.trim().parse::<u32>().unwrap_or(0);
            } else if msg.starts_with("core-update:done:") {
                self.update_banner.downloading = false;
                self.show_toast("Обновление установлено, перезапуск...");
            } else if let Some(err_str) = msg.strip_prefix("core-update:error:") {
                self.update_banner.downloading = false;
                self.show_toast(format!("Обновление: {err_str}"));
            } else if let Some(upd_str) = msg.strip_prefix("update:status:") {
                if let Ok(doc) = serde_json::from_str::<Value>(upd_str) {
                    let st = doc.get("status").and_then(Value::as_str).unwrap_or("");
                    match st {
                        "available" => {
                            self.update_banner.available = true;
                            self.update_banner.tag = doc
                                .get("tag")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            self.update_banner.notes = doc
                                .get("notes")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                        }
                        "up-to-date" => {
                            self.show_toast("Установлена актуальная версия Tachyon");
                        }
                        "downloading" => {
                            self.update_banner.downloading = true;
                            self.update_banner.progress_pct =
                                doc.get("progress").and_then(Value::as_u64).unwrap_or(0) as u32;
                        }
                        "error" => {
                            self.update_banner.downloading = false;
                            let err = doc
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("Ошибка обновления");
                            self.show_toast(err.to_string());
                        }
                        _ => {}
                    }
                }
            } else if let Some(prog) = msg.strip_prefix("lists-update:progress:") {
                self.show_toast(format!("Обновление списков маршрутизации: {prog}"));
            } else if let Some(done) = msg.strip_prefix("lists-update:done:") {
                self.show_toast(format!("Списки маршрутов .trs обновлены ({done})"));
                self.reconnect_if_active();
            } else if let Some(done_str) = msg.strip_prefix("lists:refreshed:") {
                if let Ok(doc) = serde_json::from_str::<Value>(done_str) {
                    let ok = doc.get("ok").and_then(Value::as_u64).unwrap_or(0);
                    let total = doc.get("total").and_then(Value::as_u64).unwrap_or(0);
                    self.show_toast(format!("Списки маршрутов обновлены ({ok}/{total})"));
                }
            }
        }

        if needs_notify {
            cx.notify();
        }
    }

    pub fn toggle_connection(&mut self) {
        if self.vpn_status == "connected" || self.vpn_status == "connecting" {
            let v = self.vpn.clone();
            self.rt.spawn(async move {
                v.disconnect().await;
            });
        } else {
            if self.state.active_server().is_none() && self.state.vpn_prefs.route != "desync" {
                // Автоматический запуск в режиме пакетной десинхронизации (Desync) без подписок и серверов
                self.state.desync_prefs.enabled = true;
                self.state.vpn_prefs.route = "desync".to_string();
                self.state.save();
                self.show_toast("Запуск в режиме прямой пакетной десинхронизации (Desync) без прокси-сервера");
            }
            let payload = self.state.build_connect_payload(None);
            let v = self.vpn.clone();
            self.rt.spawn(async move {
                v.connect(payload).await;
            });
        }
    }

    pub fn reconnect_if_active(&mut self) {
        self.state.save();
        if self.vpn_status == "connected" {
            let payload = self.state.build_connect_payload(None);
            let v = self.vpn.clone();
            self.rt.spawn(async move {
                v.connect(payload).await;
            });
        }
    }

    pub fn refresh_exit_info(&mut self) {
        self.exit_info.loading = true;
        let v = self.vpn.clone();
        let eq = self.event_queue.clone();
        self.rt.spawn(async move {
            let res = v.check_exit_node_info().await;
            if let Ok(mut g) = eq.lock() {
                g.push(format!("exit:geo:{res}"));
            }
        });
    }

    pub fn ping_all_nodes(&mut self) {
        let targets: Vec<(String, String)> = self
            .state
            .servers
            .iter()
            .filter(|s| !s.is_balancer)
            .map(|s| (s.id.clone(), s.vless.clone()))
            .collect();
        if targets.is_empty() {
            return;
        }
        let eq = self.event_queue.clone();
        self.rt.spawn(async move {
            let total = targets.len();
            let mut reachable = 0usize;
            for (id, uri) in targets {
                let badge = detect_protocol_badge(&uri);
                let ms = if let Some((host, port)) = extract_host_port_from_uri(&uri) {
                    if matches!(badge, "AWG" | "WG" | "HY2" | "TUIC" | "WDTT") {
                        // UDP-based protocols: TCP port is typically closed, so try ICMP or fallback TCP
                        let icmp = icmp_or_tcp_ping_ms(&host, 2000).await;
                        if icmp > 0 {
                            icmp
                        } else {
                            tcp_connect_ms(&host, port, 1800).await
                        }
                    } else {
                        let tcp = tcp_connect_ms(&host, port, 2200).await;
                        if tcp > 0 {
                            tcp
                        } else {
                            icmp_or_tcp_ping_ms(&host, 1800).await
                        }
                    }
                } else {
                    -1
                };
                if ms > 0 {
                    reachable += 1;
                }
                if let Ok(mut g) = eq.lock() {
                    g.push(format!("pong:{id}:{ms}"));
                }
            }
            if let Ok(mut g) = eq.lock() {
                let done = json!({ "reachable": reachable, "total": total }).to_string();
                g.push(format!("ping:batch:done:{done}"));
            }
        });
    }

    pub fn select_fastest_node(&mut self) {
        if let Some(best) = self
            .state
            .servers
            .iter()
            .filter(|s| !s.is_balancer && s.ping_ms.unwrap_or(-1) > 0)
            .min_by_key(|s| s.ping_ms.unwrap_or(999_999))
        {
            let best_id = best.id.clone();
            let best_name = best.name.clone();
            let best_ms = best.ping_ms.unwrap_or(0);
            self.state.active_id = best_id;
            self.show_toast(format!("Выбран быстрый узел: {best_name} ({best_ms} мс)"));
            self.reconnect_if_active();
        } else {
            self.ping_all_nodes();
            self.show_toast("Запущен замер задержки узлов...");
        }
    }

    pub fn add_single_server_uri(&mut self, raw_input: &str, custom_name: Option<&str>) {
        let trimmed = raw_input.trim();
        if trimmed.is_empty() {
            return;
        }
        let v = self.vpn.clone();
        let sub_payload = if let Some(h) = custom_name.filter(|s| !s.trim().is_empty()) {
            json!({ "url": trimmed, "handle": h }).to_string()
        } else {
            trimmed.to_string()
        };
        self.rt.spawn(async move {
            v.import_subscription(sub_payload).await;
        });
    }

    pub fn import_conf_file_dialog(&mut self) {
        let paths = pick_conf_files_native();
        if paths.is_empty() {
            return;
        }
        let mut added = 0usize;
        for path in paths {
            if let Ok(content) = fs::read_to_string(&path) {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("AWG Config")
                    .to_string();
                self.add_single_server_uri(&content, Some(&stem));
                added += 1;
            }
        }
        if added > 0 {
            self.show_toast(format!("Импортировано файлов конфигурации: {added}"));
        }
    }

    fn handle_subscription_result(&mut self, sub_str: &str) {
        let Ok(doc) = serde_json::from_str::<Value>(sub_str) else {
            return;
        };
        if doc.get("error").is_some() {
            let err = doc
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Не удалось разобрать ссылку или конфиг");
            self.show_toast(format!("Ошибка импорта: {err}"));
            return;
        }

        let handle = doc
            .get("handle")
            .and_then(Value::as_str)
            .unwrap_or("Импорт")
            .to_string();
        let url = doc
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let is_remote_sub = url.starts_with("http://") || url.starts_with("https://");

        let sub_id = if is_remote_sub {
            if let Some(existing) = self.state.subscriptions.iter().find(|s| s.url == url) {
                Some(existing.id.clone())
            } else {
                Some(format!("sub-{}", self.state.subscriptions.len() + 1))
            }
        } else {
            None
        };

        if let Some(sid) = &sub_id {
            self.state
                .servers
                .retain(|s| s.sub_id.as_deref() != Some(sid.as_str()));
        }

        let mut imported_count = 0usize;
        let mut first_added_id = None;
        if let Some(arr) = doc.get("servers").and_then(Value::as_array) {
            for item in arr {
                let Some(vless) = item.get("vless").and_then(Value::as_str) else {
                    continue;
                };
                let mut name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("Узел")
                    .to_string();
                if !is_remote_sub && arr.len() == 1 && !handle.is_empty() && handle != "Подписка"
                {
                    if name.starts_with("Узел #") || name == "WireGuard" || name == "AmneziaWG" {
                        name = handle.clone();
                    }
                }
                let country = item
                    .get("country")
                    .and_then(Value::as_str)
                    .unwrap_or("auto")
                    .to_string();
                let is_balancer = item
                    .get("isBalancer")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let balancer_mode = item
                    .get("balancerMode")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let member_count = item
                    .get("memberCount")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize);
                let id = format!(
                    "node-{}-{}",
                    self.state.servers.len() + 1,
                    imported_count + 1
                );
                if first_added_id.is_none() {
                    first_added_id = Some(id.clone());
                }
                self.state.servers.push(ServerNode {
                    id,
                    name,
                    vless: vless.to_string(),
                    country,
                    sub_id: sub_id.clone(),
                    is_balancer,
                    balancer_mode,
                    member_count,
                    ping_ms: None,
                    alive: None,
                });
                imported_count += 1;
            }
        }

        if let Some(sid) = sub_id {
            let meta = doc
                .get("meta")
                .and_then(|m| serde_json::from_value::<SubscriptionMeta>(m.clone()).ok());
            if let Some(existing) = self.state.subscriptions.iter_mut().find(|s| s.id == sid) {
                existing.handle = handle.clone();
                existing.count = imported_count;
                existing.meta = meta;
            } else {
                self.state.subscriptions.push(SubscriptionItem {
                    id: sid,
                    handle: handle.clone(),
                    url,
                    updated_at: "только что".to_string(),
                    count: imported_count,
                    meta,
                });
            }
        }

        if let Some(fid) = first_added_id {
            self.state.active_id = fid;
        }
        self.state.save();
        self.ping_all_nodes();
        self.show_toast(format!("Добавлено узлов: {imported_count}"));
    }

    pub fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.active_field == ActiveField::None {
            return;
        }
        let key = event.keystroke.key.as_str();
        let mods = &event.keystroke.modifiers;

        if key == "escape" {
            self.active_field = ActiveField::None;
            cx.notify();
            return;
        }

        if (mods.control || mods.platform) && key.eq_ignore_ascii_case("v") {
            if let Some(clip) = cx.read_from_clipboard() {
                if let Some(text) = clip.text() {
                    self.append_to_active_field(&text);
                    cx.notify();
                }
            }
            return;
        }

        if key == "backspace" {
            self.pop_from_active_field();
            cx.notify();
            return;
        }

        if key == "enter" {
            match self.active_field {
                ActiveField::NodeUriInput | ActiveField::NodeNameInput => {
                    let uri = self.node_uri_input.trim().to_string();
                    let name = self.node_name_input.trim().to_string();
                    if !uri.is_empty() {
                        self.add_single_server_uri(
                            &uri,
                            if name.is_empty() { None } else { Some(&name) },
                        );
                        self.node_uri_input.clear();
                        self.node_name_input.clear();
                    }
                }
                ActiveField::SubUrlInput | ActiveField::SubHandleInput => {
                    let url = self.sub_url_input.trim().to_string();
                    let handle = self.sub_handle_input.trim().to_string();
                    if !url.is_empty() {
                        self.add_single_server_uri(
                            &url,
                            if handle.is_empty() {
                                None
                            } else {
                                Some(&handle)
                            },
                        );
                        self.sub_url_input.clear();
                        self.sub_handle_input.clear();
                    }
                }
                ActiveField::CustomRuleValue => {
                    self.submit_custom_rule();
                }
                _ => {}
            }
            cx.notify();
            return;
        }

        if !mods.control && !mods.alt && !mods.platform {
            if let Some(ch) = &event.keystroke.key_char {
                if !ch.chars().all(|c| c.is_control()) {
                    self.append_to_active_field(ch);
                    cx.notify();
                }
            } else if key == "space" {
                self.append_to_active_field(" ");
                cx.notify();
            }
        }
    }

    fn append_to_active_field(&mut self, text: &str) {
        let cleaned = text.replace('\r', "");
        match self.active_field {
            ActiveField::None => {}
            ActiveField::ServerSearch => {
                self.server_search.push_str(&cleaned.replace('\n', " "));
            }
            ActiveField::NodeUriInput => {
                // Keep newlines for multi-line WireGuard / AmneziaWG .conf paste
                self.node_uri_input.push_str(&cleaned);
            }
            ActiveField::NodeNameInput => {
                self.node_name_input.push_str(&cleaned.replace('\n', " "));
            }
            ActiveField::SubUrlInput => {
                self.sub_url_input.push_str(&cleaned);
            }
            ActiveField::SubHandleInput => {
                self.sub_handle_input.push_str(&cleaned.replace('\n', " "));
            }
            ActiveField::RouteSearch => {
                self.route_search.push_str(&cleaned.replace('\n', " "));
            }
            ActiveField::CustomRuleValue => {
                self.custom_rule_value.push_str(&cleaned.replace('\n', " "));
            }
            ActiveField::CustomDns => {
                self.state
                    .vpn_prefs
                    .custom_dns
                    .push_str(&cleaned.replace('\n', ""));
                self.state.save();
            }
        }
    }

    fn pop_from_active_field(&mut self) {
        let target = match self.active_field {
            ActiveField::None => return,
            ActiveField::ServerSearch => &mut self.server_search,
            ActiveField::NodeUriInput => &mut self.node_uri_input,
            ActiveField::NodeNameInput => &mut self.node_name_input,
            ActiveField::SubUrlInput => &mut self.sub_url_input,
            ActiveField::SubHandleInput => &mut self.sub_handle_input,
            ActiveField::RouteSearch => &mut self.route_search,
            ActiveField::CustomRuleValue => &mut self.custom_rule_value,
            ActiveField::CustomDns => &mut self.state.vpn_prefs.custom_dns,
        };
        target.pop();
    }

    pub fn submit_custom_rule(&mut self) {
        let val = self.custom_rule_value.trim().to_string();
        if val.is_empty() {
            return;
        }
        let id = format!("rule-{}", self.state.custom_rules.len() + 1);
        self.state.custom_rules.push(CustomRule {
            id,
            rule_type: self.custom_rule_type.clone(),
            value: val,
            action: self.custom_rule_action.clone(),
        });
        self.custom_rule_value.clear();
        self.reconnect_if_active();
    }
}

fn format_mb_per_sec(bps: u64) -> String {
    let mbs = (bps as f64) / (1024.0 * 1024.0);
    format!("{mbs:.1}")
}

fn format_bytes_human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} ГБ", b / GB)
    } else if b >= MB {
        format!("{:.1} МБ", b / MB)
    } else if b >= KB {
        format!("{:.0} КБ", b / KB)
    } else {
        format!("{bytes} Б")
    }
}

fn format_uptime(since: Option<Instant>) -> String {
    let Some(t) = since else {
        return "00:00".to_string();
    };
    let secs = t.elapsed().as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

fn render_flag_badge(cc: &str, size_px: f32, t: Theme) -> AnyElement {
    if let Some(image) = flag_image(cc) {
        img(image)
            .w(px(size_px))
            .h(px(size_px * 0.75))
            .rounded(px(3.0))
            .into_any_element()
    } else {
        div()
            .w(px(size_px))
            .h(px(size_px * 0.75))
            .rounded(px(3.0))
            .bg(t.bg_hover)
            .border_1()
            .border_color(t.border)
            .flex()
            .items_center()
            .justify_center()
            .text_size(px(9.0))
            .text_color(t.text_dim)
            .child(cc.to_ascii_uppercase())
            .into_any_element()
    }
}

impl TachyonApp {
    fn render_titlebar(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let app_ver = env!("CARGO_PKG_VERSION");
        div()
            .h(px(40.0))
            .w_full()
            .px(px(14.0))
            .bg(t.bg)
            .border_b_1()
            .border_color(t.border)
            .flex()
            .items_center()
            .justify_between()
            .on_mouse_down(MouseButton::Left, |ev: &MouseDownEvent, window, _| {
                if ev.click_count == 2 {
                    window.zoom_window();
                } else {
                    window.start_window_move();
                }
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.0))
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
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(13.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Tachyon"),
                                    )
                                    .child(
                                        div()
                                            .px(px(5.0))
                                            .py(px(1.0))
                                            .rounded(px(4.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .text_size(px(10.0))
                                            .text_color(t.text_dim)
                                            .child(app_ver),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(10.0))
                                    .text_color(t.text_mute)
                                    .child("Маршрутизация и туннелирование"),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .id("btn-theme-toggle")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.bg_hover))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.state.light_theme = !this.state.light_theme;
                                this.state.save();
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
                            .id("btn-win-min")
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
                            .id("btn-win-max")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.bg_hover))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(|_, window, _| {
                                window.zoom_window();
                            })
                            .child(
                                svg()
                                    .path("icons/max.svg")
                                    .size(px(11.0))
                                    .text_color(t.text_dim),
                            ),
                    )
                    .child(
                        div()
                            .id("btn-win-close")
                            .w(px(28.0))
                            .h(px(26.0))
                            .rounded(px(6.0))
                            .hover(|s| s.bg(t.red_bg))
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .on_click(cx.listener(|this, _, _, _| {
                                let v = this.vpn.clone();
                                this.rt.block_on(async move {
                                    v.disconnect().await;
                                });
                                std::process::exit(0);
                            }))
                            .child(
                                svg()
                                    .path("icons/close.svg")
                                    .size(px(12.0))
                                    .text_color(t.text_dim),
                            ),
                    ),
            )
    }

    fn render_navbar(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let rules_cnt = self.state.active_rules_count();
        let nodes_cnt = self.state.servers.len();

        let tabs: [(Tab, &'static str, &'static str, Option<usize>); 6] = [
            (Tab::Tunnel, "icons/power.svg", "Туннель", None),
            (Tab::Desync, "icons/bolt.svg", "Desync", None),
            (Tab::Routes, "icons/route.svg", "Маршруты", Some(rules_cnt)),
            (Tab::Nodes, "icons/server.svg", "Узлы", Some(nodes_cnt)),
            (Tab::Traffic, "icons/activity.svg", "Трафик", None),
            (Tab::Options, "icons/sliders.svg", "Опции", None),
        ];

        div()
            .w_full()
            .px(px(16.0))
            .pt(px(8.0))
            .pb(px(6.0))
            .flex()
            .justify_center()
            .child(
                div()
                    .w_full()
                    .max_w(px(880.0))
                    .p(px(4.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .children(tabs.into_iter().map(|(tab_id, icon, label, badge)| {
                        let active = self.tab == tab_id;
                        div()
                            .id(SharedString::from(format!("nav-{label}")))
                            .flex_1()
                            .h(px(32.0))
                            .rounded(px(8.0))
                            .cursor_pointer()
                            .bg(if active { t.bg_elev } else { gpui::rgba(0x00000000) })
                            .border_1()
                            .border_color(if active {
                                t.border_hi
                            } else {
                                gpui::rgba(0x00000000)
                            })
                            .hover(|s| s.bg(if active { t.bg_elev } else { t.bg_hover }))
                            .flex()
                            .items_center()
                            .justify_center()
                            .gap(px(6.0))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.tab = tab_id;
                                this.active_field = ActiveField::None;
                                if tab_id == Tab::Traffic {
                                    let v = this.vpn.clone();
                                    let eq = this.event_queue.clone();
                                    this.rt.spawn(async move {
                                        let data = v.get_connections_json().await;
                                        if let Ok(mut g) = eq.lock() {
                                            g.push(format!("conn:data:{data}"));
                                        }
                                    });
                                } else if tab_id == Tab::Routes && this.running_apps.is_empty() {
                                    let apps = enumerate_apps();
                                    this.running_apps = apps;
                                }
                                cx.notify();
                            }))
                            .child(svg().path(icon).size(px(13.0)).text_color(if active {
                                t.accent
                            } else {
                                t.text_dim
                            }))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(if active {
                                        FontWeight::SEMIBOLD
                                    } else {
                                        FontWeight::MEDIUM
                                    })
                                    .text_color(if active { t.text } else { t.text_dim })
                                    .child(label),
                            )
                            .when_some(badge, |el, cnt| {
                                el.child(
                                    div()
                                        .px(px(5.0))
                                        .py(px(1.0))
                                        .rounded(px(4.0))
                                        .bg(if active { t.accent_bg } else { t.bg_hover })
                                        .text_size(px(10.0))
                                        .text_color(if active { t.accent } else { t.text_dim })
                                        .child(cnt.to_string()),
                                )
                            })
                    })),
            )
    }

    fn render_footer(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let core_ver = option_env!("TACHYON_CORE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
        let dns_label = if self.state.vpn_prefs.dns == "custom"
            && !self.state.vpn_prefs.custom_dns.is_empty()
        {
            self.state.vpn_prefs.custom_dns.as_str()
        } else {
            self.state.vpn_prefs.dns.as_str()
        };

        div()
            .h(px(30.0))
            .w_full()
            .px(px(16.0))
            .bg(t.bg)
            .border_t_1()
            .border_color(t.border)
            .flex()
            .items_center()
            .justify_between()
            .text_size(px(11.0))
            .text_color(t.text_dim)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .w(px(6.0))
                            .h(px(6.0))
                            .rounded(px(3.0))
                            .bg(if self.vpn_status == "connected" {
                                t.green
                            } else {
                                t.text_mute
                            }),
                    )
                    .child(format!("Ядро tachyon-core {core_ver}  ·  DNS: {dns_label}")),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .child(format!(
                        "Узлов: {}  ·  Правил: {}",
                        self.state.servers.len(),
                        self.state.active_rules_count()
                    ))
                    .child(
                        div()
                            .id("btn-open-log-modal")
                            .cursor_pointer()
                            .text_color(t.accent)
                            .hover(|s| s.underline())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.log_tail = this.vpn.get_log_tail(140);
                                this.modal = ModalKind::KernelLog;
                                cx.notify();
                            }))
                            .child("Лог ядра"),
                    ),
            )
    }

    fn render_tunnel_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let is_connected = self.vpn_status == "connected";
        let is_connecting = self.vpn_status == "connecting";
        let active_srv = self.state.active_server().cloned();

        let status_label = if is_connected {
            "Защищено"
        } else if is_connecting {
            "Подключение..."
        } else {
            "Отключено"
        };

        let stack_badge = if self.state.vpn_prefs.mode == "tun" {
            "TUN · WINTUN"
        } else {
            "SYSTEM PROXY"
        };

        // Group filtered servers by country
        let query = self.server_search.trim().to_lowercase();
        let mut by_country: BTreeMap<String, Vec<ServerNode>> = BTreeMap::new();
        let mut filtered_total = 0usize;
        for srv in &self.state.servers {
            if !query.is_empty() {
                let ctitle = country_title_ru(&srv.country).to_lowercase();
                if !srv.name.to_lowercase().contains(&query) && !ctitle.contains(&query) {
                    continue;
                }
            }
            filtered_total += 1;
            by_country
                .entry(srv.country.clone())
                .or_default()
                .push(srv.clone());
        }

        div()
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .flex()
            .gap(px(14.0))
            .child(
                // Left Hero Orb Card (390px)
                div()
                    .w(px(390.0))
                    .h_full()
                    .p(px(18.0))
                    .rounded(px(16.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(if is_connected {
                        t.green_border
                    } else {
                        t.border
                    })
                    .flex()
                    .flex_col()
                    .justify_between()
                    .child(
                        // Top status badges
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .px(px(10.0))
                                    .py(px(4.0))
                                    .rounded(px(99.0))
                                    .bg(if is_connected {
                                        t.green_bg
                                    } else if is_connecting {
                                        t.amber_bg
                                    } else {
                                        t.bg_elev
                                    })
                                    .border_1()
                                    .border_color(if is_connected {
                                        t.green_border
                                    } else if is_connecting {
                                        t.amber_border
                                    } else {
                                        t.border
                                    })
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .w(px(7.0))
                                            .h(px(7.0))
                                            .rounded(px(4.0))
                                            .bg(if is_connected {
                                                t.green
                                            } else if is_connecting {
                                                t.amber
                                            } else {
                                                t.text_mute
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(if is_connected {
                                                t.green
                                            } else if is_connecting {
                                                t.amber
                                            } else {
                                                t.text_soft
                                            })
                                            .child(status_label),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .text_size(px(10.0))
                                            .text_color(t.text_dim)
                                            .child(stack_badge),
                                    )
                                    .child(
                                        div()
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .text_size(px(10.0))
                                            .text_color(t.text_soft)
                                            .child(format_uptime(self.connected_since)),
                                    ),
                            ),
                    )
                    .child(
                        // Center Power Orb
                        div()
                            .w_full()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap(px(12.0))
                            .child(
                                div()
                                    .w(px(164.0))
                                    .h(px(164.0))
                                    .rounded(px(82.0))
                                    .border_1()
                                    .border_color(if is_connected {
                                        t.green_border
                                    } else {
                                        t.border_hi
                                    })
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        div()
                                            .id("btn-power-orb")
                                            .w(px(124.0))
                                            .h(px(124.0))
                                            .rounded(px(62.0))
                                            .cursor_pointer()
                                            .bg(if is_connected {
                                                t.green_bg
                                            } else {
                                                t.bg_elev
                                            })
                                            .border_2()
                                            .border_color(if is_connected {
                                                t.green
                                            } else if is_connecting {
                                                t.amber
                                            } else {
                                                t.accent_border
                                            })
                                            .hover(|s| s.bg(t.bg_hover))
                                            .flex()
                                            .flex_col()
                                            .items_center()
                                            .justify_center()
                                            .gap(px(6.0))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.toggle_connection();
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/bolt.svg")
                                                    .size(px(24.0))
                                                    .text_color(if is_connected {
                                                        t.green
                                                    } else {
                                                        t.accent
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(if is_connected {
                                                        t.green
                                                    } else {
                                                        t.text_soft
                                                    })
                                                    .child(if is_connected {
                                                        format!(
                                                            "↓ {} МБ/с",
                                                            format_mb_per_sec(self.rx_bps)
                                                        )
                                                    } else {
                                                        "ВКЛЮЧИТЬ".to_string()
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(if !self.last_error.is_empty() && !is_connected {
                                        t.red
                                    } else {
                                        t.text_dim
                                    })
                                    .child(if is_connected {
                                        "Активно · Нажмите для отключения".to_string()
                                    } else if !self.last_error.is_empty() {
                                        truncate_str(&self.last_error, 46)
                                    } else {
                                        "Готов к запуску туннеля".to_string()
                                    }),
                            )
                            .when_some(self.live_balancer.as_ref().filter(|_| is_connected), |el, lb| {
                                let cur = lb
                                    .get("selected")
                                    .and_then(Value::as_str)
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or("автовыбор");
                                let mode = lb
                                    .get("mode")
                                    .and_then(Value::as_str)
                                    .unwrap_or("stability");
                                el.child(
                                    div()
                                        .px(px(8.0))
                                        .py(px(3.0))
                                        .rounded(px(6.0))
                                        .bg(t.accent_bg)
                                        .border_1()
                                        .border_color(t.accent_border)
                                        .text_size(px(10.0))
                                        .text_color(t.accent)
                                        .child(format!("Балансировщик ({mode}) · Узел: {cur}")),
                                )
                            }),
                    )
                    .child(
                        // Bottom Active Node bar
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .id("btn-active-node-card")
                                    .flex_1()
                                    .p(px(10.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.tab = Tab::Nodes;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(10.0))
                                            .child(render_flag_badge(
                                                active_srv
                                                    .as_ref()
                                                    .map(|s| s.country.as_str())
                                                    .unwrap_or("xx"),
                                                26.0,
                                                t,
                                            ))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .child(
                                                        div()
                                                            .text_size(px(12.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(t.text)
                                                            .child(
                                                                active_srv
                                                                    .as_ref()
                                                                    .map(|s| {
                                                                        truncate_str(&s.name, 20)
                                                                    })
                                                                    .unwrap_or_else(|| {
                                                                        "Прямой Desync (без узла)"
                                                                            .to_string()
                                                                    }),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.0))
                                                            .text_color(t.text_dim)
                                                            .child(
                                                                active_srv
                                                                    .as_ref()
                                                                    .map(|s| {
                                                                        format!(
                                                                            "{} · {}",
                                                                            country_title_ru(
                                                                                &s.country
                                                                            ),
                                                                            detect_protocol_badge(
                                                                                &s.vless
                                                                            )
                                                                        )
                                                                    })
                                                                    .unwrap_or_else(|| {
                                                                        format!(
                                                                            "Пресет: {} · Нажмите для добавления узлов",
                                                                            self.state.desync_prefs.preset
                                                                        )
                                                                    }),
                                                            ),
                                                    ),
                                            ),
                                    )
                                    .when_some(
                                        active_srv.as_ref().and_then(|s| s.ping_ms),
                                        |el, ms| {
                                            el.child(
                                                div()
                                                    .px(px(6.0))
                                                    .py(px(2.0))
                                                    .rounded(px(5.0))
                                                    .bg(t.bg_card)
                                                    .text_size(px(10.0))
                                                    .text_color(if ms > 0 {
                                                        t.green
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .child(if ms > 0 {
                                                        format!("{ms} мс")
                                                    } else {
                                                        "—".to_string()
                                                    }),
                                            )
                                        },
                                    ),
                            )
                            .child(
                                div()
                                    .id("btn-fastest-node")
                                    .w(px(38.0))
                                    .h(px(44.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.select_fastest_node();
                                        cx.notify();
                                    }))
                                    .child(
                                        svg()
                                            .path("icons/bolt.svg")
                                            .size(px(14.0))
                                            .text_color(t.accent),
                                    ),
                            ),
                    ),
            )
            .child(
                // Right column: Telemetry + Mode + Quick toggles + Server list
                div()
                    .flex_1()
                    .h_full()
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .child(
                        // Top 2 telemetry cards
                        div()
                            .w_full()
                            .flex()
                            .gap(px(10.0))
                            .child(
                                // Exit Node Card
                                div()
                                    .flex_1()
                                    .p(px(12.0))
                                    .rounded(px(12.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .flex_col()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .w_full()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_dim)
                                                    .child("• Выходной узел"),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-check-exit-geo")
                                                    .px(px(8.0))
                                                    .py(px(3.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(4.0))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.refresh_exit_info();
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/refresh.svg")
                                                            .size(px(11.0))
                                                            .text_color(t.text_soft),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.0))
                                                            .text_color(t.text_soft)
                                                            .child("Проверить"),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(16.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(if self.exit_info.loading {
                                                "Проверка...".to_string()
                                            } else if self.exit_info.ok {
                                                self.exit_info.ip.clone()
                                            } else {
                                                "Нет ответа".to_string()
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(if self.exit_info.ok {
                                                format!(
                                                    "{} {} · {} ({} мс)",
                                                    self.exit_info.country,
                                                    self.exit_info.city,
                                                    self.exit_info.isp,
                                                    self.exit_info.latency_ms
                                                )
                                            } else if !self.exit_info.error.is_empty() {
                                                self.exit_info.error.clone()
                                            } else {
                                                "Проверьте подключение".to_string()
                                            }),
                                    ),
                            )
                            .child(
                                // Speed Card
                                div()
                                    .flex_1()
                                    .p(px(12.0))
                                    .rounded(px(12.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.accent)
                                                    .child("• Приём"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(17.0))
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(t.text)
                                                    .child(format!(
                                                        "{} МБ/с",
                                                        format_mb_per_sec(self.rx_bps)
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child(format!(
                                                        "Всего: {}",
                                                        format_bytes_human(self.rx_total)
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.green)
                                                    .child("• Отдача"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(17.0))
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(t.text)
                                                    .child(format!(
                                                        "{} МБ/с",
                                                        format_mb_per_sec(self.tx_bps)
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child(format!(
                                                        "Всего: {}",
                                                        format_bytes_human(self.tx_total)
                                                    )),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        // Routing Mode Segmented Bar
                        div()
                            .w_full()
                            .p(px(10.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Режим маршрутизации"),
                                    )
                                    .child(
                                        div()
                                            .id("link-lists-desync")
                                            .cursor_pointer()
                                            .text_size(px(11.0))
                                            .text_color(t.accent)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.tab = Tab::Routes;
                                                cx.notify();
                                            }))
                                            .child("Списки и Desync ↗"),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .p(px(3.0))
                                    .rounded(px(8.0))
                                    .bg(t.bg_elev)
                                    .flex()
                                    .gap(px(3.0))
                                    .children(
                                        [
                                            ("all", "Весь ПК"),
                                            ("selective", "Точечно"),
                                            ("desync", "Только Desync"),
                                            ("apps", "Приложения"),
                                        ]
                                        .into_iter()
                                        .map(|(code, title)| {
                                            let active = self.state.vpn_prefs.route == code;
                                            div()
                                                .id(SharedString::from(format!("route-seg-{code}")))
                                                .flex_1()
                                                .h(px(26.0))
                                                .rounded(px(6.0))
                                                .cursor_pointer()
                                                .bg(if active {
                                                    t.bg_card
                                                } else {
                                                    gpui::rgba(0x00000000)
                                                })
                                                .border_1()
                                                .border_color(if active {
                                                    t.border_hi
                                                } else {
                                                    gpui::rgba(0x00000000)
                                                })
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .text_size(px(11.0))
                                                .font_weight(if active {
                                                    FontWeight::SEMIBOLD
                                                } else {
                                                    FontWeight::NORMAL
                                                })
                                                .text_color(if active {
                                                    t.text
                                                } else {
                                                    t.text_dim
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.route = code.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(title)
                                        }),
                                    ),
                            ),
                    )
                    .child(
                        // 3 Quick Toggle Cards: Desync / Stack / Kill Switch
                        div()
                            .w_full()
                            .flex()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .id("card-quick-desync")
                                    .flex_1()
                                    .p(px(10.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(if self.state.desync_prefs.enabled {
                                        t.amber_border
                                    } else {
                                        t.border
                                    })
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.state.desync_prefs.enabled =
                                            !this.state.desync_prefs.enabled;
                                        this.reconnect_if_active();
                                        cx.notify();
                                    }))
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        svg()
                                            .path("icons/bolt.svg")
                                            .size(px(14.0))
                                            .text_color(if self.state.desync_prefs.enabled {
                                                t.amber
                                            } else {
                                                t.text_dim
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child("Пакетный Desync"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(if self.state.desync_prefs.enabled {
                                                        t.amber
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .child(if self.state.desync_prefs.enabled {
                                                        "Активен · Adaptive"
                                                    } else {
                                                        "Выключен"
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("card-quick-stack")
                                    .flex_1()
                                    .p(px(10.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(if self.state.vpn_prefs.mode == "tun" {
                                        t.accent_border
                                    } else {
                                        t.border
                                    })
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.state.vpn_prefs.mode =
                                            if this.state.vpn_prefs.mode == "tun" {
                                                "proxy".to_string()
                                            } else {
                                                "tun".to_string()
                                            };
                                        this.reconnect_if_active();
                                        cx.notify();
                                    }))
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        svg()
                                            .path("icons/globe.svg")
                                            .size(px(14.0))
                                            .text_color(t.accent),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child("Сетевой стек"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.accent)
                                                    .child(if self.state.vpn_prefs.mode == "tun" {
                                                        "TUN · Wintun"
                                                    } else {
                                                        "Системный прокси"
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("card-quick-ks")
                                    .flex_1()
                                    .p(px(10.0))
                                    .rounded(px(10.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(if self.state.vpn_prefs.kill_switch {
                                        t.red_border
                                    } else {
                                        t.border
                                    })
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let next = !this.state.vpn_prefs.kill_switch;
                                        this.state.vpn_prefs.kill_switch = next;
                                        this.vpn.set_kill_switch(next);
                                        this.state.save();
                                        cx.notify();
                                    }))
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        svg()
                                            .path("icons/lock.svg")
                                            .size(px(14.0))
                                            .text_color(if self.state.vpn_prefs.kill_switch {
                                                t.red
                                            } else {
                                                t.text_dim
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child("Kill Switch"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(if self.state.vpn_prefs.kill_switch {
                                                        t.red
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .child(if self.state.vpn_prefs.kill_switch {
                                                        "Активен"
                                                    } else {
                                                        "Выключен"
                                                    }),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        // Servers & Locations Card
                        div()
                            .flex_1()
                            .w_full()
                            .p(px(12.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .overflow_hidden()
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text_soft)
                                                    .child("• Серверы и локации"),
                                            )
                                            .child(
                                                div()
                                                    .px(px(6.0))
                                                    .py(px(1.0))
                                                    .rounded(px(4.0))
                                                    .bg(t.accent_bg)
                                                    .text_size(px(10.0))
                                                    .text_color(t.accent)
                                                    .child(filtered_total.to_string()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .id("input-srv-search")
                                                    .w(px(190.0))
                                                    .h(px(26.0))
                                                    .px(px(8.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(
                                                        if self.active_field
                                                            == ActiveField::ServerSearch
                                                        {
                                                            t.accent
                                                        } else {
                                                            t.border
                                                        },
                                                    )
                                                    .cursor_text()
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(6.0))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.active_field =
                                                            ActiveField::ServerSearch;
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/search.svg")
                                                            .size(px(11.0))
                                                            .text_color(t.text_dim),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(11.0))
                                                            .text_color(
                                                                if self.server_search.is_empty() {
                                                                    t.text_mute
                                                                } else {
                                                                    t.text
                                                                },
                                                            )
                                                            .child(if self.server_search.is_empty() {
                                                                "Поиск страны или узла..."
                                                                    .to_string()
                                                            } else {
                                                                self.server_search.clone()
                                                            }),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-ping-all")
                                                    .h(px(26.0))
                                                    .px(px(8.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(4.0))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.ping_all_nodes();
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/bolt.svg")
                                                            .size(px(11.0))
                                                            .text_color(t.text_soft),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(11.0))
                                                            .text_color(t.text_soft)
                                                            .child("Пинг"),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-subs-modal")
                                                    .h(px(26.0))
                                                    .px(px(8.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(4.0))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.modal = ModalKind::Subscriptions;
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/server.svg")
                                                            .size(px(11.0))
                                                            .text_color(t.text_soft),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(11.0))
                                                            .text_color(t.text_soft)
                                                            .child("Подписки"),
                                                    ),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("tunnel-servers-scroll")
                                    .flex_1()
                                    .w_full()
                                    .overflow_y_scroll()
                                    .flex()
                                    .flex_col()
                                    .gap(px(6.0))
                                    .children(by_country.into_iter().map(|(cc, list)| {
                                        let collapsed = self.collapsed_countries.contains(&cc);
                                        let cc_toggle = cc.clone();
                                        let best_ms = list
                                            .iter()
                                            .filter_map(|s| s.ping_ms)
                                            .filter(|&m| m > 0)
                                            .min();

                                        div()
                                            .w_full()
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "country-hdr-{cc}"
                                                    )))
                                                    .w_full()
                                                    .h(px(30.0))
                                                    .px(px(10.0))
                                                    .rounded(px(8.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .flex()
                                                    .items_center()
                                                    .justify_between()
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        if !this
                                                            .collapsed_countries
                                                            .remove(&cc_toggle)
                                                        {
                                                            this.collapsed_countries
                                                                .insert(cc_toggle.clone());
                                                        }
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .items_center()
                                                            .gap(px(8.0))
                                                            .child(render_flag_badge(&cc, 18.0, t))
                                                            .child(
                                                                div()
                                                                    .text_size(px(11.5))
                                                                    .font_weight(
                                                                        FontWeight::SEMIBOLD,
                                                                    )
                                                                    .text_color(t.text)
                                                                    .child(country_title_ru(&cc)),
                                                            )
                                                            .child(
                                                                div()
                                                                    .px(px(5.0))
                                                                    .rounded(px(4.0))
                                                                    .bg(t.bg_card)
                                                                    .text_size(px(10.0))
                                                                    .text_color(t.text_dim)
                                                                    .child(list.len().to_string()),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .items_center()
                                                            .gap(px(6.0))
                                                            .when_some(best_ms, |el, ms| {
                                                                el.child(
                                                                    div()
                                                                        .text_size(px(10.5))
                                                                        .text_color(t.green)
                                                                        .child(format!("{ms} мс")),
                                                                )
                                                            })
                                                            .child(
                                                                svg()
                                                                    .path(if collapsed {
                                                                        "icons/chevron_right.svg"
                                                                    } else {
                                                                        "icons/chevron_down.svg"
                                                                    })
                                                                    .size(px(12.0))
                                                                    .text_color(t.text_dim),
                                                            ),
                                                    ),
                                            )
                                            .when(!collapsed, |el| {
                                                el.child(
                                                    div()
                                                        .w_full()
                                                        .flex()
                                                        .flex_wrap()
                                                        .gap(px(6.0))
                                                        .children(list.into_iter().map(|srv| {
                                                            let is_sel =
                                                                srv.id == self.state.active_id;
                                                            let sid = srv.id.clone();
                                                            let proto =
                                                                detect_protocol_badge(&srv.vless);
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "srv-chip-{}",
                                                                    srv.id
                                                                )))
                                                                .w(px(236.0))
                                                                .p(px(8.0))
                                                                .rounded(px(8.0))
                                                                .bg(if is_sel {
                                                                    t.accent_bg
                                                                } else {
                                                                    t.bg_elev
                                                                })
                                                                .border_1()
                                                                .border_color(if is_sel {
                                                                    t.accent_border
                                                                } else {
                                                                    t.border
                                                                })
                                                                .cursor_pointer()
                                                                .hover(|s| s.bg(t.bg_hover))
                                                                .flex()
                                                                .items_center()
                                                                .justify_between()
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        this.state.active_id =
                                                                            sid.clone();
                                                                        this.reconnect_if_active();
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                                .child(
                                                                    div()
                                                                        .flex()
                                                                        .items_center()
                                                                        .gap(px(7.0))
                                                                        .child(render_flag_badge(
                                                                            &srv.country,
                                                                            18.0,
                                                                            t,
                                                                        ))
                                                                        .child(
                                                                            div()
                                                                                .text_size(px(11.0))
                                                                                .font_weight(
                                                                                    FontWeight::MEDIUM,
                                                                                )
                                                                                .text_color(t.text)
                                                                                .child(
                                                                                    truncate_str(
                                                                                        &srv.name,
                                                                                        17,
                                                                                    ),
                                                                                ),
                                                                        ),
                                                                )
                                                                .child(
                                                                    div()
                                                                        .flex()
                                                                        .items_center()
                                                                        .gap(px(5.0))
                                                                        .child(
                                                                            div()
                                                                                .px(px(4.0))
                                                                                .py(px(1.0))
                                                                                .rounded(px(4.0))
                                                                                .bg(t.green_bg)
                                                                                .text_size(px(9.0))
                                                                                .font_weight(
                                                                                    FontWeight::BOLD,
                                                                                )
                                                                                .text_color(t.green)
                                                                                .child(proto),
                                                                        )
                                                                        .when_some(
                                                                            srv.ping_ms,
                                                                            |el, ms| {
                                                                                el.child(
                                                                                    div()
                                                                                        .text_size(
                                                                                            px(10.0),
                                                                                        )
                                                                                        .text_color(
                                                                                            if ms
                                                                                                > 0
                                                                                            {
                                                                                                t.green
                                                                                            } else {
                                                                                                t.text_mute
                                                                                            },
                                                                                        )
                                                                                        .child(
                                                                                            if ms
                                                                                                > 0
                                                                                            {
                                                                                                format!(
                                                                                                    "{ms} мс"
                                                                                                )
                                                                                            } else {
                                                                                                "—"
                                                                                                    .to_string()
                                                                                            },
                                                                                        ),
                                                                                )
                                                                            },
                                                                        ),
                                                                )
                                                        })),
                                                )
                                            })
                                    })),
                            ),
                    ),
            )
    }
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

impl TachyonApp {
    fn render_desync_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let d = &self.state.desync_prefs;

        div()
            .id("desync-scroll")
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Header card
                div()
                    .w_full()
                    .p(px(12.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(if d.enabled { t.amber_border } else { t.border })
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(12.0))
                            .child(
                                div()
                                    .w(px(36.0))
                                    .h(px(36.0))
                                    .rounded(px(9.0))
                                    .bg(if d.enabled { t.amber_bg } else { t.bg_elev })
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(svg().path("icons/bolt.svg").size(px(18.0)).text_color(
                                        if d.enabled { t.amber } else { t.text_dim },
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Пакетная десинхронизация (Desync)"),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child("Фрагментация TLS ClientHello, OOB-маркеры и инъекция QUIC Initial для прямого соединения"),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id("btn-desync-master")
                            .px(px(14.0))
                            .py(px(6.0))
                            .rounded(px(8.0))
                            .cursor_pointer()
                            .bg(if d.enabled { t.amber_bg } else { t.bg_elev })
                            .border_1()
                            .border_color(if d.enabled { t.amber_border } else { t.border })
                            .text_size(px(12.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(if d.enabled { t.amber } else { t.text_soft })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.state.desync_prefs.enabled = !this.state.desync_prefs.enabled;
                                this.reconnect_if_active();
                                cx.notify();
                            }))
                            .child(if d.enabled { "Активен" } else { "Включить" }),
                    ),
            )
            .child(
                // Presets row (synced with vpn.rs::DesyncOptions::parse)
                div()
                    .w_full()
                    .flex()
                    .gap(px(8.0))
                    .children(
                        [
                            ("auto", "Авто (Adaptive)", "Multi-Disorder + QUIC Fake 6x + Автоподбор"),
                            ("youtube_discord", "YouTube + Discord", "Multi-Disorder + TLSRec + QUIC 8x"),
                            ("multi_disorder", "Multi-Disorder", "Каскадная нарезка SNI с обратным порядком"),
                            ("fake_split", "Fake + Split", "Мягкое разбиение TLS без инверсии сегментов"),
                            ("tlsrec", "Чистый TLS Record", "Нарезка записи TLS без фейковых пакетов"),
                        ]
                        .into_iter()
                        .map(|(pid, title, desc)| {
                            let active = d.preset == pid || (pid == "auto" && d.preset == "adaptive");
                            div()
                                .id(SharedString::from(format!("desync-preset-{pid}")))
                                .flex_1()
                                .p(px(10.0))
                                .rounded(px(10.0))
                                .bg(if active { t.accent_bg } else { t.bg_card })
                                .border_1()
                                .border_color(if active { t.accent_border } else { t.border })
                                .cursor_pointer()
                                .hover(|s| s.bg(t.bg_hover))
                                .flex()
                                .flex_col()
                                .gap(px(3.0))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.state.desync_prefs.preset = pid.to_string();
                                    match pid {
                                        "youtube_discord" => {
                                            this.state.desync_prefs.mode = "multidisorder".to_string();
                                            this.state.desync_prefs.fooling = "md5sig+badsum".to_string();
                                            this.state.desync_prefs.split_pos = "1,sniext+1,host+1,midsld".to_string();
                                            this.state.desync_prefs.tlsrec_first = true;
                                            this.state.desync_prefs.fake_ttl = 5;
                                            this.state.desync_prefs.repeats = 6;
                                            this.state.desync_prefs.quic_fake = true;
                                            this.state.desync_prefs.udp_fake = true;
                                            this.state.desync_prefs.quic_repeats = 8;
                                        }
                                        "multi_disorder" => {
                                            this.state.desync_prefs.mode = "multidisorder".to_string();
                                            this.state.desync_prefs.fooling = "md5sig+badsum".to_string();
                                            this.state.desync_prefs.split_pos = "1,sniext+1,midsld".to_string();
                                            this.state.desync_prefs.tlsrec_first = true;
                                            this.state.desync_prefs.fake_ttl = 5;
                                            this.state.desync_prefs.repeats = 6;
                                            this.state.desync_prefs.quic_fake = true;
                                            this.state.desync_prefs.udp_fake = true;
                                        }
                                        "fake_split" => {
                                            this.state.desync_prefs.mode = "fake_split".to_string();
                                            this.state.desync_prefs.fooling = "md5sig".to_string();
                                            this.state.desync_prefs.split_pos = "sniext+1".to_string();
                                            this.state.desync_prefs.tlsrec_first = true;
                                            this.state.desync_prefs.fake_ttl = 5;
                                            this.state.desync_prefs.repeats = 4;
                                            this.state.desync_prefs.quic_fake = true;
                                            this.state.desync_prefs.udp_fake = true;
                                        }
                                        "tlsrec" => {
                                            this.state.desync_prefs.mode = "tlsrec".to_string();
                                            this.state.desync_prefs.split_pos = "sniext+1".to_string();
                                            this.state.desync_prefs.tlsrec_first = true;
                                            this.state.desync_prefs.quic_fake = false;
                                            this.state.desync_prefs.udp_fake = false;
                                        }
                                        _ => {
                                            this.state.desync_prefs.mode = "multidisorder".to_string();
                                            this.state.desync_prefs.fooling = "md5sig+badsum".to_string();
                                            this.state.desync_prefs.split_pos = "1,sniext+1,host+1,midsld".to_string();
                                            this.state.desync_prefs.tlsrec_first = true;
                                            this.state.desync_prefs.fake_ttl = 5;
                                            this.state.desync_prefs.repeats = 6;
                                            this.state.desync_prefs.quic_fake = true;
                                            this.state.desync_prefs.udp_fake = true;
                                            this.state.desync_prefs.auto_tune = true;
                                        }
                                    }
                                    this.reconnect_if_active();
                                    cx.notify();
                                }))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(if active { t.accent } else { t.text })
                                        .child(title),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.0))
                                        .text_color(t.text_dim)
                                        .child(desc),
                                )
                        }),
                    ),
            )
            .child(
                // Strategy selectors row (Mode, Fooling, SplitPos, FakeSNI)
                div()
                    .w_full()
                    .p(px(12.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap(px(8.0))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Метод Fooling:"),
                                    )
                                    .children(
                                        [
                                            ("md5sig+badsum", "MD5Sig + BadSum"),
                                            ("md5sig", "TCP MD5Sig"),
                                            ("badsum", "Bad Checksum"),
                                            ("badseq", "Bad Seq"),
                                            ("ts", "TCP Timestamp"),
                                        ]
                                        .into_iter()
                                        .map(|(fc, fl)| {
                                            let act = d.fooling == fc;
                                            div()
                                                .id(SharedString::from(format!("ds-fool-{fc}")))
                                                .px(px(8.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.5))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.desync_prefs.fooling = fc.to_string();
                                                    this.state.desync_prefs.preset = "custom".to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(fl)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Fake TTL:"),
                                    )
                                    .children([3u32, 4, 5, 6, 8].into_iter().map(|ttl_val| {
                                        let act = d.fake_ttl == ttl_val;
                                        div()
                                            .id(SharedString::from(format!("ds-ttl-{ttl_val}")))
                                            .px(px(7.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .cursor_pointer()
                                            .bg(if act { t.amber_bg } else { t.bg_elev })
                                            .text_size(px(10.5))
                                            .text_color(if act { t.amber } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.desync_prefs.fake_ttl = ttl_val;
                                                this.state.desync_prefs.preset = "custom".to_string();
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(ttl_val.to_string())
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Точки разреза SNI:"),
                                    )
                                    .children(
                                        [
                                            ("1,sniext+1,host+1,midsld", "Каскад (4 точки)"),
                                            ("1,sniext+1,midsld", "SNI + MidSLD"),
                                            ("sniext+1", "Начало SNI"),
                                            ("midsld", "Середина домена"),
                                        ]
                                        .into_iter()
                                        .map(|(sp, sl)| {
                                            let act = d.split_pos == sp;
                                            div()
                                                .id(SharedString::from(format!("ds-sp-{sl}")))
                                                .px(px(8.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.5))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.desync_prefs.split_pos = sp.to_string();
                                                    this.state.desync_prefs.preset = "custom".to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(sl)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Fake SNI:"),
                                    )
                                    .children(
                                        [
                                            "www.google.com",
                                            "rzd.ru",
                                            "vk.com",
                                            "ya.ru",
                                        ]
                                        .into_iter()
                                        .map(|sni| {
                                            let act = d.fake_sni == sni;
                                            div()
                                                .id(SharedString::from(format!("ds-sni-{sni}")))
                                                .px(px(7.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.desync_prefs.fake_sni = sni.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(sni)
                                        }),
                                    ),
                            ),
                    ),
            )
            .child(
                // Fine parameters grid
                div()
                    .w_full()
                    .flex()
                    .gap(px(12.0))
                    .child(
                        // TCP / TLS column
                        div()
                            .flex_1()
                            .p(px(14.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child("Параметры TCP и TLS"),
                            )
                            .child(self.render_toggle_row(
                                "toggle-tlsrec-first",
                                "Дробление записи TLS (TLSRec First)",
                                "Разбиение TLS Record до отправки TCP-сегментов",
                                d.tlsrec_first,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.tlsrec_first =
                                        !this.state.desync_prefs.tlsrec_first;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-tls-frag",
                                "Фрагментация записей TLS на прокси",
                                "Разбиение TLS ClientHello для прокси-узлов",
                                self.state.vpn_prefs.tls_fragment,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.vpn_prefs.tls_fragment =
                                        !this.state.vpn_prefs.tls_fragment;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-auto-direct",
                                "Прямой Desync для YouTube и Discord",
                                "Отправлять YouTube и Discord напрямую через Desync мимо VPN",
                                d.auto_direct,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.auto_direct =
                                        !this.state.desync_prefs.auto_direct;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-auto-tune",
                                "Адаптивный автоподбор при RST/Timeout",
                                "Автоматическая ротация стратегии для проблемных доменов",
                                d.auto_tune,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.auto_tune =
                                        !this.state.desync_prefs.auto_tune;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(
                        // UDP / QUIC column
                        div()
                            .flex_1()
                            .p(px(14.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child("Параметры UDP, QUIC и Голоса"),
                            )
                            .child(self.render_toggle_row(
                                "toggle-quic-fake",
                                "Десинхронизация QUIC Initial / UDP",
                                "Предварительная отправка фейковых UDP-датаграмм (443, 50000–65535)",
                                d.quic_fake && d.udp_fake,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    let next = !(this.state.desync_prefs.quic_fake
                                        && this.state.desync_prefs.udp_fake);
                                    this.state.desync_prefs.quic_fake = next;
                                    this.state.desync_prefs.udp_fake = next;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-block-quic",
                                "Принудительный перевод браузера с QUIC на TCP",
                                "Блокировать исходящий UDP:443 для гарантированного TLS Desync",
                                d.block_quic,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.block_quic =
                                        !this.state.desync_prefs.block_quic;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-discord-udp",
                                "Голосовые шлюзы Discord UDP / STUN",
                                "Инициализация IP Discovery и WebRTC на голосовых портах",
                                d.discord_udp_fake,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    let next = !this.state.desync_prefs.discord_udp_fake;
                                    this.state.desync_prefs.discord_udp_fake = next;
                                    this.state.desync_prefs.stun_fake = next;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-ipfrag",
                                "IPv4/IPv6 фрагментация (IPFrag2)",
                                "Разбиение пакетов на сетевом уровне L3",
                                d.ipfrag,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.ipfrag =
                                        !this.state.desync_prefs.ipfrag;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            )),
                    ),
            )
    }

    fn render_routes_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Sub-navigation bar
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .p(px(3.0))
                            .rounded(px(8.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .gap(px(4.0))
                            .children(
                                [
                                    (RouteSubTab::Catalog, "Каталог сервисов"),
                                    (RouteSubTab::Custom, "Свои правила"),
                                    (RouteSubTab::Apps, "Приложения ПК"),
                                ]
                                .into_iter()
                                .map(|(st, label)| {
                                    let active = self.route_subtab == st;
                                    div()
                                        .id(SharedString::from(format!("route-subtab-{label}")))
                                        .px(px(12.0))
                                        .py(px(5.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .bg(if active {
                                            t.bg_elev
                                        } else {
                                            gpui::rgba(0x00000000)
                                        })
                                        .text_size(px(11.5))
                                        .font_weight(if active {
                                            FontWeight::SEMIBOLD
                                        } else {
                                            FontWeight::NORMAL
                                        })
                                        .text_color(if active { t.text } else { t.text_dim })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.route_subtab = st;
                                            if st == RouteSubTab::Apps
                                                && this.running_apps.is_empty()
                                            {
                                                this.running_apps = enumerate_apps();
                                            }
                                            cx.notify();
                                        }))
                                        .child(label)
                                }),
                            ),
                    )
                    .child(
                        div()
                            .id("btn-refresh-rulesets")
                            .px(px(10.0))
                            .py(px(5.0))
                            .rounded(px(8.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .on_click(cx.listener(|this, _, _, cx| {
                                let v = this.vpn.clone();
                                this.rt.spawn(async move {
                                    v.refresh_rulesets(None).await;
                                });
                                this.show_toast("Обновление баз маршрутов...");
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/refresh.svg")
                                    .size(px(12.0))
                                    .text_color(t.accent),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(t.text_soft)
                                    .child("Обновить базы .srs"),
                            ),
                    ),
            )
            .child(match self.route_subtab {
                RouteSubTab::Catalog => self.render_routes_catalog(t, cx).into_any_element(),
                RouteSubTab::Custom => self.render_routes_custom(t, cx).into_any_element(),
                RouteSubTab::Apps => self.render_routes_apps(t, cx).into_any_element(),
            })
    }

    fn render_routes_catalog(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let q = self.route_search.trim().to_lowercase();
        let filtered: Vec<_> = ROUTE_CATALOG
            .iter()
            .filter(|e| {
                q.is_empty()
                    || e.name.to_lowercase().contains(&q)
                    || e.desc.to_lowercase().contains(&q)
                    || e.group.to_lowercase().contains(&q)
                    || e.id.to_lowercase().contains(&q)
            })
            .collect();

        div()
            .flex_1()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .overflow_hidden()
            .child(
                // Quick scenarios + Search bar
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .children(
                                [
                                    ("ru_desync", "РФ напрямую + YT/Discord Desync"),
                                    ("desync_only", "Только Desync (без VPN)"),
                                    ("selective_vpn", "Точечный туннель"),
                                    ("adblock_on", "+ Блок рекламы"),
                                    ("reset_all", "Сбросить"),
                                ]
                                .into_iter()
                                .map(|(sc_id, sc_label)| {
                                    div()
                                        .id(SharedString::from(format!("route-scen-{sc_id}")))
                                        .px(px(8.0))
                                        .py(px(4.0))
                                        .rounded(px(6.0))
                                        .bg(t.bg_card)
                                        .border_1()
                                        .border_color(t.border)
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover))
                                        .text_size(px(10.5))
                                        .text_color(if sc_id == "reset_all" {
                                            t.red
                                        } else {
                                            t.text_soft
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            match sc_id {
                                                "ru_desync" => {
                                                    this.state.vpn_prefs.route = "all".to_string();
                                                    this.state.desync_prefs.enabled = true;
                                                    this.state.list_modes.insert("ru_domains".to_string(), "direct".to_string());
                                                    this.state.list_modes.insert("geoip_ru".to_string(), "direct".to_string());
                                                    this.state.list_modes.insert("ru_only_inside".to_string(), "direct".to_string());
                                                    this.state.list_modes.insert("youtube".to_string(), "desync".to_string());
                                                    this.state.list_modes.insert("discord".to_string(), "desync".to_string());
                                                    this.show_toast("Применён сценарий: РФ напрямую + YT/Discord Desync");
                                                }
                                                "desync_only" => {
                                                    this.state.vpn_prefs.route = "desync".to_string();
                                                    this.state.desync_prefs.enabled = true;
                                                    this.state.list_modes.insert("youtube".to_string(), "desync".to_string());
                                                    this.state.list_modes.insert("discord".to_string(), "desync".to_string());
                                                    this.show_toast("Применён сценарий: Только Desync (без VPN)");
                                                }
                                                "selective_vpn" => {
                                                    this.state.vpn_prefs.route = "selective".to_string();
                                                    for k in ["ru_blocked", "youtube", "discord", "meta", "twitter", "ai_all", "openai", "claude", "gemini"] {
                                                        this.state.list_modes.insert(k.to_string(), "vpn".to_string());
                                                    }
                                                    this.show_toast("Применён сценарий: Точечный туннель");
                                                }
                                                "adblock_on" => {
                                                    for k in ["ads_all", "adguard", "win_telemetry"] {
                                                        this.state.list_modes.insert(k.to_string(), "block".to_string());
                                                    }
                                                    this.show_toast("Включена блокировка рекламы и телеметрии");
                                                }
                                                "reset_all" => {
                                                    for v in this.state.list_modes.values_mut() {
                                                        *v = "off".to_string();
                                                    }
                                                    this.show_toast("Все списки каталога сброшены в Выкл");
                                                }
                                                _ => {}
                                            }
                                            this.reconnect_if_active();
                                            cx.notify();
                                        }))
                                        .child(sc_label)
                                }),
                            ),
                    )
                    .child(
                        div()
                            .id("input-route-search")
                            .w(px(230.0))
                            .h(px(28.0))
                            .px(px(8.0))
                            .rounded(px(6.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(if self.active_field == ActiveField::RouteSearch {
                                t.accent
                            } else {
                                t.border
                            })
                            .cursor_text()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::RouteSearch;
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/search.svg")
                                    .size(px(11.0))
                                    .text_color(t.text_dim),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(if self.route_search.is_empty() {
                                        t.text_mute
                                    } else {
                                        t.text
                                    })
                                    .child(if self.route_search.is_empty() {
                                        "Поиск из 55 сервисов...".to_string()
                                    } else {
                                        self.route_search.clone()
                                    }),
                            ),
                    ),
            )
            .child(
                div()
                    .id("routes-catalog-scroll")
                    .flex_1()
                    .w_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.0))
                    .children(filtered.into_iter().map(|entry| {
                        let current_mode = self
                            .state
                            .list_modes
                            .get(entry.id)
                            .map(String::as_str)
                            .unwrap_or("off");
                        let eid = entry.id;

                        div()
                            .w(px(345.0))
                            .p(px(10.0))
                            .rounded(px(10.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(match current_mode {
                                "vpn" => t.accent_border,
                                "desync" => t.amber_border,
                                "direct" => t.green_border,
                                "block" => t.red_border,
                                _ => t.border,
                            })
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text)
                                            .child(entry.name),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(10.0))
                                            .text_color(t.text_mute)
                                            .child(entry.group),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(t.text_dim)
                                    .child(entry.desc),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .p(px(2.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .flex()
                                    .gap(px(2.0))
                                    .children(
                                        [
                                            ("off", "Выкл"),
                                            ("vpn", "Туннель"),
                                            ("desync", "Desync"),
                                            ("direct", "Прямой"),
                                            ("block", "Блок"),
                                        ]
                                        .into_iter()
                                        .map(|(mcode, mlabel)| {
                                            let active = current_mode == mcode;
                                            div()
                                                .id(SharedString::from(format!(
                                                    "cat-{eid}-{mcode}"
                                                )))
                                                .flex_1()
                                                .h(px(22.0))
                                                .rounded(px(4.0))
                                                .cursor_pointer()
                                                .bg(if active {
                                                    match mcode {
                                                        "vpn" => t.accent_bg,
                                                        "desync" => t.amber_bg,
                                                        "direct" => t.green_bg,
                                                        "block" => t.red_bg,
                                                        _ => t.bg_card,
                                                    }
                                                } else {
                                                    gpui::rgba(0x00000000)
                                                })
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .text_size(px(10.0))
                                                .font_weight(if active {
                                                    FontWeight::SEMIBOLD
                                                } else {
                                                    FontWeight::NORMAL
                                                })
                                                .text_color(if active {
                                                    match mcode {
                                                        "vpn" => t.accent,
                                                        "desync" => t.amber,
                                                        "direct" => t.green,
                                                        "block" => t.red,
                                                        _ => t.text,
                                                    }
                                                } else {
                                                    t.text_dim
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state
                                                        .list_modes
                                                        .insert(eid.to_string(), mcode.to_string());
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(mlabel)
                                        }),
                                    ),
                            )
                    })),
            )
    }

    fn render_routes_custom(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_1()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Add custom rule bar
                div()
                    .w_full()
                    .p(px(10.0))
                    .rounded(px(10.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .children(
                        [
                            ("domain", "Домен"),
                            ("cidr", "IP / CIDR"),
                            ("process", "Процесс"),
                        ]
                        .into_iter()
                        .map(|(rt, rlabel)| {
                            let active = self.custom_rule_type == rt;
                            div()
                                .id(SharedString::from(format!("cr-type-{rt}")))
                                .px(px(8.0))
                                .py(px(5.0))
                                .rounded(px(6.0))
                                .cursor_pointer()
                                .bg(if active { t.accent_bg } else { t.bg_elev })
                                .text_size(px(11.0))
                                .text_color(if active { t.accent } else { t.text_dim })
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.custom_rule_type = rt.to_string();
                                    cx.notify();
                                }))
                                .child(rlabel)
                        }),
                    )
                    .child(
                        div()
                            .id("input-custom-rule")
                            .flex_1()
                            .h(px(30.0))
                            .px(px(10.0))
                            .rounded(px(6.0))
                            .bg(t.bg_elev)
                            .border_1()
                            .border_color(if self.active_field == ActiveField::CustomRuleValue {
                                t.accent
                            } else {
                                t.border
                            })
                            .cursor_text()
                            .flex()
                            .items_center()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::CustomRuleValue;
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .text_color(if self.custom_rule_value.is_empty() {
                                        t.text_mute
                                    } else {
                                        t.text
                                    })
                                    .child(if self.custom_rule_value.is_empty() {
                                        "example.com, 1.2.3.0/24 или game.exe...".to_string()
                                    } else {
                                        self.custom_rule_value.clone()
                                    }),
                            ),
                    )
                    .children(
                        [
                            ("vpn", "В туннель"),
                            ("desync", "Desync"),
                            ("direct", "Напрямую"),
                            ("block", "Блок"),
                        ]
                        .into_iter()
                        .map(|(act, alabel)| {
                            let active = self.custom_rule_action == act;
                            div()
                                .id(SharedString::from(format!("cr-act-{act}")))
                                .px(px(8.0))
                                .py(px(5.0))
                                .rounded(px(6.0))
                                .cursor_pointer()
                                .bg(if active { t.bg_hover } else { t.bg_elev })
                                .border_1()
                                .border_color(if active { t.border_hi } else { t.border })
                                .text_size(px(11.0))
                                .text_color(if active { t.text } else { t.text_dim })
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.custom_rule_action = act.to_string();
                                    cx.notify();
                                }))
                                .child(alabel)
                        }),
                    )
                    .child(
                        div()
                            .id("btn-add-custom-rule")
                            .px(px(12.0))
                            .h(px(30.0))
                            .rounded(px(6.0))
                            .bg(t.accent)
                            .cursor_pointer()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(gpui::rgb(0x0B0B0D))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.submit_custom_rule();
                                cx.notify();
                            }))
                            .child("Добавить"),
                    ),
            )
            .child(
                div()
                    .id("custom-rules-scroll")
                    .flex_1()
                    .w_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .children(self.state.custom_rules.iter().map(|rule| {
                        let rid = rule.id.clone();
                        div()
                            .w_full()
                            .p(px(10.0))
                            .rounded(px(8.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .px(px(6.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .bg(t.bg_elev)
                                            .text_size(px(10.0))
                                            .text_color(t.text_dim)
                                            .child(rule.rule_type.to_uppercase()),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text)
                                            .child(rule.value.clone()),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .px(px(8.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .bg(t.accent_bg)
                                            .text_size(px(10.5))
                                            .text_color(t.accent)
                                            .child(rule.action.to_uppercase()),
                                    )
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("del-rule-{rid}")))
                                            .w(px(24.0))
                                            .h(px(24.0))
                                            .rounded(px(6.0))
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.red_bg))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.custom_rules.retain(|r| r.id != rid);
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/trash.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.red),
                                            ),
                                    ),
                            )
                    })),
            )
    }

    fn render_routes_apps(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_1()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .overflow_hidden()
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .text_color(t.text_soft)
                                    .child(format!(
                                        "Выбрано приложений для туннелирования: {}",
                                        self.state.routed_apps.len()
                                    )),
                            )
                            .when(!self.state.routed_apps.is_empty(), |el| {
                                el.child(
                                    div()
                                        .id("btn-clear-routed-apps")
                                        .px(px(8.0))
                                        .py(px(3.0))
                                        .rounded(px(5.0))
                                        .bg(t.bg_card)
                                        .border_1()
                                        .border_color(t.border)
                                        .cursor_pointer()
                                        .text_size(px(10.5))
                                        .text_color(t.red)
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.state.routed_apps.clear();
                                            this.reconnect_if_active();
                                            cx.notify();
                                        }))
                                        .child("Очистить выбор"),
                                )
                            }),
                    )
                    .child(
                        div()
                            .id("btn-rescan-apps")
                            .px(px(10.0))
                            .py(px(4.0))
                            .rounded(px(6.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.running_apps = enumerate_apps();
                                this.show_toast(format!(
                                    "Найдено активных процессов: {}",
                                    this.running_apps.len()
                                ));
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/refresh.svg")
                                    .size(px(11.0))
                                    .text_color(t.accent),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(t.text_soft)
                                    .child("Обновить список процессов"),
                            ),
                    ),
            )
            .child(
                div()
                    .id("routes-apps-scroll")
                    .flex_1()
                    .w_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.0))
                    .children(self.running_apps.iter().map(|app| {
                        let proc_name = app.proc.clone();
                        let selected = self
                            .state
                            .routed_apps
                            .iter()
                            .any(|p| p.eq_ignore_ascii_case(&proc_name));

                        div()
                            .id(SharedString::from(format!("app-chip-{}", app.proc)))
                            .w(px(260.0))
                            .p(px(10.0))
                            .rounded(px(8.0))
                            .bg(if selected { t.accent_bg } else { t.bg_card })
                            .border_1()
                            .border_color(if selected { t.accent_border } else { t.border })
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .justify_between()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(pos) = this
                                    .state
                                    .routed_apps
                                    .iter()
                                    .position(|p| p.eq_ignore_ascii_case(&proc_name))
                                {
                                    this.state.routed_apps.remove(pos);
                                } else {
                                    this.state.routed_apps.push(proc_name.clone());
                                }
                                this.reconnect_if_active();
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .text_size(px(11.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text)
                                            .child(truncate_str(&app.name, 22)),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(10.0))
                                            .text_color(t.text_dim)
                                            .child(app.proc.clone()),
                                    ),
                            )
                            .child(
                                div()
                                    .px(px(6.0))
                                    .py(px(2.0))
                                    .rounded(px(4.0))
                                    .bg(if selected { t.accent } else { t.bg_elev })
                                    .text_size(px(10.0))
                                    .text_color(if selected {
                                        gpui::rgb(0x0B0B0D)
                                    } else {
                                        t.text_dim
                                    })
                                    .child(if selected { "Туннель" } else { "Прямой" }),
                            )
                    })),
            )
    }
}

impl TachyonApp {
    fn render_nodes_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Import & Actions Card
                div()
                    .w_full()
                    .p(px(12.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap(px(8.0))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child("Импорт узлов, ссылок (vless://, awg://, vpn://, hy2://) и .conf файлов"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("btn-import-conf-file")
                                            .h(px(28.0))
                                            .px(px(10.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .flex()
                                            .items_center()
                                            .gap(px(6.0))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.import_conf_file_dialog();
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/folder.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.accent),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_soft)
                                                    .child("Файл .conf / .json"),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id("btn-paste-clipboard-uri")
                                            .h(px(28.0))
                                            .px(px(10.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .flex()
                                            .items_center()
                                            .gap(px(6.0))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                if let Some(clip) = cx.read_from_clipboard() {
                                                    if let Some(txt) = clip.text() {
                                                        this.add_single_server_uri(&txt, None);
                                                    }
                                                }
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/copy.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.text_soft),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_soft)
                                                    .child("Вставить из буфера"),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id("btn-provision-warp-awg")
                                            .h(px(28.0))
                                            .px(px(10.0))
                                            .rounded(px(6.0))
                                            .bg(t.green_bg)
                                            .border_1()
                                            .border_color(t.green_border)
                                            .cursor_pointer()
                                            .flex()
                                            .items_center()
                                            .gap(px(6.0))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.show_toast(
                                                    "Генерация профиля Cloudflare WARP (AWG)...",
                                                );
                                                this.rt.spawn(async move {
                                                    let res = v.provision_warp_awg().await;
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(format!("warp:result:{res}"));
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/shield.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.green),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.green)
                                                    .child("+ Cloudflare WARP (AWG)"),
                                            ),
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
                                div()
                                    .id("input-node-uri")
                                    .flex_1()
                                    .h(px(32.0))
                                    .px(px(10.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(
                                        if self.active_field == ActiveField::NodeUriInput {
                                            t.accent
                                        } else {
                                            t.border
                                        },
                                    )
                                    .cursor_text()
                                    .flex()
                                    .items_center()
                                    .overflow_hidden()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::NodeUriInput;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .text_size(px(11.5))
                                            .text_color(if self.node_uri_input.is_empty() {
                                                t.text_mute
                                            } else {
                                                t.text
                                            })
                                            .child(if self.node_uri_input.is_empty() {
                                                "Вставьте vless://, awg://, vpn://, ссылку подписки или текст [Interface] .conf..."
                                                    .to_string()
                                            } else {
                                                truncate_str(
                                                    &self.node_uri_input.replace('\n', " ↵ "),
                                                    78,
                                                )
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .id("input-node-name")
                                    .w(px(170.0))
                                    .h(px(32.0))
                                    .px(px(10.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(
                                        if self.active_field == ActiveField::NodeNameInput {
                                            t.accent
                                        } else {
                                            t.border
                                        },
                                    )
                                    .cursor_text()
                                    .flex()
                                    .items_center()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::NodeNameInput;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .text_size(px(11.5))
                                            .text_color(if self.node_name_input.is_empty() {
                                                t.text_mute
                                            } else {
                                                t.text
                                            })
                                            .child(if self.node_name_input.is_empty() {
                                                "Название (необяз.)".to_string()
                                            } else {
                                                self.node_name_input.clone()
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .id("btn-submit-node-uri")
                                    .h(px(32.0))
                                    .px(px(14.0))
                                    .rounded(px(6.0))
                                    .bg(t.accent)
                                    .cursor_pointer()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(gpui::rgb(0x0B0B0D))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let uri = this.node_uri_input.trim().to_string();
                                        let name = this.node_name_input.trim().to_string();
                                        if !uri.is_empty() {
                                            this.add_single_server_uri(
                                                &uri,
                                                if name.is_empty() { None } else { Some(&name) },
                                            );
                                            this.node_uri_input.clear();
                                            this.node_name_input.clear();
                                        }
                                        cx.notify();
                                    }))
                                    .child("Добавить"),
                            ),
                    ),
            )
            .child(
                // Balancer & Cascade Settings Card
                div()
                    .w_full()
                    .p(px(10.0))
                    .rounded(px(10.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(t.text_soft)
                                    .child("Алгоритм автобалансировщика:"),
                            )
                            .children(
                                [
                                    ("stability", "Stability (EMA)"),
                                    ("least_test", "Min RTT"),
                                    ("least_load", "Least Load"),
                                    ("hedged", "Hedged"),
                                    ("failover", "Failover"),
                                ]
                                .into_iter()
                                .map(|(bm, blabel)| {
                                    let active = self.state.vpn_prefs.balancer_mode == bm;
                                    div()
                                        .id(SharedString::from(format!("bm-mode-{bm}")))
                                        .px(px(8.0))
                                        .py(px(4.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .bg(if active { t.accent_bg } else { t.bg_elev })
                                        .text_size(px(10.5))
                                        .text_color(if active { t.accent } else { t.text_dim })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.state.vpn_prefs.balancer_mode = bm.to_string();
                                            this.reconnect_if_active();
                                            cx.notify();
                                        }))
                                        .child(blabel)
                                }),
                            ),
                    )
                    .child(
                        div()
                            .id("btn-open-subs-from-nodes")
                            .px(px(10.0))
                            .py(px(4.0))
                            .rounded(px(6.0))
                            .bg(t.bg_elev)
                            .border_1()
                            .border_color(t.border)
                            .cursor_pointer()
                            .text_size(px(11.0))
                            .text_color(t.accent)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.modal = ModalKind::Subscriptions;
                                cx.notify();
                            }))
                            .child(format!(
                                "Подписки ({})",
                                self.state.subscriptions.len()
                            )),
                    ),
            )
            .child(
                // Protocol filter & cleanup bar
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .children(
                                [
                                    ("all", "Все"),
                                    ("alive", "Доступные"),
                                    ("AWG", "AmneziaWG / WG"),
                                    ("REALITY", "VLESS Reality"),
                                    ("XHTTP", "XHTTP / WS"),
                                    ("HY2", "Hysteria2 / TUIC"),
                                ]
                                .into_iter()
                                .map(|(fid, flabel)| {
                                    let active = self.node_filter == fid;
                                    div()
                                        .id(SharedString::from(format!("nf-chip-{fid}")))
                                        .px(px(8.0))
                                        .py(px(4.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .bg(if active { t.accent_bg } else { t.bg_card })
                                        .border_1()
                                        .border_color(if active { t.accent_border } else { t.border })
                                        .text_size(px(10.5))
                                        .text_color(if active { t.accent } else { t.text_dim })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.node_filter = fid.to_string();
                                            cx.notify();
                                        }))
                                        .child(flabel)
                                }),
                            )
                            .child(
                                div()
                                    .id("btn-filter-hide-ru-by")
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .cursor_pointer()
                                    .bg(if self.hide_ru_by { t.amber_bg } else { t.bg_card })
                                    .border_1()
                                    .border_color(if self.hide_ru_by {
                                        t.amber_border
                                    } else {
                                        t.border
                                    })
                                    .text_size(px(10.5))
                                    .text_color(if self.hide_ru_by { t.amber } else { t.text_dim })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.hide_ru_by = !this.hide_ru_by;
                                        cx.notify();
                                    }))
                                    .child("Без РФ/РБ"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .id("btn-nodes-ping-all")
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(10.5))
                                    .text_color(t.text_soft)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.ping_all_nodes();
                                        cx.notify();
                                    }))
                                    .child("Замерить все"),
                            )
                            .child(
                                div()
                                    .id("btn-nodes-prune-dead")
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.red_bg))
                                    .text_size(px(10.5))
                                    .text_color(t.red)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let before = this.state.servers.len();
                                        this.state.servers.retain(|s| {
                                            s.is_balancer || s.ping_ms.unwrap_or(1) > 0
                                        });
                                        let removed = before.saturating_sub(this.state.servers.len());
                                        if !this
                                            .state
                                            .servers
                                            .iter()
                                            .any(|s| s.id == this.state.active_id)
                                        {
                                            this.state.active_id = this
                                                .state
                                                .servers
                                                .first()
                                                .map(|s| s.id.clone())
                                                .unwrap_or_default();
                                        }
                                        this.state.save();
                                        this.show_toast(format!(
                                            "Удалено недоступных узлов: {removed}"
                                        ));
                                        cx.notify();
                                    }))
                                    .child("Очистить недоступные"),
                            ),
                    ),
            )
            .child(
                // Full server table
                div()
                    .id("nodes-full-scroll")
                    .flex_1()
                    .w_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .children(
                        self.state
                            .servers
                            .iter()
                            .filter(|srv| {
                                if self.hide_ru_by
                                    && matches!(srv.country.as_str(), "ru" | "by")
                                {
                                    return false;
                                }
                                let p = detect_protocol_badge(&srv.vless);
                                match self.node_filter.as_str() {
                                    "alive" => srv.is_balancer || srv.ping_ms.unwrap_or(-1) > 0,
                                    "AWG" => matches!(p, "AWG" | "WG"),
                                    "REALITY" => matches!(p, "REALITY" | "VLESS"),
                                    "XHTTP" => matches!(p, "XHTTP" | "WS" | "GRPC"),
                                    "HY2" => matches!(p, "HY2" | "TUIC" | "WDTT"),
                                    _ => true,
                                }
                            })
                            .map(|srv| {
                                let is_sel = srv.id == self.state.active_id;
                        let is_relay = srv.id == self.state.vpn_prefs.relay_id;
                        let sid = srv.id.clone();
                        let sid_del = srv.id.clone();
                        let sid_relay = srv.id.clone();
                        let srv_uri = srv.vless.clone();
                        let proto = detect_protocol_badge(&srv.vless);

                        div()
                            .id(SharedString::from(format!("node-row-{}", srv.id)))
                            .w_full()
                            .p(px(10.0))
                            .rounded(px(10.0))
                            .bg(if is_sel { t.accent_bg } else { t.bg_card })
                            .border_1()
                            .border_color(if is_sel { t.accent_border } else { t.border })
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .id(SharedString::from(format!("node-sel-{}", srv.id)))
                                    .flex_1()
                                    .cursor_pointer()
                                    .flex()
                                    .items_center()
                                    .gap(px(10.0))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.state.active_id = sid.clone();
                                        this.reconnect_if_active();
                                        cx.notify();
                                    }))
                                    .child(render_flag_badge(&srv.country, 22.0, t))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(12.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child(srv.name.clone()),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child(format!(
                                                        "{} · {}",
                                                        country_title_ru(&srv.country),
                                                        proto
                                                    )),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .when_some(srv.ping_ms, |el, ms| {
                                        el.child(
                                            div()
                                                .px(px(6.0))
                                                .py(px(2.0))
                                                .rounded(px(4.0))
                                                .bg(t.bg_elev)
                                                .text_size(px(10.5))
                                                .text_color(if ms > 0 {
                                                    t.green
                                                } else {
                                                    t.text_mute
                                                })
                                                .child(if ms > 0 {
                                                    format!("{ms} мс")
                                                } else {
                                                    "Недоступен".to_string()
                                                }),
                                        )
                                    })
                                    .child(
                                        div()
                                            .id(SharedString::from(format!(
                                                "btn-relay-{}",
                                                srv.id
                                            )))
                                            .px(px(7.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .cursor_pointer()
                                            .bg(if is_relay { t.amber_bg } else { t.bg_elev })
                                            .border_1()
                                            .border_color(if is_relay {
                                                t.amber_border
                                            } else {
                                                t.border
                                            })
                                            .text_size(px(10.0))
                                            .text_color(if is_relay {
                                                t.amber
                                            } else {
                                                t.text_dim
                                            })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                if this.state.vpn_prefs.relay_id == sid_relay {
                                                    this.state.vpn_prefs.relay_id.clear();
                                                } else {
                                                    this.state.vpn_prefs.relay_id =
                                                        sid_relay.clone();
                                                }
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(if is_relay {
                                                "Каскад (Вход)"
                                            } else {
                                                "В каскад"
                                            }),
                                    )
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("btn-copy-{}", srv.id)))
                                            .w(px(26.0))
                                            .h(px(26.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.write_to_clipboard(ClipboardItem::new_string(
                                                    srv_uri.clone(),
                                                ));
                                                this.show_toast("Ссылка скопирована в буфер обмена");
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/copy.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.text_soft),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("btn-del-{}", srv.id)))
                                            .w(px(26.0))
                                            .h(px(26.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.red_bg))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.servers.retain(|s| s.id != sid_del);
                                                if this.state.active_id == sid_del {
                                                    this.state.active_id = this
                                                        .state
                                                        .servers
                                                        .first()
                                                        .map(|s| s.id.clone())
                                                        .unwrap_or_default();
                                                }
                                                this.state.save();
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/trash.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.red),
                                            ),
                                    ),
                            )
                    })),
            )
    }

    fn render_traffic_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("traffic-scroll")
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Top row: Speedtest + Diagnostics Matrix
                div()
                    .w_full()
                    .flex()
                    .gap(px(10.0))
                    .child(
                        // Speedtest card
                        div()
                            .flex_1()
                            .p(px(12.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Тест пропускной способности"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(4.0))
                                            .children([25u32, 100, 500].into_iter().map(|sz| {
                                                let act = self.speedtest_size_mb == sz;
                                                div()
                                                    .id(SharedString::from(format!("st-sz-{sz}")))
                                                    .px(px(6.0))
                                                    .py(px(3.0))
                                                    .rounded(px(5.0))
                                                    .cursor_pointer()
                                                    .bg(if act { t.accent_bg } else { t.bg_elev })
                                                    .text_size(px(10.0))
                                                    .text_color(if act {
                                                        t.accent
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.speedtest_size_mb = sz;
                                                        cx.notify();
                                                    }))
                                                    .child(format!("{sz} МБ"))
                                            }))
                                            .child(
                                                div()
                                                    .id("btn-run-speedtest")
                                                    .px(px(10.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(if self.speedtest.running {
                                                        t.red_bg
                                                    } else {
                                                        t.accent_bg
                                                    })
                                                    .border_1()
                                                    .border_color(if self.speedtest.running {
                                                        t.red_border
                                                    } else {
                                                        t.accent_border
                                                    })
                                                    .cursor_pointer()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(if self.speedtest.running {
                                                        t.red
                                                    } else {
                                                        t.accent
                                                    })
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        if this.speedtest.running {
                                                            this.vpn.cancel_speedtest();
                                                            this.speedtest.running = false;
                                                        } else {
                                                            this.speedtest.running = true;
                                                            this.speedtest.progress = 0;
                                                            let sz = this.speedtest_size_mb;
                                                            let prov = this.speedtest_provider.clone();
                                                            let v = this.vpn.clone();
                                                            let eq = this.event_queue.clone();
                                                            this.rt.spawn(async move {
                                                                let res =
                                                                    v.run_speedtest(sz, &prov).await;
                                                                if let Ok(mut g) = eq.lock() {
                                                                    g.push(format!(
                                                                        "speedtest:result:{res}"
                                                                    ));
                                                                }
                                                            });
                                                        }
                                                        cx.notify();
                                                    }))
                                                    .child(if self.speedtest.running {
                                                        "Остановить"
                                                    } else {
                                                        "Запустить"
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(20.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(format!(
                                                "{:.1} Мбит/с  ({:.1} МБ/с)",
                                                self.speedtest.mbps, self.speedtest.mbs
                                            )),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(format!(
                                                "Пик: {:.1} Мбит/с · TTFB: {} мс",
                                                self.speedtest.peak_mbps, self.speedtest.ttfb_ms
                                            )),
                                    ),
                            ),
                    )
                    .child(
                        // Connectivity Matrix card
                        div()
                            .flex_1()
                            .p(px(12.0))
                            .rounded(px(12.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_col()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Матрица связности и самодиагностика"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .id("btn-run-selfcheck")
                                                    .px(px(8.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .text_size(px(10.5))
                                                    .text_color(t.accent)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.self_check_items.clear();
                                                        let v = this.vpn.clone();
                                                        this.rt.spawn(async move {
                                                            v.run_self_check().await;
                                                        });
                                                        cx.notify();
                                                    }))
                                                    .child("Самодиагностика"),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-run-diag-matrix")
                                                    .px(px(8.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .text_size(px(10.5))
                                                    .text_color(t.text_soft)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.diag_running = true;
                                                        let v = this.vpn.clone();
                                                        let eq = this.event_queue.clone();
                                                        this.rt.spawn(async move {
                                                            let res = v.run_diagnostics_matrix().await;
                                                            if let Ok(mut g) = eq.lock() {
                                                                g.push(format!("diag:matrix:{res}"));
                                                            }
                                                        });
                                                        cx.notify();
                                                    }))
                                                    .child(if self.diag_running {
                                                        "Проверка..."
                                                    } else {
                                                        "Маршруты"
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .flex_wrap()
                                    .gap(px(6.0))
                                    .children(self.diag_items.iter().map(|item| {
                                        div()
                                            .px(px(8.0))
                                            .py(px(4.0))
                                            .rounded(px(6.0))
                                            .bg(if item.ok { t.green_bg } else { t.red_bg })
                                            .text_size(px(10.5))
                                            .text_color(if item.ok { t.green } else { t.red })
                                            .child(format!(
                                                "{}: {} ({} мс)",
                                                item.title, item.status, item.ms
                                            ))
                                    }))
                                    .children(self.self_check_items.iter().map(|sc| {
                                        let ok = sc.get("status").and_then(Value::as_str) == Some("ok")
                                            || sc.get("ok").and_then(Value::as_bool) == Some(true);
                                        let title = sc
                                            .get("label")
                                            .or_else(|| sc.get("title"))
                                            .and_then(Value::as_str)
                                            .unwrap_or("Проверка");
                                        let detail = sc
                                            .get("detail")
                                            .and_then(Value::as_str)
                                            .unwrap_or("");
                                        div()
                                            .px(px(8.0))
                                            .py(px(4.0))
                                            .rounded(px(6.0))
                                            .bg(if ok { t.accent_bg } else { t.amber_bg })
                                            .text_size(px(10.0))
                                            .text_color(if ok { t.accent } else { t.amber })
                                            .child(format!("{title}: {detail}"))
                                    })),
                            ),
                    ),
            )
            .child(
                // Active Connections Card
                div()
                    .flex_1()
                    .w_full()
                    .p(px(12.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap(px(8.0))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(format!(
                                                "Активные сессии ({})",
                                                self.connections.len()
                                            )),
                                    )
                                    .children(
                                        [
                                            ("all", "Все"),
                                            ("PROXY", "Туннель"),
                                            ("DESYNC", "Desync"),
                                            ("DIRECT", "Прямые"),
                                        ]
                                        .into_iter()
                                        .map(|(cf, clabel)| {
                                            let act = self.conn_filter == cf;
                                            div()
                                                .id(SharedString::from(format!("cf-chip-{cf}")))
                                                .px(px(7.0))
                                                .py(px(2.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.conn_filter = cf.to_string();
                                                    cx.notify();
                                                }))
                                                .child(clabel)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("btn-refresh-conns")
                                            .px(px(8.0))
                                            .py(px(4.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .cursor_pointer()
                                            .text_size(px(11.0))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, _| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.rt.spawn(async move {
                                                    let data = v.get_connections_json().await;
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(format!("conn:data:{data}"));
                                                    }
                                                });
                                            }))
                                            .child("Обновить"),
                                    )
                                    .child(
                                        div()
                                            .id("btn-close-all-conns")
                                            .px(px(8.0))
                                            .py(px(4.0))
                                            .rounded(px(6.0))
                                            .bg(t.red_bg)
                                            .cursor_pointer()
                                            .text_size(px(11.0))
                                            .text_color(t.red)
                                            .on_click(cx.listener(|this, _, _, _| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.rt.spawn(async move {
                                                    v.close_connection(None).await;
                                                    let data = v.get_connections_json().await;
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(format!("conn:data:{data}"));
                                                    }
                                                });
                                            }))
                                            .child("Сбросить все"),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id("conns-list-scroll")
                            .flex_1()
                            .w_full()
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .children(
                                self.connections
                                    .iter()
                                    .filter(|c| {
                                        if self.conn_filter == "all" {
                                            return true;
                                        }
                                        let ch = c.chain.to_uppercase();
                                        match self.conn_filter.as_str() {
                                            "PROXY" => ch.contains("PROXY") || ch.contains("VPN"),
                                            "DESYNC" => ch.contains("DESYNC"),
                                            "DIRECT" => ch.contains("DIRECT"),
                                            _ => true,
                                        }
                                    })
                                    .take(80)
                                    .enumerate()
                                    .map(|(idx, c)| {
                                        let host_for_rule = c
                                            .host
                                            .split(':')
                                            .next()
                                            .unwrap_or(&c.host)
                                            .to_string();
                                        div()
                                            .w_full()
                                            .px(px(8.0))
                                            .py(px(6.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .text_size(px(11.0))
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(8.0))
                                                    .child(
                                                        div()
                                                            .px(px(5.0))
                                                            .rounded(px(4.0))
                                                            .bg(t.bg_card)
                                                            .text_size(px(9.5))
                                                            .text_color(t.accent)
                                                            .child(c.net.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .font_weight(FontWeight::MEDIUM)
                                                            .text_color(t.text)
                                                            .child(truncate_str(&c.host, 34)),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_color(t.text_mute)
                                                            .child(format!("({})", c.process)),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(8.0))
                                                    .child(
                                                        div()
                                                            .text_color(t.green)
                                                            .child(c.chain.clone()),
                                                    )
                                                    .child(div().text_color(t.text_dim).child(
                                                        format!(
                                                            "↓ {}  ↑ {}",
                                                            format_bytes_human(c.dl),
                                                            format_bytes_human(c.ul)
                                                        ),
                                                    ))
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "conn-rule-vpn-{idx}"
                                                            )))
                                                            .px(px(6.0))
                                                            .py(px(2.0))
                                                            .rounded(px(4.0))
                                                            .bg(t.bg_card)
                                                            .cursor_pointer()
                                                            .text_size(px(9.5))
                                                            .text_color(t.accent)
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    if !host_for_rule.is_empty() {
                                                                        let rid = format!(
                                                                            "rule-{}",
                                                                            this.state
                                                                                .custom_rules
                                                                                .len()
                                                                                + 1
                                                                        );
                                                                        this.state
                                                                            .custom_rules
                                                                            .push(CustomRule {
                                                                                id: rid,
                                                                                rule_type:
                                                                                    "domain"
                                                                                        .to_string(),
                                                                                value:
                                                                                    host_for_rule
                                                                                        .clone(),
                                                                                action: "vpn"
                                                                                    .to_string(),
                                                                            });
                                                                        this.show_toast(format!(
                                                                            "{host_for_rule} добавлен в Туннель"
                                                                        ));
                                                                        this.reconnect_if_active();
                                                                        cx.notify();
                                                                    }
                                                                },
                                                            ))
                                                            .child("+ Туннель"),
                                                    ),
                                            )
                                    }),
                            ),
                    ),
            )
    }

    fn render_options_tab(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let p = &self.state.vpn_prefs;

        div()
            .id("options-scroll")
            .size_full()
            .px(px(16.0))
            .py(px(8.0))
            .overflow_y_scroll()
            .flex()
            .gap(px(12.0))
            .child(
                // Left column: Network & DNS
                div()
                    .flex_1()
                    .p(px(14.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child("Сеть, DNS и интерфейс TUN"),
                            )
                            .child(
                                div()
                                    .id("btn-run-dns-bench")
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(10.5))
                                    .text_color(t.accent)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.dns_running = true;
                                        let v = this.vpn.clone();
                                        let eq = this.event_queue.clone();
                                        this.rt.spawn(async move {
                                            let res = v.run_dns_benchmark().await;
                                            if let Ok(mut g) = eq.lock() {
                                                g.push(format!("dns:bench:{res}"));
                                            }
                                        });
                                        cx.notify();
                                    }))
                                    .child(if self.dns_running {
                                        "Замер DNS..."
                                    } else {
                                        "Замерить DNS"
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(t.text_dim)
                                    .child("Резолвер DNS (DoH / Защищённый DNS)"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap(px(6.0))
                                    .children(
                                        [
                                            ("1.1.1.1", "Cloudflare 1.1.1.1"),
                                            ("8.8.8.8", "Google 8.8.8.8"),
                                            ("9.9.9.9", "Quad9 9.9.9.9"),
                                            ("94.140.14.14", "AdGuard DNS"),
                                            ("77.88.8.8", "Яндекс 77.88.8.8"),
                                        ]
                                        .into_iter()
                                        .map(|(dval, dlabel)| {
                                            let active = p.dns == dval;
                                            div()
                                                .id(SharedString::from(format!("dns-opt-{dval}")))
                                                .px(px(10.0))
                                                .py(px(5.0))
                                                .rounded(px(6.0))
                                                .cursor_pointer()
                                                .bg(if active { t.accent_bg } else { t.bg_elev })
                                                .border_1()
                                                .border_color(if active {
                                                    t.accent_border
                                                } else {
                                                    t.border
                                                })
                                                .text_size(px(11.0))
                                                .text_color(if active {
                                                    t.accent
                                                } else {
                                                    t.text_soft
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.dns = dval.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(dlabel)
                                        }),
                                    ),
                            )
                            .when(!self.dns_bench.is_empty(), |el| {
                                el.child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_wrap()
                                        .gap(px(6.0))
                                        .children(self.dns_bench.iter().map(|b| {
                                            div()
                                                .px(px(7.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .bg(if b.ms > 0 { t.green_bg } else { t.red_bg })
                                                .text_size(px(10.0))
                                                .text_color(if b.ms > 0 { t.green } else { t.red })
                                                .child(format!("{}: {} мс", b.name, b.ms))
                                        })),
                                )
                            }),
                    )
                    .child(
                        // DNS Route Mode + MTU selector row
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child("Маршрут DNS:"),
                                    )
                                    .children(
                                        [
                                            ("split_ru", "Split (.ru напрямую)"),
                                            ("proxy", "Через туннель"),
                                            ("direct", "Напрямую"),
                                        ]
                                        .into_iter()
                                        .map(|(drm, drl)| {
                                            let act = p.dns_route_mode == drm;
                                            div()
                                                .id(SharedString::from(format!("opt-drm-{drm}")))
                                                .px(px(7.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.dns_route_mode =
                                                        drm.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(drl)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child("MTU:"),
                                    )
                                    .children([1280u32, 1360, 1400, 1420, 1500].into_iter().map(
                                        |mval| {
                                            let act = p.tun_mtu == mval;
                                            div()
                                                .id(SharedString::from(format!("opt-mtu-{mval}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.tun_mtu = mval;
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(mval.to_string())
                                        },
                                    )),
                            ),
                    )
                    .child(self.render_toggle_row(
                        "opt-fake-ip",
                        "Виртуальный пул FakeIP (198.18.0.0/15)",
                        "Мгновенный DNS-ответ и маршрутизация по доменным именам без задержки",
                        p.fake_ip,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.fake_ip = !this.state.vpn_prefs.fake_ip;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-ru-bypass",
                        "Прямой маршрут для РФ (.ru / .рф / GeoIP RU)",
                        "Сайты, банки и госсервисы РФ работают напрямую без задержки",
                        p.ru_bypass,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.ru_bypass = !this.state.vpn_prefs.ru_bypass;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-sniff",
                        "Инспекция протоколов (TLS SNI / HTTP Sniffing)",
                        "Точное определение доменов из заголовков пакетов",
                        p.sniff,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.sniff = !this.state.vpn_prefs.sniff;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-strict-route",
                        "Строгая маршрутизация TUN (Strict Route)",
                        "Защита от утечек DNS и WebRTC мимо виртуального адаптера",
                        p.strict_route,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.strict_route = !this.state.vpn_prefs.strict_route;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    )),
            )
            .child(
                // Right column: System & Updates
                div()
                    .flex_1()
                    .p(px(14.0))
                    .rounded(px(12.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child("Система, автозапуск и обновления"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child("Лог:"),
                                    )
                                    .children(
                                        ["warn", "info", "debug", "error"]
                                            .into_iter()
                                            .map(|lvl| {
                                                let act = p.log_level == lvl;
                                                div()
                                                    .id(SharedString::from(format!("opt-log-{lvl}")))
                                                    .px(px(6.0))
                                                    .py(px(2.0))
                                                    .rounded(px(4.0))
                                                    .cursor_pointer()
                                                    .bg(if act { t.accent_bg } else { t.bg_elev })
                                                    .text_size(px(10.0))
                                                    .text_color(if act {
                                                        t.accent
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.state.vpn_prefs.log_level =
                                                            lvl.to_string();
                                                        this.reconnect_if_active();
                                                        cx.notify();
                                                    }))
                                                    .child(lvl.to_uppercase())
                                            }),
                                    ),
                            ),
                    )
                    .child(self.render_toggle_row(
                        "opt-autostart",
                        "Запускать вместе с ОС",
                        "Автоматический старт Tachyon при входе в систему",
                        p.autostart,
                        t,
                        cx.listener(|this, _, _, cx| {
                            let next = !this.state.vpn_prefs.autostart;
                            this.state.vpn_prefs.autostart = next;
                            crate::set_autostart(next);
                            this.state.save();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-autoconnect",
                        "Автоподключение при старте",
                        "Сразу поднимать активный туннель при открытии клиента",
                        p.auto_connect,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.auto_connect = !this.state.vpn_prefs.auto_connect;
                            this.state.save();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-allow-lan",
                        "Доступ из локальной сети (Allow LAN)",
                        "Разрешить подключение других устройств домашней сети к прокси-порту",
                        p.allow_lan,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.allow_lan = !this.state.vpn_prefs.allow_lan;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-adblock",
                        "Блокировка рекламы и телеметрии",
                        "Фильтрация рекламных сетей на уровне маршрутизатора",
                        p.adblock,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.adblock = !this.state.vpn_prefs.adblock;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(
                        div()
                            .w_full()
                            .pt(px(4.0))
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .id("btn-check-updates")
                                    .px(px(12.0))
                                    .py(px(6.0))
                                    .rounded(px(8.0))
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(11.5))
                                    .text_color(t.text_soft)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let v = this.vpn.clone();
                                        this.rt.spawn(async move {
                                            v.check_github_update(false).await;
                                        });
                                        this.show_toast("Проверка обновлений на GitHub...");
                                        cx.notify();
                                    }))
                                    .child("Проверить обновления"),
                            )
                            .when(self.update_banner.available, |el| {
                                el.child(
                                    div()
                                        .id("btn-install-update")
                                        .px(px(12.0))
                                        .py(px(6.0))
                                        .rounded(px(8.0))
                                        .bg(t.green)
                                        .cursor_pointer()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(gpui::rgb(0x0B0B0D))
                                        .on_click(cx.listener(|this, _, _, _| {
                                            let v = this.vpn.clone();
                                            this.rt.spawn(async move {
                                                v.install_github_update().await;
                                            });
                                        }))
                                        .child(format!("Установить {}", self.update_banner.tag)),
                                )
                            }),
                    ),
            )
    }

    fn render_toggle_row<F>(
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
            .w_full()
            .p(px(10.0))
            .rounded(px(8.0))
            .bg(t.bg_elev)
            .border_1()
            .border_color(if checked { t.accent_border } else { t.border })
            .cursor_pointer()
            .on_click(on_click)
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
                            .text_size(px(11.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text)
                            .child(title),
                    )
                    .child(div().text_size(px(10.0)).text_color(t.text_dim).child(subtitle)),
            )
            .child(
                div()
                    .w(px(34.0))
                    .h(px(18.0))
                    .p(px(2.0))
                    .rounded(px(9.0))
                    .bg(if checked { t.accent } else { t.bg_card })
                    .flex()
                    .items_center()
                    .justify_end()
                    .when(!checked, |el| el.justify_start())
                    .child(
                        div()
                            .w(px(14.0))
                            .h(px(14.0))
                            .rounded(px(7.0))
                            .bg(if checked {
                                gpui::rgb(0x0B0B0D)
                            } else {
                                t.text_dim
                            }),
                    ),
            )
    }

    fn render_modal_overlay(&self, t: Theme, cx: &mut Context<Self>) -> Option<AnyElement> {
        match self.modal {
            ModalKind::None => None,
            ModalKind::Subscriptions => Some(
                div()
                    .id("modal-backdrop-subs")
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .bg(gpui::rgba(0x000000A6))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .w(px(620.0))
                            .max_h(px(520.0))
                            .p(px(16.0))
                            .rounded(px(14.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border_hi)
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Управление подписками и контейнерами"),
                                    )
                                    .child(
                                        div()
                                            .id("btn-close-subs-modal")
                                            .w(px(26.0))
                                            .h(px(26.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .cursor_pointer()
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.modal = ModalKind::None;
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/close.svg")
                                                    .size(px(12.0))
                                                    .text_color(t.text_dim),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .id("input-sub-url")
                                            .flex_1()
                                            .h(px(32.0))
                                            .px(px(10.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(
                                                if self.active_field == ActiveField::SubUrlInput {
                                                    t.accent
                                                } else {
                                                    t.border
                                                },
                                            )
                                            .cursor_text()
                                            .flex()
                                            .items_center()
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.active_field = ActiveField::SubUrlInput;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .text_size(px(11.5))
                                                    .text_color(if self.sub_url_input.is_empty() {
                                                        t.text_mute
                                                    } else {
                                                        t.text
                                                    })
                                                    .child(if self.sub_url_input.is_empty() {
                                                        "https://... или happ://... или vpn://..."
                                                            .to_string()
                                                    } else {
                                                        truncate_str(&self.sub_url_input, 56)
                                                    }),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id("btn-add-sub-submit")
                                            .px(px(14.0))
                                            .h(px(32.0))
                                            .rounded(px(6.0))
                                            .bg(t.accent)
                                            .cursor_pointer()
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .text_size(px(11.5))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(gpui::rgb(0x0B0B0D))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let url = this.sub_url_input.trim().to_string();
                                                if !url.is_empty() {
                                                    this.add_single_server_uri(&url, None);
                                                    this.sub_url_input.clear();
                                                }
                                                cx.notify();
                                            }))
                                            .child("Подключить"),
                                    ),
                            )
                            .child(
                                div()
                                    .id("subs-modal-scroll")
                                    .flex_1()
                                    .w_full()
                                    .overflow_y_scroll()
                                    .flex()
                                    .flex_col()
                                    .gap(px(6.0))
                                    .children(self.state.subscriptions.iter().map(|sub| {
                                        let sub_url = sub.url.clone();
                                        let sub_handle = sub.handle.clone();
                                        let sid = sub.id.clone();
                                        div()
                                            .w_full()
                                            .p(px(10.0))
                                            .rounded(px(8.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .child(
                                                        div()
                                                            .text_size(px(12.0))
                                                            .font_weight(FontWeight::BOLD)
                                                            .text_color(t.text)
                                                            .child(sub.handle.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.5))
                                                            .text_color(t.text_dim)
                                                            .child(format!(
                                                                "Узлов: {} · {}",
                                                                sub.count,
                                                                truncate_str(&sub.url, 44)
                                                            )),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap(px(6.0))
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "refresh-sub-{sid}"
                                                            )))
                                                            .px(px(8.0))
                                                            .py(px(4.0))
                                                            .rounded(px(6.0))
                                                            .bg(t.bg_card)
                                                            .cursor_pointer()
                                                            .text_size(px(10.5))
                                                            .text_color(t.accent)
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.add_single_server_uri(
                                                                        &sub_url,
                                                                        Some(&sub_handle),
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child("Обновить"),
                                                    )
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "del-sub-{sid}"
                                                            )))
                                                            .px(px(8.0))
                                                            .py(px(4.0))
                                                            .rounded(px(6.0))
                                                            .bg(t.red_bg)
                                                            .cursor_pointer()
                                                            .text_size(px(10.5))
                                                            .text_color(t.red)
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.state
                                                                        .subscriptions
                                                                        .retain(|s| s.id != sid);
                                                                    this.state.servers.retain(
                                                                        |s| {
                                                                            s.sub_id.as_deref()
                                                                                != Some(
                                                                                    sid.as_str(),
                                                                                )
                                                                        },
                                                                    );
                                                                    this.state.save();
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child("Удалить"),
                                                    ),
                                            )
                                    })),
                            ),
                    )
                    .into_any_element(),
            ),
            ModalKind::KernelLog => Some(
                div()
                    .id("modal-backdrop-log")
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .bg(gpui::rgba(0x000000A6))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .w(px(760.0))
                            .h(px(480.0))
                            .p(px(16.0))
                            .rounded(px(14.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border_hi)
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child("Журнал ядра tachyon-core"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .id("btn-refresh-log")
                                                    .px(px(10.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_soft)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.log_tail = this.vpn.get_log_tail(140);
                                                        cx.notify();
                                                    }))
                                                    .child("Обновить"),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-copy-log")
                                                    .px(px(10.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .text_size(px(11.0))
                                                    .text_color(t.accent)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        cx.write_to_clipboard(
                                                            ClipboardItem::new_string(
                                                                this.log_tail.clone(),
                                                            ),
                                                        );
                                                        this.show_toast("Лог скопирован");
                                                        cx.notify();
                                                    }))
                                                    .child("Копировать"),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-close-log-modal")
                                                    .w(px(26.0))
                                                    .h(px(26.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .flex()
                                                    .items_center()
                                                    .justify_center()
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.modal = ModalKind::None;
                                                        cx.notify();
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
                                    .id("log-modal-scroll")
                                    .flex_1()
                                    .w_full()
                                    .p(px(10.0))
                                    .rounded(px(8.0))
                                    .bg(t.bg)
                                    .border_1()
                                    .border_color(t.border)
                                    .overflow_y_scroll()
                                    .text_size(px(10.5))
                                    .text_color(t.text_soft)
                                    .child(if self.log_tail.trim().is_empty() {
                                        "Журнал пуст.".to_string()
                                    } else {
                                        self.log_tail.clone()
                                    }),
                            ),
                    )
                    .into_any_element(),
            ),
        }
    }
}

impl Render for TachyonApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = Theme::for_mode(self.state.light_theme);

        div()
            .id("tachyon-root")
            .size_full()
            .bg(t.bg)
            .text_color(t.text)
            .relative()
            .flex()
            .flex_col()
            .on_key_down(cx.listener(Self::handle_key_down))
            .child(self.render_titlebar(t, cx))
            .child(self.render_navbar(t, cx))
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .overflow_hidden()
                    .child(match self.tab {
                        Tab::Tunnel => self.render_tunnel_tab(t, cx).into_any_element(),
                        Tab::Desync => self.render_desync_tab(t, cx).into_any_element(),
                        Tab::Routes => self.render_routes_tab(t, cx).into_any_element(),
                        Tab::Nodes => self.render_nodes_tab(t, cx).into_any_element(),
                        Tab::Traffic => self.render_traffic_tab(t, cx).into_any_element(),
                        Tab::Options => self.render_options_tab(t, cx).into_any_element(),
                    }),
            )
            .child(self.render_footer(t, cx))
            .when_some(self.toast.as_ref(), |el, (msg, _)| {
                el.child(
                    div()
                        .absolute()
                        .bottom(px(40.0))
                        .left_0()
                        .w_full()
                        .flex()
                        .justify_center()
                        .child(
                            div()
                                .px(px(14.0))
                                .py(px(7.0))
                                .rounded(px(99.0))
                                .bg(t.bg_elev)
                                .border_1()
                                .border_color(t.border_hi)
                                .flex()
                                .items_center()
                                .gap(px(8.0))
                                .child(
                                    div()
                                        .w(px(7.0))
                                        .h(px(7.0))
                                        .rounded(px(4.0))
                                        .bg(t.green),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text)
                                        .child(msg.clone()),
                                ),
                        ),
                )
            })
            .children(self.render_modal_overlay(t, cx))
    }
}

fn pick_conf_files_native() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ps = r#"Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'WireGuard / AmneziaWG (*.conf;*.json;*.txt)|*.conf;*.json;*.txt|All files (*.*)|*.*'; $d.Multiselect = $true; if ($d.ShowDialog() -eq 'OK') { $d.FileNames -join "`n" }"#;
        if let Ok(out) = Command::new("powershell")
            .args(["-NoProfile", "-Sta", "-Command", ps])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            return text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("zenity")
            .args(["--file-selection", "--multiple", "--separator=\n"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            return text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let script = r#"POSIX path of (choose file with prompt "Выберите файл .conf")"#;
        if let Ok(out) = Command::new("osascript").args(["-e", script]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            return text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
        }
    }
    Vec::new()
}
