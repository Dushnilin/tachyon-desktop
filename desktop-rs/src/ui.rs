use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpui::component::Sizable as _;
use gpui::component::input::{Input, InputEvent, InputState};
use gpui::prelude::*;
use gpui::{
    AnyElement, App, ClipboardItem, Context, Entity, FontWeight, Render, SharedString,
    Subscription, Window, WindowControlArea, div, img, px, svg,
};
#[cfg(not(target_os = "windows"))]
use gpui::{MouseButton, MouseDownEvent};
use serde_json::{Value, json};

use crate::icons::flag_image;
use crate::state::{
    CustomRule, PersistedState, ROUTE_CATALOG, ServerNode, SubscriptionItem, SubscriptionMeta,
    country_title_for_lang, detect_protocol_badge, extract_host_port_from_uri,
};
use crate::theme::Theme;
use crate::vpn::{
    BalancerMember, BalancerPayload, RunningApp, VpnManager, balancer_country_presets,
    encode_balancer_uri, enumerate_apps, probe_endpoint_median_ms,
};
#[cfg(target_os = "macos")]
use crate::vpn::{install_macos_helper, macos_helper_status, uninstall_macos_helper};

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
pub enum ModalKind {
    None,
    Subscriptions,
    KernelLog,
    Balancer,
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
    #[allow(dead_code)]
    pub id: String,
    pub title: String,
    #[allow(dead_code)]
    pub subtitle: String,
    pub ok: bool,
    pub status: String,
    pub ms: i64,
}

#[derive(Clone, Debug)]
pub struct DnsBenchItem {
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
    #[allow(dead_code)]
    pub host: String,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub id: String,
    pub net: String,
    pub host: String,
    pub ip_port: String,
    pub process: String,
    pub chain: String,
    #[allow(dead_code)]
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

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LayoutMetrics {
    width: f32,
    height: f32,
    avail_w: f32,
    narrow: bool,
    compact: bool,
    short: bool,
    wide: bool,
    is_maximized: bool,
}

fn adaptive_card_width(avail: f32, min_card: f32, max_cols: usize, gap: f32) -> f32 {
    if avail <= min_card + 20.0 {
        return avail.max(200.0);
    }
    let cols = (((avail + gap) / (min_card + gap)).floor() as usize).clamp(1, max_cols);
    ((avail - gap * (cols.saturating_sub(1) as f32)) / (cols as f32)).floor()
}

pub struct TachyonApp {
    pub state: PersistedState,
    pub tab: Tab,
    pub route_subtab: RouteSubTab,
    pub modal: ModalKind,
    pub vpn: Arc<VpnManager>,
    pub rt: Arc<tokio::runtime::Runtime>,
    pub event_queue: Arc<Mutex<Vec<String>>>,

    // Native input states
    pub server_search_input: Entity<InputState>,
    pub route_search_input: Entity<InputState>,
    pub custom_rule_input: Entity<InputState>,
    pub custom_rule_tw_input: Entity<InputState>,
    pub node_uri_input_state: Entity<InputState>,
    pub node_name_input_state: Entity<InputState>,
    pub sub_url_input_state: Entity<InputState>,
    pub custom_dns_input_state: Entity<InputState>,
    pub ntp_server_input_state: Entity<InputState>,
    pub fake_sni_input_state: Entity<InputState>,
    pub udp_out_range_input_state: Entity<InputState>,
    pub udp_fake_payload_input_state: Entity<InputState>,
    pub desync_probe_input_state: Entity<InputState>,
    pub diag_target_input_state: Entity<InputState>,
    pub bal_url_input_state: Entity<InputState>,
    pub bal_include_input_state: Entity<InputState>,
    pub bal_exclude_input_state: Entity<InputState>,
    pub bal_words_input_state: Entity<InputState>,
    pub auto_ping_interval_input: Entity<InputState>,
    pub pasted_multiline_uri: Option<String>,
    _input_subscriptions: Vec<Subscription>,

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
    pub route_search: String,
    pub custom_rule_type: String,
    pub custom_rule_value: String,
    pub custom_rule_action: String,
    pub custom_rule_time_window: String,
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
    pub log_filter_level: String,
    pub toast: Option<(String, Instant)>,
    pub update_banner: UpdateBanner,
    pub last_conns_poll: Instant,
    // Живой RTT через туннель (не затирает прямой пинг узла)
    pub live_rtt_ms: Option<i64>,
    // Автопинг
    pub last_auto_ping: Instant,
    pub auto_ping_busy: Option<Instant>,
    // Трей и новые функции ядра
    pub close_to_tray_flag: Arc<AtomicBool>,
    pub desync_probe_domain: String,
    pub desync_probe_busy: bool,
    pub desync_probe_report: Option<String>,
    pub adaptive_snapshot: Vec<core_runtime::outbound::desync::GuiLearnedDomain>,
    pub adaptive_l3_scores: Vec<u32>,
    pub traffic_flight_mode: bool,
    pub flight_entries: Vec<Value>,
    pub diag_target: String,
    pub diag_busy: bool,
    pub inspector_report: Option<String>,
    pub memory_report: Option<Value>,
    #[cfg(target_os = "macos")]
    pub macos_helper_installed: bool,
    #[cfg(target_os = "macos")]
    pub macos_helper_busy: bool,
}

impl TachyonApp {
    pub fn is_en(&self) -> bool {
        self.state.language.eq_ignore_ascii_case("en")
    }

    pub fn tr(&self, ru: &'static str, en: &'static str) -> &'static str {
        if self.is_en() { en } else { ru }
    }

    pub fn country_title(&self, cc: &str) -> &'static str {
        country_title_for_lang(cc, &self.state.language)
    }

    pub fn new(
        vpn: Arc<VpnManager>,
        rt: Arc<tokio::runtime::Runtime>,
        event_queue: Arc<Mutex<Vec<String>>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let state = PersistedState::load();
        crate::theme::sync_kit_theme(state.light_theme, cx);
        let is_en = state.language.eq_ignore_ascii_case("en");
        let custom_dns_init = state.vpn_prefs.custom_dns.clone();
        let ntp_server_init = state.vpn_prefs.ntp_server.clone();
        let fake_sni_init = state.desync_prefs.fake_sni.clone();
        let udp_out_range_init = state.desync_prefs.udp_out_range.clone();
        let udp_fake_payload_init = state.desync_prefs.udp_fake_payload.clone();
        let bal_url_init = state.vpn_prefs.balancer_url.clone();
        let bal_include_init = state.vpn_prefs.balancer_include_regex.clone();
        let bal_exclude_init = state.vpn_prefs.balancer_exclude_regex.clone();
        let bal_words_init = state.vpn_prefs.balancer_excluded_countries.join(", ");
        let auto_ping_iv_init = format_interval_short(state.auto_ping.interval_s, is_en);
        let log_filter_init = state.vpn_prefs.log_level.clone();
        #[cfg(target_os = "macos")]
        let macos_helper_init = macos_helper_status().0;
        let close_to_tray_flag = Arc::new(AtomicBool::new(state.vpn_prefs.close_to_tray));

        let server_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "Search country or node..."
            } else {
                "Поиск страны или узла..."
            })
        });
        let route_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "Search 55 services..."
            } else {
                "Поиск из 55 сервисов..."
            })
        });
        let custom_rule_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "example.com, 1.2.3.0/24 or game.exe..."
            } else {
                "example.com, 1.2.3.0/24 или game.exe..."
            })
        });
        let node_uri_input_state = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "Paste vless://, awg://, vpn://, hy2://, wdtt://, tewfai://, subscription or [Interface] .conf..."
            } else {
                "Вставьте vless://, awg://, vpn://, hy2://, wdtt://, tewfai://, подписку или [Interface] .conf..."
            })
        });
        let node_name_input_state = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "Name (optional)"
            } else {
                "Название (необяз.)"
            })
        });
        let sub_url_input_state = cx.new(|cx| {
            InputState::new(window, cx).placeholder("https://... / happ://... / vpn://...")
        });
        let custom_dns_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(custom_dns_init.clone())
                .placeholder(if is_en {
                    "https://dns.example.com/dns-query or 1.1.1.1"
                } else {
                    "https://dns.example.com/dns-query или 1.1.1.1"
                })
        });
        let custom_rule_tw_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(if is_en {
                "Schedule (opt): mon-fri 09:00-18:00"
            } else {
                "Расписание (необяз.): mon-fri 09:00-18:00"
            })
        });
        let ntp_server_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(ntp_server_init)
                .placeholder("time.cloudflare.com")
        });
        let fake_sni_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(fake_sni_init)
                .placeholder("www.google.com, ya.ru, vk.com")
        });
        let udp_out_range_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(udp_out_range_init)
                .placeholder("1-2")
        });
        let udp_fake_payload_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(udp_fake_payload_init)
                .placeholder("0x000100002112a442...")
        });
        let desync_probe_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value("www.youtube.com")
                .placeholder("www.youtube.com")
        });
        let diag_target_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value("youtube.com")
                .placeholder("youtube.com")
        });
        let bal_url_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(bal_url_init)
                .placeholder("https://www.gstatic.com/generate_204")
        });
        let bal_include_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(bal_include_init)
                .placeholder(if is_en {
                    "e.g. LTE|Whitelist"
                } else {
                    "Например: LTE|Whitelist|МТС"
                })
        });
        let bal_exclude_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(bal_exclude_init)
                .placeholder(if is_en {
                    "e.g. backup|test|expired"
                } else {
                    "Например: резерв|тест|expired"
                })
        });
        let bal_words_input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(bal_words_init)
                .placeholder(if is_en {
                    "RU, KZ, BY, ads, vip"
                } else {
                    "RU, KZ, BY, реклама, vip"
                })
        });
        let auto_ping_interval_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(auto_ping_iv_init)
                .placeholder("60s / 10m / 1h")
        });

        let subs = vec![
            cx.subscribe_in(&server_search_input, window, |this, state, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.server_search = state.read(cx).value().to_string();
                    cx.notify();
                }
            }),
            cx.subscribe_in(&route_search_input, window, |this, state, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.route_search = state.read(cx).value().to_string();
                    cx.notify();
                }
            }),
            cx.subscribe_in(
                &custom_rule_input,
                window,
                |this, state, event, window, cx| match event {
                    InputEvent::Change => {
                        this.custom_rule_value = state.read(cx).value().to_string();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        this.submit_custom_rule_ui(window, cx);
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &node_uri_input_state,
                window,
                |this, state, event, window, cx| match event {
                    InputEvent::Change => {
                        let val = state.read(cx).value().to_string();
                        if let Some(raw) = &this.pasted_multiline_uri
                            && val != raw.trim().replace('\n', " ↵ ")
                        {
                            this.pasted_multiline_uri = None;
                        }
                        this.node_uri_input = val;
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        this.submit_node_uri_ui(window, cx);
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &node_name_input_state,
                window,
                |this, state, event, window, cx| match event {
                    InputEvent::Change => {
                        this.node_name_input = state.read(cx).value().to_string();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        this.submit_node_uri_ui(window, cx);
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &sub_url_input_state,
                window,
                |this, state, event, window, cx| match event {
                    InputEvent::Change => {
                        this.sub_url_input = state.read(cx).value().to_string();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        this.submit_sub_url_ui(window, cx);
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &custom_dns_input_state,
                window,
                |this, state, event, _, cx| match event {
                    InputEvent::Change => {
                        this.state.vpn_prefs.custom_dns = state.read(cx).value().trim().to_string();
                        this.state.save();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } | InputEvent::Blur => {
                        this.state.vpn_prefs.custom_dns = state.read(cx).value().trim().to_string();
                        this.state.save();
                        if this.state.vpn_prefs.dns == "custom" {
                            this.reconnect_if_active();
                        }
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &custom_rule_tw_input,
                window,
                |this, state, event, window, cx| match event {
                    InputEvent::Change => {
                        this.custom_rule_time_window = state.read(cx).value().trim().to_string();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        this.submit_custom_rule_ui(window, cx);
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &ntp_server_input_state,
                window,
                |this, state, event, _, cx| match event {
                    InputEvent::Change => {
                        this.state.vpn_prefs.ntp_server = state.read(cx).value().trim().to_string();
                        this.state.save();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } | InputEvent::Blur => {
                        this.state.vpn_prefs.ntp_server = state.read(cx).value().trim().to_string();
                        this.state.save();
                        if this.state.vpn_prefs.ntp_enabled {
                            this.reconnect_if_active();
                        }
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &fake_sni_input_state,
                window,
                |this, state, event, _, cx| match event {
                    InputEvent::Change => {
                        this.state.desync_prefs.fake_sni = state.read(cx).value().to_string();
                        this.state.save();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } | InputEvent::Blur => {
                        this.state.desync_prefs.fake_sni =
                            state.read(cx).value().trim().to_string();
                        this.state.save();
                        this.reconnect_if_active();
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &udp_out_range_input_state,
                window,
                |this, state, event, _, cx| match event {
                    InputEvent::Change => {
                        this.state.desync_prefs.udp_out_range =
                            state.read(cx).value().trim().to_string();
                        this.state.save();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } | InputEvent::Blur => {
                        this.state.desync_prefs.udp_out_range =
                            state.read(cx).value().trim().to_string();
                        this.state.save();
                        this.reconnect_if_active();
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &udp_fake_payload_input_state,
                window,
                |this, state, event, _, cx| match event {
                    InputEvent::Change => {
                        this.state.desync_prefs.udp_fake_payload =
                            state.read(cx).value().trim().to_string();
                        this.state.save();
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } | InputEvent::Blur => {
                        this.state.desync_prefs.udp_fake_payload =
                            state.read(cx).value().trim().to_string();
                        this.state.save();
                        this.reconnect_if_active();
                        cx.notify();
                    }
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &desync_probe_input_state,
                window,
                |this, state, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.desync_probe_domain = state.read(cx).value().trim().to_string();
                        cx.notify();
                    }
                },
            ),
            cx.subscribe_in(
                &diag_target_input_state,
                window,
                |this, state, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.diag_target = state.read(cx).value().trim().to_string();
                        cx.notify();
                    }
                },
            ),
            cx.subscribe_in(&bal_url_input_state, window, |this, state, event, _, cx| {
                if matches!(event, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                    let v = state.read(cx).value().trim().to_string();
                    if (v.starts_with("http://") || v.starts_with("https://"))
                        && v != this.state.vpn_prefs.balancer_url
                    {
                        this.state.vpn_prefs.balancer_url = v;
                        this.reconnect_if_active();
                        cx.notify();
                    }
                }
            }),
            cx.subscribe_in(
                &bal_include_input_state,
                window,
                |this, state, event, _, cx| {
                    if matches!(event, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                        let v = state.read(cx).value().trim().to_string();
                        if v != this.state.vpn_prefs.balancer_include_regex {
                            this.state.vpn_prefs.balancer_include_regex = v;
                            this.reconnect_if_active();
                            cx.notify();
                        }
                    }
                },
            ),
            cx.subscribe_in(
                &bal_exclude_input_state,
                window,
                |this, state, event, _, cx| {
                    if matches!(event, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                        let v = state.read(cx).value().trim().to_string();
                        if v != this.state.vpn_prefs.balancer_exclude_regex {
                            this.state.vpn_prefs.balancer_exclude_regex = v;
                            this.reconnect_if_active();
                            cx.notify();
                        }
                    }
                },
            ),
            cx.subscribe_in(
                &bal_words_input_state,
                window,
                |this, state, event, _, cx| {
                    if matches!(event, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                        let parsed: Vec<String> = state
                            .read(cx)
                            .value()
                            .split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect();
                        if parsed != this.state.vpn_prefs.balancer_excluded_countries {
                            this.state.vpn_prefs.balancer_excluded_countries = parsed;
                            this.reconnect_if_active();
                            cx.notify();
                        }
                    }
                },
            ),
            cx.subscribe_in(
                &auto_ping_interval_input,
                window,
                |this, state, event, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                        let raw = state.read(cx).value().to_string();
                        if let Some(secs) = parse_duration_secs(&raw) {
                            this.state.auto_ping.interval_s = secs;
                            this.state.save();
                        }
                        let norm =
                            format_interval_short(this.state.auto_ping.interval_s, this.is_en());
                        state.update(cx, |s, cx| s.set_value(norm, window, cx));
                        cx.notify();
                    }
                },
            ),
        ];

        crate::tray::register_main_window();
        crate::tray::update_status(false, is_en);
        let ctt_flag = close_to_tray_flag.clone();
        let eq_close = event_queue.clone();
        window.on_window_should_close(cx, move |_window, _cx| {
            if ctt_flag.load(Ordering::Acquire) && crate::tray::hide_to_tray() {
                return false;
            }
            if let Ok(mut g) = eq_close.lock() {
                g.push("tray:exit".to_string());
            }
            false
        });

        let mut app = Self {
            state,
            tab: Tab::Tunnel,
            route_subtab: RouteSubTab::Catalog,
            modal: ModalKind::None,
            vpn,
            rt,
            event_queue,
            server_search_input,
            route_search_input,
            custom_rule_input,
            custom_rule_tw_input,
            node_uri_input_state,
            node_name_input_state,
            sub_url_input_state,
            custom_dns_input_state,
            ntp_server_input_state,
            fake_sni_input_state,
            udp_out_range_input_state,
            udp_fake_payload_input_state,
            desync_probe_input_state,
            diag_target_input_state,
            bal_url_input_state,
            bal_include_input_state,
            bal_exclude_input_state,
            bal_words_input_state,
            auto_ping_interval_input,
            pasted_multiline_uri: None,
            _input_subscriptions: subs,
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
            route_search: String::new(),
            custom_rule_type: "domain".to_string(),
            custom_rule_value: String::new(),
            custom_rule_action: "vpn".to_string(),
            custom_rule_time_window: String::new(),
            collapsed_countries: HashSet::new(),
            connections: Vec::new(),
            running_apps: Vec::new(),
            diag_items: Vec::new(),
            diag_running: false,
            dns_bench: Vec::new(),
            dns_running: false,
            speedtest: SpeedtestStatus::default(),
            log_tail: String::new(),
            log_filter_level: log_filter_init,
            toast: None,
            update_banner: UpdateBanner::default(),
            last_conns_poll: Instant::now(),
            live_rtt_ms: None,
            last_auto_ping: Instant::now(),
            auto_ping_busy: None,
            close_to_tray_flag,
            desync_probe_domain: "www.youtube.com".to_string(),
            desync_probe_busy: false,
            desync_probe_report: None,
            adaptive_snapshot: core_runtime::outbound::desync::gui_snapshot_learned_domains(),
            adaptive_l3_scores: core_runtime::outbound::desync::gui_snapshot_l3_scores().to_vec(),
            traffic_flight_mode: false,
            flight_entries: Vec::new(),
            diag_target: "youtube.com".to_string(),
            diag_busy: false,
            inspector_report: None,
            memory_report: None,
            #[cfg(target_os = "macos")]
            macos_helper_installed: macos_helper_init,
            #[cfg(target_os = "macos")]
            macos_helper_busy: false,
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

    pub fn quit_app(&mut self) {
        let v = self.vpn.clone();
        self.rt.block_on(async move {
            v.disconnect().await;
        });
        crate::tray::shutdown();
        std::process::exit(0);
    }

    pub fn refresh_adaptive_brain(&mut self) {
        self.adaptive_snapshot = core_runtime::outbound::desync::gui_snapshot_learned_domains();
        self.adaptive_l3_scores = core_runtime::outbound::desync::gui_snapshot_l3_scores().to_vec();
    }

    fn current_desync_options(&self) -> crate::vpn::DesyncOptions {
        crate::vpn::ConnectOptions::parse(&self.state.build_connect_payload(None))
            .map(|c| c.desync)
            .unwrap_or_default()
    }

    pub fn drain_backend_events(&mut self, cx: &mut Context<Self>) {
        let mut drained = Vec::new();
        if let Ok(mut guard) = self.event_queue.lock()
            && !guard.is_empty()
        {
            std::mem::swap(&mut drained, &mut *guard);
        }

        let mut needs_notify = false;
        if let Some((_, ts)) = &self.toast
            && ts.elapsed() > Duration::from_secs(4)
        {
            self.toast = None;
            needs_notify = true;
        }
        if self.vpn_status == "connected" {
            needs_notify = true;
            if self.tab == Tab::Traffic
                && self.last_conns_poll.elapsed() >= Duration::from_millis(1800)
            {
                self.last_conns_poll = Instant::now();
                let v = self.vpn.clone();
                let eq = self.event_queue.clone();
                self.rt.spawn(async move {
                    let data = v.get_connections_json().await;
                    if let Ok(mut g) = eq.lock() {
                        g.push(format!("conn:data:{data}"));
                    }
                });
            }
        }

        // Автопинг по таймеру
        if self.state.auto_ping.enabled {
            let interval = Duration::from_secs(self.state.auto_ping.interval_s.max(3));
            // Сбрасываем зависший busy через 90с
            if matches!(self.auto_ping_busy, Some(ts) if ts.elapsed() > Duration::from_secs(90)) {
                self.auto_ping_busy = None;
            }
            if self.auto_ping_busy.is_none() && self.last_auto_ping.elapsed() >= interval {
                self.last_auto_ping = Instant::now();
                self.run_auto_ping();
            }
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
                                    self.trigger_auto_ping_debounced();
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
                                if prev != "disconnected" {
                                    self.trigger_auto_ping_debounced();
                                }
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
                    if let Some(ping) = doc.get("ping").and_then(Value::as_i64)
                        && ping > 0
                    {
                        // RTT «через туннель» — хранится отдельно, не затирает прямой пинг узла
                        self.live_rtt_ms = Some(ping);
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
                    self.trigger_auto_ping_debounced();
                } else if status == "disconnected" {
                    self.connected_since = None;
                    self.rx_bps = 0;
                    self.tx_bps = 0;
                    self.live_balancer = None;
                    self.live_rtt_ms = None;
                    if prev != "disconnected" {
                        self.trigger_auto_ping_debounced();
                    }
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
                    let now = now_unix_secs();
                    if let Some(srv) = self.state.servers.iter_mut().find(|s| s.id == id) {
                        srv.ping_ms = Some(ms);
                        srv.ping_at = Some(now);
                        srv.alive = Some(ms > 0);
                    }
                }
            } else if msg == "ping:auto:done" {
                self.auto_ping_busy = None;
                self.state.save();
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
            } else if msg == "tray:toggle-vpn" {
                self.toggle_connection();
            } else if msg == "tray:exit" {
                self.quit_app();
            } else if let Some(warp_str) = msg.strip_prefix("warp:result:") {
                if let Ok(doc) = serde_json::from_str::<Value>(warp_str) {
                    if doc.get("ok").and_then(Value::as_bool) == Some(true) {
                        if let Some(uri) = doc.get("uri").and_then(Value::as_str) {
                            let name = doc
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("Cloudflare WARP (AmneziaWG)");
                            self.add_single_server_uri(uri, Some(name));
                            if let Some(m_uri) = doc
                                .get("masque_uri")
                                .and_then(Value::as_str)
                                .filter(|s| !s.trim().is_empty())
                            {
                                self.add_single_server_uri(m_uri, Some("Cloudflare WARP (MASQUE)"));
                            }
                            self.show_toast(self.tr(
                                "Профиль Cloudflare WARP создан и добавлен",
                                "Cloudflare WARP profile created and added",
                            ));
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
                if let Ok(doc) = serde_json::from_str::<Value>(conn_str)
                    && let Some(arr) = doc
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
                        let direct = item.get("direct").and_then(Value::as_bool).unwrap_or(false);
                        let desync = item.get("desync").and_then(Value::as_bool).unwrap_or(false);
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
                        let ip_raw = item
                            .get("ip")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .or_else(|| {
                                item.get("metadata")
                                    .and_then(|m| m.get("destinationIP"))
                                    .and_then(Value::as_str)
                            })
                            .unwrap_or("");
                        let port_str = item.get("port").and_then(Value::as_str).unwrap_or("");
                        let ip_port = if !ip_raw.is_empty() && !port_str.is_empty() {
                            format!("{ip_raw}:{port_str}")
                        } else if !ip_raw.is_empty() {
                            ip_raw.to_string()
                        } else {
                            String::new()
                        };
                        let host_raw = item
                            .get("host")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .or_else(|| {
                                item.get("metadata").and_then(|m| {
                                    m.get("host")
                                        .and_then(Value::as_str)
                                        .filter(|s| !s.is_empty())
                                })
                            })
                            .unwrap_or(if ip_raw.is_empty() { "—" } else { ip_raw });
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
                                    m.get("processPath")
                                        .or_else(|| m.get("process"))
                                        .and_then(Value::as_str)
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
                            ip_port,
                            process,
                            chain,
                            rule,
                            dl,
                            ul,
                        });
                    }
                    self.connections = rows;
                }
            } else if let Some(diag_str) = msg.strip_prefix("diag:matrix:") {
                self.diag_running = false;
                if let Ok(doc) = serde_json::from_str::<Value>(diag_str)
                    && let Some(arr) = doc.get("items").and_then(Value::as_array)
                {
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
                if let Ok(doc) = serde_json::from_str::<Value>(dns_str)
                    && let Some(arr) = doc.get("results").and_then(Value::as_array)
                {
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
            } else if let Some(ps) = msg.strip_prefix("probe:stream:") {
                self.desync_probe_busy = false;
                self.refresh_adaptive_brain();
                if let Ok(doc) = serde_json::from_str::<Value>(ps) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.desync_probe_report = Some(format!("HTTPS-поток: {err}"));
                    } else {
                        let ok = doc.get("ok").and_then(Value::as_bool).unwrap_or(false);
                        let v32 = doc
                            .get("verified_32k")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let st = doc.get("status").and_then(Value::as_str).unwrap_or("—");
                        let rtt = doc.get("rtt_ms").and_then(Value::as_u64).unwrap_or(0);
                        let rx = doc.get("rx_app_bytes").and_then(Value::as_u64).unwrap_or(0);
                        let reason = doc
                            .get("block_reason")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let detail = doc.get("detail").and_then(Value::as_str).unwrap_or("");
                        self.desync_probe_report = Some(format!(
                            "HTTPS: {} · 32K={} · {st} · {rtt} ms · rx={rx} B{}{}",
                            if ok { "OK" } else { "FAIL" },
                            if v32 { "да" } else { "нет" },
                            if reason.is_empty() {
                                String::new()
                            } else {
                                format!(" · {reason}")
                            },
                            if detail.is_empty() {
                                String::new()
                            } else {
                                format!(" ({detail})")
                            },
                        ));
                    }
                }
            } else if let Some(pt) = msg.strip_prefix("probe:ttl:") {
                self.desync_probe_busy = false;
                if let Ok(doc) = serde_json::from_str::<Value>(pt) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.desync_probe_report = Some(format!("TTL: {err}"));
                    } else {
                        let ttl = doc.get("optimal_ttl").and_then(Value::as_u64).unwrap_or(0);
                        let summary = doc.get("summary").and_then(Value::as_str).unwrap_or("");
                        self.desync_probe_report = Some(format!("Optimal TTL={ttl} · {summary}"));
                    }
                }
            } else if let Some(dr) = msg.strip_prefix("diag:route:") {
                self.diag_busy = false;
                if let Ok(doc) = serde_json::from_str::<Value>(dr) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.inspector_report = Some(format!("Route Check: {err}"));
                    } else {
                        let tgt = doc.get("target").and_then(Value::as_str).unwrap_or("—");
                        let out = doc
                            .get("effective_outbound")
                            .or_else(|| doc.get("outbound"))
                            .and_then(Value::as_str)
                            .unwrap_or("—");
                        let rule = doc
                            .get("matched_rule")
                            .and_then(Value::as_str)
                            .unwrap_or("final");
                        let advice = doc
                            .pointer("/probe/advice")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        self.inspector_report = Some(format!(
                            "{tgt} -> {out} ({rule}){}",
                            if advice.is_empty() {
                                String::new()
                            } else {
                                format!(" · {advice}")
                            }
                        ));
                    }
                }
            } else if let Some(dd) = msg.strip_prefix("diag:dns:") {
                self.diag_busy = false;
                if let Ok(doc) = serde_json::from_str::<Value>(dd) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.inspector_report = Some(format!("DNS Check: {err}"));
                    } else {
                        let dom = doc.get("domain").and_then(Value::as_str).unwrap_or("—");
                        let st = doc.get("status").and_then(Value::as_str).unwrap_or("—");
                        let adv = doc.get("advice").and_then(Value::as_str).unwrap_or("");
                        self.inspector_report = Some(format!("DNS {dom}: {st} ({adv})"));
                    }
                }
            } else if let Some(dl) = msg.strip_prefix("diag:leak:") {
                self.diag_busy = false;
                if let Ok(doc) = serde_json::from_str::<Value>(dl) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.inspector_report = Some(format!("Leak Audit: {err}"));
                    } else {
                        let st = doc.get("status").and_then(Value::as_str).unwrap_or("—");
                        let v4 = doc
                            .pointer("/ipv4/outbound")
                            .and_then(Value::as_str)
                            .unwrap_or("—");
                        let v6 = doc
                            .pointer("/ipv6/outbound")
                            .and_then(Value::as_str)
                            .unwrap_or("—");
                        let stun = doc
                            .pointer("/webrtc_stun/outbound")
                            .and_then(Value::as_str)
                            .unwrap_or("—");
                        let dns_ok = doc
                            .pointer("/dns/engine_enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.inspector_report = Some(format!(
                            "Audit={st} · IPv4:{v4} · IPv6:{v6} · STUN:{stun} · DNS:{}",
                            if dns_ok { "on" } else { "off" }
                        ));
                    }
                }
            } else if let Some(dm) = msg.strip_prefix("diag:mem:") {
                self.diag_busy = false;
                if let Ok(doc) = serde_json::from_str::<Value>(dm) {
                    if let Some(err) = doc.get("error").and_then(Value::as_str) {
                        self.show_toast(format!("Memory: {err}"));
                    } else {
                        let rss = doc.get("rss_bytes").and_then(Value::as_u64).unwrap_or(0);
                        let lvl = doc
                            .get("pressure_level")
                            .and_then(Value::as_str)
                            .unwrap_or("normal");
                        let conns = doc
                            .pointer("/connections/active_connections")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let fk = doc
                            .pointer("/dns/fakeip_entries")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        self.memory_report = Some(doc.clone());
                        self.inspector_report = Some(format!(
                            "RSS: {} · Pressure: {lvl} · Conns: {conns} · FakeIP: {fk}",
                            format_bytes_human(rss)
                        ));
                    }
                }
            } else if let Some(fl) = msg.strip_prefix("diag:flight:") {
                if let Ok(doc) = serde_json::from_str::<Value>(fl)
                    && let Some(arr) = doc.get("entries").and_then(Value::as_array)
                {
                    self.flight_entries = arr.clone();
                }
            } else if msg == "diag:flight:cleared" {
                self.flight_entries.clear();
                self.show_toast(self.tr("Журнал соединений очищен", "Flight log cleared"));
            } else if let Some(tmsg) = msg.strip_prefix("toast:") {
                self.show_toast(tmsg.to_string());
            } else if let Some(mh) = msg.strip_prefix("macos_helper:done:") {
                self.handle_macos_helper_event(mh);
            }
        }

        crate::tray::update_status(self.vpn_status == "connected", self.is_en());

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
                self.show_toast(
                    "Запуск в режиме прямой пакетной десинхронизации (Desync) без прокси-сервера",
                );
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

    async fn probe_single_uri_ms(uri: &str) -> i64 {
        let badge = detect_protocol_badge(uri);
        if let Some((host, port)) = extract_host_port_from_uri(uri) {
            let is_udp = matches!(badge, "AWG" | "WG" | "HY2" | "TUIC" | "WDTT");
            probe_endpoint_median_ms(&host, port, is_udp).await
        } else {
            -1
        }
    }

    pub fn ping_single_node(&mut self, id: String) {
        let Some(srv) = self.state.servers.iter_mut().find(|s| s.id == id) else {
            return;
        };
        if srv.is_balancer {
            self.ping_all_nodes();
            return;
        }
        srv.ping_ms = None;
        let uri = srv.vless.clone();
        let name = srv.name.clone();
        let eq = self.event_queue.clone();
        let is_en = self.is_en();
        self.show_toast(if is_en {
            format!("Pinging {name}...")
        } else {
            format!("Пинг узла: {name}...")
        });
        self.rt.spawn(async move {
            let ms = Self::probe_single_uri_ms(&uri).await;
            if let Ok(mut g) = eq.lock() {
                g.push(format!("pong:{id}:{ms}"));
            }
        });
    }

    pub fn ping_country_nodes(&mut self, cc: String) {
        let mut targets = Vec::new();
        for srv in &mut self.state.servers {
            if !srv.is_balancer && srv.country == cc {
                srv.ping_ms = None;
                targets.push((srv.id.clone(), srv.vless.clone()));
            }
        }
        if targets.is_empty() {
            return;
        }
        self.spawn_ping_batch(targets, false);
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
        self.spawn_ping_batch(targets, false);
    }

    fn spawn_ping_batch(&self, targets: Vec<(String, String)>, is_auto: bool) {
        let eq = self.event_queue.clone();
        self.rt.spawn(async move {
            let total = targets.len();
            let sem = Arc::new(tokio::sync::Semaphore::new(16));
            let reachable = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut handles = Vec::with_capacity(total);
            for (id, uri) in targets {
                let sem_cl = sem.clone();
                let eq_cl = eq.clone();
                let reach_cl = reachable.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem_cl.acquire().await;
                    let ms = Self::probe_single_uri_ms(&uri).await;
                    if ms > 0 {
                        reach_cl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Ok(mut g) = eq_cl.lock() {
                        g.push(format!("pong:{id}:{ms}"));
                    }
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            let r = reachable.load(std::sync::atomic::Ordering::Relaxed);
            if let Ok(mut g) = eq.lock() {
                if is_auto {
                    g.push("ping:auto:done".to_string());
                } else {
                    let done = json!({ "reachable": r, "total": total }).to_string();
                    g.push(format!("ping:batch:done:{done}"));
                }
            }
        });
    }

    pub fn run_auto_ping(&mut self) {
        let ap = &self.state.auto_ping;
        let targets: Vec<(String, String)> = self
            .state
            .servers
            .iter()
            .filter(|s| !s.is_balancer && (ap.all || ap.ids.contains(&s.id)))
            .map(|s| (s.id.clone(), s.vless.clone()))
            .collect();
        if targets.is_empty() {
            return;
        }
        self.auto_ping_busy = Some(Instant::now());
        self.spawn_ping_batch(targets, true);
    }

    pub fn trigger_auto_ping_debounced(&mut self) {
        if self.state.auto_ping.enabled
            && self.auto_ping_busy.is_none()
            && self.last_auto_ping.elapsed() >= Duration::from_secs(15)
        {
            self.last_auto_ping = Instant::now();
            self.run_auto_ping();
        }
    }

    pub fn toggle_auto_ping(&mut self) {
        self.state.auto_ping.enabled = !self.state.auto_ping.enabled;
        self.last_auto_ping = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        self.state.save();
    }

    pub fn cycle_auto_ping_interval(&mut self) {
        const STEPS: [u64; 8] = [15, 30, 60, 120, 300, 600, 1800, 3600];
        let cur = self.state.auto_ping.interval_s;
        self.state.auto_ping.interval_s =
            STEPS.iter().copied().find(|&x| x > cur).unwrap_or(STEPS[0]);
        self.state.save();
    }

    #[cfg(target_os = "macos")]
    fn handle_macos_helper_event(&mut self, payload: &str) {
        self.macos_helper_busy = false;
        self.macos_helper_installed = macos_helper_status().0;
        let msg = payload
            .strip_prefix("1:")
            .or_else(|| payload.strip_prefix("0:"))
            .unwrap_or(payload);
        self.show_toast(msg.to_string());
    }

    #[cfg(not(target_os = "macos"))]
    fn handle_macos_helper_event(&mut self, _payload: &str) {}

    #[cfg(target_os = "macos")]
    fn trigger_macos_helper_action(&mut self, install: bool) {
        if self.macos_helper_busy {
            return;
        }
        self.macos_helper_busy = true;
        let eq = self.event_queue.clone();
        let is_en = self.is_en();
        let ok_msg = if install {
            if is_en {
                "macOS helper installed"
            } else {
                "Помощник macOS установлен"
            }
        } else if is_en {
            "macOS helper removed"
        } else {
            "Помощник macOS удалён"
        };
        self.rt.spawn_blocking(move || {
            let res = if install {
                install_macos_helper()
            } else {
                uninstall_macos_helper()
            };
            let msg = match res {
                Ok(()) => format!("macos_helper:done:1:{ok_msg}"),
                Err(e) => format!("macos_helper:done:0:{e}"),
            };
            if let Ok(mut g) = eq.lock() {
                g.push(msg);
            }
        });
    }

    pub fn toggle_auto_ping_all(&mut self) {
        self.state.auto_ping.all = !self.state.auto_ping.all;
        self.state.save();
    }

    pub fn toggle_ping_selected(&mut self, id: &str) {
        let ap = &mut self.state.auto_ping;
        if let Some(pos) = ap.ids.iter().position(|x| x == id) {
            ap.ids.remove(pos);
        } else {
            ap.ids.push(id.to_string());
        }
        ap.all = false;
        self.state.save();
    }

    pub fn create_custom_balancer_from_nodes(&mut self) {
        let members: Vec<BalancerMember> = self
            .state
            .servers
            .iter()
            .filter(|s| {
                if s.is_balancer {
                    return false;
                }
                if self.hide_ru_by && matches!(s.country.as_str(), "ru" | "by") {
                    return false;
                }
                true
            })
            .map(|s| BalancerMember {
                name: s.name.clone(),
                vless: s.vless.clone(),
                country: s.country.clone(),
            })
            .collect();

        if members.len() < 2 {
            let msg = self.tr(
                "Нужно минимум 2 узла для создания балансировщика",
                "At least 2 nodes are required to create a balancer",
            );
            self.show_toast(msg.to_string());
            return;
        }

        let mode = self.state.vpn_prefs.balancer_mode.clone();
        let name = if self.is_en() {
            format!("Smart Balancer ({mode}, {} nodes)", members.len())
        } else {
            format!("Балансировщик ({mode}, {} узлов)", members.len())
        };
        let payload = BalancerPayload {
            name: name.clone(),
            mode: mode.clone(),
            url: self.state.vpn_prefs.balancer_url.clone(),
            interval: self.state.vpn_prefs.balancer_interval.clone(),
            tolerance: self.state.vpn_prefs.balancer_tolerance,
            pool: self.state.vpn_prefs.balancer_pool as u32,
            pool_tolerance: self.state.vpn_prefs.balancer_tolerance,
            sticky_hash: self.state.vpn_prefs.balancer_sticky_hash.clone(),
            quota_mib: self.state.vpn_prefs.balancer_quota_mib,
            members: members.clone(),
        };
        let uri = encode_balancer_uri(&payload);
        let id = format!("bal-custom-{}", self.state.servers.len() + 1);
        self.state.servers.insert(
            0,
            ServerNode {
                id: id.clone(),
                name: name.clone(),
                vless: uri,
                country: "xx".to_string(),
                sub_id: None,
                is_balancer: true,
                balancer_mode: Some(mode),
                member_count: Some(members.len()),
                ping_ms: None,
                ping_at: None,
                alive: Some(true),
            },
        );
        self.state.active_id = id;
        self.reconnect_if_active();
        let msg = if self.is_en() {
            format!("Created & selected: {name}")
        } else {
            format!("Создан и выбран: {name}")
        };
        self.show_toast(msg);
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
                if !is_remote_sub
                    && arr.len() == 1
                    && !handle.is_empty()
                    && handle != "Подписка"
                    && (name.starts_with("Узел #") || name == "WireGuard" || name == "AmneziaWG")
                {
                    name = handle.clone();
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
                    ping_at: None,
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
        if imported_count > 0 {
            if self.state.auto_ping.enabled && self.auto_ping_busy.is_none() {
                self.last_auto_ping = Instant::now();
                self.run_auto_ping();
            } else if !self.state.auto_ping.enabled {
                self.ping_all_nodes();
            }
        }
        self.show_toast(format!("Добавлено узлов: {imported_count}"));
    }

    pub fn sync_input_placeholders(&self, window: &mut Window, cx: &mut Context<Self>) {
        let srv_ph = self.tr("Поиск страны или узла...", "Search country or node...");
        let route_ph = self.tr("Поиск из 55 сервисов...", "Search 55 services...");
        let rule_ph = self.tr(
            "example.com, 1.2.3.0/24 или game.exe...",
            "example.com, 1.2.3.0/24 or game.exe...",
        );
        let uri_ph = self.tr(
            "Вставьте vless://, awg://, vpn://, hy2://, wdtt://, tewfai://, подписку или [Interface] .conf...",
            "Paste vless://, awg://, vpn://, hy2://, wdtt://, tewfai://, subscription or [Interface] .conf...",
        );
        let name_ph = self.tr("Название (необяз.)", "Name (optional)");
        let dns_ph = self.tr(
            "https://dns.example.com/dns-query или 1.1.1.1",
            "https://dns.example.com/dns-query or 1.1.1.1",
        );

        self.server_search_input
            .update(cx, |s, cx| s.set_placeholder(srv_ph, window, cx));
        self.route_search_input
            .update(cx, |s, cx| s.set_placeholder(route_ph, window, cx));
        self.custom_rule_input
            .update(cx, |s, cx| s.set_placeholder(rule_ph, window, cx));
        self.node_uri_input_state
            .update(cx, |s, cx| s.set_placeholder(uri_ph, window, cx));
        self.node_name_input_state
            .update(cx, |s, cx| s.set_placeholder(name_ph, window, cx));
        self.custom_dns_input_state
            .update(cx, |s, cx| s.set_placeholder(dns_ph, window, cx));
        let bal_inc_ph = self.tr("Например: LTE|Whitelist|МТС", "e.g. LTE|Whitelist");
        let bal_exc_ph = self.tr("Например: резерв|тест|expired", "e.g. backup|test|expired");
        let bal_words_ph = self.tr("RU, KZ, BY, реклама, vip", "RU, KZ, BY, ads, vip");
        self.bal_include_input_state
            .update(cx, |s, cx| s.set_placeholder(bal_inc_ph, window, cx));
        self.bal_exclude_input_state
            .update(cx, |s, cx| s.set_placeholder(bal_exc_ph, window, cx));
        self.bal_words_input_state
            .update(cx, |s, cx| s.set_placeholder(bal_words_ph, window, cx));
    }

    pub fn submit_custom_rule_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let raw = self.custom_rule_input.read(cx).value().to_string();
        self.custom_rule_time_window = self
            .custom_rule_tw_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if self.apply_custom_rules_raw(&raw) {
            self.custom_rule_value.clear();
            self.custom_rule_time_window.clear();
            self.custom_rule_input
                .update(cx, |s, cx| s.set_value("", window, cx));
            self.custom_rule_tw_input
                .update(cx, |s, cx| s.set_value("", window, cx));
        }
    }

    fn apply_custom_rules_raw(&mut self, raw: &str) -> bool {
        let entries = parse_custom_rule_entries(&self.custom_rule_type, raw);
        if entries.is_empty() {
            return false;
        }
        let mut next_num = self
            .state
            .custom_rules
            .iter()
            .filter_map(|r| r.id.strip_prefix("rule-")?.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            + 1;

        for (rtype, val) in entries {
            if let Some(existing) = self
                .state
                .custom_rules
                .iter_mut()
                .find(|r| r.rule_type == rtype && r.value.eq_ignore_ascii_case(&val))
            {
                existing.action = self.custom_rule_action.clone();
                existing.time_window = self.custom_rule_time_window.clone();
            } else {
                let id = format!("rule-{next_num}");
                next_num += 1;
                self.state.custom_rules.push(CustomRule {
                    id,
                    rule_type: rtype,
                    value: val,
                    action: self.custom_rule_action.clone(),
                    time_window: self.custom_rule_time_window.clone(),
                });
            }
        }
        self.state.save();
        self.reconnect_if_active();
        true
    }

    pub fn submit_node_uri_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let raw_uri = self
            .pasted_multiline_uri
            .take()
            .unwrap_or_else(|| self.node_uri_input_state.read(cx).value().to_string());
        let uri = raw_uri.trim().to_string();
        let name = self
            .node_name_input_state
            .read(cx)
            .value()
            .trim()
            .to_string();
        if !uri.is_empty() {
            self.add_single_server_uri(&uri, if name.is_empty() { None } else { Some(&name) });
            self.node_uri_input.clear();
            self.node_name_input.clear();
            self.node_uri_input_state
                .update(cx, |s, cx| s.set_value("", window, cx));
            self.node_name_input_state
                .update(cx, |s, cx| s.set_value("", window, cx));
        }
    }

    pub fn submit_sub_url_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let url = self.sub_url_input_state.read(cx).value().trim().to_string();
        if !url.is_empty() {
            self.add_single_server_uri(&url, None);
            self.sub_url_input.clear();
            self.sub_url_input_state
                .update(cx, |s, cx| s.set_value("", window, cx));
        }
    }
}

fn is_ip_or_cidr(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((ip_part, prefix_part)) = s.split_once('/')
        && let Ok(ip) = ip_part.parse::<std::net::IpAddr>()
        && let Ok(prefix) = prefix_part.parse::<u8>()
    {
        return match ip {
            std::net::IpAddr::V4(_) => prefix <= 32,
            std::net::IpAddr::V6(_) => prefix <= 128,
        };
    }
    false
}

fn strip_url_to_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    let without_scheme = if lower.starts_with("https://") {
        &trimmed[8..]
    } else if lower.starts_with("http://") {
        &trimmed[7..]
    } else {
        trimmed
    };
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    let host_only = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let no_port = if let Some((h, p)) = host_only.rsplit_once(':') {
        if !h.is_empty() && !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host_only
        }
    } else {
        host_only
    };
    no_port
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .trim()
        .to_lowercase()
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Парсит интервал (`60`, `60s`, `10m`, `1h`, русские `с`/`м`/`ч`) с зажатием в `5..=86400`.
pub fn parse_duration_secs(raw: &str) -> Option<u64> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    let (num_str, mult) = if let Some(n) = s
        .strip_suffix("сек")
        .or_else(|| s.strip_suffix('s'))
        .or_else(|| s.strip_suffix('с'))
    {
        (n, 1u64)
    } else if let Some(n) = s
        .strip_suffix("мин")
        .or_else(|| s.strip_suffix('m'))
        .or_else(|| s.strip_suffix('м'))
    {
        (n, 60u64)
    } else if let Some(n) = s
        .strip_suffix("час")
        .or_else(|| s.strip_suffix('h'))
        .or_else(|| s.strip_suffix('ч'))
    {
        (n, 3600u64)
    } else {
        (s.as_str(), 1u64)
    };
    let val = num_str.trim().parse::<u64>().ok()?;
    if val == 0 {
        return None;
    }
    Some(val.saturating_mul(mult).clamp(5, 86_400))
}

fn format_interval_short(secs: u64, is_en: bool) -> String {
    if secs >= 3600 && secs.is_multiple_of(3600) {
        format!("{}{}", secs / 3600, if is_en { "h" } else { "ч" })
    } else if (secs >= 60 && secs.is_multiple_of(60)) || secs >= 3600 {
        format!("{}{}", secs / 60, if is_en { "m" } else { "м" })
    } else {
        format!("{secs}{}", if is_en { "s" } else { "с" })
    }
}

fn format_ping_age(ping_at: Option<u64>, now: u64, is_en: bool) -> Option<(String, u64)> {
    let ts = ping_at?;
    let age = now.saturating_sub(ts);
    let label = if age < 60 {
        if is_en { "now" } else { "только что" }.to_string()
    } else if age < 3600 {
        format!("{}{}", age / 60, if is_en { "m" } else { "м" })
    } else {
        format!("{}{}", age / 3600, if is_en { "h" } else { "ч" })
    };
    Some((label, age))
}

fn ping_badge_style(
    ping_ms: Option<i64>,
    ping_at: Option<u64>,
    now: u64,
    stale_thresh: u64,
    is_en: bool,
    compact: bool,
    t: Theme,
) -> (gpui::Rgba, gpui::Rgba, String) {
    let age_info = format_ping_age(ping_at, now, is_en);
    let stale = age_info
        .as_ref()
        .is_some_and(|(_, age)| *age > stale_thresh);
    match ping_ms {
        Some(ms) if ms > 0 => {
            let col = if stale { t.text_mute } else { t.green };
            let base = if compact {
                format!("{ms}{}", if is_en { "ms" } else { "мс" })
            } else {
                format!("{ms} {}", if is_en { "ms" } else { "мс" })
            };
            let txt = if let Some((age_s, _)) = age_info {
                format!("{base} · {age_s}")
            } else {
                base
            };
            (col, col, txt)
        }
        Some(_) => {
            let col = if stale { t.text_mute } else { t.red };
            let base = if compact {
                "×".to_string()
            } else if is_en {
                "Dead".to_string()
            } else {
                "Недоступен".to_string()
            };
            let txt = if let Some((age_s, _)) = age_info {
                format!("{base} · {age_s}")
            } else {
                base
            };
            (col, col, txt)
        }
        None => {
            let text_col = if compact { t.text_mute } else { t.text_soft };
            let txt = if compact {
                "—".to_string()
            } else if is_en {
                "Ping".to_string()
            } else {
                "Пинг".to_string()
            };
            (t.text_dim, text_col, txt)
        }
    }
}

pub fn parse_custom_rule_entries(selected_type: &str, raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let sel = selected_type.trim().to_ascii_lowercase();
    if sel == "domain_regex" || sel == "regex" {
        for line in raw.lines() {
            let pat = line.trim();
            if !pat.is_empty() && regex::Regex::new(pat).is_ok() {
                out.push(("domain_regex".to_string(), pat.to_string()));
            }
        }
        return out;
    }
    for part in raw.split([',', ';', '\n']) {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        if sel == "port" || sel == "port_range" {
            let norm = token.replace('-', ":");
            if let Some((a, b)) = norm.split_once(':') {
                if a.trim().parse::<u16>().is_ok() && b.trim().parse::<u16>().is_ok() {
                    out.push(("port".to_string(), format!("{}:{}", a.trim(), b.trim())));
                }
            } else if let Ok(p) = token.parse::<u16>()
                && p > 0
            {
                out.push(("port".to_string(), p.to_string()));
            }
            continue;
        }
        if sel == "cidr" || sel == "ip" {
            out.push(("cidr".to_string(), token.to_string()));
            continue;
        }
        if sel == "process" {
            let proc_name = std::path::Path::new(token)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.is_empty())
                .unwrap_or(token)
                .to_string();
            out.push(("process".to_string(), proc_name));
            continue;
        }

        if is_ip_or_cidr(token) {
            out.push(("cidr".to_string(), token.to_string()));
            continue;
        }
        if token.to_ascii_lowercase().starts_with("keyword:") {
            out.push(("domain".to_string(), token.to_string()));
            continue;
        }
        if token.to_ascii_lowercase().ends_with(".exe") {
            let proc_name = std::path::Path::new(token)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.is_empty())
                .unwrap_or(token)
                .to_string();
            out.push(("process".to_string(), proc_name));
            continue;
        }

        let cleaned = strip_url_to_host(token);
        if cleaned.is_empty() {
            continue;
        }
        if is_ip_or_cidr(&cleaned) {
            out.push(("cidr".to_string(), cleaned));
        } else if cleaned.ends_with(".exe") {
            out.push(("process".to_string(), cleaned));
        } else {
            out.push(("domain".to_string(), cleaned));
        }
    }
    out
}

fn styled_input(state: &Entity<InputState>, height: gpui::Pixels, font_px: f32, t: Theme) -> Input {
    let input = Input::new(state)
        .small()
        .cleanable(true)
        .text_size(px(font_px))
        .py(px(2.0))
        .bg(t.bg_elev)
        .border_color(t.border)
        .rounded(px(6.0));
    Styled::h(input, height)
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
    fn render_titlebar(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let app_ver = env!("CARGO_PKG_VERSION");
        let titlebar_drag =
            div()
                .id("titlebar-drag")
                .flex_1()
                .min_w(px(0.0))
                .overflow_hidden()
                .h_full()
                .pl(px(if m.narrow { 10.0 } else { 14.0 }))
                .pr(px(8.0))
                .flex()
                .items_center()
                .gap(px(if m.narrow { 8.0 } else { 10.0 }))
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
                        .min_w(px(0.0))
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
                        .when(!m.narrow, |el| {
                            el.child(div().text_size(px(10.0)).text_color(t.text_mute).child(
                                self.tr(
                                    "Маршрутизация и туннелирование",
                                    "Routing & Tunneling Engine",
                                ),
                            ))
                        }),
                );

        #[cfg(not(target_os = "windows"))]
        let titlebar_drag =
            titlebar_drag.on_mouse_down(MouseButton::Left, |ev: &MouseDownEvent, window, _| {
                if ev.click_count == 2 {
                    window.zoom_window();
                } else {
                    window.start_window_move();
                }
            });

        div()
            .h(px(40.0))
            .w_full()
            .bg(t.bg)
            .border_b_1()
            .border_color(t.border)
            .flex()
            .items_center()
            .justify_between()
            .child(titlebar_drag)
            .child(
                div()
                    .pr(px(if m.narrow { 8.0 } else { 14.0 }))
                    .h_full()
                    .flex_shrink_0()
                    .occlude()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        div()
                            .id("btn-lang-toggle")
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
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.state.language = if this.is_en() {
                                    "ru".to_string()
                                } else {
                                    "en".to_string()
                                };
                                this.state.save();
                                this.sync_input_placeholders(window, cx);
                                crate::tray::update_status(
                                    this.vpn_status == "connected",
                                    this.is_en(),
                                );
                                cx.notify();
                            }))
                            .child(if self.is_en() { "EN" } else { "RU" }),
                    )
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
                                crate::theme::sync_kit_theme(this.state.light_theme, cx);
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
                    .when(cfg!(target_os = "windows"), |el| {
                        el.child(
                            div()
                                .id("btn-win-tray")
                                .w(px(28.0))
                                .h(px(26.0))
                                .rounded(px(6.0))
                                .hover(|s| s.bg(t.bg_hover))
                                .cursor_pointer()
                                .flex()
                                .items_center()
                                .justify_center()
                                .on_click(|_, _, _| {
                                    let _ = crate::tray::hide_to_tray();
                                })
                                .child(
                                    svg()
                                        .path("icons/tray.svg")
                                        .size(px(12.0))
                                        .text_color(t.text_dim),
                                ),
                        )
                    })
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
                            .on_click(cx.listener(|this, _, window, _| {
                                if this.state.vpn_prefs.minimize_to_tray
                                    && crate::tray::hide_to_tray()
                                {
                                    return;
                                }
                                window.minimize_window();
                            }))
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
                                if !crate::tray::toggle_maximize_window() {
                                    window.zoom_window();
                                }
                            })
                            .child(
                                svg()
                                    .path(if m.is_maximized {
                                        "icons/restore.svg"
                                    } else {
                                        "icons/max.svg"
                                    })
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
                                if this.state.vpn_prefs.close_to_tray && crate::tray::hide_to_tray()
                                {
                                    return;
                                }
                                this.quit_app();
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

    fn render_navbar(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let rules_cnt = self.state.active_rules_count();
        let nodes_cnt = self.state.servers.len();

        let tabs: [(Tab, &'static str, &'static str, Option<usize>); 6] = [
            (
                Tab::Tunnel,
                "icons/power.svg",
                self.tr("Туннель", "Tunnel"),
                None,
            ),
            (Tab::Desync, "icons/bolt.svg", "Desync", None),
            (
                Tab::Routes,
                "icons/route.svg",
                self.tr("Маршруты", "Routes"),
                Some(rules_cnt),
            ),
            (
                Tab::Nodes,
                "icons/server.svg",
                self.tr("Узлы", "Nodes"),
                Some(nodes_cnt),
            ),
            (
                Tab::Traffic,
                "icons/activity.svg",
                self.tr("Трафик", "Traffic"),
                None,
            ),
            (
                Tab::Options,
                "icons/sliders.svg",
                self.tr("Опции", "Settings"),
                None,
            ),
        ];

        div()
            .w_full()
            .px(px(if m.narrow { 10.0 } else { 16.0 }))
            .pt(px(8.0))
            .pb(px(6.0))
            .flex()
            .items_center()
            .when(m.width >= 920.0, |el| {
                el.child(
                    div()
                        .flex_1()
                        .h(px(36.0))
                        .window_control_area(WindowControlArea::Drag),
                )
            })
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
                    .flex_wrap()
                    .items_center()
                    .gap(px(4.0))
                    .children(tabs.into_iter().map(|(tab_id, icon, label, badge)| {
                        let active = self.tab == tab_id;
                        div()
                            .id(SharedString::from(format!("nav-{label}")))
                            .flex_1()
                            .min_w(px(if m.narrow { 92.0 } else { 108.0 }))
                            .h(px(if m.narrow { 30.0 } else { 32.0 }))
                            .px(px(if m.narrow { 6.0 } else { 8.0 }))
                            .rounded(px(8.0))
                            .cursor_pointer()
                            .bg(if active {
                                t.bg_elev
                            } else {
                                gpui::rgba(0x00000000)
                            })
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
                            .gap(px(if m.narrow { 4.0 } else { 6.0 }))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.tab = tab_id;
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
                                    .whitespace_nowrap()
                                    .text_size(px(if m.narrow { 11.5 } else { 12.0 }))
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
            .when(m.width >= 920.0, |el| {
                el.child(
                    div()
                        .flex_1()
                        .h(px(36.0))
                        .window_control_area(WindowControlArea::Drag),
                )
            })
    }

    fn render_footer(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let core_ver = option_env!("TACHYON_CORE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
        let dns_label = if self.state.vpn_prefs.dns == "custom"
            && !self.state.vpn_prefs.custom_dns.is_empty()
        {
            self.state.vpn_prefs.custom_dns.as_str()
        } else {
            self.state.vpn_prefs.dns.as_str()
        };

        div()
            .min_h(px(30.0))
            .w_full()
            .px(px(if m.narrow { 10.0 } else { 16.0 }))
            .py(px(4.0))
            .bg(t.bg)
            .border_t_1()
            .border_color(t.border)
            .flex()
            .flex_wrap()
            .items_center()
            .justify_between()
            .gap(px(6.0))
            .text_size(px(11.0))
            .text_color(t.text_dim)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .min_w(px(0.0))
                    .child(div().w(px(6.0)).h(px(6.0)).rounded(px(3.0)).bg(
                        if self.vpn_status == "connected" {
                            t.green
                        } else {
                            t.text_mute
                        },
                    ))
                    .child(if m.narrow {
                        format!("core {core_ver}")
                    } else if self.is_en() {
                        format!("Core tachyon-core {core_ver}  ·  DNS: {dns_label}")
                    } else {
                        format!("Ядро tachyon-core {core_ver}  ·  DNS: {dns_label}")
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(10.0))
                    .min_w(px(0.0))
                    .when(!m.narrow, |el| {
                        el.child(if self.is_en() {
                            format!(
                                "Nodes: {}  ·  Rules: {}",
                                self.state.servers.len(),
                                self.state.active_rules_count()
                            )
                        } else {
                            format!(
                                "Узлов: {}  ·  Правил: {}",
                                self.state.servers.len(),
                                self.state.active_rules_count()
                            )
                        })
                    })
                    .child(
                        div()
                            .id("btn-open-log-modal")
                            .cursor_pointer()
                            .text_color(t.accent)
                            .hover(|s| s.underline())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.log_tail =
                                    this.vpn.get_log_tail_filtered(200, &this.log_filter_level);
                                this.modal = ModalKind::KernelLog;
                                cx.notify();
                            }))
                            .child(self.tr("Лог ядра", "Core Log")),
                    ),
            )
    }

    fn render_tunnel_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_connected = self.vpn_status == "connected";
        let is_connecting = self.vpn_status == "connecting";
        let active_srv = self.state.active_server().cloned();
        let stack_tunnel = m.compact || m.short;
        let left_w = if m.width < 1100.0 { 300.0 } else { 360.0 };
        let right_w = if stack_tunnel {
            m.avail_w
        } else {
            (m.avail_w - left_w - 14.0).max(320.0)
        };
        let grid_w = (right_w - 36.0).max(200.0);
        let srv_card_w = adaptive_card_width(grid_w, 200.0, 5, 6.0);
        let stack_telemetry = right_w < 540.0;

        let status_label = if is_connected {
            self.tr("Защищено", "Protected")
        } else if is_connecting {
            self.tr("Подключение...", "Connecting...")
        } else {
            self.tr("Отключено", "Disconnected")
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
                let ctitle = self.country_title(&srv.country).to_lowercase();
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

        let hero_card =
                // Left Hero Orb Card
                div()
                    .when(stack_tunnel, |el| el.w_full().flex_none())
                    .when(!stack_tunnel, |el| el.w(px(left_w)).h_full())
                    .p(px(if m.narrow { 14.0 } else { 18.0 }))
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
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
                                                            "↓ {} {}",
                                                            format_mb_per_sec(self.rx_bps),
                                                            self.tr("МБ/с", "MB/s")
                                                        )
                                                    } else {
                                                        self.tr("ВКЛЮЧИТЬ", "CONNECT").to_string()
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
                                        self.tr(
                                            "Активно · Нажмите для отключения",
                                            "Active · Click to disconnect",
                                        )
                                        .to_string()
                                    } else if !self.last_error.is_empty() {
                                        truncate_str(&self.last_error, 46)
                                    } else {
                                        self.tr("Готов к запуску туннеля", "Ready to connect")
                                            .to_string()
                                    }),
                            )
                            .when_some(self.live_balancer.as_ref().filter(|_| is_connected), |el, lb| {
                                let mode = lb
                                    .get("mode")
                                    .and_then(Value::as_str)
                                    .unwrap_or("stability");
                                let cur_owned = lb
                                    .get("now")
                                    .or_else(|| lb.get("selected"))
                                    .and_then(Value::as_str)
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(self.tr("автовыбор", "auto"))
                                    .to_string();
                                let members_all: Vec<String> = lb
                                    .get("all")
                                    .and_then(Value::as_array)
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(Value::as_str)
                                            .map(str::to_string)
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                el.child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_col()
                                        .items_center()
                                        .gap(px(5.0))
                                        .child(
                                            div()
                                                .px(px(8.0))
                                                .py(px(3.0))
                                                .rounded(px(6.0))
                                                .bg(t.accent_bg)
                                                .border_1()
                                                .border_color(t.accent_border)
                                                .text_size(px(10.0))
                                                .text_color(t.accent)
                                                .child(if self.is_en() {
                                                    format!("Balancer ({mode}) · Node: {cur_owned}")
                                                } else {
                                                    format!(
                                                        "Балансировщик ({mode}) · Узел: {cur_owned}"
                                                    )
                                                }),
                                        )
                                        .when(members_all.len() >= 2, |mel| {
                                            mel.child(
                                                div()
                                                    .w_full()
                                                    .flex()
                                                    .flex_wrap()
                                                    .justify_center()
                                                    .gap(px(4.0))
                                                    .children(members_all.into_iter().take(8).map(
                                                        |mem| {
                                                            let is_now = mem == cur_owned;
                                                            let mem_click = mem.clone();
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "bal-mem-{mem}"
                                                                )))
                                                                .px(px(6.0))
                                                                .py(px(2.0))
                                                                .rounded(px(5.0))
                                                                .cursor_pointer()
                                                                .bg(if is_now {
                                                                    t.accent_bg
                                                                } else {
                                                                    t.bg_elev
                                                                })
                                                                .border_1()
                                                                .border_color(if is_now {
                                                                    t.accent_border
                                                                } else {
                                                                    t.border
                                                                })
                                                                .text_size(px(9.5))
                                                                .text_color(if is_now {
                                                                    t.accent
                                                                } else {
                                                                    t.text_dim
                                                                })
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        let v = this.vpn.clone();
                                                                        let eq =
                                                                            this.event_queue.clone();
                                                                        let tgt = mem_click.clone();
                                                                        let en = this.is_en();
                                                                        this.rt.spawn(async move {
                                                                            let ok = v
                                                                                .select_balancer_member(
                                                                                    &tgt,
                                                                                )
                                                                                .await;
                                                                            if ok {
                                                                                let payload = v
                                                                                    .check_exit_node_info(
                                                                                    )
                                                                                    .await;
                                                                                if let Ok(mut g) =
                                                                                    eq.lock()
                                                                                {
                                                                                    g.push(format!(
                                                                                        "exit:geo:{payload}"
                                                                                    ));
                                                                                }
                                                                            } else if let Ok(mut g) =
                                                                                eq.lock()
                                                                            {
                                                                                g.push(format!(
                                                                                    "error:{}",
                                                                                    if en {
                                                                                        "Failed to switch balancer node"
                                                                                    } else {
                                                                                        "Не удалось переключить узел балансировщика"
                                                                                    }
                                                                                ));
                                                                            }
                                                                        });
                                                                        this.show_toast(if this.is_en() {
                                                                            format!("Switching to {mem_click}")
                                                                        } else {
                                                                            format!("Переключение на {mem_click}")
                                                                        });
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                                .child(truncate_str(&mem, 14))
                                                        },
                                                    )),
                                            )
                                        }),
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
                                    .min_w(px(0.0))
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
                                    .gap(px(6.0))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.tab = Tab::Nodes;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
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
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .flex()
                                                    .flex_col()
                                                    .child(
                                                        div()
                                                            .w_full()
                                                            .truncate()
                                                            .text_size(px(12.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(t.text)
                                                            .child(
                                                                active_srv
                                                                    .as_ref()
                                                                    .map(|s| s.name.clone())
                                                                    .unwrap_or_else(|| {
                                                                        self.tr(
                                                                            "Прямой Desync (без узла)",
                                                                            "Direct Desync (no proxy)",
                                                                        )
                                                                        .to_string()
                                                                    }),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .w_full()
                                                            .truncate()
                                                            .text_size(px(10.0))
                                                            .text_color(t.text_dim)
                                                            .child(
                                                                active_srv
                                                                    .as_ref()
                                                                    .map(|s| {
                                                                        format!(
                                                                            "{} · {}",
                                                                            self.country_title(
                                                                                &s.country
                                                                            ),
                                                                            detect_protocol_badge(
                                                                                &s.vless
                                                                            )
                                                                        )
                                                                    })
                                                                    .unwrap_or_else(|| {
                                                                        if self.is_en() {
                                                                            format!(
                                                                                "Preset: {} · Click to add nodes",
                                                                                self.state.desync_prefs.preset
                                                                            )
                                                                        } else {
                                                                            format!(
                                                                                "Пресет: {} · Нажмите для добавления узлов",
                                                                                self.state.desync_prefs.preset
                                                                            )
                                                                        }
                                                                    }),
                                                            ),
                                                    ),
                                            ),
                                    )
                                    .when_some(
                                        // Когда подключены — показываем RTT через туннель,
                                        // когда нет — прямой пинг узла
                                        self.live_rtt_ms
                                            .map(|ms| (true, ms))
                                            .or_else(|| {
                                                active_srv
                                                    .as_ref()
                                                    .and_then(|s| s.ping_ms)
                                                    .map(|ms| (false, ms))
                                            }),
                                        |el, (via_tunnel, ms)| {
                                            el.child(
                                                div()
                                                    .flex_shrink_0()
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
                                                        let prefix = if via_tunnel {
                                                            self.tr("Туннель", "Tunnel")
                                                        } else {
                                                            self.tr("До сервера", "Direct")
                                                        };
                                                        format!(
                                                            "{prefix}: {ms} {}",
                                                            self.tr("мс", "ms")
                                                        )
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
                                    .flex_shrink_0()
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
                    );

        let right_col =
                // Right column: Telemetry + Mode + Quick toggles + Server list
                div()
                    .min_w(px(0.0))
                    .when(!stack_tunnel, |el| el.flex_1().h_full())
                    .when(stack_tunnel, |el| el.w_full().flex_none())
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .child(
                        // Top 2 telemetry cards
                        div()
                            .w_full()
                            .flex()
                            .flex_shrink_0()
                            .when(stack_telemetry, |el| el.flex_col())
                            .gap(px(10.0))
                            .child(
                                // Exit Node Card
                                div()
                                    .when(!stack_telemetry, |el| el.flex_1())
                                    .when(stack_telemetry, |el| el.w_full().flex_none())
                                    .min_w(px(0.0))
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
                                            .flex_wrap()
                                            .items_center()
                                            .justify_between()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_dim)
                                                    .child(self.tr("• Выходной узел", "• Exit Node")),
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
                                                            .child(self.tr("Проверить", "Check")),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(16.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(if self.exit_info.loading {
                                                self.tr("Проверка...", "Checking...").to_string()
                                            } else if self.exit_info.ok {
                                                self.exit_info.ip.clone()
                                            } else {
                                                self.tr("Нет ответа", "No response").to_string()
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(if self.exit_info.ok {
                                                format!(
                                                    "{} {} · {} ({} {})",
                                                    self.exit_info.country,
                                                    self.exit_info.city,
                                                    self.exit_info.isp,
                                                    self.exit_info.latency_ms,
                                                    self.tr("мс", "ms")
                                                )
                                            } else if !self.exit_info.error.is_empty() {
                                                self.exit_info.error.clone()
                                            } else {
                                                self.tr(
                                                    "Проверьте подключение",
                                                    "Verify connection",
                                                )
                                                .to_string()
                                            }),
                                    ),
                            )
                            .child(
                                // Speed Card
                                div()
                                    .when(!stack_telemetry, |el| el.flex_1())
                                    .when(stack_telemetry, |el| el.w_full().flex_none())
                                    .min_w(px(0.0))
                                    .p(px(12.0))
                                    .rounded(px(12.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .flex_wrap()
                                    .justify_between()
                                    .gap(px(10.0))
                                    .child(
                                        div()
                                            .min_w(px(95.0))
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.accent)
                                                    .child(self.tr("• Приём", "• Download")),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(17.0))
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(t.text)
                                                    .child(format!(
                                                        "{} {}",
                                                        format_mb_per_sec(self.rx_bps),
                                                        self.tr("МБ/с", "MB/s")
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child(format!(
                                                        "{}: {}",
                                                        self.tr("Всего", "Total"),
                                                        format_bytes_human(self.rx_total)
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .min_w(px(95.0))
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(t.green)
                                                    .child(self.tr("• Отдача", "• Upload")),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(17.0))
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(t.text)
                                                    .child(format!(
                                                        "{} {}",
                                                        format_mb_per_sec(self.tx_bps),
                                                        self.tr("МБ/с", "MB/s")
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child(format!(
                                                        "{}: {}",
                                                        self.tr("Всего", "Total"),
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
                            .flex_shrink_0()
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
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child(self.tr("Режим маршрутизации", "Routing Mode")),
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
                                            .child(self.tr("Списки и Desync ↗", "Lists & Desync ↗")),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .p(px(3.0))
                                    .rounded(px(8.0))
                                    .bg(t.bg_elev)
                                    .flex()
                                    .flex_wrap()
                                    .gap(px(3.0))
                                    .children(
                                        [
                                            ("all", self.tr("Весь ПК", "Full PC")),
                                            ("selective", self.tr("Точечно", "Selective")),
                                            ("desync", self.tr("Только Desync", "Desync Only")),
                                            ("apps", self.tr("Приложения", "Apps")),
                                        ]
                                        .into_iter()
                                        .map(|(code, title)| {
                                            let active = self.state.vpn_prefs.route == code;
                                            div()
                                                .id(SharedString::from(format!("route-seg-{code}")))
                                                .flex_1()
                                                .min_w(px(88.0))
                                                .h(px(26.0))
                                                .px(px(6.0))
                                                .whitespace_nowrap()
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
                            .flex_shrink_0()
                            .flex_wrap()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .id("card-quick-desync")
                                    .flex_1()
                                    .min_w(px(150.0))
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
                                            .flex_shrink_0()
                                            .text_color(if self.state.desync_prefs.enabled {
                                                t.amber
                                            } else {
                                                t.text_dim
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child(self.tr("Пакетный Desync", "Packet Desync")),
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
                                                        self.tr("Активен · Adaptive", "Active · Adaptive")
                                                    } else {
                                                        self.tr("Выключен", "Disabled")
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("card-quick-stack")
                                    .flex_1()
                                    .min_w(px(150.0))
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
                                            .flex_shrink_0()
                                            .text_color(t.accent),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child(self.tr("Сетевой стек", "Network Stack")),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.accent)
                                                    .child(if self.state.vpn_prefs.mode == "tun" {
                                                        "TUN · Wintun"
                                                    } else {
                                                        self.tr("Системный прокси", "System Proxy")
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("card-quick-ks")
                                    .flex_1()
                                    .min_w(px(150.0))
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
                                            .flex_shrink_0()
                                            .text_color(if self.state.vpn_prefs.kill_switch {
                                                t.red
                                            } else {
                                                t.text_dim
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
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
                                                        self.tr("Активен", "Active")
                                                    } else {
                                                        self.tr("Выключен", "Disabled")
                                                    }),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        // Servers & Locations Card
                        div()
                            .when(!stack_tunnel, |el| el.flex_1().min_h(px(200.0)))
                            .when(stack_tunnel, |el| el.h(px(340.0)).flex_none())
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
                                    .flex_wrap()
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
                                                    .child(self.tr(
                                                        "• Серверы и локации",
                                                        "• Servers & Locations",
                                                    )),
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
                                            .flex_wrap()
                                            .items_center()
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .id("input-srv-search")
                                                    .flex_1()
                                                    .min_w(px(120.0))
                                                    .max_w(px(200.0))
                                                    .h(px(26.0))
                                                    .child(
                                                        styled_input(
                                                            &self.server_search_input,
                                                            px(26.0),
                                                            11.0,
                                                            t,
                                                        )
                                                        .prefix(
                                                            svg()
                                                                .path("icons/search.svg")
                                                                .size(px(11.0))
                                                                .text_color(t.text_dim),
                                                        ),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-tunnel-import-conf")
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
                                                        this.import_conf_file_dialog();
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/folder.svg")
                                                            .size(px(11.0))
                                                            .text_color(t.accent),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(11.0))
                                                            .text_color(t.text_soft)
                                                            .child("+ .conf"),
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
                                                            .child(self.tr("Пинг", "Ping")),
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
                                                            .child(self.tr(
                                                                "Подписки",
                                                                "Subscriptions",
                                                            )),
                                                    ),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("tunnel-servers-scroll")
                                    .flex_1()
                                    .min_h(px(0.0))
                                    .w_full()
                                    .overflow_y_scroll()
                                    .child(
                                        div()
                                            .w_full()
                                            .flex()
                                            .flex_col()
                                            .gap(px(6.0))
                                            .children(by_country.into_iter().map(|(cc, list)| {
                                        let collapsed = self.collapsed_countries.contains(&cc);
                                        let cc_toggle = cc.clone();
                                        let cc_ping = cc.clone();
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
                                                    .min_w(px(0.0))
                                                    .h(px(30.0))
                                                    .px(px(10.0))
                                                    .rounded(px(8.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .flex()
                                                    .items_center()
                                                    .justify_between()
                                                    .gap(px(6.0))
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
                                                            .flex_1()
                                                            .min_w(px(0.0))
                                                            .flex()
                                                            .items_center()
                                                            .gap(px(8.0))
                                                            .child(render_flag_badge(&cc, 18.0, t))
                                                            .child(
                                                                div()
                                                                    .truncate()
                                                                    .text_size(px(11.5))
                                                                    .font_weight(
                                                                        FontWeight::SEMIBOLD,
                                                                    )
                                                                    .text_color(t.text)
                                                                    .child(self.country_title(&cc)),
                                                            )
                                                            .child(
                                                                div()
                                                                    .flex_shrink_0()
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
                                                            .flex_shrink_0()
                                                            .flex()
                                                            .items_center()
                                                            .gap(px(6.0))
                                                            .child(
                                                                div()
                                                                    .id(SharedString::from(format!(
                                                                        "country-ping-btn-{cc}"
                                                                    )))
                                                                    .px(px(6.0))
                                                                    .py(px(2.0))
                                                                    .rounded(px(4.0))
                                                                    .bg(t.bg_card)
                                                                    .hover(|s| s.bg(t.bg_hover))
                                                                    .flex()
                                                                    .items_center()
                                                                    .gap(px(4.0))
                                                                    .on_click(cx.listener(
                                                                        move |this, _, _, cx| {
                                                                            this.ping_country_nodes(
                                                                                cc_ping.clone(),
                                                                            );
                                                                            cx.notify();
                                                                        },
                                                                    ))
                                                                    .child(
                                                                        svg()
                                                                            .path("icons/bolt.svg")
                                                                            .size(px(9.5))
                                                                            .text_color(
                                                                                if best_ms.is_some()
                                                                                {
                                                                                    t.green
                                                                                } else {
                                                                                    t.text_dim
                                                                                },
                                                                            ),
                                                                    )
                                                                    .child(
                                                                        div()
                                                                            .text_size(px(10.0))
                                                                            .text_color(
                                                                                if best_ms.is_some()
                                                                                {
                                                                                    t.green
                                                                                } else {
                                                                                    t.text_dim
                                                                                },
                                                                            )
                                                                            .child(
                                                                                if let Some(ms) =
                                                                                    best_ms
                                                                                {
                                                                                    if self.is_en()
                                                                                    {
                                                                                        format!(
                                                                                            "{ms} ms"
                                                                                        )
                                                                                    } else {
                                                                                        format!(
                                                                                            "{ms} мс"
                                                                                        )
                                                                                    }
                                                                                } else {
                                                                                    self.tr(
                                                                                        "Пинг",
                                                                                        "Ping",
                                                                                    )
                                                                                    .to_string()
                                                                                },
                                                                            ),
                                                                    ),
                                                            )
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
                                                            let sid_ping = srv.id.clone();
                                                            let proto =
                                                                detect_protocol_badge(&srv.vless);
                                                            let stale_thresh =
                                                                (self.state.auto_ping.interval_s * 2)
                                                                    .max(300);
                                                            let (ping_icon_col, ping_text_col, ping_label) =
                                                                ping_badge_style(
                                                                    srv.ping_ms,
                                                                    srv.ping_at,
                                                                    now_unix_secs(),
                                                                    stale_thresh,
                                                                    self.is_en(),
                                                                    true,
                                                                    t,
                                                                );
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "srv-chip-{}",
                                                                    srv.id
                                                                )))
                                                                .w(px(srv_card_w))
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
                                                                .flex()
                                                                .items_center()
                                                                .justify_between()
                                                                .gap(px(4.0))
                                                                .child(
                                                                    div()
                                                                        .id(SharedString::from(
                                                                            format!(
                                                                                "srv-sel-{}",
                                                                                srv.id
                                                                            ),
                                                                        ))
                                                                        .flex_1()
                                                                        .min_w(px(0.0))
                                                                        .cursor_pointer()
                                                                        .flex()
                                                                        .items_center()
                                                                        .gap(px(7.0))
                                                                        .on_click(cx.listener(
                                                                            move |this, _, _, cx| {
                                                                                this.state
                                                                                    .active_id =
                                                                                    sid.clone();
                                                                                this.reconnect_if_active();
                                                                                cx.notify();
                                                                            },
                                                                        ))
                                                                        .child(render_flag_badge(
                                                                            &srv.country,
                                                                            18.0,
                                                                            t,
                                                                        ))
                                                                        .child(
                                                                            div()
                                                                                .flex_1()
                                                                                .min_w(px(0.0))
                                                                                .truncate()
                                                                                .text_size(px(11.0))
                                                                                .font_weight(
                                                                                    FontWeight::MEDIUM,
                                                                                )
                                                                                .text_color(t.text)
                                                                                .child(
                                                                                    srv.name.clone(),
                                                                                ),
                                                                        ),
                                                                )
                                                                .child(
                                                                    div()
                                                                        .flex_shrink_0()
                                                                        .flex()
                                                                        .items_center()
                                                                        .gap(px(4.0))
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
                                                                        .child(
                                                                            div()
                                                                                .id(SharedString::from(
                                                                                    format!(
                                                                                        "srv-ping-{}",
                                                                                        srv.id
                                                                                    ),
                                                                                ))
                                                                                .px(px(4.0))
                                                                                .py(px(1.0))
                                                                                .rounded(px(4.0))
                                                                                .bg(t.bg_card)
                                                                                .cursor_pointer()
                                                                                .hover(|s| {
                                                                                    s.bg(t.bg_hover)
                                                                                })
                                                                                .flex()
                                                                                .items_center()
                                                                                .gap(px(3.0))
                                                                                .on_click(cx.listener(
                                                                                    move |this, _, _, cx| {
                                                                                        this.ping_single_node(
                                                                                            sid_ping.clone(),
                                                                                        );
                                                                                        cx.notify();
                                                                                    },
                                                                                ))
                                                                                .child(
                                                                                    svg()
                                                                                        .path("icons/bolt.svg")
                                                                                        .size(px(9.0))
                                                                                        .text_color(
                                                                                            ping_icon_col,
                                                                                        ),
                                                                                )
                                                                                .child(
                                                                                    div()
                                                                                        .text_size(
                                                                                            px(9.5),
                                                                                        )
                                                                                        .text_color(
                                                                                            ping_text_col,
                                                                                        )
                                                                                        .child(
                                                                                            ping_label,
                                                                                        ),
                                                                                ),
                                                                        ),
                                                                )
                                                        })),
                                                )
                                            })
                                    })),
                                    ),
                            ),
                    );

        if stack_tunnel {
            div()
                .id("tunnel-scroll")
                .size_full()
                .overflow_y_scroll()
                .child(
                    div()
                        .w_full()
                        .px(px(if m.narrow { 10.0 } else { 16.0 }))
                        .py(px(8.0))
                        .flex()
                        .flex_col()
                        .gap(px(10.0))
                        .child(hero_card)
                        .child(right_col),
                )
                .into_any_element()
        } else {
            div()
                .id("tunnel-scroll")
                .size_full()
                .px(px(if m.narrow { 10.0 } else { 16.0 }))
                .py(px(8.0))
                .flex()
                .flex_row()
                .gap(px(14.0))
                .child(hero_card)
                .child(right_col)
                .into_any_element()
        }
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
    fn render_desync_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let d = &self.state.desync_prefs;
        let preset_w = adaptive_card_width(m.avail_w - 8.0, 175.0, 5, 8.0);

        div()
            .id("desync-scroll")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .w_full()
                    .px(px(if m.narrow { 10.0 } else { 16.0 }))
                    .py(px(8.0))
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(200.0))
                                    .flex()
                                    .items_center()
                                    .gap(px(12.0))
                                    .child(
                                        div()
                                            .w(px(36.0))
                                            .h(px(36.0))
                                            .flex_shrink_0()
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
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .flex()
                                            .flex_col()
                                    .child(
                                        div()
                                            .w_full()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Пакетная десинхронизация (Desync)",
                                                "Packet Desynchronization (Desync)",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .w_full()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(self.tr(
                                                "Фрагментация TLS ClientHello, OOB-маркеры и инъекция QUIC Initial для прямого соединения (работает без VPN-подписок)",
                                                "TLS ClientHello fragmentation, OOB markers and QUIC Initial injection for direct connectivity (works without VPN subscriptions)",
                                            )),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .id("btn-desync-reset-cache")
                                    .px(px(12.0))
                                    .py(px(6.0))
                                    .rounded(px(8.0))
                                    .cursor_pointer()
                                    .bg(t.bg_elev)
                                    .border_1()
                                    .border_color(t.border)
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_soft)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        core_runtime::outbound::desync::reset_adaptive_state();
                                        this.show_toast(this.tr(
                                            "Кэш адаптивного подбора очищен",
                                            "Adaptive optimization cache cleared",
                                        ));
                                        this.reconnect_if_active();
                                        cx.notify();
                                    }))
                                    .child(self.tr("Сбросить кэш", "Reset Cache")),
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
                                    .child(if d.enabled {
                                        self.tr("Активен", "Active")
                                    } else {
                                        self.tr("Включить", "Enable")
                                    }),
                            ),
                    ),
            )
            .child(
                // Presets row (synced with vpn.rs::DesyncOptions::parse)
                div()
                    .w_full()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.0))
                    .children(
                        [
                            (
                                "auto",
                                self.tr("Авто (Adaptive)", "Auto (Adaptive)"),
                                self.tr(
                                    "Multi-Disorder + QUIC Fake 6x + Автоподбор",
                                    "Multi-Disorder + QUIC Fake 6x + Auto-tune",
                                ),
                            ),
                            (
                                "youtube_discord",
                                "YouTube + Discord",
                                self.tr(
                                    "Multi-Disorder + TLSRec + QUIC 8x",
                                    "Multi-Disorder + TLSRec + QUIC 8x",
                                ),
                            ),
                            (
                                "multi_disorder",
                                "Multi-Disorder",
                                self.tr(
                                    "Каскадная нарезка SNI с обратным порядком",
                                    "Cascading SNI slicing with reverse order",
                                ),
                            ),
                            (
                                "fake_split",
                                "Fake + Split",
                                self.tr(
                                    "Мягкое разбиение TLS без инверсии сегментов",
                                    "Soft TLS splitting without segment inversion",
                                ),
                            ),
                            (
                                "tlsrec",
                                self.tr("Чистый TLS Record", "Pure TLS Record"),
                                self.tr(
                                    "Нарезка записи TLS без фейковых пакетов",
                                    "TLS record slicing without fake packets",
                                ),
                            ),
                        ]
                        .into_iter()
                        .map(|(pid, title, desc)| {
                            let active = d.preset == pid || (pid == "auto" && d.preset == "adaptive");
                            div()
                                .id(SharedString::from(format!("desync-preset-{pid}")))
                                .w(px(preset_w))
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
                                        .w_full()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(if active { t.accent } else { t.text })
                                        .child(title),
                                )
                                .child(
                                    div()
                                        .w_full()
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
                        // Mode + Repeats + Delay row
                        div()
                            .w_full()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .min_w(px(0.0))
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child(self.tr("Режим:", "Mode:")),
                                    )
                                    .children(
                                        [
                                            ("multidisorder", "MultiDisorder"),
                                            ("multisplit", "MultiSplit"),
                                            ("fake_disorder", "Fake+Disorder"),
                                            ("fake_split", "Fake+Split"),
                                            ("disorder", "Disorder"),
                                            ("split", "Split"),
                                            ("tlsrec", "TLSRec"),
                                            ("oob", "OOB"),
                                            ("disoob", "DisOOB"),
                                        ]
                                        .into_iter()
                                        .map(|(mc, ml)| {
                                            let act = d.mode == mc;
                                            div()
                                                .id(SharedString::from(format!("ds-mode-{mc}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.desync_prefs.mode = mc.to_string();
                                                    this.state.desync_prefs.preset = "custom".to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(ml)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .min_w(px(0.0))
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child(self.tr("Повторы:", "Repeats:")),
                                    )
                                    .children([2u32, 4, 6, 8, 12].into_iter().map(|rep| {
                                        let act = d.repeats == rep;
                                        div()
                                            .id(SharedString::from(format!("ds-rep-{rep}")))
                                            .px(px(6.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .cursor_pointer()
                                            .bg(if act { t.amber_bg } else { t.bg_elev })
                                            .text_size(px(10.0))
                                            .text_color(if act { t.amber } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.desync_prefs.repeats = rep;
                                                this.state.desync_prefs.preset = "custom".to_string();
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(format!("{rep}x"))
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child("Fooling:"),
                                    )
                                    .children(
                                        [
                                            ("md5sig+badsum", "MD5Sig+BadSum"),
                                            ("md5sig", "MD5Sig"),
                                            ("badsum", "BadSum"),
                                            ("badseq", "BadSeq"),
                                            ("ts", "TCP TS"),
                                            ("ttl", "AutoTTL"),
                                            ("datanoack", "DataNoAck"),
                                            ("hopbyhop", "HopByHop"),
                                            ("fad", "FAD"),
                                        ]
                                        .into_iter()
                                        .map(|(fc, fl)| {
                                            let act = d.fooling == fc;
                                            div()
                                                .id(SharedString::from(format!("ds-fool-{fc}")))
                                                .px(px(7.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
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
                                    .min_w(px(0.0))
                                    .flex()
                                    .flex_wrap()
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child(self.tr("Точки разреза SNI:", "SNI Split Pos:")),
                                    )
                                    .children(
                                        [
                                            (
                                                "1,sniext+1,host+1,midsld",
                                                self.tr("Каскад (4 точки)", "Cascade (4 pts)"),
                                            ),
                                            ("1,sniext+1,midsld", "SNI + MidSLD"),
                                            ("sniext+1", self.tr("Начало SNI", "SNI Start")),
                                            ("midsld", self.tr("Середина домена", "Mid Domain")),
                                        ]
                                        .into_iter()
                                        .map(|(sp, sl)| {
                                            let act = d.split_pos == sp;
                                            div()
                                                .id(SharedString::from(format!("ds-sp-{sp}")))
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
                                    .flex_wrap()
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
                                                .on_click(cx.listener(move |this, _, window, cx| {
                                                    this.state.desync_prefs.fake_sni = sni.to_string();
                                                    this.fake_sni_input_state.update(cx, |st, cx| {
                                                        st.set_value(sni, window, cx);
                                                    });
                                                    this.state.save();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(sni)
                                        }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(t.text_dim)
                                    .child(self.tr("Пул SNI (через запятую):", "SNI Pool (comma-sep):")),
                            )
                            .child(
                                div()
                                    .id("input-fake-sni-pool")
                                    .flex_1()
                                    .min_w(px(180.0))
                                    .h(px(28.0))
                                    .child(styled_input(&self.fake_sni_input_state, px(28.0), 11.0, t)),
                            ),
                    ),
            )
            .child(
                // Fine parameters grid
                div()
                    .w_full()
                    .flex()
                    .when(m.compact, |el| el.flex_col())
                    .gap(px(12.0))
                    .child(
                        // TCP / TLS column
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                                    .child(self.tr("Параметры TCP и TLS", "TCP & TLS Parameters")),
                            )
                            .child(self.render_toggle_row(
                                "toggle-tlsrec-first",
                                self.tr(
                                    "Дробление записи TLS (TLSRec First)",
                                    "TLS Record Slicing (TLSRec First)",
                                ),
                                self.tr(
                                    "Разбиение TLS Record до отправки TCP-сегментов",
                                    "Split TLS Record before sending TCP segments",
                                ),
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
                                self.tr(
                                    "Фрагментация записей TLS на прокси",
                                    "Proxy TLS Record Fragmentation",
                                ),
                                self.tr(
                                    "Разбиение TLS ClientHello для прокси-узлов",
                                    "Fragment TLS ClientHello on proxy outbounds",
                                ),
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
                                self.tr(
                                    "Прямой Desync для YouTube и Discord",
                                    "Direct Desync for YouTube & Discord",
                                ),
                                self.tr(
                                    "Отправлять YouTube и Discord напрямую через Desync мимо VPN",
                                    "Route YouTube and Discord directly via Desync bypassing VPN",
                                ),
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
                                self.tr(
                                    "Адаптивный автоподбор при RST/Timeout",
                                    "Adaptive Auto-Tune on RST/Timeout",
                                ),
                                self.tr(
                                    "Автоматическая ротация стратегии для проблемных доменов",
                                    "Automatic strategy rotation for degraded domains",
                                ),
                                d.auto_tune,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.auto_tune =
                                        !this.state.desync_prefs.auto_tune;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-seqovl-syndata",
                                self.tr(
                                    "Перекрытие TCP Seq (SeqOvl) и SynData",
                                    "TCP Seq Overlap (SeqOvl) & SynData",
                                ),
                                self.tr(
                                    "Смещение последовательности TCP-сегментов на уровне ядра",
                                    "Kernel-level TCP sequence overlap and SYN payload",
                                ),
                                d.seqovl > 0 || d.syndata,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    let next = !(this.state.desync_prefs.seqovl > 0
                                        || this.state.desync_prefs.syndata);
                                    this.state.desync_prefs.seqovl = if next { 1 } else { 0 };
                                    this.state.desync_prefs.syndata = next;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-wsize-wscale",
                                self.tr(
                                    "Сжатие TCP-окна (wsize=1, scale=1)",
                                    "TCP Window Clamping (wsize=1, scale=1)",
                                ),
                                self.tr(
                                    "Предконнектное уменьшение окна приёма на этапе SYN для принудительной фрагментации ServerHello",
                                    "Pre-connect SYN receive window clamping to force ServerHello fragmentation",
                                ),
                                d.wsize > 0 || d.wscale.is_some(),
                                t,
                                cx.listener(|this, _, _, cx| {
                                    let next = !(this.state.desync_prefs.wsize > 0
                                        || this.state.desync_prefs.wscale.is_some());
                                    if next {
                                        this.state.desync_prefs.wsize = 1;
                                        this.state.desync_prefs.wscale = Some(1);
                                    } else {
                                        this.state.desync_prefs.wsize = 0;
                                        this.state.desync_prefs.wscale = None;
                                    }
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-host-fake",
                                self.tr(
                                    "Перезапись HTTP Host (Host Fake)",
                                    "HTTP Host Rewrite (Host Fake)",
                                ),
                                self.tr(
                                    "Подмена заголовка Host в фейковом HTTP/TLS-пакете на домен-ловушку",
                                    "Replace Host header in fake HTTP/TLS packet with decoy domain",
                                ),
                                d.host_fake,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.host_fake =
                                        !this.state.desync_prefs.host_fake;
                                    this.state.save();
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(
                        // UDP / QUIC / Anti-cheat column
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                                    .child(self.tr(
                                        "UDP, QUIC, Голос и защита Античитов",
                                        "UDP, QUIC, Voice & Anti-Cheat Protection",
                                    )),
                            )
                            .child(self.render_toggle_row(
                                "toggle-anticheat-bypass",
                                self.tr(
                                    "Совместимость с античитами и играми (RICOCHET / EAC / Vanguard)",
                                    "Anti-Cheat & Game Bypass (RICOCHET / EAC / BattlEye / Vanguard)",
                                ),
                                self.tr(
                                    "Прямой обход игровых процессов и UDP-портов без инъекций и без OpenProcess",
                                    "Direct bypass for game processes & UDP ports without packet injection or OpenProcess",
                                ),
                                d.anticheat_bypass,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.anticheat_bypass =
                                        !this.state.desync_prefs.anticheat_bypass;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-lists-override-game",
                                self.tr(
                                    "Приоритет доменных списков над байпасом игр",
                                    "Domain Lists Override Game Bypass",
                                ),
                                self.tr(
                                    "Применять списки маршрутизации (CDN обновлений) к лаунчерам и играм, сохраняя прямой UDP",
                                    "Apply domain lists (patch CDNs) to game launchers while keeping game UDP direct",
                                ),
                                d.lists_override_game_bypass,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.lists_override_game_bypass =
                                        !this.state.desync_prefs.lists_override_game_bypass;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-quic-fake",
                                self.tr(
                                    "Десинхронизация QUIC Initial / UDP",
                                    "QUIC Initial / UDP Desynchronization",
                                ),
                                self.tr(
                                    "Предварительная отправка фейковых UDP-датаграмм (443, 50000–50100)",
                                    "Send preliminary fake UDP datagrams (443, 50000–50100)",
                                ),
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
                                self.tr(
                                    "Принудительный перевод браузера с QUIC на TCP",
                                    "Force Browser Fallback from QUIC to TCP",
                                ),
                                self.tr(
                                    "Блокировать исходящий UDP:443 для гарантированного TLS Desync",
                                    "Block outbound UDP:443 to enforce TLS Desync over TCP",
                                ),
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
                                self.tr(
                                    "Голосовые шлюзы Discord UDP / STUN",
                                    "Discord Voice Gateways UDP / STUN",
                                ),
                                self.tr(
                                    "Инициализация IP Discovery и WebRTC на голосовых портах",
                                    "Initialize IP Discovery and WebRTC on voice ports",
                                ),
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
                                self.tr(
                                    "IPv4/IPv6 фрагментация (IPFrag2)",
                                    "IPv4/IPv6 Fragmentation (IPFrag2)",
                                ),
                                self.tr(
                                    "Разбиение пакетов на сетевом уровне L3",
                                    "Fragment packets at L3 network layer",
                                ),
                                d.ipfrag,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.ipfrag =
                                        !this.state.desync_prefs.ipfrag;
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(self.render_toggle_row(
                                "toggle-udp-keep-socket",
                                self.tr(
                                    "Общий сокет UDP (UDP Keep Socket)",
                                    "Reuse Bound UDP Socket",
                                ),
                                self.tr(
                                    "Отправка фейковых UDP-пакетов с того же локального порта, что и рабочий поток",
                                    "Emit fake UDP datagrams from the same bound socket as payload traffic",
                                ),
                                d.udp_keep_socket,
                                t,
                                cx.listener(|this, _, _, cx| {
                                    this.state.desync_prefs.udp_keep_socket =
                                        !this.state.desync_prefs.udp_keep_socket;
                                    this.state.save();
                                    this.reconnect_if_active();
                                    cx.notify();
                                }),
                            ))
                            .child(
                                div()
                                    .w_full()
                                    .pt(px(4.0))
                                    .flex()
                                    .flex_wrap()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(120.0))
                                            .flex()
                                            .flex_col()
                                            .gap(px(3.0))
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child("UDP Out Range (1-2)"),
                                            )
                                            .child(
                                                div()
                                                    .id("input-udp-out-range")
                                                    .w_full()
                                                    .h(px(28.0))
                                                    .child(styled_input(
                                                        &self.udp_out_range_input_state,
                                                        px(28.0),
                                                        11.0,
                                                        t,
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(160.0))
                                            .flex()
                                            .flex_col()
                                            .gap(px(3.0))
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_dim)
                                                    .child("UDP Fake Payload (0x...)"),
                                            )
                                            .child(
                                                div()
                                                    .id("input-udp-fake-payload")
                                                    .w_full()
                                                    .h(px(28.0))
                                                    .child(styled_input(
                                                        &self.udp_fake_payload_input_state,
                                                        px(28.0),
                                                        11.0,
                                                        t,
                                                    )),
                                            ),
                                    ),
                            ),
                    ),
            )
            .child(
                // AdaptiveBrain + Live Probes row
                div()
                    .w_full()
                    .flex()
                    .when(m.compact, |el| el.flex_col())
                    .gap(px(12.0))
                    .child(
                        // AdaptiveBrain card
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                                    .w_full()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Адаптивная таблица (AdaptiveBrain)",
                                                "Adaptive Table (AdaptiveBrain)",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap(px(5.0))
                                            .child(
                                                div()
                                                    .id("btn-ab-refresh")
                                                    .px(px(8.0))
                                                    .py(px(4.0))
                                                    .rounded(px(5.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_soft)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.refresh_adaptive_brain();
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr("Обновить", "Refresh")),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-ab-sanitize")
                                                    .px(px(8.0))
                                                    .py(px(4.0))
                                                    .rounded(px(5.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .text_size(px(10.0))
                                                    .text_color(t.amber)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        core_runtime::outbound::desync::gui_sanitize_poisoned_cap_entries();
                                                        this.refresh_adaptive_brain();
                                                        this.show_toast(this.tr(
                                                            "Повреждённые записи очищены",
                                                            "Corrupted entries sanitized",
                                                        ));
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr(
                                                        "Очистить битые",
                                                        "Sanitize",
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-ab-reset")
                                                    .px(px(8.0))
                                                    .py(px(4.0))
                                                    .rounded(px(5.0))
                                                    .bg(t.red_bg)
                                                    .cursor_pointer()
                                                    .text_size(px(10.0))
                                                    .text_color(t.red)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        core_runtime::outbound::desync::reset_adaptive_state();
                                                        this.refresh_adaptive_brain();
                                                        this.show_toast(this.tr(
                                                            "Адаптивная таблица сброшена",
                                                            "Adaptive state reset",
                                                        ));
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr("Сбросить", "Reset")),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(10.0))
                                    .text_color(t.text_dim)
                                    .child(format!(
                                        "{}: {} · L3: [{}]",
                                        self.tr("Доменов в памяти", "Learned hosts"),
                                        self.adaptive_snapshot.len(),
                                        self.adaptive_l3_scores
                                            .iter()
                                            .take(8)
                                            .map(|n| n.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    )),
                            )
                            .when(self.adaptive_snapshot.is_empty(), |el| {
                                el.child(
                                    div()
                                        .py(px(6.0))
                                        .text_size(px(10.5))
                                        .text_color(t.text_mute)
                                        .child(self.tr(
                                            "Домены появятся здесь после активного трафика или пробы.",
                                            "Domains will appear here after active traffic or probing.",
                                        )),
                                )
                            })
                            .when(!self.adaptive_snapshot.is_empty(), |el| {
                                let recipe_len =
                                    core_runtime::outbound::desync::ADAPTIVE_RECIPES.len().max(1);
                                el.child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_col()
                                        .gap(px(4.0))
                                        .children(self.adaptive_snapshot.iter().take(24).enumerate().map(
                                            |(idx, dom)| {
                                                let h_pin = dom.host.clone();
                                                let h_del = dom.host.clone();
                                                let next_rid =
                                                    ((dom.recipe_id as usize + 1) % recipe_len) as u8;
                                                div()
                                                    .w_full()
                                                    .px(px(8.0))
                                                    .py(px(5.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .flex()
                                                    .flex_wrap()
                                                    .items_center()
                                                    .justify_between()
                                                    .gap(px(6.0))
                                                    .child(
                                                        div()
                                                            .min_w(px(0.0))
                                                            .flex()
                                                            .flex_wrap()
                                                            .items_center()
                                                            .gap(px(6.0))
                                                            .child(
                                                                div()
                                                                    .px(px(4.0))
                                                                    .py(px(1.0))
                                                                    .rounded(px(4.0))
                                                                    .bg(t.bg_card)
                                                                    .text_size(px(9.5))
                                                                    .text_color(t.accent)
                                                                    .child(dom.tier.clone()),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_size(px(10.5))
                                                                    .font_weight(FontWeight::MEDIUM)
                                                                    .text_color(t.text)
                                                                    .child(truncate_str(&dom.host, 28)),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_size(px(9.5))
                                                                    .text_color(t.text_dim)
                                                                    .child(format!(
                                                                        "#{} {} {}{}",
                                                                        dom.recipe_id,
                                                                        dom.mode,
                                                                        if dom.verified_32k { "· 32K" } else { "" },
                                                                        if dom.consecutive_fails > 0 {
                                                                            format!(" · err:{}", dom.consecutive_fails)
                                                                        } else {
                                                                            String::new()
                                                                        }
                                                                    )),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .flex_shrink_0()
                                                            .flex()
                                                            .items_center()
                                                            .gap(px(4.0))
                                                            .child(
                                                                div()
                                                                    .id(SharedString::from(format!(
                                                                        "ab-pin-{idx}"
                                                                    )))
                                                                    .px(px(6.0))
                                                                    .py(px(2.0))
                                                                    .rounded(px(4.0))
                                                                    .bg(t.bg_card)
                                                                    .border_1()
                                                                    .border_color(t.border)
                                                                    .cursor_pointer()
                                                                    .text_size(px(9.5))
                                                                    .text_color(t.text_soft)
                                                                    .on_click(cx.listener(
                                                                        move |this, _, _, cx| {
                                                                            core_runtime::outbound::desync::gui_pin_domain_recipe(
                                                                                &h_pin, next_rid,
                                                                            );
                                                                            this.refresh_adaptive_brain();
                                                                            cx.notify();
                                                                        },
                                                                    ))
                                                                    .child(format!("R#{next_rid}")),
                                                            )
                                                            .child(
                                                                div()
                                                                    .id(SharedString::from(format!(
                                                                        "ab-del-{idx}"
                                                                    )))
                                                                    .px(px(6.0))
                                                                    .py(px(2.0))
                                                                    .rounded(px(4.0))
                                                                    .bg(t.red_bg)
                                                                    .cursor_pointer()
                                                                    .text_size(px(9.5))
                                                                    .text_color(t.red)
                                                                    .on_click(cx.listener(
                                                                        move |this, _, _, cx| {
                                                                            core_runtime::outbound::desync::gui_remove_learned_domain(
                                                                                &h_del,
                                                                            );
                                                                            this.refresh_adaptive_brain();
                                                                            cx.notify();
                                                                        },
                                                                    ))
                                                                    .child("×"),
                                                            ),
                                                    )
                                            },
                                        )),
                                )
                            }),
                    )
                    .child(
                        // Live Probes card
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                                    .child(self.tr("Живая проверка", "Live Probes")),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("input-desync-probe-host")
                                            .flex_1()
                                            .min_w(px(150.0))
                                            .h(px(28.0))
                                            .child(styled_input(
                                                &self.desync_probe_input_state,
                                                px(28.0),
                                                11.0,
                                                t,
                                            )),
                                    )
                                    .child(
                                        div()
                                            .id("btn-probe-stream")
                                            .px(px(10.0))
                                            .h(px(28.0))
                                            .rounded(px(6.0))
                                            .bg(t.accent_bg)
                                            .border_1()
                                            .border_color(t.accent_border)
                                            .cursor_pointer()
                                            .flex()
                                            .items_center()
                                            .text_size(px(10.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.accent)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let dom = this
                                                    .desync_probe_input_state
                                                    .read(cx)
                                                    .value()
                                                    .trim()
                                                    .to_string();
                                                let host = if dom.is_empty() {
                                                    "www.youtube.com".to_string()
                                                } else {
                                                    dom
                                                };
                                                let d_opts = this.current_desync_options();
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.desync_probe_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v
                                                        .run_desync_probe(&host, &d_opts)
                                                        .await
                                                    {
                                                        Ok(s) => format!("probe:stream:{s}"),
                                                        Err(e) => format!(
                                                            "probe:stream:{}",
                                                            json!({ "error": e })
                                                        ),
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("HTTPS-поток", "HTTPS Stream")),
                                    )
                                    .child(
                                        div()
                                            .id("btn-probe-ttl")
                                            .px(px(10.0))
                                            .h(px(28.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .flex()
                                            .items_center()
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let dom = this
                                                    .desync_probe_input_state
                                                    .read(cx)
                                                    .value()
                                                    .trim()
                                                    .to_string();
                                                let host = if dom.is_empty() {
                                                    "www.youtube.com".to_string()
                                                } else {
                                                    dom
                                                };
                                                let d_opts = this.current_desync_options();
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.desync_probe_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v
                                                        .run_desync_ttl_calibration(&host, &d_opts)
                                                        .await
                                                    {
                                                        Ok(s) => format!("probe:ttl:{s}"),
                                                        Err(e) => format!(
                                                            "probe:ttl:{}",
                                                            json!({ "error": e })
                                                        ),
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("Калибровка TTL", "Calibrate TTL")),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .p(px(10.0))
                                    .rounded(px(8.0))
                                    .bg(t.bg_elev)
                                    .text_size(px(10.5))
                                    .text_color(if self.desync_probe_busy {
                                        t.amber
                                    } else {
                                        t.text_soft
                                    })
                                    .child(if self.desync_probe_busy {
                                        self.tr(
                                            "Выполняется сетевая проба...",
                                            "Running network probe...",
                                        )
                                        .to_string()
                                    } else {
                                        self.desync_probe_report.clone().unwrap_or_else(|| {
                                            self.tr(
                                                "Введите домен и запустите проверку текущего профиля десинхронизации.",
                                                "Enter a domain and test the active desync configuration.",
                                            )
                                            .to_string()
                                        })
                                    }),
                            ),
                    ),
            ),
        )
    }

    fn render_routes_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .size_full()
            .px(px(if m.narrow { 10.0 } else { 16.0 }))
            .py(px(8.0))
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Sub-navigation bar
                div()
                    .w_full()
                    .flex_shrink_0()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap(px(8.0))
                    .child(
                        div()
                            .p(px(3.0))
                            .rounded(px(8.0))
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .flex_wrap()
                            .gap(px(4.0))
                            .children(
                                [
                                    (
                                        RouteSubTab::Catalog,
                                        self.tr("Каталог сервисов", "Service Catalog"),
                                    ),
                                    (RouteSubTab::Custom, self.tr("Свои правила", "Custom Rules")),
                                    (RouteSubTab::Apps, self.tr("Приложения ПК", "PC Apps")),
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
                                this.show_toast(this.tr(
                                    "Обновление баз маршрутов...",
                                    "Updating route databases...",
                                ));
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
                                    .child(self.tr("Обновить базы .srs", "Update .srs DBs")),
                            ),
                    ),
            )
            .child(match self.route_subtab {
                RouteSubTab::Catalog => self.render_routes_catalog(m, t, cx).into_any_element(),
                RouteSubTab::Custom => self.render_routes_custom(m, t, cx).into_any_element(),
                RouteSubTab::Apps => self.render_routes_apps(m, t, cx).into_any_element(),
            })
    }

    fn render_routes_catalog(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let cat_w = adaptive_card_width(m.avail_w - 12.0, 255.0, 4, 8.0);
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
            .min_h(px(0.0))
            .w_full()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .overflow_hidden()
            .child(
                // Quick scenarios + Search bar
                div()
                    .w_full()
                    .flex_shrink_0()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(6.0))
                            .children(
                                [
                                    (
                                        "ru_desync",
                                        self.tr(
                                            "РФ напрямую + YT/Discord Desync",
                                            "RU Direct + YT/Discord Desync",
                                        ),
                                    ),
                                    (
                                        "desync_only",
                                        self.tr("Только Desync (без VPN)", "Desync Only (No VPN)"),
                                    ),
                                    (
                                        "selective_vpn",
                                        self.tr("Точечный туннель", "Selective Tunnel"),
                                    ),
                                    ("adblock_on", self.tr("+ Блок рекламы", "+ AdBlock")),
                                    ("reset_all", self.tr("Сбросить", "Reset")),
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
                                                    this.show_toast(this.tr(
                                                        "Применён сценарий: РФ напрямую + YT/Discord Desync",
                                                        "Scenario applied: RU Direct + YT/Discord Desync",
                                                    ));
                                                }
                                                "desync_only" => {
                                                    this.state.vpn_prefs.route = "desync".to_string();
                                                    this.state.desync_prefs.enabled = true;
                                                    this.state.list_modes.insert("youtube".to_string(), "desync".to_string());
                                                    this.state.list_modes.insert("discord".to_string(), "desync".to_string());
                                                    this.show_toast(this.tr(
                                                        "Применён сценарий: Только Desync (без VPN)",
                                                        "Scenario applied: Desync Only (No VPN)",
                                                    ));
                                                }
                                                "selective_vpn" => {
                                                    this.state.vpn_prefs.route = "selective".to_string();
                                                    for k in ["ru_blocked", "youtube", "discord", "meta", "twitter", "ai_all", "openai", "claude", "gemini"] {
                                                        this.state.list_modes.insert(k.to_string(), "vpn".to_string());
                                                    }
                                                    this.show_toast(this.tr(
                                                        "Применён сценарий: Точечный туннель",
                                                        "Scenario applied: Selective Tunnel",
                                                    ));
                                                }
                                                "adblock_on" => {
                                                    for k in ["ads_all", "adguard", "win_telemetry"] {
                                                        this.state.list_modes.insert(k.to_string(), "block".to_string());
                                                    }
                                                    this.show_toast(this.tr(
                                                        "Включена блокировка рекламы и телеметрии",
                                                        "Ad & telemetry blocking enabled",
                                                    ));
                                                }
                                                "reset_all" => {
                                                    for v in this.state.list_modes.values_mut() {
                                                        *v = "off".to_string();
                                                    }
                                                    this.show_toast(this.tr(
                                                        "Все списки каталога сброшены в Выкл",
                                                        "All catalog lists reset to Off",
                                                    ));
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
                            .when(m.narrow, |el| el.w_full())
                            .when(!m.narrow, |el| el.w(px(230.0)))
                            .h(px(28.0))
                            .child(
                                styled_input(&self.route_search_input, px(28.0), 11.0, t)
                                    .bg(t.bg_card)
                                    .prefix(
                                        svg()
                                            .path("icons/search.svg")
                                            .size(px(11.0))
                                            .text_color(t.text_dim),
                                    ),
                            ),
                    ),
            )
            .child(
                div()
                    .id("routes-catalog-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .w_full()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .w_full()
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
                                    .w(px(cat_w))
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
                                            .gap(px(6.0))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(12.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text)
                                                    .child(entry.name),
                                            )
                                            .child(
                                                div()
                                                    .flex_shrink_0()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_mute)
                                                    .child(entry.group),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .w_full()
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
                                            .flex_wrap()
                                            .gap(px(2.0))
                                            .children(
                                                [
                                                    ("off", self.tr("Выкл", "Off")),
                                                    ("vpn", self.tr("Туннель", "Tunnel")),
                                                    ("desync", "Desync"),
                                                    ("direct", self.tr("Прямой", "Direct")),
                                                    ("block", self.tr("Блок", "Block")),
                                                ]
                                                .into_iter()
                                                .map(|(mcode, mlabel)| {
                                                    let active = current_mode == mcode;
                                                    div()
                                                        .id(SharedString::from(format!(
                                                            "cat-{eid}-{mcode}"
                                                        )))
                                                        .flex_1()
                                                        .min_w(px(44.0))
                                                        .px(px(4.0))
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
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.state.list_modes.insert(
                                                                    eid.to_string(),
                                                                    mcode.to_string(),
                                                                );
                                                                this.reconnect_if_active();
                                                                cx.notify();
                                                            },
                                                        ))
                                                        .child(mlabel)
                                                }),
                                            ),
                                    )
                            })),
                    ),
            )
    }

    fn render_routes_custom(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let _ = m.narrow;
        div()
            .flex_1()
            .min_h(px(0.0))
            .w_full()
            .flex()
            .flex_col()
            .gap(px(10.0))
            .child(
                // Add custom rule bar
                div()
                    .w_full()
                    .flex_shrink_0()
                    .p(px(10.0))
                    .rounded(px(10.0))
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .children(
                        [
                            ("domain", self.tr("Домен", "Domain")),
                            ("domain_regex", "Regex"),
                            ("cidr", "IP / CIDR"),
                            ("port", self.tr("Порт", "Port")),
                            ("process", self.tr("Процесс", "Process")),
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
                            .min_w(px(180.0))
                            .h(px(30.0))
                            .child(styled_input(&self.custom_rule_input, px(30.0), 11.5, t)),
                    )
                    .child(
                        div()
                            .id("input-custom-rule-tw")
                            .when(m.narrow, |el| el.w_full())
                            .when(!m.narrow, |el| el.w(px(176.0)))
                            .h(px(30.0))
                            .child(styled_input(&self.custom_rule_tw_input, px(30.0), 10.5, t)),
                    )
                    .children(
                        [
                            ("vpn", self.tr("В туннель", "Tunnel")),
                            ("desync", "Desync"),
                            ("direct", self.tr("Напрямую", "Direct")),
                            ("block", self.tr("Блок", "Block")),
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
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.submit_custom_rule_ui(window, cx);
                                cx.notify();
                            }))
                            .child(self.tr("Добавить", "Add")),
                    ),
            )
            .child(
                div()
                    .id("custom-rules-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .w_full()
                    .overflow_y_scroll()
                    .child(div().w_full().flex().flex_col().gap(px(6.0)).children(
                        self.state.custom_rules.iter().map(|rule| {
                            let rid = rule.id.clone();
                            let tw = rule.time_window.trim().to_string();
                            div()
                                .w_full()
                                .p(px(10.0))
                                .rounded(px(8.0))
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap(px(6.0))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(160.0))
                                        .flex()
                                        .flex_wrap()
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
                                                .min_w(px(0.0))
                                                .text_size(px(12.0))
                                                .font_weight(FontWeight::MEDIUM)
                                                .text_color(t.text)
                                                .child(rule.value.clone()),
                                        )
                                        .when(!tw.is_empty(), |el| {
                                            el.child(
                                                div()
                                                    .px(px(6.0))
                                                    .py(px(2.0))
                                                    .rounded(px(4.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .text_size(px(9.5))
                                                    .text_color(t.text_dim)
                                                    .child(tw),
                                            )
                                        }),
                                )
                                .child(
                                    div()
                                        .flex_shrink_0()
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
                                                    this.state.save();
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
                        }),
                    )),
            )
    }

    fn render_routes_apps(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let app_w = adaptive_card_width(m.avail_w - 12.0, 220.0, 5, 8.0);
        div()
            .flex_1()
            .min_h(px(0.0))
            .w_full()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .overflow_hidden()
            .child(
                div()
                    .w_full()
                    .flex_shrink_0()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(8.0))
                            .child(div().text_size(px(11.5)).text_color(t.text_soft).child(
                                if self.is_en() {
                                    format!(
                                        "Selected apps for tunneling: {}",
                                        self.state.routed_apps.len()
                                    )
                                } else {
                                    format!(
                                        "Выбрано приложений для туннелирования: {}",
                                        self.state.routed_apps.len()
                                    )
                                },
                            ))
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
                                        .child(self.tr("Очистить выбор", "Clear Selection")),
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
                                this.show_toast(if this.is_en() {
                                    format!("Found active processes: {}", this.running_apps.len())
                                } else {
                                    format!(
                                        "Найдено активных процессов: {}",
                                        this.running_apps.len()
                                    )
                                });
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/refresh.svg")
                                    .size(px(11.0))
                                    .text_color(t.accent),
                            )
                            .child(div().text_size(px(11.0)).text_color(t.text_soft).child(
                                self.tr("Обновить список процессов", "Refresh Process List"),
                            )),
                    ),
            )
            .child(
                div()
                    .id("routes-apps-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .w_full()
                    .overflow_y_scroll()
                    .child(div().w_full().flex().flex_wrap().gap(px(8.0)).children(
                        self.running_apps.iter().map(|app| {
                            let proc_name = app.proc.clone();
                            let selected = self
                                .state
                                .routed_apps
                                .iter()
                                .any(|p| p.eq_ignore_ascii_case(&proc_name));

                            div()
                                .id(SharedString::from(format!("app-chip-{}", app.proc)))
                                .w(px(app_w))
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
                                .gap(px(6.0))
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
                                        .flex_1()
                                        .min_w(px(0.0))
                                        .flex()
                                        .flex_col()
                                        .child(
                                            div()
                                                .w_full()
                                                .truncate()
                                                .text_size(px(11.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(t.text)
                                                .child(app.name.clone()),
                                        )
                                        .child(
                                            div()
                                                .w_full()
                                                .truncate()
                                                .text_size(px(10.0))
                                                .text_color(t.text_dim)
                                                .child(app.proc.clone()),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex_shrink_0()
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
                                        .child(if selected {
                                            self.tr("Туннель", "Tunnel")
                                        } else {
                                            self.tr("Прямой", "Direct")
                                        }),
                                )
                        }),
                    )),
            )
    }
}

impl TachyonApp {
    fn render_nodes_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let scroll_outer = m.compact || m.short;

        let import_card =
                // Import & Actions Card
                div()
                    .w_full()
                    .flex_shrink_0()
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(200.0))
                                    .text_size(px(12.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr(
                                        "Импорт узлов (VLESS, AWG 2/3/3.1, HY2, TUIC, WDTT, Tewfai, Mieru, VMess, Trojan, SS) и .conf",
                                        "Import Nodes (VLESS, AWG 2/3/3.1, HY2, TUIC, WDTT, Tewfai, Mieru, VMess, Trojan, SS) & .conf",
                                    )),
                            )
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .flex()
                                    .flex_wrap()
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
                                                    .child(self.tr(
                                                        "Файл .conf / AWG 2-3.1",
                                                        ".conf / AWG 2-3.1 File",
                                                    )),
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
                                                if let Some(clip) = cx.read_from_clipboard()
                                                    && let Some(txt) = clip.text() {
                                                        this.add_single_server_uri(&txt, None);
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
                                                    .child(self.tr(
                                                        "Вставить из буфера",
                                                        "Paste Clipboard",
                                                    )),
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
                                                this.show_toast(this.tr(
                                                    "Генерация профиля Cloudflare WARP (AWG)...",
                                                    "Generating Cloudflare WARP (AWG) profile...",
                                                ));
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
                            .flex_wrap()
                            .items_center()
                            .gap(px(8.0))
                            .child({
                                let view_entity = cx.entity().clone();
                                let node_uri_entity = self.node_uri_input_state.clone();
                                div()
                                    .id("input-node-uri")
                                    .flex_1()
                                    .min_w(px(180.0))
                                    .h(px(32.0))
                                    .child(
                                        styled_input(&self.node_uri_input_state, px(32.0), 11.5, t)
                                            .on_paste(move |clip, window, cx| {
                                                if let Some(raw_text) = clip.text() {
                                                    let normalized = raw_text.replace('\r', "");
                                                    if normalized.contains('\n') {
                                                        let preview =
                                                            normalized.trim().replace('\n', " ↵ ");
                                                        node_uri_entity.update(cx, |s, cx| {
                                                            s.set_value(
                                                                preview.clone(),
                                                                window,
                                                                cx,
                                                            );
                                                        });
                                                        view_entity.update(cx, |this, cx| {
                                                            this.pasted_multiline_uri =
                                                                Some(normalized);
                                                            this.node_uri_input = preview;
                                                            cx.notify();
                                                        });
                                                        return true;
                                                    }
                                                }
                                                false
                                            }),
                                    )
                            })
                            .child(
                                div()
                                    .id("input-node-name")
                                    .when(m.narrow, |el| el.w_full())
                                    .when(!m.narrow, |el| el.w(px(170.0)))
                                    .h(px(32.0))
                                    .child(styled_input(
                                        &self.node_name_input_state,
                                        px(32.0),
                                        11.5,
                                        t,
                                    )),
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
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.submit_node_uri_ui(window, cx);
                                        cx.notify();
                                    }))
                                    .child(self.tr("Добавить", "Add")),
                            ),
                    );

        let balancer_card =
                // Balancer & Cascade Settings Card (all 12 engine strategies + parameters)
                div()
                    .w_full()
                    .flex_shrink_0()
                    .p(px(10.0))
                    .rounded(px(10.0))
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(200.0))
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_soft)
                                            .child(self.tr("Балансировщик:", "Balancer:")),
                                    )
                                    .children(
                                        [
                                            ("stability", "Stability (EMA)"),
                                            ("least_test", "Min RTT"),
                                            ("least_load", "Least Load"),
                                            ("hedged", "Hedged"),
                                            ("failover", "Failover"),
                                            ("sticky", "Sticky"),
                                            ("weighted", "Weighted"),
                                            ("passive", "Passive"),
                                            ("priority", "Priority"),
                                            ("throughput", "Throughput"),
                                            ("quota", "Quota"),
                                            ("round_robin", "Round Robin"),
                                        ]
                                        .into_iter()
                                        .map(|(bm, blabel)| {
                                            let active = self.state.vpn_prefs.balancer_mode == bm;
                                            div()
                                                .id(SharedString::from(format!("bm-mode-{bm}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if active { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if active {
                                                    t.accent
                                                } else {
                                                    t.text_dim
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.balancer_mode =
                                                        bm.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(blabel)
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("btn-create-custom-balancer")
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .bg(t.accent_bg)
                                            .border_1()
                                            .border_color(t.accent_border)
                                            .cursor_pointer()
                                            .text_size(px(10.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.accent)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.create_custom_balancer_from_nodes();
                                                cx.notify();
                                            }))
                                            .child(self.tr(
                                                "+ Собрать балансировщик",
                                                "+ Create Balancer",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .id("btn-open-balancer-settings")
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .flex()
                                            .items_center()
                                            .gap(px(4.0))
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                let url = this.state.vpn_prefs.balancer_url.clone();
                                                let inc = this
                                                    .state
                                                    .vpn_prefs
                                                    .balancer_include_regex
                                                    .clone();
                                                let exc = this
                                                    .state
                                                    .vpn_prefs
                                                    .balancer_exclude_regex
                                                    .clone();
                                                let words = this
                                                    .state
                                                    .vpn_prefs
                                                    .balancer_excluded_countries
                                                    .join(", ");
                                                this.bal_url_input_state
                                                    .update(cx, |st, cx| st.set_value(url, window, cx));
                                                this.bal_include_input_state
                                                    .update(cx, |st, cx| st.set_value(inc, window, cx));
                                                this.bal_exclude_input_state
                                                    .update(cx, |st, cx| st.set_value(exc, window, cx));
                                                this.bal_words_input_state.update(cx, |st, cx| {
                                                    st.set_value(words, window, cx)
                                                });
                                                this.modal = ModalKind::Balancer;
                                                cx.notify();
                                            }))
                                            .child(
                                                svg()
                                                    .path("icons/sliders.svg")
                                                    .size(px(11.0))
                                                    .text_color(t.text_dim),
                                            )
                                            .child(self.tr("Настройки", "Settings")),
                                    )
                                    .child(
                                        div()
                                            .id("btn-open-subs-from-nodes")
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(5.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.modal = ModalKind::Subscriptions;
                                                cx.notify();
                                            }))
                                            .child(if self.is_en() {
                                                format!(
                                                    "Subscriptions ({})",
                                                    self.state.subscriptions.len()
                                                )
                                            } else {
                                                format!(
                                                    "Подписки ({})",
                                                    self.state.subscriptions.len()
                                                )
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Пул узлов:", "Pool Size:")),
                                    )
                                    .children([4usize, 8, 12, 16, 24].into_iter().map(|pl| {
                                        let act = self.state.vpn_prefs.balancer_pool == pl;
                                        div()
                                            .id(SharedString::from(format!("bm-pool-{pl}")))
                                            .px(px(6.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .cursor_pointer()
                                            .bg(if act { t.accent_bg } else { t.bg_elev })
                                            .text_size(px(10.0))
                                            .text_color(if act { t.accent } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.vpn_prefs.balancer_pool = pl;
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(pl.to_string())
                                    }))
                                    .child(
                                        div()
                                            .pl(px(8.0))
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Допуск RTT:", "Tolerance:")),
                                    )
                                    .children([30u32, 50, 80, 120, 200].into_iter().map(|tol| {
                                        let act = self.state.vpn_prefs.balancer_tolerance == tol;
                                        div()
                                            .id(SharedString::from(format!("bm-tol-{tol}")))
                                            .px(px(6.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .cursor_pointer()
                                            .bg(if act { t.amber_bg } else { t.bg_elev })
                                            .text_size(px(10.0))
                                            .text_color(if act { t.amber } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.vpn_prefs.balancer_tolerance = tol;
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(format!("{tol}ms"))
                                    })),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Интервал проверки:", "Probe Interval:")),
                                    )
                                    .children(["30s", "1m", "3m", "5m"].into_iter().map(|iv| {
                                        let act = self.state.vpn_prefs.balancer_interval == iv;
                                        div()
                                            .id(SharedString::from(format!("bm-iv-{iv}")))
                                            .px(px(6.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .cursor_pointer()
                                            .bg(if act { t.accent_bg } else { t.bg_elev })
                                            .text_size(px(10.0))
                                            .text_color(if act { t.accent } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.vpn_prefs.balancer_interval =
                                                    iv.to_string();
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(iv)
                                    }))
                                    .child(
                                        div()
                                            .pl(px(8.0))
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Квота ротации:", "Quota:")),
                                    )
                                    .children([0u32, 512, 2048, 10240].into_iter().map(|q_mib| {
                                        let act = self.state.vpn_prefs.balancer_quota_mib == q_mib;
                                        let qlabel = match q_mib {
                                            0 => self.tr("Выкл", "Off").to_string(),
                                            512 => "512 MB".to_string(),
                                            2048 => "2 GB".to_string(),
                                            _ => "10 GB".to_string(),
                                        };
                                        div()
                                            .id(SharedString::from(format!("bm-q-{q_mib}")))
                                            .px(px(6.0))
                                            .py(px(2.0))
                                            .rounded(px(4.0))
                                            .cursor_pointer()
                                            .bg(if act { t.green_bg } else { t.bg_elev })
                                            .text_size(px(10.0))
                                            .text_color(if act { t.green } else { t.text_dim })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.state.vpn_prefs.balancer_quota_mib = q_mib;
                                                this.reconnect_if_active();
                                                cx.notify();
                                            }))
                                            .child(qlabel)
                                    })),
                            ),
                    );

        let filter_bar =
                // Protocol filter & cleanup bar
                div()
                    .w_full()
                    .flex_shrink_0()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap(px(6.0))
                    .child(
                        div()
                            .min_w(px(0.0))
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(5.0))
                            .children(
                                [
                                    ("all", self.tr("Все", "All")),
                                    ("alive", self.tr("Доступные", "Alive")),
                                    ("AWG", "AWG / WG"),
                                    ("REALITY", "Reality / VLESS"),
                                    ("XHTTP", "XHTTP / WS / gRPC"),
                                    ("HY2", "HY2 / TUIC / WDTT"),
                                    ("TEWFAI", "Tewfai / Mieru"),
                                    ("VMESS", "VMess / Trojan / SS"),
                                    ("BALANCER", "Balancer"),
                                ]
                                .into_iter()
                                .map(|(fid, flabel)| {
                                    let active = self.node_filter == fid;
                                    div()
                                        .id(SharedString::from(format!("nf-chip-{fid}")))
                                        .px(px(7.0))
                                        .py(px(4.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .bg(if active { t.accent_bg } else { t.bg_card })
                                        .border_1()
                                        .border_color(if active { t.accent_border } else { t.border })
                                        .text_size(px(10.0))
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
                                    .px(px(7.0))
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
                                    .text_size(px(10.0))
                                    .text_color(if self.hide_ru_by { t.amber } else { t.text_dim })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.hide_ru_by = !this.hide_ru_by;
                                        cx.notify();
                                    }))
                                    .child(self.tr("Без РФ/РБ", "Hide RU/BY")),
                            ),
                    )
                    .child(
                        div()
                            .min_w(px(0.0))
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .id("btn-nodes-autoping-toggle")
                                    .px(px(8.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(if self.state.auto_ping.enabled {
                                        t.green_bg
                                    } else {
                                        t.bg_card
                                    })
                                    .border_1()
                                    .border_color(if self.state.auto_ping.enabled {
                                        t.green_border
                                    } else {
                                        t.border
                                    })
                                    .cursor_pointer()
                                    .text_size(px(10.5))
                                    .text_color(if self.state.auto_ping.enabled {
                                        t.green
                                    } else {
                                        t.text_dim
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_auto_ping();
                                        cx.notify();
                                    }))
                                    .child(if self.state.auto_ping.enabled {
                                        self.tr("Автопинг: Вкл", "Auto-Ping: On")
                                    } else {
                                        self.tr("Автопинг: Выкл", "Auto-Ping: Off")
                                    }),
                            )
                            .child(
                                div()
                                    .id("btn-nodes-autoping-iv")
                                    .px(px(7.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(10.5))
                                    .text_color(t.text_soft)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.cycle_auto_ping_interval();
                                        let norm = format_interval_short(
                                            this.state.auto_ping.interval_s,
                                            this.is_en(),
                                        );
                                        this.auto_ping_interval_input
                                            .update(cx, |s, cx| s.set_value(norm, window, cx));
                                        cx.notify();
                                    }))
                                    .child(format_interval_short(
                                        self.state.auto_ping.interval_s,
                                        self.is_en(),
                                    )),
                            )
                            .child(
                                div()
                                    .id("btn-nodes-autoping-scope")
                                    .px(px(7.0))
                                    .py(px(4.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_card)
                                    .border_1()
                                    .border_color(t.border)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .text_size(px(10.5))
                                    .text_color(t.text_dim)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_auto_ping_all();
                                        cx.notify();
                                    }))
                                    .child(if self.state.auto_ping.all {
                                        self.tr("Все узлы", "All Nodes")
                                    } else {
                                        self.tr("Выбранные", "Selected")
                                    }),
                            )
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
                                    .child(self.tr("Замерить все", "Ping All")),
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
                                        this.show_toast(if this.is_en() {
                                            format!("Removed unreachable nodes: {removed}")
                                        } else {
                                            format!("Удалено недоступных узлов: {removed}")
                                        });
                                        cx.notify();
                                    }))
                                    .child(self.tr("Очистить недоступные", "Prune Dead")),
                            ),
                    );

        let nodes_list =
                // Full server table
                div()
                    .id("nodes-full-scroll")
                    .when(!scroll_outer, |el| el.flex_1().min_h(px(0.0)))
                    .when(scroll_outer, |el| el.h(px(340.0)).flex_none())
                    .w_full()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .w_full()
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
                                    "XHTTP" => matches!(p, "XHTTP" | "WS" | "GRPC" | "HTTPUP"),
                                    "HY2" => matches!(p, "HY2" | "TUIC" | "WDTT" | "QUIC"),
                                    "TEWFAI" => matches!(p, "TEWFAI" | "MIERU" | "TRUST" | "JUICITY"),
                                    "VMESS" => matches!(
                                        p,
                                        "VMESS"
                                            | "TROJAN"
                                            | "SS"
                                            | "ANYTLS"
                                            | "SHADOWTLS"
                                            | "NAIVE"
                                            | "FPTN"
                                            | "TOR"
                                            | "SSH"
                                            | "SOCKS"
                                            | "HTTP"
                                    ),
                                    "BALANCER" => srv.is_balancer || p == "BALANCER",
                                    _ => true,
                                }
                            })
                            .map(|srv| {
                                let is_sel = srv.id == self.state.active_id;
                                let is_relay = srv.id == self.state.vpn_prefs.relay_id;
                                let sid = srv.id.clone();
                                let sid_ping = srv.id.clone();
                                let sid_del = srv.id.clone();
                                let sid_relay = srv.id.clone();
                                let sid_ap = srv.id.clone();
                                let is_ap_sel = !srv.is_balancer
                                    && (self.state.auto_ping.all
                                        || self.state.auto_ping.ids.contains(&srv.id));
                                let srv_uri = srv.vless.clone();
                                let proto = detect_protocol_badge(&srv.vless);
                                let stale_thresh =
                                    (self.state.auto_ping.interval_s * 2).max(300);
                                let (ping_icon_col, ping_text_col, ping_label) = ping_badge_style(
                                    srv.ping_ms,
                                    srv.ping_at,
                                    now_unix_secs(),
                                    stale_thresh,
                                    self.is_en(),
                                    false,
                                    t,
                                );

                                div()
                                    .id(SharedString::from(format!("node-row-{}", srv.id)))
                                    .w_full()
                                    .p(px(10.0))
                                    .rounded(px(10.0))
                                    .bg(if is_sel { t.accent_bg } else { t.bg_card })
                                    .border_1()
                                    .border_color(if is_sel { t.accent_border } else { t.border })
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("node-sel-{}", srv.id)))
                                            .flex_1()
                                            .min_w(px(160.0))
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
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .flex()
                                                    .flex_col()
                                                    .child(
                                                        div()
                                                            .w_full()
                                                            .truncate()
                                                            .text_size(px(12.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(t.text)
                                                            .child(srv.name.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .w_full()
                                                            .truncate()
                                                            .text_size(px(10.0))
                                                            .text_color(t.text_dim)
                                                            .child(format!(
                                                                "{} · {}",
                                                                self.country_title(&srv.country),
                                                                proto
                                                            )),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .items_center()
                                            .gap(px(6.0))
                                            .when(!srv.is_balancer, |el| {
                                                el.child(
                                                    div()
                                                        .id(SharedString::from(format!(
                                                            "chk-autoping-{}",
                                                            srv.id
                                                        )))
                                                        .w(px(22.0))
                                                        .h(px(22.0))
                                                        .rounded(px(5.0))
                                                        .bg(if is_ap_sel {
                                                            t.green_bg
                                                        } else {
                                                            t.bg_elev
                                                        })
                                                        .border_1()
                                                        .border_color(if is_ap_sel {
                                                            t.green_border
                                                        } else {
                                                            t.border
                                                        })
                                                        .cursor_pointer()
                                                        .flex()
                                                        .items_center()
                                                        .justify_center()
                                                        .on_click(cx.listener(move |this, _, _, cx| {
                                                            this.toggle_ping_selected(&sid_ap);
                                                            cx.notify();
                                                        }))
                                                        .when(is_ap_sel, |cel| {
                                                            cel.child(
                                                                svg()
                                                                    .path("icons/check.svg")
                                                                    .size(px(11.0))
                                                                    .text_color(t.green),
                                                            )
                                                        }),
                                                )
                                            })
                                            .child(
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "btn-node-ping-{}",
                                                        srv.id
                                                    )))
                                                    .px(px(7.0))
                                                    .py(px(3.0))
                                                    .rounded(px(5.0))
                                                    .bg(t.bg_elev)
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .flex()
                                                    .items_center()
                                                    .gap(px(4.0))
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.ping_single_node(sid_ping.clone());
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/bolt.svg")
                                                            .size(px(10.0))
                                                            .text_color(ping_icon_col),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.5))
                                                            .text_color(ping_text_col)
                                                            .child(ping_label),
                                                    ),
                                            )
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
                                                        if this.state.vpn_prefs.relay_id
                                                            == sid_relay
                                                        {
                                                            this.state.vpn_prefs.relay_id.clear();
                                                        } else {
                                                            this.state.vpn_prefs.relay_id =
                                                                sid_relay.clone();
                                                        }
                                                        this.reconnect_if_active();
                                                        cx.notify();
                                                    }))
                                                    .child(if is_relay {
                                                        self.tr("Каскад (Вход)", "Relay (Entry)")
                                                    } else {
                                                        self.tr("В каскад", "Set Relay")
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "btn-copy-{}",
                                                        srv.id
                                                    )))
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
                                                        cx.write_to_clipboard(
                                                            ClipboardItem::new_string(
                                                                srv_uri.clone(),
                                                            ),
                                                        );
                                                        this.show_toast(this.tr(
                                                            "Ссылка скопирована в буфер обмена",
                                                            "Link copied to clipboard",
                                                        ));
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
                                                    .id(SharedString::from(format!(
                                                        "btn-del-{}",
                                                        srv.id
                                                    )))
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
                                                        this.state
                                                            .servers
                                                            .retain(|s| s.id != sid_del);
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
                            }),
                        ),
                    );

        if scroll_outer {
            div()
                .id("nodes-tab-scroll")
                .size_full()
                .overflow_y_scroll()
                .child(
                    div()
                        .w_full()
                        .px(px(if m.narrow { 10.0 } else { 16.0 }))
                        .py(px(8.0))
                        .flex()
                        .flex_col()
                        .gap(px(10.0))
                        .child(import_card)
                        .child(balancer_card)
                        .child(filter_bar)
                        .child(nodes_list),
                )
                .into_any_element()
        } else {
            div()
                .id("nodes-tab-scroll")
                .size_full()
                .px(px(if m.narrow { 10.0 } else { 16.0 }))
                .py(px(8.0))
                .flex()
                .flex_col()
                .gap(px(10.0))
                .child(import_card)
                .child(balancer_card)
                .child(filter_bar)
                .child(nodes_list)
                .into_any_element()
        }
    }

    fn render_traffic_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .id("traffic-scroll")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .w_full()
                    .px(px(if m.narrow { 10.0 } else { 16.0 }))
                    .py(px(8.0))
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .child(
                        // Top row: Speedtest + Diagnostics Matrix
                        div()
                            .w_full()
                            .flex()
                            .when(m.compact, |el| el.flex_col())
                            .gap(px(10.0))
                            .child(
                                // Speedtest card
                                div()
                                    .when(!m.compact, |el| el.flex_1())
                                    .when(m.compact, |el| el.w_full().flex_none())
                                    .min_w(px(0.0))
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
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Тест пропускной способности",
                                                "Throughput Speedtest",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
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
                                                    .child(if self.is_en() {
                                                        format!("{sz} MB")
                                                    } else {
                                                        format!("{sz} МБ")
                                                    })
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
                                                        self.tr("Остановить", "Stop")
                                                    } else {
                                                        self.tr("Запустить", "Start")
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(20.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(if self.is_en() {
                                                format!(
                                                    "{:.1} Mbps  ({:.1} MB/s)",
                                                    self.speedtest.mbps, self.speedtest.mbs
                                                )
                                            } else {
                                                format!(
                                                    "{:.1} Мбит/с  ({:.1} МБ/с)",
                                                    self.speedtest.mbps, self.speedtest.mbs
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_dim)
                                            .child(if self.is_en() {
                                                format!(
                                                    "Peak: {:.1} Mbps · TTFB: {} ms",
                                                    self.speedtest.peak_mbps, self.speedtest.ttfb_ms
                                                )
                                            } else {
                                                format!(
                                                    "Пик: {:.1} Мбит/с · TTFB: {} мс",
                                                    self.speedtest.peak_mbps, self.speedtest.ttfb_ms
                                                )
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        // Connectivity Matrix card
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .min_w(px(0.0))
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Матрица связности и самодиагностика",
                                                "Connectivity Matrix & Self-Check",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
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
                                                    .child(self.tr(
                                                        "Самодиагностика",
                                                        "Self-Check",
                                                    )),
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
                                                        self.tr("Проверка...", "Checking...")
                                                    } else {
                                                        self.tr("Маршруты", "Routes")
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
                                                "{}: {} ({} {})",
                                                item.title,
                                                item.status,
                                                item.ms,
                                                self.tr("мс", "ms")
                                            ))
                                    }))
                                    .children(self.self_check_items.iter().map(|sc| {
                                        let ok = sc.get("status").and_then(Value::as_str) == Some("ok")
                                            || sc.get("ok").and_then(Value::as_bool) == Some(true);
                                        let title = sc
                                            .get("label")
                                            .or_else(|| sc.get("title"))
                                            .and_then(Value::as_str)
                                            .unwrap_or(self.tr("Проверка", "Check"));
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
                // Kernel Inspector Card
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr("Инспектор ядра", "Kernel Inspector")),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("input-diag-target")
                                            .w(px(if m.narrow { 150.0 } else { 200.0 }))
                                            .h(px(28.0))
                                            .child(styled_input(
                                                &self.diag_target_input_state,
                                                px(28.0),
                                                11.0,
                                                t,
                                            )),
                                    )
                                    .child(
                                        div()
                                            .id("btn-insp-route")
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(6.0))
                                            .bg(t.accent_bg)
                                            .border_1()
                                            .border_color(t.accent_border)
                                            .cursor_pointer()
                                            .text_size(px(10.5))
                                            .text_color(t.accent)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let tgt = this
                                                    .diag_target_input_state
                                                    .read(cx)
                                                    .value()
                                                    .trim()
                                                    .to_string();
                                                let target = if tgt.is_empty() {
                                                    "youtube.com".to_string()
                                                } else {
                                                    tgt
                                                };
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.diag_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v.route_check(&target, true).await {
                                                        Ok(s) => format!("diag:route:{s}"),
                                                        Err(e) => {
                                                            format!("diag:route:{}", json!({ "error": e }))
                                                        }
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("Маршрут", "Route")),
                                    )
                                    .child(
                                        div()
                                            .id("btn-insp-dns")
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let tgt = this
                                                    .diag_target_input_state
                                                    .read(cx)
                                                    .value()
                                                    .trim()
                                                    .to_string();
                                                let host = if tgt.is_empty() {
                                                    "example.com".to_string()
                                                } else {
                                                    tgt
                                                };
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.diag_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v.dns_check(&host).await {
                                                        Ok(s) => format!("diag:dns:{s}"),
                                                        Err(e) => {
                                                            format!("diag:dns:{}", json!({ "error": e }))
                                                        }
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child("DNS"),
                                    )
                                    .child(
                                        div()
                                            .id("btn-insp-leak")
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.diag_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v.leak_audit().await {
                                                        Ok(s) => format!("diag:leak:{s}"),
                                                        Err(e) => {
                                                            format!("diag:leak:{}", json!({ "error": e }))
                                                        }
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("Аудит утечек", "Leak Audit")),
                                    )
                                    .child(
                                        div()
                                            .id("btn-insp-mem")
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .text_size(px(10.5))
                                            .text_color(t.text_soft)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.diag_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v.memory_stats().await {
                                                        Ok(s) => format!("diag:mem:{s}"),
                                                        Err(e) => {
                                                            format!("diag:mem:{}", json!({ "error": e }))
                                                        }
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("Память", "Memory")),
                                    )
                                    .child(
                                        div()
                                            .id("btn-insp-trim")
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .border_1()
                                            .border_color(t.border)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .text_size(px(10.5))
                                            .text_color(t.amber)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.diag_busy = true;
                                                this.rt.spawn(async move {
                                                    let msg = match v.memory_trim().await {
                                                        Ok(s) => format!("diag:mem:{s}"),
                                                        Err(e) => {
                                                            format!("diag:mem:{}", json!({ "error": e }))
                                                        }
                                                    };
                                                    if let Ok(mut g) = eq.lock() {
                                                        g.push(msg);
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(self.tr("Сжать кэш", "Trim Cache")),
                                    ),
                            ),
                    )
                    .when(self.diag_busy || self.inspector_report.is_some(), |el| {
                        el.child(
                            div()
                                .w_full()
                                .min_w(px(0.0))
                                .px(px(10.0))
                                .py(px(6.0))
                                .rounded(px(6.0))
                                .bg(t.bg_elev)
                                .text_size(px(10.5))
                                .text_color(if self.diag_busy { t.amber } else { t.text_soft })
                                .child(if self.diag_busy {
                                    self.tr("Запрос к API ядра...", "Querying core API...")
                                        .to_string()
                                } else {
                                    self.inspector_report.clone().unwrap_or_default()
                                }),
                        )
                    }),
            )
            .child(
                // Active Connections Card
                div()
                    .w_full()
                    .min_h(px(280.0))
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
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .id("btn-conns-mode-live")
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(6.0))
                                            .cursor_pointer()
                                            .bg(if !self.traffic_flight_mode {
                                                t.accent_bg
                                            } else {
                                                t.bg_elev
                                            })
                                            .border_1()
                                            .border_color(if !self.traffic_flight_mode {
                                                t.accent_border
                                            } else {
                                                t.border
                                            })
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(if !self.traffic_flight_mode {
                                                t.accent
                                            } else {
                                                t.text_soft
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.traffic_flight_mode = false;
                                                cx.notify();
                                            }))
                                            .child(if self.is_en() {
                                                format!("Active ({})", self.connections.len())
                                            } else {
                                                format!("Активные ({})", self.connections.len())
                                            }),
                                    )
                                    .child(
                                        div()
                                            .id("btn-conns-mode-flight")
                                            .px(px(8.0))
                                            .py(px(3.0))
                                            .rounded(px(6.0))
                                            .cursor_pointer()
                                            .bg(if self.traffic_flight_mode {
                                                t.accent_bg
                                            } else {
                                                t.bg_elev
                                            })
                                            .border_1()
                                            .border_color(if self.traffic_flight_mode {
                                                t.accent_border
                                            } else {
                                                t.border
                                            })
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(if self.traffic_flight_mode {
                                                t.accent
                                            } else {
                                                t.text_soft
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.traffic_flight_mode = true;
                                                let v = this.vpn.clone();
                                                let eq = this.event_queue.clone();
                                                this.rt.spawn(async move {
                                                    if let Ok(s) = v.get_flight_recorder().await
                                                        && let Ok(mut g) = eq.lock()
                                                    {
                                                        g.push(format!("diag:flight:{s}"));
                                                    }
                                                });
                                                cx.notify();
                                            }))
                                            .child(if self.is_en() {
                                                format!(
                                                    "Flight Log ({})",
                                                    self.flight_entries.len()
                                                )
                                            } else {
                                                format!(
                                                    "Журнал ({})",
                                                    self.flight_entries.len()
                                                )
                                            }),
                                    )
                                    .when(!self.traffic_flight_mode, |el| {
                                        el.children(
                                            [
                                                ("all", self.tr("Все", "All")),
                                                ("PROXY", self.tr("Туннель", "Tunnel")),
                                                ("DESYNC", "Desync"),
                                                ("DIRECT", self.tr("Прямые", "Direct")),
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
                                                    .text_color(if act {
                                                        t.accent
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.conn_filter = cf.to_string();
                                                        cx.notify();
                                                    }))
                                                    .child(clabel)
                                            }),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
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
                                                let flight = this.traffic_flight_mode;
                                                this.rt.spawn(async move {
                                                    if flight {
                                                        if let Ok(s) = v.get_flight_recorder().await
                                                            && let Ok(mut g) = eq.lock()
                                                        {
                                                            g.push(format!("diag:flight:{s}"));
                                                        }
                                                    } else {
                                                        let data = v.get_connections_json().await;
                                                        if let Ok(mut g) = eq.lock() {
                                                            g.push(format!("conn:data:{data}"));
                                                        }
                                                    }
                                                });
                                            }))
                                            .child(self.tr("Обновить", "Refresh")),
                                    )
                                    .when(!self.traffic_flight_mode, |el| {
                                        el.child(
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
                                                .child(self.tr("Сбросить все", "Close All")),
                                        )
                                    })
                                    .when(self.traffic_flight_mode, |el| {
                                        el.child(
                                            div()
                                                .id("btn-clear-flight")
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
                                                        if v.clear_flight_recorder().await.is_ok()
                                                            && let Ok(mut g) = eq.lock()
                                                        {
                                                            g.push(
                                                                "diag:flight:cleared".to_string(),
                                                            );
                                                        }
                                                    });
                                                }))
                                                .child(self.tr("Очистить журнал", "Clear Log")),
                                        )
                                    }),
                            ),
                    )
                    .when(self.traffic_flight_mode, |el| {
                        el.child(
                            div()
                                .id("flight-list-scroll")
                                .w_full()
                                .min_h(px(180.0))
                                .max_h(px(460.0))
                                .overflow_y_scroll()
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_col()
                                        .gap(px(4.0))
                                        .when(self.flight_entries.is_empty(), |fel| {
                                            fel.child(
                                                div()
                                                    .py(px(12.0))
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_mute)
                                                    .child(self.tr(
                                                        "Записей в журнале пока нет.",
                                                        "No flight recorder entries yet.",
                                                    )),
                                            )
                                        })
                                        .children(self.flight_entries.iter().rev().take(80).map(|entry| {
                                            let net = entry
                                                .get("network")
                                                .and_then(Value::as_str)
                                                .unwrap_or("tcp")
                                                .to_ascii_uppercase();
                                            let host = entry
                                                .get("host")
                                                .and_then(Value::as_str)
                                                .filter(|s| !s.is_empty())
                                                .or_else(|| entry.get("destination").and_then(Value::as_str))
                                                .unwrap_or("—");
                                            let out = entry
                                                .get("outbound")
                                                .and_then(Value::as_str)
                                                .unwrap_or("—");
                                            let rule = entry
                                                .get("rule")
                                                .and_then(Value::as_str)
                                                .unwrap_or("final");
                                            let status = entry
                                                .get("status")
                                                .and_then(Value::as_str)
                                                .unwrap_or("");
                                            let dur = entry
                                                .get("duration_ms")
                                                .and_then(Value::as_u64)
                                                .unwrap_or(0);
                                            let dl = entry
                                                .get("download")
                                                .and_then(Value::as_u64)
                                                .unwrap_or(0);
                                            let ul = entry
                                                .get("upload")
                                                .and_then(Value::as_u64)
                                                .unwrap_or(0);
                                            div()
                                                .w_full()
                                                .px(px(8.0))
                                                .py(px(6.0))
                                                .rounded(px(6.0))
                                                .bg(t.bg_elev)
                                                .flex()
                                                .flex_wrap()
                                                .items_center()
                                                .justify_between()
                                                .gap(px(6.0))
                                                .text_size(px(10.5))
                                                .child(
                                                    div()
                                                        .min_w(px(0.0))
                                                        .flex()
                                                        .flex_wrap()
                                                        .items_center()
                                                        .gap(px(6.0))
                                                        .child(
                                                            div()
                                                                .px(px(5.0))
                                                                .rounded(px(4.0))
                                                                .bg(t.bg_card)
                                                                .text_size(px(9.5))
                                                                .text_color(t.accent)
                                                                .child(net),
                                                        )
                                                        .child(
                                                            div()
                                                                .font_weight(FontWeight::SEMIBOLD)
                                                                .text_color(t.text)
                                                                .child(truncate_str(host, 40)),
                                                        )
                                                        .child(
                                                            div()
                                                                .px(px(5.0))
                                                                .rounded(px(4.0))
                                                                .bg(t.bg_card)
                                                                .text_size(px(9.5))
                                                                .text_color(t.text_dim)
                                                                .child(format!("{out} · {rule}")),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .gap(px(8.0))
                                                        .text_color(t.text_dim)
                                                        .child(format!(
                                                            "{status} · {dur} ms · ↓{} ↑{}",
                                                            format_bytes_human(dl),
                                                            format_bytes_human(ul),
                                                        )),
                                                )
                                        })),
                                ),
                        )
                    })
                    .when(!self.traffic_flight_mode, |el| {
                        el.child(
                        div()
                            .id("conns-list-scroll")
                            .w_full()
                            .min_h(px(180.0))
                            .max_h(px(460.0))
                            .overflow_y_scroll()
                            .child(
                                div()
                                    .w_full()
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
                                        let show_ip_sub = !c.ip_port.is_empty()
                                            && c.ip_port != c.host;
                                        div()
                                            .w_full()
                                            .px(px(8.0))
                                            .py(px(6.0))
                                            .rounded(px(6.0))
                                            .bg(t.bg_elev)
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .flex_wrap()
                                            .gap(px(6.0))
                                            .text_size(px(11.0))
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .flex_wrap()
                                                    .gap(px(8.0))
                                                    .min_w(px(0.0))
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
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(t.text)
                                                            .child(truncate_str(&c.host, 42)),
                                                    )
                                                    .when(show_ip_sub, |el| {
                                                        el.child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_dim)
                                                                .child(c.ip_port.clone()),
                                                        )
                                                    })
                                                    .child(
                                                        div()
                                                            .px(px(5.0))
                                                            .py(px(1.0))
                                                            .rounded(px(4.0))
                                                            .bg(t.bg_card)
                                                            .text_size(px(9.5))
                                                            .text_color(t.text_mute)
                                                            .child(c.process.clone()),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .min_w(px(0.0))
                                                    .flex()
                                                    .flex_wrap()
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
                                                                                time_window:
                                                                                    String::new(),
                                                                            });
                                                                        this.show_toast(
                                                                            if this.is_en() {
                                                                                format!(
                                                                                    "{host_for_rule} added to Tunnel"
                                                                                )
                                                                            } else {
                                                                                format!(
                                                                                    "{host_for_rule} добавлен в Туннель"
                                                                                )
                                                                            },
                                                                        );
                                                                        this.reconnect_if_active();
                                                                        cx.notify();
                                                                    }
                                                                },
                                                            ))
                                                            .child(self.tr("+ Туннель", "+ Tunnel")),
                                                    ),
                                            )
                                    }),
                            )
                        )
                        )
                    }),
            ),
        )
    }

    fn render_options_tab(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = &self.state.vpn_prefs;

        div()
            .id("options-scroll")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .w_full()
                    .px(px(if m.narrow { 10.0 } else { 16.0 }))
                    .py(px(8.0))
                    .flex()
                    .when(m.compact, |el| el.flex_col())
                    .items_start()
                    .gap(px(12.0))
                    .child(
                        // Left column: Network & DNS
                        div()
                            .when(!m.compact, |el| el.flex_1())
                            .when(m.compact, |el| el.w_full().flex_none())
                            .min_w(px(0.0))
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
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .flex_wrap()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr(
                                        "Сеть, DNS и стек ядра TUN",
                                        "Network, DNS & Kernel TUN Stack",
                                    )),
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
                                        self.tr("Замер DNS...", "Testing DNS...")
                                    } else {
                                        self.tr("Замерить DNS", "Benchmark DNS")
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(5.0))
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(t.text_dim)
                                    .child(self.tr(
                                        "Резолвер DNS (DoH / Защищённый DNS)",
                                        "DNS Resolver (DoH / Secure DNS)",
                                    )),
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
                                            ("77.88.8.8", "Yandex 77.88.8.8"),
                                            ("custom", self.tr("Свой DNS", "Custom DNS")),
                                        ]
                                        .into_iter()
                                        .map(|(dval, dlabel)| {
                                            let active = p.dns == dval;
                                            div()
                                                .id(SharedString::from(format!("dns-opt-{dval}")))
                                                .px(px(9.0))
                                                .py(px(4.0))
                                                .rounded(px(6.0))
                                                .cursor_pointer()
                                                .bg(if active { t.accent_bg } else { t.bg_elev })
                                                .border_1()
                                                .border_color(if active {
                                                    t.accent_border
                                                } else {
                                                    t.border
                                                })
                                                .text_size(px(10.5))
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
                            .when(p.dns == "custom", |el| {
                                el.child(
                                    div()
                                        .id("input-custom-dns")
                                        .w_full()
                                        .max_w(px(m.avail_w.min(420.0)))
                                        .h(px(30.0))
                                        .child(styled_input(
                                            &self.custom_dns_input_state,
                                            px(30.0),
                                            11.5,
                                            t,
                                        )),
                                )
                            })
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Транспорт DNS:", "DNS Transport:")),
                                    )
                                    .children(
                                        [
                                            ("https", "DoH (HTTPS)"),
                                            ("h3", "DoH3 (H3)"),
                                            ("quic", "DoQ (QUIC)"),
                                            ("tls", "DoT (TLS)"),
                                            ("udp", "UDP"),
                                        ]
                                        .into_iter()
                                        .map(|(dt, dl)| {
                                            let act = p.dns_transport == dt;
                                            div()
                                                .id(SharedString::from(format!("opt-dns-tr-{dt}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .border_1()
                                                .border_color(if act {
                                                    t.accent_border
                                                } else {
                                                    t.border
                                                })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.dns_transport =
                                                        dt.to_string();
                                                    this.state.save();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(dl)
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
                                                .child(format!(
                                                    "{}: {} {}",
                                                    b.name,
                                                    b.ms,
                                                    self.tr("мс", "ms")
                                                ))
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
                            .flex_wrap()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Маршрут DNS:", "DNS Route:")),
                                    )
                                    .children(
                                        [
                                            ("split_ru", self.tr("Split (.ru напрямую)", "Split (.ru direct)")),
                                            ("proxy", self.tr("Туннель", "Tunnel")),
                                            ("direct", self.tr("Напрямую", "Direct")),
                                        ]
                                        .into_iter()
                                        .map(|(drm, drl)| {
                                            let act = p.dns_route_mode == drm;
                                            div()
                                                .id(SharedString::from(format!("opt-drm-{drm}")))
                                                .px(px(6.0))
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
                                    .flex_wrap()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
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
                    .child(
                        // DNS Strategy + TUN Stack row
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .flex_wrap()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Стратегия IP:", "IP Strategy:")),
                                    )
                                    .children(
                                        [
                                            ("prefer_ipv4", "Prefer IPv4"),
                                            ("ipv4_only", "IPv4 Only"),
                                            ("prefer_ipv6", "Prefer IPv6"),
                                        ]
                                        .into_iter()
                                        .map(|(st, sl)| {
                                            let act = p.dns_strategy == st;
                                            div()
                                                .id(SharedString::from(format!("opt-dns-st-{st}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.accent_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.accent } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.dns_strategy =
                                                        st.to_string();
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
                                    .flex_wrap()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr("Стек TUN:", "TUN Stack:")),
                                    )
                                    .children(
                                        [
                                            ("mixed", "Mixed"),
                                            ("system", "System"),
                                            ("gvisor", "gVisor"),
                                        ]
                                        .into_iter()
                                        .map(|(stk, sl)| {
                                            let act = p.tun_stack == stk;
                                            div()
                                                .id(SharedString::from(format!("opt-stk-{stk}")))
                                                .px(px(6.0))
                                                .py(px(3.0))
                                                .rounded(px(5.0))
                                                .cursor_pointer()
                                                .bg(if act { t.amber_bg } else { t.bg_elev })
                                                .text_size(px(10.0))
                                                .text_color(if act { t.amber } else { t.text_dim })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.state.vpn_prefs.tun_stack =
                                                        stk.to_string();
                                                    this.reconnect_if_active();
                                                    cx.notify();
                                                }))
                                                .child(sl)
                                        }),
                                    ),
                            ),
                    )
                    .child(self.render_toggle_row(
                        "opt-fake-ip",
                        self.tr(
                            "Виртуальный пул FakeIP (198.18.0.0/15)",
                            "Virtual FakeIP Pool (198.18.0.0/15)",
                        ),
                        self.tr(
                            "Мгновенный DNS-ответ и маршрутизация по доменным именам без задержки",
                            "Instant DNS response and zero-latency domain routing",
                        ),
                        p.fake_ip,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.fake_ip = !this.state.vpn_prefs.fake_ip;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-dns-revmap",
                        self.tr(
                            "Обратный кэш доменов DNS (Reverse Mapping)",
                            "DNS Reverse Domain Mapping",
                        ),
                        self.tr(
                            "Отображение реальных доменных имён в списке активных сессий",
                            "Display resolved domain names in active session monitor",
                        ),
                        p.dns_reverse_mapping,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.dns_reverse_mapping =
                                !this.state.vpn_prefs.dns_reverse_mapping;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-ru-bypass",
                        self.tr(
                            "Прямой маршрут для РФ (.ru / .рф / GeoIP RU)",
                            "Direct Route for RU (.ru / .рф / GeoIP RU)",
                        ),
                        self.tr(
                            "Сайты, банки и госсервисы РФ работают напрямую без задержки",
                            "Local sites, banking and domestic services connect directly",
                        ),
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
                        self.tr(
                            "Инспекция протоколов (TLS SNI / HTTP Sniffing)",
                            "Protocol Sniffing (TLS SNI / HTTP Host)",
                        ),
                        self.tr(
                            "Точное определение доменов из первых пакетов соединения",
                            "Accurate domain extraction from initial connection packets",
                        ),
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
                        self.tr(
                            "Строгая маршрутизация TUN (Strict Route)",
                            "Strict TUN Routing (Strict Route)",
                        ),
                        self.tr(
                            "Защита от утечек DNS и WebRTC мимо виртуального адаптера",
                            "Prevent DNS and WebRTC leaks outside virtual adapter",
                        ),
                        p.strict_route,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.strict_route = !this.state.vpn_prefs.strict_route;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-ipv6",
                        self.tr(
                            "Поддержка IPv6 (TUN + FakeIPv6)",
                            "IPv6 Support (TUN + FakeIPv6)",
                        ),
                        self.tr(
                            "Включить двойной стек IPv6 в адаптере TUN и пуле FakeIPv6 (fc00::/18)",
                            "Enable dual-stack IPv6 in TUN interface and FakeIPv6 pool (fc00::/18)",
                        ),
                        p.ipv6_enabled,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.ipv6_enabled = !this.state.vpn_prefs.ipv6_enabled;
                            this.state.save();
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-ntp",
                        self.tr(
                            "Синхронизация времени NTP",
                            "NTP Time Synchronization",
                        ),
                        self.tr(
                            "Точное системное время для проверки TLS-сертификатов и токенов сессий",
                            "Accurate clock synchronization for TLS certificates and session validation",
                        ),
                        p.ntp_enabled,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.ntp_enabled = !this.state.vpn_prefs.ntp_enabled;
                            this.state.save();
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .when(p.ntp_enabled, |el| {
                        el.child(
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .flex_wrap()
                                .gap(px(8.0))
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .text_color(t.text_dim)
                                        .child(self.tr("Сервер NTP:", "NTP Server:")),
                                )
                                .child(
                                    div()
                                        .id("input-ntp-server")
                                        .w_full()
                                        .max_w(px(m.avail_w.min(300.0)))
                                        .h(px(30.0))
                                        .child(styled_input(
                                            &self.ntp_server_input_state,
                                            px(30.0),
                                            11.5,
                                            t,
                                        )),
                                ),
                        )
                    }),
            )
            .child(
                // Right column: Engine, Language, System & Updates
                div()
                    .when(!m.compact, |el| el.flex_1())
                    .when(m.compact, |el| el.w_full().flex_none())
                    .min_w(px(0.0))
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
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .flex_wrap()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(self.tr(
                                        "Движок, язык и система",
                                        "Engine, Language & System",
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(6.0))
                                    .child(
                                        // Language selector in options
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(3.0))
                                            .children(
                                                [("ru", "Русский"), ("en", "English")]
                                                    .into_iter()
                                                    .map(|(lc, ltitle)| {
                                                        let act = if lc == "en" {
                                                            self.is_en()
                                                        } else {
                                                            !self.is_en()
                                                        };
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "opt-lang-{lc}"
                                                            )))
                                                            .px(px(7.0))
                                                            .py(px(2.0))
                                                            .rounded(px(4.0))
                                                            .cursor_pointer()
                                                            .bg(if act {
                                                                t.accent_bg
                                                            } else {
                                                                t.bg_elev
                                                            })
                                                            .text_size(px(10.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(if act {
                                                                t.accent
                                                            } else {
                                                                t.text_dim
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, window, cx| {
                                                                    this.state.language =
                                                                        lc.to_string();
                                                                    this.state.save();
                                                                    this.sync_input_placeholders(
                                                                        window, cx,
                                                                    );
                                                                    crate::tray::update_status(
                                                                        this.vpn_status
                                                                            == "connected",
                                                                        this.is_en(),
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child(ltitle)
                                                    }),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(3.0))
                                            .children(
                                                ["warn", "info", "debug", "error"]
                                                    .into_iter()
                                                    .map(|lvl| {
                                                        let act = p.log_level == lvl;
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "opt-log-{lvl}"
                                                            )))
                                                            .px(px(6.0))
                                                            .py(px(2.0))
                                                            .rounded(px(4.0))
                                                            .cursor_pointer()
                                                            .bg(if act {
                                                                t.accent_bg
                                                            } else {
                                                                t.bg_elev
                                                            })
                                                            .text_size(px(10.0))
                                                            .text_color(if act {
                                                                t.accent
                                                            } else {
                                                                t.text_dim
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.state
                                                                        .vpn_prefs
                                                                        .log_level =
                                                                        lvl.to_string();
                                                                    this.log_filter_level =
                                                                        lvl.to_string();
                                                                    this.state.save();
                                                                    this.log_tail = this
                                                                        .vpn
                                                                        .get_log_tail_filtered(
                                                                            200,
                                                                            &this.log_filter_level,
                                                                        );
                                                                    if this.vpn_status == "connected"
                                                                    {
                                                                        let v = this.vpn.clone();
                                                                        let eq =
                                                                            this.event_queue.clone();
                                                                        let lvl_str =
                                                                            lvl.to_string();
                                                                        let is_en = this.is_en();
                                                                        this.rt.spawn(async move {
                                                                            let ok = v
                                                                                .set_live_log_level(
                                                                                    &lvl_str,
                                                                                )
                                                                                .await;
                                                                            let msg = if ok {
                                                                                if is_en {
                                                                                    format!("toast:Log level updated: {}", lvl_str.to_uppercase())
                                                                                } else {
                                                                                    format!("toast:Уровень лога изменён: {}", lvl_str.to_uppercase())
                                                                                }
                                                                            } else if is_en {
                                                                                "toast:Log level saved (applies on reconnect)".to_string()
                                                                            } else {
                                                                                "toast:Уровень лога сохранён (применится при переподключении)".to_string()
                                                                            };
                                                                            if let Ok(mut g) = eq.lock() {
                                                                                g.push(msg);
                                                                            }
                                                                        });
                                                                    }
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child(lvl.to_uppercase())
                                                    }),
                                            ),
                                    ),
                            ),
                    )
                    .child(self.render_toggle_row(
                        "opt-find-process",
                        self.tr(
                            "Определение процессов (Safe Snapshot без OpenProcess)",
                            "Process Matching (Safe Snapshot without OpenProcess)",
                        ),
                        self.tr(
                            "Маршрутизация по приложениям без срабатывания античитов",
                            "Per-application routing safe for kernel anti-cheats",
                        ),
                        p.route_find_process,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.route_find_process =
                                !this.state.vpn_prefs.route_find_process;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-fullcone-nat",
                        self.tr(
                            "FullCone NAT для игр и голосовых вызовов",
                            "FullCone NAT for Gaming & Voice Calls",
                        ),
                        self.tr(
                            "Открытый тип NAT для UDP-сессий, WebRTC и мультиплеера",
                            "Open NAT mapping for UDP gaming, WebRTC and voice",
                        ),
                        p.route_fullcone_nat,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.route_fullcone_nat =
                                !this.state.vpn_prefs.route_fullcone_nat;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-smart-queue",
                        self.tr(
                            "Умная очередь пакетов (Smart Queue / Pacing)",
                            "Smart Packet Queue & Pacing",
                        ),
                        self.tr(
                            "Снижение джиттера и задержек при высокой загрузке канала",
                            "Reduce bufferbloat and jitter under heavy load",
                        ),
                        p.route_smart_queue,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.route_smart_queue =
                                !this.state.vpn_prefs.route_smart_queue;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-autostart",
                        self.tr("Запускать вместе с ОС", "Launch at OS Startup"),
                        self.tr(
                            "Автоматический старт Tachyon при входе в систему",
                            "Automatically start Tachyon when logging in",
                        ),
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
                        self.tr("Автоподключение при старте", "Auto-Connect on Launch"),
                        self.tr(
                            "Сразу поднимать активный туннель при открытии клиента",
                            "Immediately connect active tunnel when app starts",
                        ),
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
                        self.tr(
                            "Доступ из локальной сети (Allow LAN)",
                            "Allow LAN Connections",
                        ),
                        self.tr(
                            "Разрешить подключение других устройств домашней сети к прокси-порту",
                            "Allow other devices on local network to use proxy port",
                        ),
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
                        self.tr(
                            "Блокировка рекламы и телеметрии",
                            "Block Ads & Telemetry",
                        ),
                        self.tr(
                            "Фильтрация рекламных сетей на уровне маршрутизатора",
                            "Router-level filtering of ad and tracking domains",
                        ),
                        p.adblock,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.adblock = !this.state.vpn_prefs.adblock;
                            this.reconnect_if_active();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-close-to-tray",
                        self.tr(
                            "Сворачивать в трей при закрытии",
                            "Close Window to System Tray",
                        ),
                        self.tr(
                            "Кнопка закрытия окна скрывает клиент в область уведомлений вместо выхода",
                            "Clicking close hides the window to system tray instead of exiting",
                        ),
                        p.close_to_tray,
                        t,
                        cx.listener(|this, _, _, cx| {
                            let next = !this.state.vpn_prefs.close_to_tray;
                            this.state.vpn_prefs.close_to_tray = next;
                            this.close_to_tray_flag
                                .store(next, std::sync::atomic::Ordering::Relaxed);
                            this.state.save();
                            cx.notify();
                        }),
                    ))
                    .child(self.render_toggle_row(
                        "opt-minimize-to-tray",
                        self.tr(
                            "Сворачивать в трей при минимизации",
                            "Minimize Window to System Tray",
                        ),
                        self.tr(
                            "Кнопка сворачивания скрывает окно в область уведомлений",
                            "Minimize button hides the window into the system tray",
                        ),
                        p.minimize_to_tray,
                        t,
                        cx.listener(|this, _, _, cx| {
                            this.state.vpn_prefs.minimize_to_tray =
                                !this.state.vpn_prefs.minimize_to_tray;
                            this.state.save();
                            cx.notify();
                        }),
                    ))
                    .child(
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
                            .flex_wrap()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(150.0))
                                    .flex()
                                    .flex_col()
                                    .gap(px(2.0))
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Интервал автопинга узлов",
                                                "Node Auto-Ping Interval",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(t.text_dim)
                                            .child(self.tr(
                                                "Задаётся в секундах, минутах или часах (например 60s, 10m, 1h)",
                                                "Enter seconds, minutes or hours (e.g. 60s, 10m, 1h)",
                                            )),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .id("input-autoping-interval")
                                            .w(px(84.0))
                                            .h(px(28.0))
                                            .child(styled_input(
                                                &self.auto_ping_interval_input,
                                                px(28.0),
                                                11.0,
                                                t,
                                            )),
                                    )
                                    .children(
                                        [15u64, 60, 300, 600, 1800, 3600]
                                            .into_iter()
                                            .map(|sec| {
                                                let act = self.state.auto_ping.interval_s == sec;
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "opt-ap-iv-{sec}"
                                                    )))
                                                    .px(px(6.0))
                                                    .py(px(3.0))
                                                    .rounded(px(4.0))
                                                    .cursor_pointer()
                                                    .bg(if act {
                                                        t.accent_bg
                                                    } else {
                                                        t.bg_card
                                                    })
                                                    .border_1()
                                                    .border_color(if act {
                                                        t.accent_border
                                                    } else {
                                                        t.border
                                                    })
                                                    .text_size(px(10.0))
                                                    .text_color(if act {
                                                        t.accent
                                                    } else {
                                                        t.text_dim
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.state.auto_ping.interval_s = sec;
                                                            this.state.save();
                                                            let norm = format_interval_short(
                                                                sec,
                                                                this.is_en(),
                                                            );
                                                            this.auto_ping_interval_input.update(
                                                                cx,
                                                                |s, cx| {
                                                                    s.set_value(norm, window, cx)
                                                                },
                                                            );
                                                            cx.notify();
                                                        },
                                                    ))
                                                    .child(format_interval_short(
                                                        sec,
                                                        self.is_en(),
                                                    ))
                                            }),
                                    ),
                            ),
                    )
                    .children(self.render_macos_helper_row(t, cx))
                    .child(
                        div()
                            .w_full()
                            .pt(px(2.0))
                            .flex()
                            .items_center()
                            .justify_between()
                            .flex_wrap()
                            .gap(px(8.0))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_wrap()
                                    .gap(px(8.0))
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
                                                this.show_toast(this.tr(
                                                    "Проверка обновлений на GitHub...",
                                                    "Checking GitHub for updates...",
                                                ));
                                                cx.notify();
                                            }))
                                            .child(self.tr(
                                                "Проверить обновления",
                                                "Check for Updates",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .id("btn-quit-app")
                                            .px(px(12.0))
                                            .py(px(6.0))
                                            .rounded(px(8.0))
                                            .bg(t.red_bg)
                                            .border_1()
                                            .border_color(t.red)
                                            .cursor_pointer()
                                            .hover(|s| s.opacity(0.9))
                                            .text_size(px(11.5))
                                            .text_color(t.red)
                                            .on_click(cx.listener(|this, _, _, _| {
                                                this.quit_app();
                                            }))
                                            .child(self.tr(
                                                "Выйти из Tachyon",
                                                "Quit Tachyon",
                                            )),
                                    ),
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
                                        .child(if self.is_en() {
                                            format!("Install {}", self.update_banner.tag)
                                        } else {
                                            format!("Установить {}", self.update_banner.tag)
                                        }),
                                )
                            }),
                    ),
                ),
            )
    }

    #[cfg(target_os = "macos")]
    fn render_macos_helper_row(&self, t: Theme, cx: &mut Context<Self>) -> Option<AnyElement> {
        let installed = self.macos_helper_installed;
        let busy = self.macos_helper_busy;
        Some(
            div()
                .w_full()
                .p(px(10.0))
                .rounded(px(8.0))
                .bg(t.bg_elev)
                .border_1()
                .border_color(if installed {
                    t.green_border
                } else {
                    t.border
                })
                .flex()
                .items_center()
                .justify_between()
                .flex_wrap()
                .gap(px(8.0))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(160.0))
                        .flex()
                        .flex_col()
                        .gap(px(2.0))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.0))
                                .child(
                                    div()
                                        .text_size(px(12.0))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text)
                                        .child(self.tr(
                                            "Системный помощник macOS",
                                            "macOS Privileged Helper",
                                        )),
                                )
                                .child(
                                    div()
                                        .px(px(6.0))
                                        .py(px(1.0))
                                        .rounded(px(4.0))
                                        .bg(if installed {
                                            t.green_bg
                                        } else {
                                            t.bg_card
                                        })
                                        .text_size(px(9.5))
                                        .text_color(if installed {
                                            t.green
                                        } else {
                                            t.text_dim
                                        })
                                        .child(if busy {
                                            self.tr("Выполняется...", "Working...")
                                        } else if installed {
                                            self.tr("Установлен", "Installed")
                                        } else {
                                            self.tr("Не установлен", "Not installed")
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(t.text_dim)
                                .child(self.tr(
                                    "LaunchDaemon для запуска TUN и маршрутов без повторного запроса пароля",
                                    "LaunchDaemon to manage TUN and routes without repeated admin prompts",
                                )),
                        ),
                )
                .child(
                    div()
                        .id("btn-macos-helper-action")
                        .px(px(10.0))
                        .py(px(5.0))
                        .rounded(px(6.0))
                        .bg(if installed {
                            t.red_bg
                        } else {
                            t.accent_bg
                        })
                        .border_1()
                        .border_color(if installed {
                            t.red
                        } else {
                            t.accent_border
                        })
                        .cursor_pointer()
                        .hover(|s| s.opacity(0.9))
                        .text_size(px(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(if installed { t.red } else { t.accent })
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.trigger_macos_helper_action(!installed);
                            cx.notify();
                        }))
                        .child(if installed {
                            self.tr("Удалить", "Uninstall")
                        } else {
                            self.tr("Установить", "Install")
                        }),
                )
                .into_any_element(),
        )
    }

    #[cfg(not(target_os = "macos"))]
    fn render_macos_helper_row(&self, _t: Theme, _cx: &mut Context<Self>) -> Option<AnyElement> {
        None
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
            .flex_shrink_0()
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
                    .min_w(px(0.0))
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .w_full()
                            .text_size(px(11.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text)
                            .child(title),
                    )
                    .child(
                        div()
                            .w_full()
                            .text_size(px(10.0))
                            .text_color(t.text_dim)
                            .child(subtitle),
                    ),
            )
            .child(
                div()
                    .w(px(34.0))
                    .h(px(18.0))
                    .flex_shrink_0()
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

    // ───────────────────────── Balancer settings modal ─────────────────────────

    fn bal_chip(
        &self,
        key: String,
        label: String,
        active: bool,
        t: Theme,
        cx: &mut Context<Self>,
        on: impl Fn(&mut Self, &mut Window, &mut Context<Self>) + 'static,
    ) -> AnyElement {
        div()
            .id(SharedString::from(format!("balc-{key}")))
            .px(px(7.0))
            .py(px(3.0))
            .rounded(px(5.0))
            .cursor_pointer()
            .border_1()
            .border_color(if active { t.accent_border } else { t.border })
            .bg(if active { t.accent_bg } else { t.bg_elev })
            .text_size(px(10.5))
            .text_color(if active { t.accent } else { t.text_dim })
            .on_click(cx.listener(move |this, _, window, cx| {
                on(this, window, cx);
                this.reconnect_if_active();
                cx.notify();
            }))
            .child(label)
            .into_any_element()
    }

    fn bal_title(text: &str, t: Theme) -> AnyElement {
        div()
            .pt(px(4.0))
            .text_size(px(11.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(t.text_soft)
            .child(text.to_string())
            .into_any_element()
    }

    fn bal_hint(text: &str, t: Theme) -> AnyElement {
        div()
            .text_size(px(10.0))
            .text_color(t.text_mute)
            .child(text.to_string())
            .into_any_element()
    }

    fn bal_row(chips: Vec<AnyElement>) -> AnyElement {
        div()
            .w_full()
            .flex()
            .flex_wrap()
            .gap(px(5.0))
            .children(chips)
            .into_any_element()
    }

    fn bal_toggle_in(list: &mut Vec<String>, value: &str) {
        if list.iter().any(|x| x.eq_ignore_ascii_case(value)) {
            list.retain(|x| !x.eq_ignore_ascii_case(value));
        } else {
            list.push(value.to_string());
        }
    }

    fn render_balancer_modal(
        &self,
        m: LayoutMetrics,
        t: Theme,
        max_h: f32,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let en = self.is_en();
        let pf = &self.state.vpn_prefs;
        let mut body: Vec<AnyElement> = Vec::new();

        // Live status
        if self.vpn_status == "connected"
            && let Some(lb) = self.live_balancer.as_ref()
        {
            let mode = lb.get("mode").and_then(Value::as_str).unwrap_or("-");
            let now = lb
                .get("now")
                .or_else(|| lb.get("selected"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            let cnt = lb
                .get("all")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            body.push(
                div()
                    .w_full()
                    .p(px(8.0))
                    .rounded(px(8.0))
                    .bg(t.green_bg)
                    .border_1()
                    .border_color(t.green_border)
                    .text_size(px(10.5))
                    .text_color(t.green)
                    .child(if en {
                        format!("Active node: {now} · core mode: {mode} · nodes in pool: {cnt}")
                    } else {
                        format!("Активный узел: {now} · режим ядра: {mode} · узлов: {cnt}")
                    })
                    .into_any_element(),
            );
        }

        // Multi-URL
        body.push(Self::bal_title(
            self.tr(
                "Мульти-URL балансировщик по сервисам",
                "Per-service multi-URL balancer",
            ),
            t,
        ));
        body.push(Self::bal_hint(
            self.tr(
                "Отдельный пул urltest со своим проверочным URL для каждого сервиса. Работает, когда выбран балансировщик.",
                "A dedicated urltest pool with its own probe URL per service. Active when a balancer is selected.",
            ),
            t,
        ));
        let multi_on = pf.balancer_multi_service;
        let mut svc_chips = vec![self.bal_chip(
            "multi-toggle".into(),
            if multi_on {
                self.tr("Включён", "Enabled").to_string()
            } else {
                self.tr("Выключен", "Disabled").to_string()
            },
            multi_on,
            t,
            cx,
            |this, _, _| {
                this.state.vpn_prefs.balancer_multi_service =
                    !this.state.vpn_prefs.balancer_multi_service;
            },
        )];
        for (sid, title) in [
            ("youtube", "YouTube"),
            ("telegram", "Telegram"),
            ("discord", "Discord"),
            ("instagram", "Instagram"),
            ("openai", "ChatGPT / AI"),
            ("https", "HTTPS"),
        ] {
            let active = pf.balancer_multi_services.iter().any(|x| x == sid);
            svc_chips.push(self.bal_chip(
                format!("svc-{sid}"),
                title.to_string(),
                active,
                t,
                cx,
                move |this, _, _| {
                    let list = &mut this.state.vpn_prefs.balancer_multi_services;
                    if list.iter().any(|x| x == sid) {
                        // хотя бы один сервис должен остаться выбранным
                        if list.len() > 1 {
                            list.retain(|x| x != sid);
                        }
                    } else {
                        list.push(sid.to_string());
                    }
                },
            ));
        }
        body.push(Self::bal_row(svc_chips));

        // Algorithms
        body.push(Self::bal_title(
            self.tr("Алгоритм выбора узла", "Node selection algorithm"),
            t,
        ));
        const MODES: [(&str, &str, &str, &str, &str, &str); 12] = [
            (
                "stability",
                "Стабильность (EWMA + Jitter)",
                "Stability (EWMA + Jitter)",
                "STABILITY",
                "Сглаженный пинг с учётом джиттера и автокарантином нестабильных узлов",
                "Smoothed latency with jitter and auto-quarantine of unstable nodes",
            ),
            (
                "least_test",
                "Минимальный пинг (Least Test)",
                "Lowest ping (Least Test)",
                "LEAST RTT",
                "Переключение на сервер с наименьшей задержкой отклика",
                "Switch to the server with the lowest response latency",
            ),
            (
                "sticky",
                "Липкие сессии (Sticky Hash)",
                "Sticky sessions (Sticky Hash)",
                "STICKY",
                "Привязка доменов и IP к одному узлу из пула без смены выходного адреса",
                "Pin domains and IPs to one pool node without changing the exit address",
            ),
            (
                "least_load",
                "Наименьшая нагрузка (Least Load)",
                "Least load",
                "LEAST LOAD",
                "Выбор менее загруженного узла с учётом активных соединений (Power of 2)",
                "Pick the less loaded node by active connections (Power of 2)",
            ),
            (
                "weighted",
                "Взвешенный (Smooth WRR)",
                "Weighted (Smooth WRR)",
                "WEIGHTED",
                "Распределение потоков пропорционально скорости отклика серверов",
                "Distribute flows proportionally to server response speed",
            ),
            (
                "hedged",
                "Параллельный старт (Hedged)",
                "Parallel start (Hedged)",
                "HEDGED",
                "Резервная попытка через второй узел при задержке рукопожатия",
                "Backup attempt via a second node when the handshake is slow",
            ),
            (
                "throughput",
                "Пиковая скорость (Throughput)",
                "Peak speed (Throughput)",
                "THROUGHPUT",
                "Приоритет узлу с максимальной измеренной пропускной способностью",
                "Prefer the node with the highest measured throughput",
            ),
            (
                "passive",
                "Пассивный (Zero Probes)",
                "Passive (Zero Probes)",
                "PASSIVE",
                "Без фоновых HTTP-проб, переключение только при ошибке соединения",
                "No background HTTP probes, switch only on connection failure",
            ),
            (
                "priority",
                "Приоритетный (Priority Tier)",
                "Priority (Priority Tier)",
                "PRIORITY",
                "Строгий порядок по списку с автовозвратом на основной сервер",
                "Strict list order with automatic return to the primary server",
            ),
            (
                "quota",
                "Квота трафика (Quota)",
                "Traffic quota (Quota)",
                "QUOTA",
                "Автоматическая ротация серверов по лимиту переданных мегабайт",
                "Rotate servers automatically by transferred megabytes",
            ),
            (
                "round_robin",
                "По кругу (Round Robin)",
                "Round Robin",
                "ROUND ROBIN",
                "Равномерное чередование быстрых серверов из Top-N пула",
                "Even rotation across the fastest servers of the Top-N pool",
            ),
            (
                "failover",
                "Отказоустойчивый (Failover)",
                "Failover",
                "FAILOVER",
                "Удержание текущего рабочего узла до полного отказа",
                "Keep the current working node until it fails completely",
            ),
        ];
        for (id, ru_t, en_t, badge, ru_s, en_s) in MODES {
            let active = pf.balancer_mode == id;
            body.push(
                div()
                    .id(SharedString::from(format!("balc-mode-{id}")))
                    .w_full()
                    .px(px(9.0))
                    .py(px(6.0))
                    .rounded(px(7.0))
                    .cursor_pointer()
                    .bg(if active { t.accent_bg } else { t.bg_elev })
                    .border_1()
                    .border_color(if active { t.accent_border } else { t.border })
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.state.vpn_prefs.balancer_mode = id.to_string();
                        this.reconnect_if_active();
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(if active { t.accent } else { t.text })
                                    .child(if en { en_t } else { ru_t }),
                            )
                            .child(
                                div()
                                    .px(px(4.0))
                                    .rounded(px(3.0))
                                    .bg(t.bg_card)
                                    .text_size(px(9.0))
                                    .text_color(if active { t.accent } else { t.text_mute })
                                    .child(badge),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(10.0))
                            .text_color(t.text_mute)
                            .child(if en { en_s } else { ru_s }),
                    )
                    .into_any_element(),
            );
        }

        // Pool / tolerance / interval
        body.push(Self::bal_title(
            self.tr("Кандидатов в пуле (Top-N)", "Candidates in pool (Top-N)"),
            t,
        ));
        body.push(Self::bal_row(
            [2usize, 3, 4, 6, 8, 12, 16, 24]
                .into_iter()
                .map(|n| {
                    self.bal_chip(
                        format!("pool-{n}"),
                        format!("Top-{n}"),
                        pf.balancer_pool == n,
                        t,
                        cx,
                        move |this, _, _| this.state.vpn_prefs.balancer_pool = n,
                    )
                })
                .collect(),
        ));
        body.push(Self::bal_title(
            self.tr(
                "Допуск гистерезиса по задержке",
                "Latency hysteresis tolerance",
            ),
            t,
        ));
        body.push(Self::bal_hint(
            self.tr(
                "Защищает от лишних переключений при небольших колебаниях пинга.",
                "Prevents needless switching on small ping fluctuations.",
            ),
            t,
        ));
        body.push(Self::bal_row(
            [30u32, 50, 80, 120, 200]
                .into_iter()
                .map(|ms| {
                    self.bal_chip(
                        format!("tol-{ms}"),
                        format!("{ms} ms"),
                        pf.balancer_tolerance == ms,
                        t,
                        cx,
                        move |this, _, _| this.state.vpn_prefs.balancer_tolerance = ms,
                    )
                })
                .collect(),
        ));
        body.push(Self::bal_title(
            self.tr("Интервал проверки доступности", "Probe interval"),
            t,
        ));
        body.push(Self::bal_row(
            ["15s", "30s", "1m", "3m", "5m"]
                .into_iter()
                .map(|iv| {
                    self.bal_chip(
                        format!("iv-{iv}"),
                        iv.to_string(),
                        pf.balancer_interval == iv,
                        t,
                        cx,
                        move |this, _, _| this.state.vpn_prefs.balancer_interval = iv.to_string(),
                    )
                })
                .collect(),
        ));

        // URL test
        body.push(Self::bal_title(
            self.tr(
                "URL проверки доступности (URL-Test)",
                "Probe URL (URL-Test)",
            ),
            t,
        ));
        body.push(Self::bal_row(
            [
                ("https://www.gstatic.com/generate_204", "Gstatic (HTTPS)"),
                ("http://cp.cloudflare.com/generate_204", "Cloudflare (HTTP)"),
                (
                    "https://cp.cloudflare.com/generate_204",
                    "Cloudflare (HTTPS)",
                ),
                (
                    "http://connectivitycheck.gstatic.com/generate_204",
                    "Connectivity check",
                ),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, (url, label))| {
                self.bal_chip(
                    format!("url-{i}"),
                    label.to_string(),
                    pf.balancer_url == url,
                    t,
                    cx,
                    move |this, window, cx| {
                        this.state.vpn_prefs.balancer_url = url.to_string();
                        this.bal_url_input_state
                            .update(cx, |st, cx| st.set_value(url, window, cx));
                    },
                )
            })
            .collect(),
        ));
        body.push(
            div()
                .w_full()
                .h(px(30.0))
                .child(styled_input(&self.bal_url_input_state, px(30.0), 11.0, t))
                .into_any_element(),
        );
        body.push(Self::bal_hint(
            self.tr(
                "Свой http/https адрес (200/204). Применяется по Enter.",
                "Custom http/https address (200/204). Applied on Enter.",
            ),
            t,
        ));

        // Sticky keys
        if pf.balancer_mode == "sticky" {
            body.push(Self::bal_title(
                self.tr(
                    "Ключи консистентного хеширования (Sticky)",
                    "Consistent-hash keys (Sticky)",
                ),
                t,
            ));
            body.push(Self::bal_row(
                [
                    ("domain", "Домен (SNI)", "Domain (SNI)"),
                    ("dest_ip", "IP назначения", "Destination IP"),
                    ("dest_port", "Порт", "Port"),
                    ("source_ip", "IP источника", "Source IP"),
                    ("process", "Процесс", "Process"),
                ]
                .into_iter()
                .map(|(key, ru, enl)| {
                    let active = pf.balancer_sticky_hash.iter().any(|x| x == key);
                    self.bal_chip(
                        format!("sticky-{key}"),
                        (if en { enl } else { ru }).to_string(),
                        active,
                        t,
                        cx,
                        move |this, _, _| {
                            let list = &mut this.state.vpn_prefs.balancer_sticky_hash;
                            if list.iter().any(|x| x == key) {
                                if list.len() > 1 {
                                    list.retain(|x| x != key);
                                }
                            } else {
                                list.push(key.to_string());
                            }
                        },
                    )
                })
                .collect(),
            ));
        }

        // Quota
        if pf.balancer_mode == "quota" {
            body.push(Self::bal_title(
                self.tr("Квота трафика на один узел", "Traffic quota per node"),
                t,
            ));
            body.push(Self::bal_row(
                [0u32, 100, 256, 512, 1024, 2048]
                    .into_iter()
                    .map(|q| {
                        let lbl = if q == 0 {
                            self.tr("Выкл", "Off").to_string()
                        } else if q >= 1024 {
                            if en {
                                format!("{} GB", q / 1024)
                            } else {
                                format!("{} ГБ", q / 1024)
                            }
                        } else if en {
                            format!("{q} MB")
                        } else {
                            format!("{q} МБ")
                        };
                        self.bal_chip(
                            format!("quota-{q}"),
                            lbl,
                            pf.balancer_quota_mib == q,
                            t,
                            cx,
                            move |this, _, _| this.state.vpn_prefs.balancer_quota_mib = q,
                        )
                    })
                    .collect(),
            ));
        }

        // Filters: countries
        body.push(Self::bal_title(
            self.tr("Исключить страны", "Exclude countries"),
            t,
        ));
        let mut country_chips: Vec<AnyElement> = balancer_country_presets()
            .map(|(code, title)| {
                let active = pf
                    .balancer_excluded_countries
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(code));
                let _ = title;
                let flag_opt = flag_image(&code.to_ascii_lowercase());
                div()
                    .id(SharedString::from(format!("balc-cc-{code}")))
                    .px(px(7.0))
                    .py(px(3.0))
                    .rounded(px(5.0))
                    .cursor_pointer()
                    .border_1()
                    .border_color(if active { t.accent_border } else { t.border })
                    .bg(if active { t.accent_bg } else { t.bg_elev })
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .text_size(px(10.5))
                    .text_color(if active { t.accent } else { t.text_dim })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        Self::bal_toggle_in(
                            &mut this.state.vpn_prefs.balancer_excluded_countries,
                            code,
                        );
                        let txt = this.state.vpn_prefs.balancer_excluded_countries.join(", ");
                        this.bal_words_input_state
                            .update(cx, |st, cx| st.set_value(txt, window, cx));
                        this.reconnect_if_active();
                        cx.notify();
                    }))
                    .when_some(flag_opt, |el, fimg| {
                        el.child(img(fimg).w(px(14.0)).h(px(10.0)).rounded(px(2.0)))
                    })
                    .child(code.to_string())
                    .into_any_element()
            })
            .collect();
        country_chips.push(self.bal_chip(
            "cc-reset".into(),
            self.tr("Сбросить", "Reset").to_string(),
            false,
            t,
            cx,
            |this, window, cx| {
                this.state.vpn_prefs.balancer_excluded_countries.clear();
                this.bal_words_input_state
                    .update(cx, |st, cx| st.set_value("", window, cx));
            },
        ));
        body.push(Self::bal_row(country_chips));
        body.push(
            div()
                .w_full()
                .h(px(30.0))
                .child(styled_input(&self.bal_words_input_state, px(30.0), 11.0, t))
                .into_any_element(),
        );
        body.push(Self::bal_hint(
            self.tr(
                "Коды стран или слова через запятую. Применяется по Enter.",
                "Country codes or words separated by commas. Applied on Enter.",
            ),
            t,
        ));

        // Filters: protocols
        body.push(Self::bal_title(
            self.tr("Исключить протоколы", "Exclude protocols"),
            t,
        ));
        let mut proto_chips: Vec<AnyElement> = [
            ("vless", "VLESS"),
            ("tewfai", "Tewfai"),
            ("wdtt", "WDTT / CSQTT"),
            ("vmess", "VMess"),
            ("trojan", "Trojan"),
            ("shadowsocks", "Shadowsocks"),
            ("hysteria2", "Hysteria 2"),
            ("tuic", "TUIC"),
            ("wireguard", "WireGuard / AWG"),
            ("anytls", "AnyTLS"),
            ("naive", "NaiveProxy"),
            ("snell", "Snell"),
            ("shadowtls", "ShadowTLS"),
            ("fptn", "FPTN"),
            ("masque", "MASQUE"),
            ("mieru", "Mieru"),
            ("trusttunnel", "TrustTunnel"),
            ("openconnect", "OpenConnect"),
            ("openvpn-client", "OpenVPN"),
            ("tailscale", "Tailscale"),
            ("mtproto", "MTProto"),
            ("ssh", "SSH"),
            ("socks", "SOCKS / HTTP"),
        ]
        .into_iter()
        .map(|(id, label)| {
            let active = pf.balancer_excluded_protocols.iter().any(|x| x == id);
            self.bal_chip(
                format!("proto-{id}"),
                label.to_string(),
                active,
                t,
                cx,
                move |this, _, _| {
                    Self::bal_toggle_in(&mut this.state.vpn_prefs.balancer_excluded_protocols, id)
                },
            )
        })
        .collect();
        proto_chips.push(self.bal_chip(
            "proto-reset".into(),
            self.tr("Сбросить", "Reset").to_string(),
            false,
            t,
            cx,
            |this, _, _| this.state.vpn_prefs.balancer_excluded_protocols.clear(),
        ));
        body.push(Self::bal_row(proto_chips));

        // Filters: RegExp
        body.push(Self::bal_title(
            self.tr("Фильтр по регулярному выражению (RegExp)", "RegExp filter"),
            t,
        ));
        body.push(Self::bal_hint(
            self.tr(
                "Оставить только серверы с нужным шаблоном или скрыть лишние. Применяется по Enter.",
                "Keep only matching servers or hide unwanted ones. Applied on Enter.",
            ),
            t,
        ));
        body.push(Self::bal_hint(self.tr("Включить:", "Include:"), t));
        body.push(
            div()
                .w_full()
                .h(px(30.0))
                .child(styled_input(
                    &self.bal_include_input_state,
                    px(30.0),
                    11.0,
                    t,
                ))
                .into_any_element(),
        );
        body.push(Self::bal_hint(self.tr("Исключить:", "Exclude:"), t));
        body.push(
            div()
                .w_full()
                .h(px(30.0))
                .child(styled_input(
                    &self.bal_exclude_input_state,
                    px(30.0),
                    11.0,
                    t,
                ))
                .into_any_element(),
        );
        body.push(Self::bal_row(vec![self.bal_chip(
            "re-reset".into(),
            self.tr("Сбросить RegExp", "Reset RegExp").to_string(),
            false,
            t,
            cx,
            |this, window, cx| {
                this.state.vpn_prefs.balancer_include_regex.clear();
                this.state.vpn_prefs.balancer_exclude_regex.clear();
                this.bal_include_input_state
                    .update(cx, |st, cx| st.set_value("", window, cx));
                this.bal_exclude_input_state
                    .update(cx, |st, cx| st.set_value("", window, cx));
            },
        )]));

        div()
            .id("modal-backdrop-balancer")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .p(px(12.0))
            .occlude()
            .bg(gpui::rgba(0x000000A6))
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .w(px((m.width - 32.0).clamp(300.0, 660.0)))
                    .h(px(max_h.min(640.0)))
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
                            .flex_shrink_0()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(14.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(t.text)
                                    .child(
                                        self.tr("Настройки балансировщика", "Balancer settings"),
                                    ),
                            )
                            .child(
                                div()
                                    .id("btn-close-balancer-modal")
                                    .w(px(26.0))
                                    .h(px(26.0))
                                    .rounded(px(6.0))
                                    .bg(t.bg_elev)
                                    .cursor_pointer()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let mut changed = false;
                                        let u = this
                                            .bal_url_input_state
                                            .read(cx)
                                            .value()
                                            .trim()
                                            .to_string();
                                        if (u.starts_with("http://") || u.starts_with("https://"))
                                            && u != this.state.vpn_prefs.balancer_url
                                        {
                                            this.state.vpn_prefs.balancer_url = u;
                                            changed = true;
                                        }
                                        let inc = this
                                            .bal_include_input_state
                                            .read(cx)
                                            .value()
                                            .trim()
                                            .to_string();
                                        if inc != this.state.vpn_prefs.balancer_include_regex {
                                            this.state.vpn_prefs.balancer_include_regex = inc;
                                            changed = true;
                                        }
                                        let exc = this
                                            .bal_exclude_input_state
                                            .read(cx)
                                            .value()
                                            .trim()
                                            .to_string();
                                        if exc != this.state.vpn_prefs.balancer_exclude_regex {
                                            this.state.vpn_prefs.balancer_exclude_regex = exc;
                                            changed = true;
                                        }
                                        let words: Vec<String> = this
                                            .bal_words_input_state
                                            .read(cx)
                                            .value()
                                            .split(',')
                                            .map(|x| x.trim().to_string())
                                            .filter(|x| !x.is_empty())
                                            .collect();
                                        if words != this.state.vpn_prefs.balancer_excluded_countries
                                        {
                                            this.state.vpn_prefs.balancer_excluded_countries =
                                                words;
                                            changed = true;
                                        }
                                        if changed {
                                            this.reconnect_if_active();
                                        }
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
                            .id("balancer-modal-scroll")
                            .flex_1()
                            .min_h(px(0.0))
                            .w_full()
                            .overflow_y_scroll()
                            .child(div().w_full().flex().flex_col().gap(px(7.0)).children(body)),
                    ),
            )
            .into_any_element()
    }

    fn render_modal_overlay(
        &self,
        m: LayoutMetrics,
        t: Theme,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let modal_max_h = (m.height - 48.0).max(260.0);
        match self.modal {
            ModalKind::None => None,
            ModalKind::Balancer => Some(self.render_balancer_modal(m, t, modal_max_h, cx)),
            ModalKind::Subscriptions => Some(
                div()
                    .id("modal-backdrop-subs")
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .p(px(12.0))
                    .occlude()
                    .bg(gpui::rgba(0x000000A6))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .w(px((m.width - 32.0).clamp(300.0, 620.0)))
                            .max_h(px(modal_max_h.min(520.0)))
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
                                    .flex_shrink_0()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .flex_wrap()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Управление подписками и контейнерами",
                                                "Manage Subscriptions & Containers",
                                            )),
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
                                    .flex_shrink_0()
                                    .flex()
                                    .gap(px(8.0))
                                    .child(div().id("input-sub-url").flex_1().h(px(32.0)).child(
                                        styled_input(&self.sub_url_input_state, px(32.0), 11.5, t),
                                    ))
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
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.submit_sub_url_ui(window, cx);
                                                cx.notify();
                                            }))
                                            .child(self.tr("Подключить", "Add")),
                                    ),
                            )
                            .child(
                                div()
                                    .id("subs-modal-scroll")
                                    .flex_1()
                                    .min_h(px(0.0))
                                    .w_full()
                                    .overflow_y_scroll()
                                    .child(div().w_full().flex().flex_col().gap(px(6.0)).children(
                                        self.state.subscriptions.iter().map(|sub| {
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
                                                .flex_wrap()
                                                .items_center()
                                                .justify_between()
                                                .gap(px(6.0))
                                                .child(
                                                    div()
                                                        .flex_1()
                                                        .min_w(px(0.0))
                                                        .flex()
                                                        .flex_col()
                                                        .child(
                                                            div()
                                                                .w_full()
                                                                .truncate()
                                                                .text_size(px(12.0))
                                                                .font_weight(FontWeight::BOLD)
                                                                .text_color(t.text)
                                                                .child(sub.handle.clone()),
                                                        )
                                                        .child(
                                                            div()
                                                                .w_full()
                                                                .truncate()
                                                                .text_size(px(10.5))
                                                                .text_color(t.text_dim)
                                                                .child(format!(
                                                                    "{}: {} · {}",
                                                                    self.tr("Узлов", "Nodes"),
                                                                    sub.count,
                                                                    truncate_str(&sub.url, 44)
                                                                )),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .flex_shrink_0()
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
                                                                .child(
                                                                    self.tr("Обновить", "Update"),
                                                                ),
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
                                                                            .retain(|s| {
                                                                                s.id != sid
                                                                            });
                                                                        this.state.servers.retain(
                                                                            |s| {
                                                                                s.sub_id.as_deref()
                                                                                    != Some(
                                                                                        sid.as_str(
                                                                                        ),
                                                                                    )
                                                                            },
                                                                        );
                                                                        this.state.save();
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                                .child(
                                                                    self.tr("Удалить", "Delete"),
                                                                ),
                                                        ),
                                                )
                                        }),
                                    )),
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
                    .p(px(12.0))
                    .bg(gpui::rgba(0x000000A6))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .w(px((m.width - 32.0).clamp(300.0, 760.0)))
                            .h(px(modal_max_h.min(480.0)))
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
                                    .flex_shrink_0()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .flex_wrap()
                                    .gap(px(6.0))
                                    .child(
                                        div()
                                            .text_size(px(14.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(t.text)
                                            .child(self.tr(
                                                "Журнал ядра tachyon-core",
                                                "tachyon-core Kernel Log",
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .items_center()
                                            .gap(px(6.0))
                                            .children(
                                                ["all", "debug", "info", "warn", "error"]
                                                    .into_iter()
                                                    .map(|flvl| {
                                                        let act = this_log_filter_eq(
                                                            &self.log_filter_level,
                                                            flvl,
                                                        );
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "log-flt-{flvl}"
                                                            )))
                                                            .px(px(7.0))
                                                            .py(px(3.0))
                                                            .rounded(px(5.0))
                                                            .cursor_pointer()
                                                            .bg(if act {
                                                                t.accent_bg
                                                            } else {
                                                                t.bg_elev
                                                            })
                                                            .border_1()
                                                            .border_color(if act {
                                                                t.accent_border
                                                            } else {
                                                                t.border
                                                            })
                                                            .text_size(px(10.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(if act {
                                                                t.accent
                                                            } else {
                                                                t.text_dim
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.log_filter_level =
                                                                        flvl.to_string();
                                                                    this.log_tail = this
                                                                        .vpn
                                                                        .get_log_tail_filtered(
                                                                            200, flvl,
                                                                        );
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child(if flvl == "all" {
                                                                self.tr("Все", "All").to_string()
                                                            } else {
                                                                flvl.to_uppercase()
                                                            })
                                                    }),
                                            )
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
                                                        this.log_tail =
                                                            this.vpn.get_log_tail_filtered(
                                                                200,
                                                                &this.log_filter_level,
                                                            );
                                                        let cnt = this
                                                            .log_tail
                                                            .lines()
                                                            .filter(|l| !l.trim().is_empty())
                                                            .count();
                                                        this.show_toast(if this.is_en() {
                                                            format!("Log refreshed: {cnt} lines")
                                                        } else {
                                                            format!("Лог обновлён: {cnt} строк")
                                                        });
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr("Обновить", "Refresh")),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-clear-log")
                                                    .px(px(10.0))
                                                    .py(px(4.0))
                                                    .rounded(px(6.0))
                                                    .bg(t.bg_elev)
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.red_bg))
                                                    .text_size(px(11.0))
                                                    .text_color(t.red)
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.vpn.clear_log_file();
                                                        this.log_tail.clear();
                                                        this.show_toast(
                                                            this.tr("Журнал очищен", "Log cleared"),
                                                        );
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr("Очистить", "Clear")),
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
                                                        this.show_toast(
                                                            this.tr("Лог скопирован", "Log copied"),
                                                        );
                                                        cx.notify();
                                                    }))
                                                    .child(self.tr("Копировать", "Copy")),
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
                                    .min_h(px(0.0))
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
                                        div()
                                            .w_full()
                                            .text_color(t.text_dim)
                                            .child(
                                                self.tr("Журнал пуст.", "Log is empty.")
                                                    .to_string(),
                                            )
                                            .into_any_element()
                                    } else {
                                        div()
                                            .w_full()
                                            .flex()
                                            .flex_col()
                                            .gap(px(2.0))
                                            .children(self.log_tail.lines().map(|line| {
                                                let col = if line.contains("[ERROR]")
                                                    || line.contains("[FATAL]")
                                                {
                                                    t.red
                                                } else if line.contains("[WARN]") {
                                                    t.amber
                                                } else if line.contains("[DEBUG]") {
                                                    t.text_dim
                                                } else {
                                                    t.text_soft
                                                };
                                                div()
                                                    .w_full()
                                                    .text_color(col)
                                                    .child(line.to_string())
                                            }))
                                            .into_any_element()
                                    }),
                            ),
                    )
                    .into_any_element(),
            ),
        }
    }
}

impl Render for TachyonApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = Theme::for_mode(self.state.light_theme);
        let vp = window.viewport_size();
        let width = f32::from(vp.width);
        let height = f32::from(vp.height);
        let narrow = width < 640.0;
        let m = LayoutMetrics {
            width,
            height,
            avail_w: (width - if narrow { 20.0 } else { 32.0 } - 8.0).max(260.0),
            narrow,
            compact: width < 960.0,
            short: height < 640.0,
            wide: width >= 1200.0,
            is_maximized: window.is_maximized(),
        };

        div()
            .id("tachyon-root")
            .size_full()
            .overflow_hidden()
            .bg(t.bg)
            .text_color(t.text)
            .relative()
            .flex()
            .flex_col()
            .child(self.render_titlebar(m, t, cx))
            .child(self.render_navbar(m, t, cx))
            .child(
                div()
                    .flex_1()
                    .min_h(px(0.0))
                    .w_full()
                    .overflow_hidden()
                    .child(match self.tab {
                        Tab::Tunnel => self.render_tunnel_tab(m, t, cx).into_any_element(),
                        Tab::Desync => self.render_desync_tab(m, t, cx).into_any_element(),
                        Tab::Routes => self.render_routes_tab(m, t, cx).into_any_element(),
                        Tab::Nodes => self.render_nodes_tab(m, t, cx).into_any_element(),
                        Tab::Traffic => self.render_traffic_tab(m, t, cx).into_any_element(),
                        Tab::Options => self.render_options_tab(m, t, cx).into_any_element(),
                    }),
            )
            .child(self.render_footer(m, t, cx))
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
                                .child(div().w(px(7.0)).h(px(7.0)).rounded(px(4.0)).bg(t.green))
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
            .children(self.render_modal_overlay(m, t, cx))
    }
}

fn pick_conf_files_native() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ps = r#"Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'Tachyon Profiles (*.conf;*.ovpn;*.json;*.txt)|*.conf;*.ovpn;*.json;*.txt|All files (*.*)|*.*'; $d.Multiselect = $true; if ($d.ShowDialog() -eq 'OK') { $d.FileNames -join "`n" }"#;
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

fn this_log_filter_eq(cur: &str, candidate: &str) -> bool {
    cur.trim().eq_ignore_ascii_case(candidate)
}

#[cfg(test)]
mod tests {
    use super::{adaptive_card_width, parse_custom_rule_entries, parse_duration_secs};

    #[test]
    fn test_adaptive_card_width_fits_all_viewports() {
        let gap = 8.0_f32;
        for vp_w in [460.0_f32, 620.0, 800.0, 940.0, 1120.0, 1440.0, 1920.0] {
            let narrow = vp_w < 640.0;
            let avail = (vp_w - if narrow { 20.0 } else { 32.0 } - 8.0).max(260.0);
            for (min_card, max_cols) in [(175.0_f32, 5usize), (255.0, 4), (220.0, 5)] {
                let card_w = adaptive_card_width(avail - 8.0, min_card, max_cols, gap);
                let inner_avail = (avail - 8.0).max(200.0);
                let cols = if inner_avail <= min_card + 20.0 {
                    1usize
                } else {
                    (((inner_avail + gap) / (min_card + gap)).floor() as usize).clamp(1, max_cols)
                };
                assert!(cols >= 1);
                let total_row_w = (cols as f32) * card_w + ((cols.saturating_sub(1)) as f32) * gap;
                assert!(
                    total_row_w <= inner_avail + 0.01,
                    "overflow at vp={vp_w}, avail={inner_avail}: cols={cols}, card_w={card_w}, row={total_row_w}"
                );
            }
        }
    }

    #[test]
    fn test_parse_custom_rule_entries() {
        assert_eq!(
            parse_custom_rule_entries("domain", "https://Example.COM/path?q=1"),
            vec![("domain".to_string(), "example.com".to_string())]
        );
        assert_eq!(
            parse_custom_rule_entries("domain", "example.com, 1.2.3.0/24, game.exe"),
            vec![
                ("domain".to_string(), "example.com".to_string()),
                ("cidr".to_string(), "1.2.3.0/24".to_string()),
                ("process".to_string(), "game.exe".to_string()),
            ]
        );
        assert_eq!(
            parse_custom_rule_entries("domain", "http://198.51.100.10:8443/api"),
            vec![("cidr".to_string(), "198.51.100.10".to_string())]
        );
        assert_eq!(
            parse_custom_rule_entries("cidr", "10.0.0.0/8, 192.168.1.1"),
            vec![
                ("cidr".to_string(), "10.0.0.0/8".to_string()),
                ("cidr".to_string(), "192.168.1.1".to_string()),
            ]
        );
        assert_eq!(
            parse_custom_rule_entries("process", r"C:\Games\Shooter\game.exe"),
            vec![("process".to_string(), "game.exe".to_string())]
        );
        assert_eq!(
            parse_custom_rule_entries("domain", "keyword:googlevideo"),
            vec![("domain".to_string(), "keyword:googlevideo".to_string())]
        );
    }

    #[test]
    fn test_parse_duration_secs() {
        assert_eq!(parse_duration_secs("60"), Some(60));
        assert_eq!(parse_duration_secs("60s"), Some(60));
        assert_eq!(parse_duration_secs("60с"), Some(60));
        assert_eq!(parse_duration_secs("10m"), Some(600));
        assert_eq!(parse_duration_secs("10м"), Some(600));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("2ч"), Some(7200));
        assert_eq!(parse_duration_secs("2"), Some(5));
        assert_eq!(parse_duration_secs("48h"), Some(86_400));
        assert_eq!(parse_duration_secs("0"), None);
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("abc"), None);
    }
}
