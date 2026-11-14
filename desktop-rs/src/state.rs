use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerNode {
    pub id: String,
    pub name: String,
    pub country: String,
    pub vless: String,
    #[serde(default)]
    pub sub_id: Option<String>,
    #[serde(default)]
    pub is_balancer: bool,
    #[serde(default)]
    pub balancer_mode: Option<String>,
    #[serde(default)]
    pub member_count: Option<usize>,
    #[serde(default)]
    pub ping_ms: Option<i64>,
    #[serde(default)]
    pub alive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SubscriptionMeta {
    #[serde(default)]
    pub title: String,
    #[serde(default, alias = "usedBytes")]
    pub used_bytes: u64,
    #[serde(default, alias = "totalBytes")]
    pub total_bytes: u64,
    #[serde(default, alias = "expireUnix")]
    pub expire_unix: u64,
    #[serde(default, alias = "supportUrl")]
    pub support_url: Option<String>,
    #[serde(default, alias = "webPageUrl")]
    pub web_page_url: Option<String>,
    #[serde(default)]
    pub announce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubscriptionItem {
    pub id: String,
    pub url: String,
    pub handle: String,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub meta: Option<SubscriptionMeta>,
}

pub type SubscriptionEntry = SubscriptionItem;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomRule {
    pub id: String,
    #[serde(default = "default_rule_type")]
    pub rule_type: String, // "domain" | "ip" | "cidr" | "process"
    pub value: String,
    #[serde(default = "default_rule_action")]
    pub action: String, // "vpn" | "desync" | "direct" | "block" | "NODE_<id>"
}

fn default_rule_type() -> String {
    "domain".to_string()
}

fn default_rule_action() -> String {
    "vpn".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VpnPrefs {
    #[serde(default = "default_mode")]
    pub mode: String, // "tun" | "proxy" | "block"
    #[serde(default = "default_route")]
    pub route: String, // "all" | "selective" | "desync" | "apps" | "apps-exclude"
    #[serde(default = "default_split_mode")]
    pub split_mode: String, // "include" | "exclude"
    #[serde(default = "default_dns")]
    pub dns: String, // "auto" | "cloudflare" | "google" | "quad9" | "adguard" | "yandex" | "custom"
    #[serde(default)]
    pub custom_dns: String,
    #[serde(default = "default_dns_bootstrap")]
    pub dns_bootstrap: String,
    #[serde(default = "default_true")]
    pub fake_ip: bool,
    #[serde(default = "default_dns_route_mode")]
    pub dns_route_mode: String, // "split_ru" | "proxy" | "direct"
    #[serde(default = "default_mtu")]
    pub tun_mtu: u32,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String, // "warn" | "info" | "debug" | "error"
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    #[serde(default = "default_true")]
    pub ru_bypass: bool,
    #[serde(default = "default_true")]
    pub sniff: bool,
    #[serde(default = "default_true")]
    pub strict_route: bool,
    #[serde(default)]
    pub adblock: bool,
    #[serde(default = "default_true")]
    pub tls_fragment: bool,
    #[serde(default)]
    pub relay_id: String,
    #[serde(default = "default_balancer_mode")]
    pub balancer_mode: String, // "stability" | "least_test" | "least_load" | "hedged" | "failover" | "sticky" | "weighted" | "passive" | "priority" | "throughput" | "quota" | "round_robin"
    #[serde(default = "default_balancer_pool")]
    pub balancer_pool: usize,
    #[serde(default = "default_balancer_tolerance")]
    pub balancer_tolerance: u32,
    #[serde(default = "default_balancer_quota")]
    pub balancer_quota_mib: u32,
    #[serde(default = "default_balancer_interval")]
    pub balancer_interval: String,
    #[serde(default = "default_dns_strategy")]
    pub dns_strategy: String, // "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
    #[serde(default = "default_true")]
    pub dns_reverse_mapping: bool,
    #[serde(default = "default_true")]
    pub route_find_process: bool,
    #[serde(default = "default_true")]
    pub route_fullcone_nat: bool,
    #[serde(default)]
    pub route_smart_queue: bool,
    #[serde(default = "default_tun_stack")]
    pub tun_stack: String, // "mixed" | "system" | "gvisor"
    #[serde(default)]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub tcp_multi_path: bool,
}

fn default_mode() -> String {
    "tun".to_string()
}
fn default_route() -> String {
    "all".to_string()
}
fn default_split_mode() -> String {
    "include".to_string()
}
fn default_dns() -> String {
    "auto".to_string()
}
fn default_dns_bootstrap() -> String {
    "77.88.8.8".to_string()
}
fn default_dns_route_mode() -> String {
    "split_ru".to_string()
}
fn default_mtu() -> u32 {
    1400
}
fn default_log_level() -> String {
    "warn".to_string()
}
fn default_true() -> bool {
    true
}
fn default_balancer_mode() -> String {
    "stability".to_string()
}
fn default_balancer_pool() -> usize {
    4
}
fn default_balancer_tolerance() -> u32 {
    80
}
fn default_balancer_quota() -> u32 {
    256
}
fn default_balancer_interval() -> String {
    "3m".to_string()
}
fn default_dns_strategy() -> String {
    "prefer_ipv4".to_string()
}
fn default_tun_stack() -> String {
    "mixed".to_string()
}

impl Default for VpnPrefs {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            route: default_route(),
            split_mode: default_split_mode(),
            dns: default_dns(),
            custom_dns: String::new(),
            dns_bootstrap: default_dns_bootstrap(),
            fake_ip: true,
            dns_route_mode: default_dns_route_mode(),
            tun_mtu: default_mtu(),
            allow_lan: false,
            log_level: default_log_level(),
            kill_switch: false,
            autostart: false,
            auto_connect: false,
            auto_reconnect: true,
            ru_bypass: true,
            sniff: true,
            strict_route: true,
            adblock: false,
            tls_fragment: true,
            relay_id: String::new(),
            balancer_mode: default_balancer_mode(),
            balancer_pool: default_balancer_pool(),
            balancer_tolerance: default_balancer_tolerance(),
            balancer_quota_mib: default_balancer_quota(),
            balancer_interval: default_balancer_interval(),
            dns_strategy: default_dns_strategy(),
            dns_reverse_mapping: true,
            route_find_process: true,
            route_fullcone_nat: true,
            route_smart_queue: false,
            tun_stack: default_tun_stack(),
            tcp_fast_open: false,
            tcp_multi_path: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DesyncPrefs {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_direct: bool,
    #[serde(default = "default_desync_preset")]
    pub preset: String, // "auto" | "youtube_discord" | "multi_disorder" | "fake_split" | "fake_disorder" | "tlsrec" | "multi_split" | "split" | "disorder" | "fake" | "oob" | "custom"
    #[serde(default = "default_desync_mode")]
    pub mode: String, // "auto" | "fake_disorder" | "fake_split" | "multi_disorder" | "multi_split" | "tlsrec" | "split" | "disorder" | "fake" | "oob"
    #[serde(default = "default_fooling")]
    pub fooling: String, // "md5sig+badsum" | "md5sig" | "badsum" | "badseq" | "ts" | "ttl"
    #[serde(default = "default_split_pos")]
    pub split_pos: String, // "1,sniext+1,host+1,midsld" | "sniext+1" | "midsld" | "1,midsld" | "2"
    #[serde(default = "default_true")]
    pub tlsrec_first: bool,
    #[serde(default)]
    pub seqovl: u32,
    #[serde(default)]
    pub syndata: bool,
    #[serde(default)]
    pub wsize: u32,
    #[serde(default)]
    pub wscale: Option<u8>,
    #[serde(default)]
    pub ipfrag: bool,
    #[serde(default)]
    pub udplen: u32,
    #[serde(default = "default_fake_ttl")]
    pub fake_ttl: u32,
    #[serde(default = "default_fake_sni")]
    pub fake_sni: String,
    #[serde(default = "default_repeats")]
    pub repeats: u32,
    #[serde(default)]
    pub split_delay_ms: u32,
    #[serde(default = "default_true")]
    pub udp_fake: bool,
    #[serde(default = "default_quic_repeats")]
    pub udp_repeats: u32,
    #[serde(default = "default_fake_ttl")]
    pub udp_fake_ttl: u32,
    #[serde(default = "default_true")]
    pub auto_tune: bool,
    #[serde(default)]
    pub block_quic: bool,
    // UI fine toggles
    #[serde(default = "default_tls_split_str")]
    pub tls_split: String,
    #[serde(default = "default_oob_str")]
    pub oob: String,
    #[serde(default = "default_true")]
    pub host_mixed_case: bool,
    #[serde(default = "default_true")]
    pub domain_padding: bool,
    #[serde(default = "default_true")]
    pub quic_fake: bool,
    #[serde(default = "default_quic_repeats")]
    pub quic_repeats: u32,
    #[serde(default = "default_true")]
    pub discord_udp_fake: bool,
    #[serde(default = "default_true")]
    pub stun_fake: bool,
    #[serde(default = "default_true")]
    pub anticheat_bypass: bool,
    #[serde(default = "default_true")]
    pub lists_override_game_bypass: bool,
}

fn default_desync_preset() -> String {
    "auto".to_string()
}
fn default_desync_mode() -> String {
    "auto".to_string()
}
fn default_fooling() -> String {
    "md5sig+badsum".to_string()
}
fn default_split_pos() -> String {
    "1,sniext+1,host+1,midsld".to_string()
}
fn default_fake_ttl() -> u32 {
    5
}
fn default_fake_sni() -> String {
    "www.google.com,rzd.ru,vk.com,ya.ru,max.ru".to_string()
}
fn default_repeats() -> u32 {
    6
}
fn default_quic_repeats() -> u32 {
    6
}
fn default_tls_split_str() -> String {
    "sni_mid".to_string()
}
fn default_oob_str() -> String {
    "tls_mid".to_string()
}

impl Default for DesyncPrefs {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_direct: true,
            preset: default_desync_preset(),
            mode: default_desync_mode(),
            fooling: default_fooling(),
            split_pos: default_split_pos(),
            tlsrec_first: true,
            seqovl: 0,
            syndata: false,
            wsize: 0,
            wscale: None,
            ipfrag: false,
            udplen: 0,
            fake_ttl: default_fake_ttl(),
            fake_sni: default_fake_sni(),
            repeats: default_repeats(),
            split_delay_ms: 0,
            udp_fake: true,
            udp_repeats: default_quic_repeats(),
            udp_fake_ttl: default_fake_ttl(),
            auto_tune: true,
            block_quic: false,
            tls_split: default_tls_split_str(),
            oob: default_oob_str(),
            host_mixed_case: true,
            domain_padding: true,
            quic_fake: true,
            quic_repeats: default_quic_repeats(),
            discord_udp_fake: true,
            stun_fake: true,
            anticheat_bypass: true,
            lists_override_game_bypass: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteCatalogItem {
    pub id: &'static str,
    pub name: &'static str,
    pub group: &'static str,
    pub desc: &'static str,
    pub default_action: &'static str, // "off" | "vpn" | "desync" | "direct" | "block"
}

pub const ROUTE_CATALOG: &[RouteCatalogItem] = &[
    // Базовые списки РФ и реестры маршрутизации
    RouteCatalogItem {
        id: "ru_domains",
        name: "Домены РФ (.ru / .рф / .su)",
        group: "Базовые списки РФ",
        desc: "Госуслуги, банки, маркетплейсы и российские сайты — всегда напрямую",
        default_action: "direct",
    },
    RouteCatalogItem {
        id: "geoip_ru",
        name: "IP-адреса и подсети РФ (GeoIP RU)",
        group: "Базовые списки РФ",
        desc: "Крупнейшие подсети российских провайдеров и дата-центров — напрямую",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "ru_only_inside",
        name: "Сервисы РФ (строго с российского IP)",
        group: "Базовые списки РФ",
        desc: "Банки, Госуслуги, ФНС, Мос.ру, РЖД, Кинопоиск, VK, Ozon, WB",
        default_action: "direct",
    },
    RouteCatalogItem {
        id: "ru_whitelist",
        name: "Белый список социально значимых ресурсов РФ",
        group: "Базовые списки РФ",
        desc: "Критическая инфраструктура, маркетплейсы, банки, госсервисы",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "ru_blocked",
        name: "Сводный реестр ограниченных в РФ ресурсов",
        group: "Базовые списки РФ",
        desc: "Объединённая база доменов и CIDR (Antifilter + Reestr + Community)",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "russia_inside",
        name: "ITDog Russia-Inside (расширенный список)",
        group: "Базовые списки РФ",
        desc: "Сервисы и CDN, замедляющиеся при работе из-за рубежа",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "antifilter",
        name: "Antifilter Community Domains",
        group: "Базовые списки РФ",
        desc: "Актуальный комьюнити-список доменов с ограниченным доступом",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "reestr",
        name: "Полный выгруженный реестр доменов",
        group: "Базовые списки РФ",
        desc: "Крупная база доменов из официальной выгрузки (высокое потребление ОЗУ)",
        default_action: "off",
    },
    // Видео, музыка и стриминг
    RouteCatalogItem {
        id: "youtube",
        name: "YouTube & Google Video",
        group: "Видео и стриминг",
        desc: "googlevideo.com, ytimg.com, youtubei, ggpht",
        default_action: "desync",
    },
    RouteCatalogItem {
        id: "twitch",
        name: "Twitch",
        group: "Видео и стриминг",
        desc: "twitch.tv, ttvnw.net, jtvnw.net, live-video.net",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "spotify",
        name: "Spotify",
        group: "Видео и стриминг",
        desc: "spotify.com, scdn.co, spotifycdn.com, audio-ak",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "netflix",
        name: "Netflix",
        group: "Видео и стриминг",
        desc: "netflix.com, nflxvideo.net, nflximg.net, nflxso.net",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "tiktok",
        name: "TikTok",
        group: "Видео и стриминг",
        desc: "tiktok.com, tiktokv.com, tiktokcdn.com, byteoversea.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "soundcloud",
        name: "SoundCloud",
        group: "Видео и стриминг",
        desc: "soundcloud.com, sndcdn.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "plex",
        name: "Plex Media",
        group: "Видео и стриминг",
        desc: "plex.tv, plex.direct, plexapp.com",
        default_action: "off",
    },
    // Мессенджеры и соцсети
    RouteCatalogItem {
        id: "discord",
        name: "Discord (Текст + Голос + CDN)",
        group: "Мессенджеры и соцсети",
        desc: "discord.com, discord.gg, discordapp.net, discord.media",
        default_action: "desync",
    },
    RouteCatalogItem {
        id: "telegram",
        name: "Telegram Messenger",
        group: "Мессенджеры и соцсети",
        desc: "telegram.org, t.me, telesco.pe и все подсети DC1–DC5",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "meta",
        name: "Instagram & Facebook (Meta)",
        group: "Мессенджеры и соцсети",
        desc: "instagram.com, cdninstagram.com, facebook.com, fbcdn.net, threads.net",
        default_action: "vpn",
    },
    RouteCatalogItem {
        id: "twitter",
        name: "X / Twitter",
        group: "Мессенджеры и соцсети",
        desc: "x.com, twitter.com, twimg.com, t.co",
        default_action: "vpn",
    },
    RouteCatalogItem {
        id: "whatsapp",
        name: "WhatsApp",
        group: "Мессенджеры и соцсети",
        desc: "whatsapp.com, whatsapp.net, wa.me",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "reddit",
        name: "Reddit",
        group: "Мессенджеры и соцсети",
        desc: "reddit.com, redd.it, redditmedia.com, redditstatic.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "linkedin",
        name: "LinkedIn",
        group: "Мессенджеры и соцсети",
        desc: "linkedin.com, licdn.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "pinterest",
        name: "Pinterest",
        group: "Мессенджеры и соцсети",
        desc: "pinterest.com, pinimg.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "4pda",
        name: "4PDA",
        group: "Мессенджеры и соцсети",
        desc: "4pda.to, 4pda.ru",
        default_action: "off",
    },
    // AI и нейросети
    RouteCatalogItem {
        id: "ai_all",
        name: "Все AI-сервисы (Сводный пакет)",
        group: "AI и нейросети",
        desc: "ChatGPT, Claude, Gemini, Grok, Perplexity, Copilot, Cursor, Midjourney, HuggingFace",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "openai",
        name: "OpenAI / ChatGPT / Sora",
        group: "AI и нейросети",
        desc: "chatgpt.com, openai.com, oaistatic.com, oaiusercontent.com",
        default_action: "vpn",
    },
    RouteCatalogItem {
        id: "claude",
        name: "Anthropic Claude",
        group: "AI и нейросети",
        desc: "claude.ai, anthropic.com",
        default_action: "vpn",
    },
    RouteCatalogItem {
        id: "gemini",
        name: "Google Gemini / AI Studio / NotebookLM",
        group: "AI и нейросети",
        desc: "gemini.google.com, aistudio.google.com, notebooklm.google.com, deepmind.google",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "grok",
        name: "xAI Grok",
        group: "AI и нейросети",
        desc: "grok.com, x.ai",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "perplexity",
        name: "Perplexity AI",
        group: "AI и нейросети",
        desc: "perplexity.ai, pplx.ai",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "copilot",
        name: "GitHub Copilot & Microsoft Copilot",
        group: "AI и нейросети",
        desc: "copilot.microsoft.com, githubcopilot.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "cursor",
        name: "Cursor AI & Windsurf",
        group: "AI и нейросети",
        desc: "cursor.sh, cursor.com, cursorapi.com, codeium.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "midjourney",
        name: "Midjourney & ElevenLabs",
        group: "AI и нейросети",
        desc: "midjourney.com, elevenlabs.io",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "huggingface",
        name: "HuggingFace & Replicate",
        group: "AI и нейросети",
        desc: "huggingface.co, hf.co, replicate.com",
        default_action: "off",
    },
    // Игры и лаунчеры
    RouteCatalogItem {
        id: "steam",
        name: "Steam (Магазин и CDN)",
        group: "Игры и лаунчеры",
        desc: "steampowered.com, steamcommunity.com, steamcontent.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "roblox",
        name: "Roblox",
        group: "Игры и лаунчеры",
        desc: "roblox.com, rbxcdn.com, роблокс-серверы",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "epicgames",
        name: "Epic Games & Fortnite",
        group: "Игры и лаунчеры",
        desc: "epicgames.com, unrealengine.com, fortnite.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "riot",
        name: "Riot Games (Valorant / LoL)",
        group: "Игры и лаунчеры",
        desc: "riotgames.com, leagueoflegends.com, playvalorant.com, riotcdn.net",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "genshin",
        name: "HoYoverse (Genshin / HSR / ZZZ)",
        group: "Игры и лаунчеры",
        desc: "hoyoverse.com, genshinimpact.com, mihoyo.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "battlenet",
        name: "Blizzard Battle.net",
        group: "Игры и лаунчеры",
        desc: "battle.net, blizzard.com, bnetcmsus-a.akamaihd.net",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "ea",
        name: "EA App / Origin / Apex",
        group: "Игры и лаунчеры",
        desc: "ea.com, origin.com, tnt-ea.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "ubisoft",
        name: "Ubisoft Connect",
        group: "Игры и лаунчеры",
        desc: "ubisoft.com, ubi.com, uplay.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "playstation",
        name: "PlayStation Network (PSN)",
        group: "Игры и лаунчеры",
        desc: "playstation.com, playstation.net, sonyentertainmentnetwork.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "xbox",
        name: "Xbox Live & Game Pass",
        group: "Игры и лаунчеры",
        desc: "xbox.com, xboxlive.com, gamepass.com",
        default_action: "off",
    },
    // Разработка, облака и трекеры
    RouteCatalogItem {
        id: "github",
        name: "GitHub",
        group: "Разработка и облака",
        desc: "github.com, githubusercontent.com, githubassets.com, ghcr.io",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "docker",
        name: "Docker Hub & Реестры контейнеров",
        group: "Разработка и облака",
        desc: "docker.io, docker.com, registry-1.docker.io, quay.io, k8s.io",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "jetbrains",
        name: "JetBrains & Загрузки IDE",
        group: "Разработка и облака",
        desc: "jetbrains.com, jetbrains.ai, plugins.jetbrains.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "figma",
        name: "Figma & Canva",
        group: "Разработка и облака",
        desc: "figma.com, canva.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "notion",
        name: "Notion",
        group: "Разработка и облака",
        desc: "notion.so, notion.site, notion-static.com",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "cloudflare",
        name: "Cloudflare CDN & WARP",
        group: "Разработка и облака",
        desc: "cloudflare.com, one.one.one.one, workers.dev, pages.dev",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "hetzner",
        name: "Hetzner Cloud (Подсети ДЦ)",
        group: "Разработка и облака",
        desc: "hetzner.com, hetzner.de, your-server.de и диапазоны IP",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "digitalocean",
        name: "DigitalOcean & AWS CloudFront",
        group: "Разработка и облака",
        desc: "digitalocean.com, digitaloceanspaces.com, cloudfront.net",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "torrents",
        name: "Торрент-трекеры (RuTracker, Rutor, NNM)",
        group: "Разработка и облака",
        desc: "Доступ к веб-зеркалам трекеров",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "speedtest",
        name: "Speedtest (Ookla / Fast / 2IP)",
        group: "Разработка и облака",
        desc: "speedtest.net, ooklaserver.net, fast.com, 2ip.ru",
        default_action: "off",
    },
    // Блокировка рекламы и телеметрии
    RouteCatalogItem {
        id: "ads_all",
        name: "Реклама, трекеры и аналитика (Сводный блок-лист)",
        group: "Блокировка и приватность",
        desc: "Крупная база рекламных сетей, баннеров и счётчиков (OISD + AdAway)",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "adguard",
        name: "Базовые домены рекламы (AdGuard Base)",
        group: "Блокировка и приватность",
        desc: "DoubleClick, Google Ads, Яндекс.Директ, мобильные рекламные SDK",
        default_action: "off",
    },
    RouteCatalogItem {
        id: "win_telemetry",
        name: "Телеметрия Windows и сборщики данных",
        group: "Блокировка и приватность",
        desc: "vortex.data.microsoft.com, settings-win.data.microsoft.com, watson",
        default_action: "off",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub servers: Vec<ServerNode>,
    #[serde(default, alias = "active_server_id")]
    pub active_id: String,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionItem>,
    #[serde(default)]
    pub vpn_prefs: VpnPrefs,
    #[serde(default)]
    pub desync_prefs: DesyncPrefs,
    #[serde(default = "default_route_actions", alias = "route_actions")]
    pub list_modes: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
    #[serde(default, alias = "selected_apps")]
    pub routed_apps: Vec<String>,
    #[serde(default)]
    pub light_theme: bool,
    #[serde(default = "default_language")]
    pub language: String,
}

fn default_language() -> String {
    "ru".to_string()
}

fn default_route_actions() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in ROUTE_CATALOG {
        if item.default_action != "off" {
            map.insert(item.id.to_string(), item.default_action.to_string());
        }
    }
    map
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            active_id: String::new(),
            subscriptions: Vec::new(),
            vpn_prefs: VpnPrefs::default(),
            desync_prefs: DesyncPrefs::default(),
            list_modes: default_route_actions(),
            custom_rules: Vec::new(),
            routed_apps: Vec::new(),
            light_theme: false,
            language: default_language(),
        }
    }
}

impl PersistedState {
    pub fn state_file_path() -> PathBuf {
        let base = crate::vpn::app_data_dir();
        let _ = fs::create_dir_all(&base);
        base.join("state.json")
    }

    pub fn normalize_servers(&mut self) -> bool {
        let mut changed = false;
        for srv in &mut self.servers {
            let detected = detect_country_code(&srv.name);
            let cur_cc = srv.country.trim().to_ascii_lowercase();
            if (cur_cc.is_empty() || cur_cc == "auto" || cur_cc == "xx")
                && detected != "auto"
                && detected != cur_cc
            {
                srv.country = detected.clone();
                changed = true;
            } else if detected != "auto" && has_regional_indicator_flags(&srv.name) && cur_cc != detected {
                srv.country = detected;
                changed = true;
            }
            let cleaned = clean_node_display_name(&srv.name);
            if !cleaned.is_empty() && cleaned != srv.name {
                srv.name = cleaned;
                changed = true;
            }
        }
        changed
    }

    pub fn load() -> Self {
        let path = Self::state_file_path();
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(mut parsed) = serde_json::from_str::<Self>(&raw) {
                for item in ROUTE_CATALOG {
                    parsed
                        .list_modes
                        .entry(item.id.to_string())
                        .or_insert_with(|| item.default_action.to_string());
                }
                if parsed.active_id.is_empty() && !parsed.servers.is_empty() {
                    parsed.active_id = parsed.servers[0].id.clone();
                }
                let normalized = parsed.normalize_servers();
                if !parsed.servers.is_empty() || !parsed.subscriptions.is_empty() {
                    if normalized {
                        parsed.save();
                    }
                    return parsed;
                }
                if migrate_from_webview_localstorage(&mut parsed) {
                    parsed.normalize_servers();
                    parsed.save();
                }
                return parsed;
            }
        }
        let mut state = Self::default();
        if migrate_from_webview_localstorage(&mut state) {
            state.normalize_servers();
            state.save();
        }
        state
    }

    pub fn save(&self) {
        let path = Self::state_file_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }

    pub fn active_server(&self) -> Option<&ServerNode> {
        if !self.active_id.is_empty() {
            if let Some(s) = self.servers.iter().find(|s| s.id == self.active_id) {
                return Some(s);
            }
        }
        self.servers.first()
    }

    pub fn active_rules_count(&self) -> usize {
        let cat_cnt = self
            .list_modes
            .values()
            .filter(|v| v.as_str() != "off")
            .count();
        cat_cnt + self.custom_rules.len() + self.routed_apps.len()
    }

    /// Build the JSON payload expected by `VpnManager::connect` (`ConnectOptions::parse`).
    pub fn build_connect_payload(&self, override_vless: Option<&str>) -> String {
        let route_pref = self.vpn_prefs.route.as_str();
        let has_any_server = self.active_server().is_some();
        let is_desync_only =
            route_pref == "desync" || route_pref == "desync-only" || !has_any_server;

        let active_vless = if let Some(ov) = override_vless {
            ov.to_string()
        } else if is_desync_only {
            String::new()
        } else {
            self.active_server()
                .map(|s| s.vless.clone())
                .unwrap_or_default()
        };

        let detour_vless = if !self.vpn_prefs.relay_id.is_empty() {
            self.servers
                .iter()
                .find(|s| s.id == self.vpn_prefs.relay_id)
                .map(|s| s.vless.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Map community lists in `{ "name": id, "action": action }` format expected by vpn.rs
        let mut community_lists: Vec<serde_json::Value> = Vec::new();
        let mut seen_lists = std::collections::HashSet::new();

        for (id, action) in &self.list_modes {
            let act = action.trim();
            if act.is_empty() || act == "off" {
                continue;
            }
            seen_lists.insert(id.clone());
            community_lists.push(serde_json::json!({
                "name": id,
                "action": act,
            }));
        }

        if self.vpn_prefs.ru_bypass {
            for id in ["ru_domains", "ru_only_inside"] {
                if !seen_lists.contains(id) {
                    seen_lists.insert(id.to_string());
                    community_lists.push(serde_json::json!({
                        "name": id,
                        "action": "direct",
                    }));
                }
            }
        }

        if self.vpn_prefs.adblock {
            for id in ["ads_all", "adguard", "win_telemetry"] {
                if !seen_lists.contains(id) {
                    seen_lists.insert(id.to_string());
                    community_lists.push(serde_json::json!({
                        "name": id,
                        "action": "block",
                    }));
                }
            }
        }

        // Map custom rules in `{ "type": ..., "value": ..., "action": ... }` format
        let custom_rules: Vec<serde_json::Value> = self
            .custom_rules
            .iter()
            .filter(|r| !r.value.trim().is_empty() && r.action != "off")
            .map(|r| {
                let rtype = if r.rule_type == "cidr" {
                    "ip"
                } else {
                    r.rule_type.as_str()
                };
                serde_json::json!({
                    "type": rtype,
                    "value": r.value.trim(),
                    "action": r.action,
                })
            })
            .collect();

        // Collect all referenced `NODE_<id>` outbounds from community lists and custom rules
        let mut extra_nodes: Vec<serde_json::Value> = Vec::new();
        let mut seen_extra_tags = std::collections::HashSet::new();
        let referenced_actions = community_lists
            .iter()
            .filter_map(|v| v.get("action").and_then(|a| a.as_str()))
            .chain(
                custom_rules
                    .iter()
                    .filter_map(|v| v.get("action").and_then(|a| a.as_str())),
            );
        for act in referenced_actions {
            if let Some(srv_id) = act.strip_prefix("NODE_") {
                if let Some(srv) = self.servers.iter().find(|s| s.id == srv_id) {
                    if seen_extra_tags.insert(act.to_string()) {
                        extra_nodes.push(serde_json::json!({
                            "tag": act,
                            "vless": srv.vless,
                        }));
                    }
                }
            }
        }

        let dns_val =
            if self.vpn_prefs.dns == "custom" && !self.vpn_prefs.custom_dns.trim().is_empty() {
                self.vpn_prefs.custom_dns.trim().to_string()
            } else {
                self.vpn_prefs.dns.clone()
            };

        let route_wire = if is_desync_only {
            "desync-only"
        } else {
            match route_pref {
                "apps" => {
                    if self.vpn_prefs.split_mode == "exclude" {
                        "apps-exclude"
                    } else {
                        "apps"
                    }
                }
                "apps-exclude" => "apps-exclude",
                "selective" => "selective",
                _ => "all",
            }
        };

        let app_rules: Vec<String> = self
            .routed_apps
            .iter()
            .filter(|a| !a.trim().is_empty())
            .map(|a| format!("PROCESS-NAME,{}", a.trim()))
            .collect();

        let balancer_json = serde_json::json!({
            "mode": self.vpn_prefs.balancer_mode,
            "pool": self.vpn_prefs.balancer_pool,
            "poolTolerance": self.vpn_prefs.balancer_tolerance,
            "tolerance": 50,
            "quotaMib": self.vpn_prefs.balancer_quota_mib,
            "interval": self.vpn_prefs.balancer_interval,
            "stickyHash": ["domain", "dest_ip", "process"]
        });

        let desync_json = serde_json::json!({
            "enabled": self.desync_prefs.enabled || is_desync_only,
            "autoDirect": self.desync_prefs.auto_direct,
            "preset": self.desync_prefs.preset,
            "mode": self.desync_prefs.mode,
            "fooling": self.desync_prefs.fooling,
            "splitPos": self.desync_prefs.split_pos,
            "tlsrecFirst": self.desync_prefs.tlsrec_first,
            "seqovl": self.desync_prefs.seqovl,
            "syndata": self.desync_prefs.syndata,
            "wsize": self.desync_prefs.wsize,
            "wscale": self.desync_prefs.wscale,
            "ipfrag": self.desync_prefs.ipfrag,
            "udplen": self.desync_prefs.udplen,
            "fakeTtl": self.desync_prefs.fake_ttl,
            "fakeSni": self.desync_prefs.fake_sni,
            "repeats": self.desync_prefs.repeats,
            "splitDelayMs": self.desync_prefs.split_delay_ms,
            "udpFake": self.desync_prefs.udp_fake && self.desync_prefs.quic_fake,
            "discordUdpFake": self.desync_prefs.discord_udp_fake,
            "udpRepeats": self.desync_prefs.quic_repeats.max(self.desync_prefs.udp_repeats),
            "udpFakeTtl": self.desync_prefs.udp_fake_ttl,
            "autoTune": self.desync_prefs.auto_tune,
            "blockQuic": self.desync_prefs.block_quic,
            "anticheatBypass": self.desync_prefs.anticheat_bypass,
            "listsOverrideGameBypass": self.desync_prefs.lists_override_game_bypass,
        });

        let payload = serde_json::json!({
            "vless": active_vless,
            "detourVless": detour_vless,
            "mode": self.vpn_prefs.mode,
            "route": route_wire,
            "rules": app_rules,
            "apps": self.routed_apps,
            "dns": dns_val,
            "dnsBootstrap": self.vpn_prefs.dns_bootstrap,
            "fakeIp": self.vpn_prefs.fake_ip,
            "dnsRouteMode": self.vpn_prefs.dns_route_mode,
            "dnsStrategy": self.vpn_prefs.dns_strategy,
            "dnsReverseMapping": self.vpn_prefs.dns_reverse_mapping,
            "routeFindProcess": self.vpn_prefs.route_find_process,
            "routeFullconeNat": self.vpn_prefs.route_fullcone_nat,
            "routeSmartQueue": self.vpn_prefs.route_smart_queue,
            "tunStack": self.vpn_prefs.tun_stack,
            "strictRoute": self.vpn_prefs.strict_route,
            "sniff": self.vpn_prefs.sniff,
            "tcpFastOpen": self.vpn_prefs.tcp_fast_open,
            "tcpMultiPath": self.vpn_prefs.tcp_multi_path,
            "mtu": self.vpn_prefs.tun_mtu,
            "allowLan": self.vpn_prefs.allow_lan,
            "proxyTlsFragment": self.vpn_prefs.tls_fragment,
            "logLevel": self.vpn_prefs.log_level,
            "killSwitch": self.vpn_prefs.kill_switch,
            "balancerMode": self.vpn_prefs.balancer_mode,
            "balancer": balancer_json,
            "communityLists": community_lists,
            "customRules": custom_rules,
            "extraNodes": extra_nodes,
            "desync": desync_json
        });

        payload.to_string()
    }
}

pub fn extract_host_port_from_uri(uri: &str) -> Option<(String, u16)> {
    let trimmed = uri.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("tachyon-balancer://")
        || trimmed.starts_with("balancer://")
    {
        return None;
    }
    if let Ok(node) = core_config::subscription::parse_share_uri(trimmed) {
        let server = node.get("server").and_then(|v| v.as_str())?.trim();
        if server.is_empty() {
            return None;
        }
        let port = node
            .get("server_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(443) as u16;
        return Some((server.to_string(), port));
    }
    let after_scheme = trimmed.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if let Some(rest) = host_port.strip_prefix('[') {
        let (ipv6, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);
        return Some((ipv6.to_string(), port));
    }
    if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(443);
        return Some((h.to_string(), port));
    }
    Some((host_port.to_string(), 443))
}

pub fn has_regional_indicator_flags(s: &str) -> bool {
    s.chars().any(|c| ('\u{1F1E6}'..='\u{1F1FF}').contains(&c))
}

/// Remove leading Unicode Regional Indicator flag pairs (e.g. `🇫🇮`, `🇪🇺`) and duplicate
/// leading 2-letter country prefixes when followed by the country name, so DirectWrite
/// never renders broken `fi`/`ee`/`eu` glyphs in front of node names.
pub fn clean_node_display_name(name: &str) -> String {
    let mut chars = name.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
            || c == '\u{FE0F}'
            || c == '\u{200D}'
            || c.is_whitespace()
        {
            chars.next();
        } else {
            break;
        }
    }
    let rest: String = chars.collect();
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        name.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn detect_country_code(name: &str) -> String {
    // 1. Check Unicode Regional Indicator pairs (`🇫🇮` = U+1F1EB U+1F1EE -> "fi")
    let chars: Vec<char> = name.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let c1 = chars[i] as u32;
        let c2 = chars[i + 1] as u32;
        if (0x1F1E6..=0x1F1FF).contains(&c1) && (0x1F1E6..=0x1F1FF).contains(&c2) {
            let b1 = b'a' + (c1 - 0x1F1E6) as u8;
            let b2 = b'a' + (c2 - 0x1F1E6) as u8;
            let code = String::from_utf8_lossy(&[b1, b2]).to_string();
            return if code == "uk" { "gb".to_string() } else { code };
        }
        i += 1;
    }

    // 2. Check Russian & English country / city names
    let lower = name.to_lowercase();
    for (needles, cc) in [
        (&["финлянд", "finland", "хельсинки", "helsinki"][..], "fi"),
        (&["эстон", "estonia", "таллин", "tallinn"][..], "ee"),
        (&["бельг", "belgium", "брюссел", "brussels"][..], "be"),
        (
            &[
                "великобритан",
                "британи",
                "англи",
                "лондон",
                "london",
                "united kingdom",
                "great britain",
            ][..],
            "gb",
        ),
        (
            &[
                "герман",
                "germany",
                "франкфурт",
                "frankfurt",
                "берлин",
                "berlin",
                "фалькенштайн",
                "нюрнберг",
            ][..],
            "de",
        ),
        (&["испан", "spain", "мадрид", "madrid", "барселон"][..], "es"),
        (&["итали", "italy", "милан", "milan", "рим", "rome"][..], "it"),
        (&["латви", "latvia", "рига", "riga"][..], "lv"),
        (&["литв", "lithuania", "вильнюс", "vilnius"][..], "lt"),
        (
            &[
                "нидерланд",
                "голланди",
                "netherlands",
                "holland",
                "амстердам",
                "amsterdam",
            ][..],
            "nl",
        ),
        (&["польш", "poland", "варшав", "warsaw"][..], "pl"),
        (
            &[
                "сша",
                "америк",
                "usa",
                "united states",
                "нью-йорк",
                "new york",
                "лос-анджелес",
                "майами",
                "чикаго",
                "даллас",
            ][..],
            "us",
        ),
        (&["турци", "turkey", "türkiye", "стамбул", "istanbul", "анталья"][..], "tr"),
        (&["франц", "france", "париж", "paris", "марсель"][..], "fr"),
        (&["швеци", "sweden", "стокгольм", "stockholm"][..], "se"),
        (&["швейцар", "switzerland", "цюрих", "zurich", "женев"][..], "ch"),
        (&["австри", "austria", "вена", "vienna"][..], "at"),
        (&["чехи", "czech", "прага", "prague"][..], "cz"),
        (&["беларус", "минск", "belarus", "minsk"][..], "by"),
        (&["казахст", "алмат", "астан", "kazakhstan", "almaty"][..], "kz"),
        (
            &[
                "росси",
                "russia",
                "москва",
                "moscow",
                "мск",
                "спб",
                "петербург",
                "питер",
                "новосибирск",
                "екатеринбург",
            ][..],
            "ru",
        ),
        (&["украин", "ukraine", "киев", "kyiv"][..], "ua"),
        (&["сингапур", "singapore"][..], "sg"),
        (&["япони", "japan", "токио", "tokyo", "осака"][..], "jp"),
        (&["коре", "korea", "сеул", "seoul"][..], "kr"),
        (&["гонконг", "hong kong", "hongkong"][..], "hk"),
        (&["оаэ", "эмират", "дубай", "dubai", "uae"][..], "ae"),
        (&["канад", "canada", "торонто", "toronto", "монреаль"][..], "ca"),
        (&["болгар", "bulgaria", "софия", "sofia"][..], "bg"),
        (&["румын", "romania", "бухарест", "bucharest"][..], "ro"),
        (&["венгр", "hungary", "будапешт", "budapest"][..], "hu"),
        (&["норвег", "norway", "осло", "oslo"][..], "no"),
        (&["дани", "denmark", "копенгаген", "copenhagen"][..], "dk"),
        (&["ирланд", "ireland", "дублин", "dublin"][..], "ie"),
        (&["израил", "israel", "тель-авив"][..], "il"),
        (&["инди", "india", "мумбаи", "mumbai"][..], "in"),
        (&["бразил", "brazil", "сан-паулу"][..], "br"),
        (&["австрал", "australia", "сидней", "sydney"][..], "au"),
        (&["молдов", "moldova", "кишин"][..], "md"),
        (&["грузи", "georgia", "тбилиси", "tbilisi"][..], "ge"),
        (&["армени", "armenia", "ереван", "yerevan"][..], "am"),
        (&["азербайджан", "azerbaijan", "баку", "baku"][..], "az"),
        (&["узбекист", "uzbekistan", "ташкент", "tashkent"][..], "uz"),
        (&["европ", "europe", "авто | белые списки", "автовыбор"][..], "eu"),
    ] {
        if needles.iter().any(|n| lower.contains(n)) {
            return cc.to_string();
        }
    }

    // 3. Fallback: explicit 2-letter ISO code token
    const KNOWN_CODES: &[&str] = &[
        "nl", "de", "fi", "us", "gb", "uk", "fr", "se", "pl", "tr", "kz", "ru", "ee", "lv", "lt",
        "ch", "at", "cz", "it", "es", "be", "sg", "jp", "kr", "hk", "ae", "ca", "bg", "ro", "hu",
        "no", "dk", "ie", "il", "in", "br", "au", "ua", "by", "md", "ge", "am", "az", "uz", "eu",
    ];
    for token in lower.split(|c: char| !c.is_alphabetic()) {
        if token.len() == 2 && KNOWN_CODES.contains(&token) {
            return if token == "uk" {
                "gb".to_string()
            } else {
                token.to_string()
            };
        }
    }
    "auto".to_string()
}

pub fn country_title_for_lang(cc: &str, lang: &str) -> &'static str {
    if lang == "en" {
        return match cc.to_ascii_lowercase().as_str() {
            "nl" => "Netherlands",
            "de" => "Germany",
            "fi" => "Finland",
            "us" => "United States",
            "gb" | "uk" => "United Kingdom",
            "fr" => "France",
            "se" => "Sweden",
            "pl" => "Poland",
            "tr" => "Turkey",
            "kz" => "Kazakhstan",
            "ru" => "Russia",
            "ee" => "Estonia",
            "lv" => "Latvia",
            "lt" => "Lithuania",
            "ch" => "Switzerland",
            "at" => "Austria",
            "cz" => "Czechia",
            "it" => "Italy",
            "es" => "Spain",
            "be" => "Belgium",
            "sg" => "Singapore",
            "jp" => "Japan",
            "kr" => "South Korea",
            "hk" => "Hong Kong",
            "ae" => "UAE",
            "ca" => "Canada",
            "bg" => "Bulgaria",
            "ro" => "Romania",
            "hu" => "Hungary",
            "no" => "Norway",
            "dk" => "Denmark",
            "ie" => "Ireland",
            "il" => "Israel",
            "in" => "India",
            "br" => "Brazil",
            "au" => "Australia",
            "ua" => "Ukraine",
            "by" => "Belarus",
            "md" => "Moldova",
            "ge" => "Georgia",
            "am" => "Armenia",
            "az" => "Azerbaijan",
            "uz" => "Uzbekistan",
            "eu" => "Europe",
            "xx" => "Balancer",
            _ => "Location",
        };
    }
    country_title_ru(cc)
}

pub fn country_title_ru(cc: &str) -> &'static str {
    match cc.to_ascii_lowercase().as_str() {
        "nl" => "Нидерланды",
        "de" => "Германия",
        "fi" => "Финляндия",
        "us" => "США",
        "gb" | "uk" => "Великобритания",
        "fr" => "Франция",
        "se" => "Швеция",
        "pl" => "Польша",
        "tr" => "Турция",
        "kz" => "Казахстан",
        "ru" => "Россия",
        "ee" => "Эстония",
        "lv" => "Латвия",
        "lt" => "Литва",
        "ch" => "Швейцария",
        "at" => "Австрия",
        "cz" => "Чехия",
        "it" => "Италия",
        "es" => "Испания",
        "be" => "Бельгия",
        "sg" => "Сингапур",
        "jp" => "Япония",
        "kr" => "Южная Корея",
        "hk" => "Гонконг",
        "ae" => "ОАЭ",
        "ca" => "Канада",
        "bg" => "Болгария",
        "ro" => "Румыния",
        "hu" => "Венгрия",
        "no" => "Норвегия",
        "dk" => "Дания",
        "ie" => "Ирландия",
        "il" => "Израиль",
        "in" => "Индия",
        "br" => "Бразилия",
        "au" => "Австралия",
        "ua" => "Украина",
        "by" => "Беларусь",
        "md" => "Молдова",
        "ge" => "Грузия",
        "am" => "Армения",
        "az" => "Азербайджан",
        "uz" => "Узбекистан",
        "eu" => "Европа",
        "xx" => "Балансировщик",
        _ => "Локация",
    }
}

pub fn detect_protocol_badge(uri: &str) -> &'static str {
    let trimmed = uri.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("tachyon-balancer://") || lower.starts_with("balancer://") {
        return "BALANCER";
    }
    if let Some(rest) = trimmed.strip_prefix("tachyon-node://") {
        let b64_part = rest.split('#').next().unwrap_or(rest).trim();
        if let Ok(bytes) = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b64_part,
        )
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_part)
        }) && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(ty) = val.get("type").and_then(|v| v.as_str())
        {
            return match ty.to_ascii_lowercase().as_str() {
                "urltest" | "selector" => "BALANCER",
                "chain" => "CHAIN",
                "wireguard" => {
                    if val.get("jc").is_some()
                        || val.get("h1").is_some()
                        || val.get("i1").is_some()
                        || val.get("header_protection_key").is_some()
                    {
                        "AWG"
                    } else {
                        "WG"
                    }
                }
                "hysteria2" | "hysteria" => "HY2",
                "tuic" => "TUIC",
                "wdtt" => {
                    if val.get("mode").and_then(|m| m.as_str()) == Some("csqtt") {
                        "CSQTT"
                    } else {
                        "WDTT"
                    }
                }
                "tewfai" => "TEWFAI",
                "mieru" => "MIERU",
                "anytls" => "ANYTLS",
                "shadowtls" => "SHADOWTLS",
                "naive" => "NAIVE",
                "trusttunnel" => "TRUSTTUNNEL",
                "masque" => "MASQUE",
                "openconnect" => "OPENCONNECT",
                "snell" => "SNELL",
                "mtproto" => "MTPROTO",
                "fptn" => "FPTN",
                "sudoku" => "SUDOKU",
                "ssh" => "SSH",
                "tor" => "TOR",
                "tailscale" => "TAILSCALE",
                "shadowsocks" => "SS",
                "trojan" => "TROJAN",
                "vmess" => "VMESS",
                "vless" => "VLESS",
                "socks" => "SOCKS5",
                "http" => "HTTP",
                _ => "PROXY",
            };
        }
        return "NODE";
    }
    if lower.starts_with("awg://") || lower.starts_with("amneziawg://") || lower.starts_with("vpn://") {
        "AWG"
    } else if lower.starts_with("wg://") || lower.starts_with("wireguard://") {
        "WG"
    } else if lower.starts_with("hy2://")
        || lower.starts_with("hysteria2://")
        || lower.starts_with("hysteria://")
        || lower.starts_with("hy://")
    {
        "HY2"
    } else if lower.starts_with("tuic://") {
        "TUIC"
    } else if lower.starts_with("qwdtt://") {
        "QWDTT"
    } else if lower.starts_with("csqtt://") {
        "CSQTT"
    } else if lower.starts_with("wdtt://") {
        "WDTT"
    } else if lower.starts_with("tewfai://") {
        "TEWFAI"
    } else if lower.starts_with("mieru://") || lower.starts_with("mierus://") {
        "MIERU"
    } else if lower.starts_with("anytls://") {
        "ANYTLS"
    } else if lower.starts_with("shadowtls://") || lower.starts_with("stls://") {
        "SHADOWTLS"
    } else if lower.starts_with("naive+") || lower.starts_with("naive://") {
        "NAIVE"
    } else if lower.starts_with("trusttunnel://") {
        "TRUSTTUNNEL"
    } else if lower.starts_with("masque://") {
        "MASQUE"
    } else if lower.starts_with("openconnect://") || lower.starts_with("anyconnect://") {
        "OPENCONNECT"
    } else if lower.starts_with("snell://") {
        "SNELL"
    } else if lower.starts_with("mtproto://") || lower.starts_with("tg://") {
        "MTPROTO"
    } else if lower.starts_with("fptn:") || lower.starts_with("fptnb:") || lower.starts_with("fptn://") {
        "FPTN"
    } else if lower.starts_with("sudoku://") {
        "SUDOKU"
    } else if lower.starts_with("ssh://") {
        "SSH"
    } else if lower.starts_with("tor://") {
        "TOR"
    } else if lower.starts_with("tailscale://") {
        "TAILSCALE"
    } else if lower.starts_with("trojan://") {
        "TROJAN"
    } else if lower.starts_with("vmess://") {
        "VMESS"
    } else if lower.starts_with("ss://") || lower.starts_with("shadowsocks://") {
        "SS"
    } else if lower.starts_with("socks5://") || lower.starts_with("socks://") || lower.starts_with("socks5h://") {
        "SOCKS5"
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        "HTTP"
    } else if lower.contains("type=xhttp") || lower.contains("type=splithttp") {
        "XHTTP"
    } else if lower.contains("security=reality") {
        "REALITY"
    } else if lower.contains("type=ws") {
        "WS"
    } else if lower.contains("type=grpc") {
        "GRPC"
    } else if lower.starts_with("vless://") {
        "VLESS"
    } else {
        "PROXY"
    }
}

/// Migrate user servers, subscriptions, active server, and rules from the previous WebView2
/// `localStorage` LevelDB (`%LOCALAPPDATA%\Tachyon\webview\EBWebView\Default\Local Storage\leveldb`)
/// so upgrading from the wry/WebView2 version to the native GPUI build preserves user data.
fn migrate_from_webview_localstorage(state: &mut PersistedState) -> bool {
    let mut leveldb_dirs: Vec<PathBuf> = Vec::new();
    let data = crate::vpn::app_data_dir();
    leveldb_dirs.push(
        data.join("webview")
            .join("EBWebView")
            .join("Default")
            .join("Local Storage")
            .join("leveldb"),
    );
    leveldb_dirs.push(data.join("Local Storage").join("leveldb"));

    for dir in leveldb_dirs {
        if !dir.is_dir() {
            continue;
        }
        if extract_legacy_webview_state(&dir, state) {
            return true;
        }
    }
    false
}

fn extract_legacy_webview_state(dir: &std::path::Path, state: &mut PersistedState) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("ldb") || ext.eq_ignore_ascii_case("log"))
                .unwrap_or(false)
        })
        .collect();

    files.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());

    let mut found_servers: Option<Vec<ServerNode>> = None;
    let mut found_subs: Option<Vec<SubscriptionItem>> = None;
    let mut found_active_id: Option<String> = None;
    let mut found_lists: Option<BTreeMap<String, String>> = None;
    let mut found_custom_rules: Option<Vec<CustomRule>> = None;

    for file in files {
        let Ok(bytes) = fs::read(&file) else {
            continue;
        };
        scan_leveldb_bytes(
            &bytes,
            &mut found_servers,
            &mut found_subs,
            &mut found_active_id,
            &mut found_lists,
            &mut found_custom_rules,
        );
    }

    let mut migrated = false;
    if let Some(srvs) = found_servers {
        if !srvs.is_empty() {
            state.servers = srvs;
            migrated = true;
        }
    }
    if let Some(subs) = found_subs {
        if !subs.is_empty() {
            state.subscriptions = subs;
            migrated = true;
        }
    }
    if let Some(aid) = found_active_id {
        if state.servers.iter().any(|s| s.id == aid) {
            state.active_id = aid;
        }
    }
    if let Some(lists) = found_lists {
        for (k, v) in lists {
            state.list_modes.insert(k, v);
        }
    }
    if let Some(rules) = found_custom_rules {
        if !rules.is_empty() {
            state.custom_rules = rules;
        }
    }
    if state.active_id.is_empty() && !state.servers.is_empty() {
        state.active_id = state.servers[0].id.clone();
    }
    migrated
}

fn scan_leveldb_bytes(
    bytes: &[u8],
    found_servers: &mut Option<Vec<ServerNode>>,
    found_subs: &mut Option<Vec<SubscriptionItem>>,
    found_active_id: &mut Option<String>,
    found_lists: &mut Option<BTreeMap<String, String>>,
    found_custom_rules: &mut Option<Vec<CustomRule>>,
) {
    for needle in [b"tachyon.servers".as_slice(), b"tachyon.subs".as_slice()] {
        let mut pos = 0;
        while pos + needle.len() < bytes.len() {
            let Some(rel) = bytes[pos..].windows(needle.len()).position(|w| w == needle) else {
                break;
            };
            let hit = pos + rel + needle.len();
            pos = hit;

            let window_end = (hit + 256 * 1024).min(bytes.len());
            let slice = &bytes[hit..window_end];
            if let Some(arr_start) = slice.iter().position(|&b| b == b'[') {
                if let Some(json_str) = extract_balanced_json_array(&slice[arr_start..]) {
                    if needle == b"tachyon.servers" {
                        if let Ok(vals) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str)
                        {
                            let mut parsed = Vec::new();
                            for v in vals {
                                let id = v
                                    .get("id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let vless = v
                                    .get("vless")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if id.is_empty() || vless.is_empty() {
                                    continue;
                                }
                                let name = v
                                    .get("name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("Узел")
                                    .to_string();
                                let country = v
                                    .get("country")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("xx")
                                    .to_string();
                                let sub_id = v
                                    .get("subId")
                                    .or_else(|| v.get("sub_id"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let is_balancer = v
                                    .get("isBalancer")
                                    .and_then(|x| x.as_bool())
                                    .unwrap_or(false);
                                let balancer_mode = v
                                    .get("balancerMode")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let member_count = v
                                    .get("memberCount")
                                    .and_then(|x| x.as_u64())
                                    .map(|n| n as usize);
                                let ping_ms = v.get("ping").and_then(|x| x.as_i64());
                                let alive = v.get("alive").and_then(|x| x.as_bool());
                                parsed.push(ServerNode {
                                    id,
                                    name,
                                    country,
                                    vless,
                                    sub_id,
                                    is_balancer,
                                    balancer_mode,
                                    member_count,
                                    ping_ms,
                                    alive,
                                });
                            }
                            if !parsed.is_empty() {
                                *found_servers = Some(parsed);
                            }
                        }
                    } else if needle == b"tachyon.subs" {
                        if let Ok(vals) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str)
                        {
                            let mut parsed = Vec::new();
                            for v in vals {
                                let id = v
                                    .get("id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let url = v
                                    .get("url")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if id.is_empty() || url.is_empty() {
                                    continue;
                                }
                                let handle = v
                                    .get("handle")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(&url)
                                    .to_string();
                                let count =
                                    v.get("count").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                                parsed.push(SubscriptionItem {
                                    id,
                                    url,
                                    handle,
                                    count,
                                    updated_at: "Из прошлой версии".to_string(),
                                    meta: None,
                                });
                            }
                            if !parsed.is_empty() {
                                *found_subs = Some(parsed);
                            }
                        }
                    }
                }
            }
        }
    }

    let lists_needle = b"tachyon.community_lists_v1";
    let mut pos = 0;
    while pos + lists_needle.len() < bytes.len() {
        let Some(rel) = bytes[pos..]
            .windows(lists_needle.len())
            .position(|w| w == lists_needle)
        else {
            break;
        };
        let hit = pos + rel + lists_needle.len();
        pos = hit;
        let window_end = (hit + 64 * 1024).min(bytes.len());
        let slice = &bytes[hit..window_end];
        if let Some(obj_start) = slice.iter().position(|&b| b == b'{') {
            if let Some(json_str) = extract_balanced_json_object(&slice[obj_start..]) {
                if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(&json_str) {
                    if !map.is_empty() {
                        *found_lists = Some(map);
                    }
                }
            }
        }
    }

    let rules_needle = b"tachyon.custom_route_rules_v1";
    let mut pos = 0;
    while pos + rules_needle.len() < bytes.len() {
        let Some(rel) = bytes[pos..]
            .windows(rules_needle.len())
            .position(|w| w == rules_needle)
        else {
            break;
        };
        let hit = pos + rel + rules_needle.len();
        pos = hit;
        let window_end = (hit + 64 * 1024).min(bytes.len());
        let slice = &bytes[hit..window_end];
        if let Some(arr_start) = slice.iter().position(|&b| b == b'[') {
            if let Some(json_str) = extract_balanced_json_array(&slice[arr_start..]) {
                if let Ok(vals) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                    let mut parsed = Vec::new();
                    for (idx, v) in vals.into_iter().enumerate() {
                        let value = v
                            .get("value")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if value.is_empty() {
                            continue;
                        }
                        let rule_type = v
                            .get("type")
                            .and_then(|x| x.as_str())
                            .unwrap_or("domain")
                            .to_string();
                        let action = v
                            .get("action")
                            .and_then(|x| x.as_str())
                            .unwrap_or("vpn")
                            .to_string();
                        parsed.push(CustomRule {
                            id: format!("migrated-rule-{}", idx + 1),
                            rule_type,
                            value,
                            action,
                        });
                    }
                    if !parsed.is_empty() {
                        *found_custom_rules = Some(parsed);
                    }
                }
            }
        }
    }

    let active_needle = b"tachyon.active";
    let mut pos = 0;
    while pos + active_needle.len() < bytes.len() {
        let Some(rel) = bytes[pos..]
            .windows(active_needle.len())
            .position(|w| w == active_needle)
        else {
            break;
        };
        let hit = pos + rel + active_needle.len();
        pos = hit;
        let slice = &bytes[hit..(hit + 128).min(bytes.len())];
        if let Some(s_pos) = slice.windows(2).position(|w| w == b"s-") {
            let tail = &slice[s_pos..];
            let id_bytes: Vec<u8> = tail
                .iter()
                .copied()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
                .collect();
            if id_bytes.len() >= 3 {
                if let Ok(s) = String::from_utf8(id_bytes) {
                    *found_active_id = Some(s);
                }
            }
        }
    }
}

fn extract_balanced_json_array(slice: &[u8]) -> Option<String> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (idx, &b) in slice.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return std::str::from_utf8(&slice[..=idx])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_balanced_json_object(slice: &[u8]) -> Option<String> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (idx, &b) in slice.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return std::str::from_utf8(&slice[..=idx])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            _ => {}
        }
    }
    None
}
