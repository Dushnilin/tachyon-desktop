/* ============================================================
   Tachyon Client – Конфигурация приложения
   ============================================================ */
window.TACHYON_CONFIG = {
  version: "0.3.2",
  core: "tachyon-core (pure-Rust)",
  github: "https://github.com/Dushnilin/tachyon-desktop",

  // Праздничное оформление: 'auto' – по дате; либо 'none'
  holiday: "none",
  holidayDates: {},

  // Профили DNS-резолвера
  dnsOptions: [
    { id: "auto", label: "Автоматически (быстрый локальный)" },
    { id: "cloudflare", label: "Cloudflare DoH (1.1.1.1)" },
    { id: "google", label: "Google DoH (8.8.8.8)" },
    { id: "adguard", label: "AdGuard DoH (блокировка рекламы)" }
  ]
};
