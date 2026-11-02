/* ============================================================
   Tachyon Client – Сервис-слой и нативный мост к tachyon-core
   ============================================================ */
window.API = (() => {
  const host = window.chrome && window.chrome.webview ? window.chrome.webview : null;
  const SUBS_KEY = "tachyon.subscriptions";
  const CUSTOM_KEY = "tachyon.custom_nodes";
  const PREFS_KEY = "tachyon.vpnprefs";
  const ACTIVE_SERVER_KEY = "tachyon.active_server_id";

  /* ---------- Подписки (Multi-Subscription Manager) ---------- */
  function getSubscriptions() {
    try {
      const list = JSON.parse(localStorage.getItem(SUBS_KEY) || "[]");
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  function saveSubscriptions(list) {
    try {
      localStorage.setItem(SUBS_KEY, JSON.stringify(list || []));
    } catch {}
    return list;
  }

  function getCustomNodes() {
    try {
      const list = JSON.parse(localStorage.getItem(CUSTOM_KEY) || "[]");
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  function saveCustomNodes(list) {
    try {
      localStorage.setItem(CUSTOM_KEY, JSON.stringify(list || []));
    } catch {}
    return list;
  }

  function getAllServers() {
    const all = [];
    const subs = getSubscriptions();
    subs.forEach(sub => {
      if (sub.enabled !== false && Array.isArray(sub.servers)) {
        sub.servers.forEach(s => {
          all.push({
            ...s,
            subId: sub.id,
            subName: sub.name || "Подписка"
          });
        });
      }
    });

    const customs = getCustomNodes();
    customs.forEach(c => {
      all.push({
        ...c,
        subId: "custom",
        subName: "Свои узлы",
        custom: true
      });
    });

    return all;
  }

  /* ---------- Открыть внешнюю ссылку ---------- */
  function openExternal(url) {
    if (host) host.postMessage("open:" + url);
    else window.open(url, "_blank");
  }

  /* ---------- Нативный мост к C# и ядру tachyon-core ---------- */
  const hasNativeVpn = !!host;
  const vpnListeners = [];
  const subListeners = [];
  const appsListListeners = [];
  const logTailListeners = [];
  const updateListeners = [];
  const trayListeners = [];
  const connListeners = [];
  const diagStepListeners = [];
  const diagDoneListeners = [];
  const hotkeysBusyListeners = [];
  const coreUpdateListeners = [];
  const coreVersionListeners = [];
  const listsUpdateListeners = [];
  const speedtestProgressListeners = [];

  const pongWaiters = new Map();
  let pingSeq = 0;
  let geoWaiter = null;
  let probeWaiter = null;
  let warpWaiter = null;
  let exitGeoWaiter = null;
  let dnsBenchWaiter = null;
  let diagMatrixWaiter = null;
  let speedtestWaiter = null;

  if (host) {
    host.addEventListener("message", (e) => {
      const d = e.data;
      if (typeof d !== "string") return;

      if (d.startsWith("vpn:")) {
        let obj;
        try { obj = JSON.parse(d.slice(4)); } catch { return; }
        vpnListeners.forEach(fn => { try { fn(obj); } catch {} });
      } else if (d.startsWith("sub:")) {
        let obj;
        try { obj = JSON.parse(d.slice(4)); } catch { return; }
        subListeners.forEach(fn => { try { fn(obj); } catch {} });
      } else if (d.startsWith("apps:list:")) {
        try {
          const arr = JSON.parse(d.slice(10));
          appsListListeners.forEach(fn => { try { fn(arr); } catch {} });
        } catch {}
      } else if (d.startsWith("log:tail:")) {
        try {
          const j = JSON.parse(d.slice(9));
          logTailListeners.forEach(fn => { try { fn(j.tail); } catch {} });
        } catch {}
      } else if (d.startsWith("pong:")) {
        const parts = d.split(":");
        const id = parts[1];
        const ms = parseInt(parts[2], 10);
        const w = pongWaiters.get(id);
        if (w) {
          pongWaiters.delete(id);
          w(Number.isFinite(ms) && ms >= 0 ? ms : null);
        }
      } else if (d.startsWith("update:")) {
        const rest = d.slice(7);
        if (rest.startsWith("available:")) {
          let info = null; try { info = JSON.parse(rest.slice(10)); } catch {}
          emitUpdate({ type: "available", info });
        } else if (rest.startsWith("ready:")) {
          let info = null; try { info = JSON.parse(rest.slice(6)); } catch {}
          emitUpdate({ type: "ready", info });
        } else if (rest.startsWith("progress:")) {
          emitUpdate({ type: "progress", percent: parseInt(rest.slice(9), 10) || 0 });
        } else if (rest === "installing") {
          emitUpdate({ type: "installing" });
        } else if (rest === "none") {
          emitUpdate({ type: "none" });
        } else if (rest.startsWith("error:")) {
          emitUpdate({ type: "error", message: rest.slice(6) });
        }
      } else if (d.startsWith("tray:")) {
        const cmd = d.slice(5);
        trayListeners.forEach(fn => { try { fn(cmd); } catch {} });
      } else if (d.startsWith("conn:data:")) {
        let obj = null; try { obj = JSON.parse(d.slice(10)); } catch {}
        if (obj) connListeners.forEach(fn => { try { fn(obj); } catch {} });
      } else if (d.startsWith("diag:step:")) {
        let obj = null; try { obj = JSON.parse(d.slice(10)); } catch {}
        if (obj) diagStepListeners.forEach(fn => { try { fn(obj); } catch {} });
      } else if (d === "diag:done") {
        diagDoneListeners.forEach(fn => { try { fn(); } catch {} });
      } else if (d.startsWith("geo:sites:")) {
        let arr = []; try { arr = JSON.parse(d.slice(10)); } catch {}
        if (geoWaiter) geoWaiter(arr);
      } else if (d.startsWith("probe:")) {
        const ms = parseInt(d.slice(6), 10);
        if (probeWaiter) probeWaiter(Number.isFinite(ms) && ms > 0 ? ms : null);
      } else if (d.startsWith("hotkeys:busy:")) {
        const keys = d.slice(13).trim();
        hotkeysBusyListeners.forEach(fn => { try { fn(keys); } catch {} });
      } else if (d.startsWith("core:version:")) {
        const ver = d.slice(13).trim();
        coreVersionListeners.forEach(fn => { try { fn(ver); } catch {} });
      } else if (d.startsWith("core-update:")) {
        const rest = d.slice(12);
        if (rest.startsWith("available:")) {
          let info = null; try { info = JSON.parse(rest.slice(10)); } catch {}
          coreUpdateListeners.forEach(fn => { try { fn({ type: "available", info }); } catch {} });
        } else if (rest.startsWith("up-to-date:")) {
          let info = null; try { info = JSON.parse(rest.slice(11)); } catch {}
          coreUpdateListeners.forEach(fn => { try { fn({ type: "up-to-date", info }); } catch {} });
        } else if (rest.startsWith("progress:")) {
          const percent = parseInt(rest.slice(9), 10) || 0;
          coreUpdateListeners.forEach(fn => { try { fn({ type: "progress", percent }); } catch {} });
        } else if (rest.startsWith("done:")) {
          let info = null; try { info = JSON.parse(rest.slice(5)); } catch {}
          coreUpdateListeners.forEach(fn => { try { fn({ type: "done", info }); } catch {} });
        } else if (rest.startsWith("error:")) {
          coreUpdateListeners.forEach(fn => { try { fn({ type: "error", message: rest.slice(6) }); } catch {} });
        }
      } else if (d.startsWith("lists-update:")) {
        const rest = d.slice(13);
        if (rest.startsWith("progress:")) {
          listsUpdateListeners.forEach(fn => { try { fn({ type: "progress", text: rest.slice(9) }); } catch {} });
        } else if (rest.startsWith("done:")) {
          listsUpdateListeners.forEach(fn => { try { fn({ type: "done", text: rest.slice(5) }); } catch {} });
        } else if (rest.startsWith("error:")) {
          listsUpdateListeners.forEach(fn => { try { fn({ type: "error", message: rest.slice(6) }); } catch {} });
        }
      } else if (d.startsWith("warp:result:")) {
        let obj = { ok: false }; try { obj = JSON.parse(d.slice(12)); } catch {}
        if (warpWaiter) { const w = warpWaiter; warpWaiter = null; w(obj); }
      } else if (d.startsWith("exit:geo:")) {
        let obj = { ok: false }; try { obj = JSON.parse(d.slice(9)); } catch {}
        if (exitGeoWaiter) { const w = exitGeoWaiter; exitGeoWaiter = null; w(obj); }
      } else if (d.startsWith("dns:bench:")) {
        let obj = { results: [] }; try { obj = JSON.parse(d.slice(10)); } catch {}
        if (dnsBenchWaiter) { const w = dnsBenchWaiter; dnsBenchWaiter = null; w(obj); }
      } else if (d.startsWith("diag:matrix:")) {
        let obj = { items: [] }; try { obj = JSON.parse(d.slice(12)); } catch {}
        if (diagMatrixWaiter) { const w = diagMatrixWaiter; diagMatrixWaiter = null; w(obj); }
      } else if (d.startsWith("speedtest:progress:")) {
        let obj = null; try { obj = JSON.parse(d.slice(19)); } catch {}
        if (obj) speedtestProgressListeners.forEach(fn => { try { fn(obj); } catch {} });
      } else if (d.startsWith("speedtest:result:")) {
        let obj = { ok: false }; try { obj = JSON.parse(d.slice(17)); } catch {}
        if (speedtestWaiter) { const w = speedtestWaiter; speedtestWaiter = null; w(obj); }
      }
    });
  }

  function emitUpdate(ev) {
    updateListeners.forEach(fn => { try { fn(ev); } catch {} });
  }

  function onVpn(fn) { vpnListeners.push(fn); }
  function onSub(fn) { subListeners.push(fn); }
  function onAppsList(fn) { appsListListeners.push(fn); }
  function onLogTail(fn) { logTailListeners.push(fn); }
  function onUpdate(fn) { updateListeners.push(fn); }
  function onTray(fn) { trayListeners.push(fn); }
  function onConnData(fn) { connListeners.push(fn); }
  function onDiagStep(fn) { diagStepListeners.push(fn); }
  function onDiagDone(fn) { diagDoneListeners.push(fn); }
  function onHotkeysBusy(fn) { hotkeysBusyListeners.push(fn); }
  function onCoreUpdate(fn) { coreUpdateListeners.push(fn); }
  function onCoreVersion(fn) { coreVersionListeners.push(fn); }
  function onListsUpdate(fn) { listsUpdateListeners.push(fn); }
  function onSpeedtestProgress(fn) { speedtestProgressListeners.push(fn); }

  function refreshLists(namesArr) {
    if (!host) return;
    const csv = Array.isArray(namesArr) && namesArr.length ? namesArr.join(",") : "";
    host.postMessage(csv ? ("lists:refresh:" + csv) : "lists:refresh");
  }

  function vpnConnect(optsOrVless) {
    if (!host) return;
    const opts = typeof optsOrVless === "string"
      ? { vless: optsOrVless, mode: "tun", route: "all", apps: [] }
      : { mode: "tun", route: "all", apps: [], ...optsOrVless };
    host.postMessage("vpn:connect:" + JSON.stringify(opts));
  }

  function vpnDisconnect() {
    if (host) host.postMessage("vpn:disconnect");
  }

  function importSubscription(input) {
    if (host) host.postMessage("vpn:sub:" + input);
  }

  function openLog() {
    if (host) host.postMessage("log:open");
  }

  function requestAppsList() {
    if (host) host.postMessage("apps:list");
  }

  function requestLogTail() {
    if (host) host.postMessage("log:tail");
  }

  function updateCheck() {
    if (host) host.postMessage("update:check");
  }

  function updateInstall() {
    if (host) host.postMessage("update:install");
  }

  function coreUpdateCheck() {
    if (host) host.postMessage("core-update:check");
  }

  function coreUpdateInstall() {
    if (host) host.postMessage("core-update:install");
  }

  function requestCoreVersion() {
    if (host) host.postMessage("core:version");
  }

  function setKillSwitch(on) {
    if (host) host.postMessage(on ? "ks:on" : "ks:off");
  }

  function setCloseTray(on) {
    if (host) host.postMessage(on ? "close-to-tray:on" : "close-to-tray:off");
  }

  function setKeepAlive(on) {
    if (host) host.postMessage(on ? "keep-alive:on" : "keep-alive:off");
  }

  function setHotkeys(on) {
    if (host) host.postMessage(on ? "hotkeys:on" : "hotkeys:off");
  }

  function setSafeMode(on) {
    if (host) host.postMessage(on ? "safe-mode:on" : "safe-mode:off");
  }

  function collectLogs() {
    if (host) host.postMessage("diag:collect");
  }

  function traySync(obj) {
    try {
      if (host) host.postMessage("tray:sync:" + JSON.stringify(obj));
    } catch {}
  }

  function getConnections() {
    if (host) host.postMessage("conn:get");
  }

  function nativePing(host_, timeout = 3500) {
    if (!host) return Promise.resolve(null);
    return new Promise(resolve => {
      const id = "p" + (++pingSeq);
      const tm = setTimeout(() => { if (pongWaiters.delete(id)) resolve(null); }, timeout);
      pongWaiters.set(id, ms => { clearTimeout(tm); resolve(ms); });
      host.postMessage(`ping:${id}:${host_}`);
    });
  }

  function nativeTcpPing(host_, port, timeout = 5000) {
    if (!host) return Promise.resolve(null);
    return new Promise(resolve => {
      const id = "t" + (++pingSeq);
      const tm = setTimeout(() => { if (pongWaiters.delete(id)) resolve(null); }, timeout);
      pongWaiters.set(id, ms => { clearTimeout(tm); resolve(ms); });
      host.postMessage(`tcping:${id}:${host_}:${port || 443}`);
    });
  }

  function selfCheck(ctx) {
    if (host) host.postMessage("selfcheck:" + JSON.stringify(ctx || {}));
  }

  function geoSites(timeout = 4000) {
    if (!host) return Promise.resolve([]);
    return new Promise(resolve => {
      const tm = setTimeout(() => { geoWaiter = null; resolve([]); }, timeout);
      geoWaiter = arr => { clearTimeout(tm); geoWaiter = null; resolve(Array.isArray(arr) ? arr : []); };
      host.postMessage("geo:sites");
    });
  }

  function vpnProbe(timeout = 12000) {
    if (!host) return Promise.resolve(null);
    return new Promise(resolve => {
      const tm = setTimeout(() => { probeWaiter = null; resolve(null); }, timeout);
      probeWaiter = ms => { clearTimeout(tm); probeWaiter = null; resolve(ms); };
      host.postMessage("vpn:probe");
    });
  }

  function openMini() {
    if (host) host.postMessage("mini:open");
  }

  function setTheme(theme) {
    if (host) host.postMessage(theme === "light" ? "theme:light" : "theme:dark");
  }

  function createWarpAwg(timeout = 15000) {
    if (!host) return Promise.resolve({ ok: false, error: "WebView2 недоступен" });
    return new Promise(resolve => {
      const tm = setTimeout(() => { warpWaiter = null; resolve({ ok: false, error: "Таймаут регистрации WARP" }); }, timeout);
      warpWaiter = res => { clearTimeout(tm); resolve(res); };
      host.postMessage("warp:create");
    });
  }

  function checkExitGeo(timeout = 7000) {
    if (!host) return Promise.resolve({ ok: false });
    return new Promise(resolve => {
      const tm = setTimeout(() => { exitGeoWaiter = null; resolve({ ok: false }); }, timeout);
      exitGeoWaiter = res => { clearTimeout(tm); resolve(res); };
      host.postMessage("exit:geo");
    });
  }

  function runDnsBenchmark(timeout = 8000) {
    if (!host) return Promise.resolve({ results: [] });
    return new Promise(resolve => {
      const tm = setTimeout(() => { dnsBenchWaiter = null; resolve({ results: [] }); }, timeout);
      dnsBenchWaiter = res => { clearTimeout(tm); resolve(res); };
      host.postMessage("dns:bench");
    });
  }

  function runDiagMatrix(timeout = 9000) {
    if (!host) return Promise.resolve({ items: [] });
    return new Promise(resolve => {
      const tm = setTimeout(() => { diagMatrixWaiter = null; resolve({ items: [] }); }, timeout);
      diagMatrixWaiter = res => { clearTimeout(tm); resolve(res); };
      host.postMessage("diag:matrix");
    });
  }

  function runSpeedtest(opts = {}, timeout = 180000) {
    if (!host) return Promise.resolve({ ok: false, error: "WebView2 недоступен" });
    const sizeMb = parseInt(opts.sizeMb, 10) || 100;
    const provider = opts.provider || "auto";
    return new Promise(resolve => {
      const tm = setTimeout(() => { speedtestWaiter = null; resolve({ ok: false, error: "Таймаут спидтеста" }); }, timeout);
      speedtestWaiter = res => { clearTimeout(tm); resolve(res); };
      host.postMessage(`speedtest:run:${sizeMb}:${provider}`);
    });
  }

  function stopSpeedtest() {
    if (host) host.postMessage("speedtest:stop");
  }

  function closeConnection(id) {
    if (!host) return;
    if (!id || id === "all") host.postMessage("conn:close:all");
    else host.postMessage("conn:close:" + id);
  }

  return {
    hasNativeVpn,
    // Native bridge methods
    vpnConnect,
    vpnDisconnect,
    importSubscription,
    openLog,
    requestAppsList,
    onAppsList,
    requestLogTail,
    onLogTail,
    updateCheck,
    updateInstall,
    onUpdate,
    coreUpdateCheck,
    coreUpdateInstall,
    requestCoreVersion,
    onCoreUpdate,
    onCoreVersion,
    refreshLists,
    onListsUpdate,
    setKillSwitch,
    setCloseTray,
    setKeepAlive,
    setHotkeys,
    setSafeMode,
    setTheme,
    createWarpAwg,
    checkExitGeo,
    runDnsBenchmark,
    runDiagMatrix,
    runSpeedtest,
    stopSpeedtest,
    onSpeedtestProgress,
    closeConnection,
    collectLogs,
    traySync,
    onTray,
    getConnections,
    onConnData,
    nativePing,
    nativeTcpPing,
    selfCheck,
    onDiagStep,
    onDiagDone,
    geoSites,
    vpnProbe,
    openMini,
    openExternal,
    onVpn,
    onSub,
    onHotkeysBusy,

    // Subscriptions and Node Storage
    getSubscriptions,
    saveSubscriptions,
    getCustomNodes,
    saveCustomNodes,
    getAllServers
  };
})();
