/* ============================================================
   Tachyon Client – Клиентская логика (tachyon-core)
   ============================================================ */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  const toastEl = $('#toast');
  let toastTimer = null;
  function toast(msg, isErr = false) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.toggle('is-err', isErr);
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 3200);
  }

  /* ---------- Модальные окна ---------- */
  function confirmDialog(msg) {
    return new Promise(resolve => {
      const modal = $('#confirmModal');
      const text = $('#confirmText');
      const yes = $('#confirmYes');
      const no = $('#confirmNo');
      if (!modal) { resolve(window.confirm(msg)); return; }
      text.textContent = msg;
      modal.hidden = false;
      const cleanup = res => {
        modal.hidden = true;
        yes.onclick = null;
        no.onclick = null;
        resolve(res);
      };
      yes.onclick = () => cleanup(true);
      no.onclick = () => cleanup(false);
      $('#confirmBackdrop').onclick = () => cleanup(false);
    });
  }

  function promptDialog(msg, defVal = '') {
    return new Promise(resolve => {
      const modal = $('#promptModal');
      const text = $('#promptText');
      const input = $('#promptInput');
      const yes = $('#promptYes');
      const no = $('#promptNo');
      if (!modal) { resolve(window.prompt(msg, defVal)); return; }
      text.textContent = msg;
      input.value = defVal;
      modal.hidden = false;
      input.focus();
      const cleanup = val => {
        modal.hidden = true;
        yes.onclick = null;
        no.onclick = null;
        resolve(val);
      };
      yes.onclick = () => cleanup(input.value.trim());
      no.onclick = () => cleanup(null);
      $('#promptBackdrop').onclick = () => cleanup(null);
      input.onkeydown = e => {
        if (e.key === 'Enter') cleanup(input.value.trim());
        if (e.key === 'Escape') cleanup(null);
      };
    });
  }

  /* ---------- Навигация и Views ---------- */
  let currentView = 'connect';
  let connPollTimer = null;

  function go(v) {
    currentView = v;
    $$('.rail__item[data-view]').forEach(b => b.classList.toggle('is-active', b.dataset.view === v));
    $$('.view').forEach(s => s.classList.toggle('is-active', s.dataset.view === v));
    if (v === 'subscriptions') {
      renderSubscriptions();
      syncFilterUiControls();
      renderServers($('#nodesSearchInput')?.value || '');
    }
    if (v === 'connect') {
      updateLocCount();
      renderServers($('#homeServerSearch')?.value || '');
    }
    if (v === 'desync') {
      syncDesyncAdvInputs();
      updateRoutingSummaryUI();
    }
    if (v === 'routing') {
      syncDetourAndRuleNodeSelects();
      renderCommunityLists();
      renderCustomRules();
    }
    if (v === 'connections') {
      window.API.getConnections();
      clearInterval(connPollTimer);
      connPollTimer = setInterval(() => {
        if (currentView === 'connections' && connected) window.API.getConnections();
      }, 2000);
    } else {
      clearInterval(connPollTimer);
    }
  }
  $$('.rail__item[data-view]').forEach(b => b.addEventListener('click', () => go(b.dataset.view)));

  /* ---------- Titlebar Controls & Window Drag ---------- */
  const host = window.chrome && window.chrome.webview ? window.chrome.webview : null;
  const plat = String(window.__tachyonPlatform || navigator.platform || navigator.userAgent || '').toLowerCase();
  const isMacOs = plat.includes('mac') || plat.includes('darwin');
  const isLinuxOs = plat.includes('linux') && !plat.includes('android');
  const TUN_BADGE = isMacOs ? 'TUN · UTUN' : (isLinuxOs ? 'TUN · LINUX' : 'TUN · WINTUN');
  const TUN_SHORT = isMacOs ? 'TUN · utun' : (isLinuxOs ? 'TUN · Linux' : 'TUN · Wintun');
  const TUN_HINT = isMacOs
    ? 'Виртуальный сетевой интерфейс macOS (utun)'
    : (isLinuxOs ? 'Виртуальный сетевой интерфейс Linux (/dev/net/tun)' : 'Виртуальный сетевой адаптер Wintun');
  $('#titlebar')?.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    if (e.target.closest('button, nav, a, input, .topbar__controls')) return;
    if (e.detail === 2) {
      if (host) host.postMessage('win:max');
      return;
    }
    if (host) host.postMessage('win:drag');
  });

  $$('.wbtn[data-win]').forEach(b => {
    b.addEventListener('click', () => {
      const act = b.dataset.win;
      if (!host) return;
      if (act === 'min') host.postMessage('win:min');
      else if (act === 'max') host.postMessage('win:max');
      else if (act === 'close') host.postMessage('win:close');
      else if (act === 'mini') window.API.openMini();
    });
  });

  const precipToggle = $('#precipToggle');
  if (precipToggle) {
    precipToggle.checked = localStorage.getItem('tachyon.precip') === '1';
    if (precipToggle.checked) window.Sky?.set('snow');
    precipToggle.addEventListener('change', () => {
      const on = precipToggle.checked;
      try { localStorage.setItem('tachyon.precip', on ? '1' : '0'); } catch {}
      window.Sky?.set(on ? 'snow' : 'none');
    });
  }

  /* ---------- Тема оформления (исключительно Dark Mode) ---------- */
  document.documentElement.dataset.theme = 'dark';
  try { localStorage.setItem('tachyon.theme', 'dark'); } catch {}

  /* ---------- Распознавание стран, флагов, протоколов и очистка названий ---------- */
  const KNOWN_FLAGS = new Set([
    'ae', 'ch', 'de', 'ee', 'es', 'fi', 'fr', 'gb', 'it',
    'jp', 'lt', 'lv', 'nl', 'pl', 'ru', 'se', 'sg', 'tr', 'us'
  ]);

  const COUNTRY_NAMES = {
    us: 'США', de: 'Германия', nl: 'Нидерланды', fi: 'Финляндия',
    gb: 'Великобритания', fr: 'Франция', tr: 'Турция', ru: 'Россия',
    se: 'Швеция', ch: 'Швейцария', pl: 'Польша', it: 'Италия',
    es: 'Испания', ee: 'Эстония', lv: 'Латвия', lt: 'Литва',
    jp: 'Япония', sg: 'Сингапур', ae: 'ОАЭ', kz: 'Казахстан',
    ca: 'Канада', at: 'Австрия', cz: 'Чехия', no: 'Норвегия',
    dk: 'Дания', ie: 'Ирландия', pt: 'Португалия', gr: 'Греция',
    il: 'Израиль', in: 'Индия', kr: 'Юж. Корея', hk: 'Гонконг',
    br: 'Бразилия', au: 'Австралия', am: 'Армения', ge: 'Грузия',
    rs: 'Сербия', ua: 'Украина', by: 'Беларусь', md: 'Молдова',
    ro: 'Румыния', bg: 'Болгария', hu: 'Венгрия', xx: 'Прочие локации'
  };

  const COUNTRY_KEYWORDS = [
    [/сша|usa|united states|америк|new york|los angeles|miami|dallas|chicago|seattle|ashburn|atlanta|phoenix|san jose/i, 'us'],
    [/герман|germany|frankfurt|франкфурт|berlin|берлин|falkenstein|nuremberg|нюрнберг|мюнхен|munich|dusseldorf/i, 'de'],
    [/нидерланд|голланди|netherlands|holland|amsterdam|амстердам|meppel|rotterdam/i, 'nl'],
    [/финлянд|finland|helsinki|хельсинки/i, 'fi'],
    [/великобритан|англи|британ|united kingdom|england|london|лондон|manchester/i, 'gb'],
    [/франц|france|paris|париж|marseille|strasbourg|страсбург/i, 'fr'],
    [/турци|turkey|türkiye|istanbul|стамбул|анталья|ankara/i, 'tr'],
    [/росси|russia|moscow|москв|spb|петербург|новосибирск|екатеринбург/i, 'ru'],
    [/швеци|sweden|stockholm|стокгольм/i, 'se'],
    [/швейцар|switzerland|zurich|цюрих|geneva|женев/i, 'ch'],
    [/польш|poland|warsaw|варшав/i, 'pl'],
    [/итали|italy|milan|милан|rome|рим/i, 'it'],
    [/испан|spain|madrid|мадрид|barcelona|барселон/i, 'es'],
    [/эстони|estonia|tallinn|таллин/i, 'ee'],
    [/латви|latvia|riga|рига/i, 'lv'],
    [/литв|lithuania|vilnius|вильнюс/i, 'lt'],
    [/япони|japan|tokyo|токио|osaka/i, 'jp'],
    [/сингапур|singapore/i, 'sg'],
    [/оаэ|эмират|uae|dubai|дубай/i, 'ae'],
    [/казахст|kazakhstan|almaty|алматы|астана|astana/i, 'kz'],
    [/канад|canada|toronto|montreal|vancouver/i, 'ca'],
    [/австри|austria|vienna|вена/i, 'at'],
    [/чехи|czech|prague|прага/i, 'cz'],
    [/норвег|norway|oslo|осло/i, 'no'],
    [/дани|denmark|copenhagen|копенгаген/i, 'dk'],
    [/ирланд|ireland|dublin|дублин/i, 'ie'],
    [/португал|portugal|lisbon|лиссабон/i, 'pt'],
    [/греци|greece|athens|афины/i, 'gr'],
    [/израил|israel|tel aviv|тель-авив/i, 'il'],
    [/инди|india|mumbai|мумбаи/i, 'in'],
    [/коре|korea|seoul|сеул/i, 'kr'],
    [/гонконг|hong kong/i, 'hk'],
    [/бразил|brazil|sao paulo/i, 'br'],
    [/австрал|australia|sydney|сидней/i, 'au'],
    [/армени|armenia|yerevan|ереван/i, 'am'],
    [/грузи|georgia|tbilisi|тбилиси/i, 'ge'],
    [/серби|serbia|belgrade|белград/i, 'rs'],
    [/украин|ukraine|kyiv|киев/i, 'ua'],
    [/беларус|belarus|minsk|минск/i, 'by'],
    [/молдов|moldova|chisinau|кишинев/i, 'md'],
    [/румын|romania|bucharest|бухарест/i, 'ro'],
    [/болгар|bulgaria|sofia|софия/i, 'bg'],
    [/венгри|hungary|budapest|будапешт/i, 'hu']
  ];

  function extractEmojiFlagCode(str) {
    if (!str) return null;
    const re = /\uD83C([\uDDE6-\uDDFF])\uD83C([\uDDE6-\uDDFF])/g;
    const m = re.exec(str);
    if (!m) return null;
    const c1 = String.fromCharCode(m[1].charCodeAt(0) - 0xDDE6 + 97);
    const c2 = String.fromCharCode(m[2].charCodeAt(0) - 0xDDE6 + 97);
    return c1 + c2;
  }

  function cleanServerName(raw, detectedCode = '') {
    if (!raw) return 'Узел VPN';
    let cleaned = String(raw)
      .replace(/\uD83C[\uDDE6-\uDDFF]\uD83C[\uDDE6-\uDDFF]/g, '')
      .replace(/[\uFE0E\uFE0F]/g, '')
      .replace(/^[\s\-–—·|]+/, '')
      .replace(/\s{2,}/g, ' ')
      .trim();
    if (detectedCode && detectedCode !== 'xx') {
      const rxLeadIso = new RegExp(`^\\[?${detectedCode}\\]?[\\s\\-–—·|:]+(?=[А-Яа-яЁёA-Za-z])`, 'i');
      const next = cleaned.replace(rxLeadIso, '').trim();
      if (next.length >= 2) cleaned = next;
    }
    return cleaned || String(raw).trim();
  }

  function detectCountryCode(s) {
    if (!s) return 'xx';
    const rawName = String(s.rawName || s.name || s.country || '');
    const emojiCode = extractEmojiFlagCode(rawName);
    if (emojiCode) return emojiCode === 'uk' ? 'gb' : emojiCode;

    for (const [rx, code] of COUNTRY_KEYWORDS) {
      if (rx.test(rawName)) return code;
    }

    const candidates = [s.code, s.country];
    for (const cand of candidates) {
      if (!cand) continue;
      const c = String(cand).trim().toLowerCase();
      if (c in COUNTRY_NAMES && c !== 'xx' && (c !== 'au' || /australia|австрал/i.test(rawName)) && (c !== 'in' || /india|инди/i.test(rawName))) {
        return c === 'uk' ? 'gb' : c;
      }
    }

    const mIso = rawName.match(/(?:^|[\s([\-_])([A-Za-z]{2})(?:$|[\s)\]\-_0-9])/);
    if (mIso) {
      const iso = mIso[1].toLowerCase() === 'uk' ? 'gb' : mIso[1].toLowerCase();
      if (iso in COUNTRY_NAMES && iso !== 'xx' && iso !== 'in' && iso !== 'at' && iso !== 'by' && iso !== 'it') {
        return iso;
      }
    }
    return 'xx';
  }

  function parseNodeMeta(vless) {
    const res = {
      proto: 'VLESS',
      sec: 'NONE',
      trans: 'TCP',
      host: '',
      port: 443,
      tags: ['VLESS']
    };
    if (!vless) return res;
    const raw = String(vless).trim();
    const low = raw.toLowerCase();

    if (low.startsWith('amneziawg://') || low.startsWith('awg://') || low.startsWith('wireguard://')) {
      res.proto = 'AWG';
      res.trans = 'UDP';
      res.tags = ['AWG'];
    } else if (low.startsWith('hysteria2://') || low.startsWith('hy2://')) {
      res.proto = 'HY2';
      res.sec = 'TLS';
      res.trans = 'QUIC';
      res.tags = ['HY2', 'QUIC'];
    } else if (low.startsWith('ss://')) {
      res.proto = 'SS';
      res.tags = ['SS'];
    } else {
      res.proto = 'VLESS';
      if (low.includes('security=reality') || low.includes('pbk=')) res.sec = 'REALITY';
      else if (low.includes('security=tls')) res.sec = 'TLS';

      const mType = low.match(/[?&]type=([a-z0-9_-]+)/);
      const t = mType ? mType[1] : 'tcp';
      if (t === 'xhttp' || t === 'splithttp') res.trans = 'XHTTP';
      else if (t === 'ws' || t === 'httpupgrade') res.trans = 'WS';
      else if (t === 'grpc') res.trans = 'GRPC';
      else if (t === 'quic') res.trans = 'QUIC';
      else res.trans = 'TCP';

      const tags = [];
      if (res.sec === 'REALITY') tags.push('REALITY');
      else tags.push('VLESS');
      if (res.trans !== 'TCP') tags.push(res.trans);
      res.tags = tags;
    }

    try {
      const mHostPort = raw.match(/@(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/);
      if (mHostPort) {
        res.host = mHostPort[1].replace(/^\[|\]$/g, '');
        const p = parseInt(mHostPort[2], 10);
        if (p > 0 && p < 65536) res.port = p;
      }
    } catch {}

    return res;
  }

  /* Кеш пингов по host:port, чтобы не терять замеры при фильтрации и перезапуске */
  let pingCache = {};
  try {
    const rawPingCache = JSON.parse(localStorage.getItem('tachyon.ping_cache') || '{}') || {};
    for (const [k, v] of Object.entries(rawPingCache)) {
      if (Number.isFinite(v) && v > 1) pingCache[k] = v;
    }
  } catch {}
  function savePingCache() {
    try { localStorage.setItem('tachyon.ping_cache', JSON.stringify(pingCache)); } catch {}
  }

  function normalizeServer(s) {
    if (!s) return s;
    const rawName = s.rawName || s.name || s.country || 'Узел VPN';
    const code = detectCountryCode({ ...s, rawName });
    const clean = cleanServerName(rawName, code);
    const meta = parseNodeMeta(s.vless);
    const endpointKey = meta.host ? `${meta.host.toLowerCase()}:${meta.port}` : '';
    const cachedPing = endpointKey && Number.isFinite(pingCache[endpointKey]) && pingCache[endpointKey] > 1
      ? pingCache[endpointKey]
      : null;
    return {
      ...s,
      rawName,
      name: clean,
      code: code.toUpperCase(),
      country: code,
      countryName: COUNTRY_NAMES[code] || code.toUpperCase(),
      meta,
      endpointKey,
      ping: Number.isFinite(s.ping) && s.ping > 1 ? s.ping : cachedPing
    };
  }

  function badgeFlagSvg(code) {
    const label = String(code || 'VPN').toUpperCase().slice(0, 2);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36"><rect width="36" height="36" rx="8" fill="#151b2b"/><rect x="1" y="1" width="34" height="34" rx="7" fill="none" stroke="#2e3b59" stroke-width="1.5"/><text x="18" y="22.5" text-anchor="middle" fill="#93c5fd" font-family="Consolas,monospace" font-weight="700" font-size="13">${label}</text></svg>`;
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  }

  function flagFor(codeOrServer) {
    const code = typeof codeOrServer === 'object' && codeOrServer !== null
      ? (codeOrServer.country && codeOrServer.country.length === 2 ? codeOrServer.country : detectCountryCode(codeOrServer))
      : String(codeOrServer || '').trim().toLowerCase();
    const norm = code === 'uk' ? 'gb' : code;
    if (KNOWN_FLAGS.has(norm)) return `flags/${norm}.svg`;
    if (/^[a-z]{2}$/.test(norm) && norm !== 'xx') return badgeFlagSvg(norm);
    return 'flags/globe.svg';
  }

  /* ---------- Состояние серверов и подписок ---------- */
  let servers = [];
  let activeId = localStorage.getItem('tachyon.active_server_id') || null;

  function ensureValidActiveServer() {
    if (!servers.length) {
      activeId = null;
      return;
    }
    const filtered = typeof getStrictlyFilteredServers === 'function' ? getStrictlyFilteredServers('') : servers;
    const pool = filtered.length ? filtered : servers;
    if (!activeId || !pool.some(s => s.id === activeId)) {
      const withPing = [...pool].filter(s => s.ping != null && s.ping > 0).sort((a, b) => a.ping - b.ping);
      const best = withPing[0] || pool[0];
      activeId = best ? best.id : null;
      if (activeId) {
        try { localStorage.setItem('tachyon.active_server_id', activeId); } catch {}
      }
    }
  }

  function loadAllServers() {
    servers = (window.API.getAllServers() || []).map(normalizeServer);
    ensureValidActiveServer();
    updateActiveServerDisplay();
    updateLocCount();
    if (currentView === 'subscriptions') {
      renderServers($('#nodesSearchInput')?.value || '');
    } else if (currentView === 'connect') {
      renderServers($('#homeServerSearch')?.value || '');
    }
  }

  function activeServer() {
    const filtered = typeof getStrictlyFilteredServers === 'function' ? getStrictlyFilteredServers('') : servers;
    const pool = filtered.length ? filtered : servers;
    return pool.find(s => s.id === activeId) || servers.find(s => s.id === activeId) || pool[0] || null;
  }

  function updateActiveServerDisplay() {
    const s = activeServer();
    if (vpnPrefs?.route === 'desync-only') {
      $('#currentServerName').textContent = 'Tachyon Desync (DPI Bypass)';
      const subEl = $('#currentServerSub');
      if (subEl) subEl.textContent = `Прямой обход блокировок без VPN · Пресет: ${DESYNC_PRESET_LABELS[desyncPrefs.preset] || 'Авто'}`;
      const flagEl = $('#pickFlag');
      if (flagEl) flagEl.src = 'flags/globe.svg';
      $('#mPing').textContent = '–';
      return;
    }
    if (s) {
      $('#currentServerName').textContent = s.name || 'Узел VPN';
      const tagsStr = (s.meta?.tags || [detectProtocol(s.vless)]).join(' · ');
      const subLabel = s.subName ? `${s.subName} · ${tagsStr}` : tagsStr;
      const subEl = $('#currentServerSub');
      if (subEl) subEl.textContent = subLabel;
      const flagEl = $('#pickFlag');
      if (flagEl) {
        flagEl.onerror = () => { flagEl.onerror = null; flagEl.src = 'flags/globe.svg'; };
        flagEl.src = flagFor(s);
      }
      $('#mPing').textContent = s.ping != null && s.ping > 0 ? s.ping : '–';
    } else {
      $('#currentServerName').textContent = 'Выберите сервер';
      const subEl = $('#currentServerSub');
      if (subEl) subEl.textContent = 'Добавьте подписку или включите режим «Desync»';
      $('#pickFlag').src = 'flags/globe.svg';
      $('#mPing').textContent = '–';
    }
  }

  function updateLocCount() {
    const filteredCount = typeof getStrictlyFilteredServers === 'function'
      ? getStrictlyFilteredServers('').length
      : servers.length;
    const el = $('#locCount');
    if (el) el.textContent = String(filteredCount);
    const badgeStr = filteredCount === servers.length
      ? `${filteredCount}`
      : `${filteredCount} / ${servers.length}`;
    const nfBadge = $('#nodesFilterCountBadge');
    if (nfBadge) nfBadge.textContent = badgeStr;
    const homeBadge = $('#homeServerCountBadge');
    if (homeBadge) homeBadge.textContent = badgeStr;
    const fStats = $('#footerStatsLabel');
    if (fStats && typeof getActiveCommunityListsArray === 'function') {
      const totalRules = getActiveCommunityListsArray().length + (customRouteRules?.length || 0);
      const nodesStr = filteredCount === servers.length ? `${filteredCount}` : `${filteredCount}/${servers.length}`;
      fStats.textContent = `Узлов: ${nodesStr} · Правил: ${totalRules}`;
    }
  }

  function plural(n, one, two, five) {
    n = Math.abs(n) % 100;
    const n1 = n % 10;
    if (n > 10 && n < 20) return five;
    if (n1 > 1 && n1 < 5) return two;
    if (n1 === 1) return one;
    return five;
  }

  function detectProtocol(vless) {
    return parseNodeMeta(vless).tags[0] || 'VLESS';
  }

  /* ---------- Рендер раздела «Узлы и подписки» ---------- */
  function renderSubscriptions() {
    const subs = window.API.getSubscriptions();
    const customs = window.API.getCustomNodes();
    const subsList = $('#subsList');
    const customList = $('#customNodesList');
    const customSection = $('#customNodesSection');
    const emptyEl = $('#subsEmpty');

    if (!subs.length && !customs.length) {
      if (emptyEl) emptyEl.hidden = false;
      if (subsList) subsList.innerHTML = '';
      if (customSection) customSection.hidden = true;
      return;
    }
    if (emptyEl) emptyEl.hidden = true;

    if (subsList) {
      subsList.innerHTML = subs.map(sub => {
        const dateStr = sub.updatedAt
          ? new Date(sub.updatedAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
          : '–';
        const nodeCount = Array.isArray(sub.servers) ? sub.servers.length : (sub.nodesCount || 0);
        let trafficInfo = '';
        if (sub.trafficTotal && sub.trafficTotal > 0) {
          const usedGB = (sub.trafficUsed / (1024 * 1024 * 1024)).toFixed(1);
          const totalGB = (sub.trafficTotal / (1024 * 1024 * 1024)).toFixed(1);
          trafficInfo = `<span><b>${usedGB}/${totalGB}</b> ГБ</span>`;
        }
        let expireInfo = '';
        if (sub.expireAt) {
          expireInfo = `<span>до <b>${escapeHtml(sub.expireAt)}</b></span>`;
        }

        return `
          <div class="sub-card" data-sub-id="${sub.id}">
            <div class="sub-card__head">
              <div class="sub-card__title">
                <span>${escapeHtml(sub.name || 'Подписка')}</span>
                <span class="sub-card__badge">${nodeCount} ${plural(nodeCount, 'узел', 'узла', 'узлов')}</span>
              </div>
              <div class="sub-card__actions">
                <button class="pill-btn sub-refresh-btn" data-sub-id="${sub.id}" title="Обновить">
                  <svg class="ic"><use href="#ic-refresh"/></svg>
                </button>
                <button class="pill-btn sub-edit-btn" data-sub-id="${sub.id}" title="Переименовать">
                  <svg class="ic"><use href="#ic-edit"/></svg>
                </button>
                <button class="pill-btn sub-del-btn" data-sub-id="${sub.id}" title="Удалить" style="color:var(--red)">
                  <svg class="ic"><use href="#ic-trash"/></svg>
                </button>
              </div>
            </div>
            <div class="sub-card__url" title="${escapeHtml(sub.url || '')}">${escapeHtml(sub.url || '')}</div>
            <div class="sub-card__meta">
              <span>Синхр: <b>${dateStr}</b></span>
              ${trafficInfo}
              ${expireInfo}
            </div>
          </div>
        `;
      }).join('');

      $$('.sub-refresh-btn', subsList).forEach(b => {
        b.addEventListener('click', () => refreshSingleSubscription(b.dataset.subId, b));
      });
      $$('.sub-edit-btn', subsList).forEach(b => {
        b.addEventListener('click', async () => {
          const id = b.dataset.subId;
          const s = subs.find(x => x.id === id);
          if (!s) return;
          const newName = await promptDialog('Название подписки:', s.name);
          if (newName) {
            s.name = newName;
            window.API.saveSubscriptions(subs);
            renderSubscriptions();
            loadAllServers();
            toast('Название обновлено');
          }
        });
      });
      $$('.sub-del-btn', subsList).forEach(b => {
        b.addEventListener('click', async () => {
          const id = b.dataset.subId;
          const s = subs.find(x => x.id === id);
          if (!s) return;
          if (await confirmDialog(`Удалить подписку «${s.name}» и все её узлы?`)) {
            const next = subs.filter(x => x.id !== id);
            window.API.saveSubscriptions(next);
            renderSubscriptions();
            loadAllServers();
            toast('Подписка удалена');
          }
        });
      });
    }

    if (customList && customSection) {
      if (customs.length) {
        customSection.hidden = false;
        customList.innerHTML = customs.map(c => {
          const nc = normalizeServer(c);
          return `
          <div class="sub-card">
            <div class="sub-card__head" style="margin-bottom:0">
              <div class="sub-card__title">
                <img class="flag-slot" src="${flagFor(nc)}" onerror="this.onerror=null;this.src='flags/globe.svg'" style="width:22px;height:22px;border-radius:5px" alt=""/>
                <span>${escapeHtml(nc.name || 'Узел')}</span>
                <span class="proto-badge">${detectProtocol(nc.vless)}</span>
              </div>
              <button class="pill-btn custom-del-btn" data-id="${c.id}" style="color:var(--red)" title="Удалить">
                <svg class="ic"><use href="#ic-trash"/></svg>
              </button>
            </div>
          </div>
        `;
        }).join('');

        $$('.custom-del-btn', customList).forEach(b => {
          b.addEventListener('click', async () => {
            const id = b.dataset.id;
            if (await confirmDialog('Удалить этот узел?')) {
              const next = customs.filter(x => x.id !== id);
              window.API.saveCustomNodes(next);
              renderSubscriptions();
              loadAllServers();
              toast('Узел удалён');
            }
          });
        });
      } else {
        customSection.hidden = true;
      }
    }
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /* ---------- Добавление подписки / узла ---------- */
  const addSubCard = $('#addSubCard');
  const subInput = $('#subInput');
  const subNameInput = $('#subNameInput');

  function openAddSubDialog(isNodeOnly = false) {
    if (!addSubCard) return;
    addSubCard.hidden = false;
    subInput.value = '';
    subNameInput.value = '';
    if (isNodeOnly) {
      $('#addSubTitle').textContent = 'Добавить ключ узла';
      subInput.placeholder = 'vless://, awg://, ss:// или hysteria2://';
      subNameInput.placeholder = 'Название узла (например: NL-1)';
    } else {
      $('#addSubTitle').textContent = 'Добавить подписку';
      subInput.placeholder = 'URL подписки (https://…) или ключ';
      subNameInput.placeholder = 'Название (например: Основная)';
    }
    subInput.focus();
  }

  $('#openAddSubBtn')?.addEventListener('click', () => openAddSubDialog(false));
  $('#openAddNodeBtn')?.addEventListener('click', () => openAddSubDialog(true));
  $('#emptyAddBtn')?.addEventListener('click', () => openAddSubDialog(false));
  $('#cancelSubBtn')?.addEventListener('click', () => { if (addSubCard) addSubCard.hidden = true; });

  let pendingImport = null;

  $('#saveSubBtn')?.addEventListener('click', () => {
    const input = (subInput?.value || '').trim();
    const name = (subNameInput?.value || '').trim();
    if (!input) { toast('Вставьте ссылку на подписку или ключ', true); return; }

    toast('Загрузка конфигурации…');
    pendingImport = { name, input };
    window.API.importSubscription(input);
  });

  window.API.onSub(res => {
    if (res.error) {
      toast('Ошибка: ' + res.error, true);
      pendingImport = null;
      return;
    }

    const srvs = res.servers || [];
    if (!srvs.length) {
      toast('Не найдено узлов в ответе', true);
      pendingImport = null;
      return;
    }

    if (pendingImport) {
      const low = pendingImport.input.toLowerCase();
      const isSingleNode = low.startsWith('vless://') ||
                           low.startsWith('awg://') ||
                           low.startsWith('amneziawg://') ||
                           low.startsWith('wireguard://') ||
                           low.startsWith('ss://') ||
                           low.startsWith('hysteria2://') ||
                           low.startsWith('hy2://');

      if (isSingleNode && srvs.length === 1) {
        const customs = window.API.getCustomNodes();
        const s = normalizeServer(srvs[0]);
        customs.push({
          id: 'custom_' + Date.now(),
          name: cleanServerName(pendingImport.name || s.name || 'Свой узел'),
          country: s.country || 'xx',
          code: s.code || 'XX',
          vless: s.vless,
          ping: null
        });
        window.API.saveCustomNodes(customs);
        toast('Узел добавлен');
      } else {
        const subs = window.API.getSubscriptions();
        const firstClean = cleanServerName(srvs[0]?.name || '');
        const subName = pendingImport.name || res.user?.handle || (firstClean ? firstClean.split(' ')[0] : 'Подписка');
        const newSub = {
          id: 'sub_' + Date.now(),
          name: subName,
          url: pendingImport.input,
          nodesCount: srvs.length,
          updatedAt: Date.now(),
          expireAt: res.subscription?.expireAt || null,
          trafficUsed: res.subscription?.trafficUsed || 0,
          trafficTotal: res.subscription?.trafficTotal || 0,
          servers: srvs.map((rawSrv, idx) => {
            const s = normalizeServer(rawSrv);
            return {
              id: `sub_${Date.now()}_${idx}`,
              name: s.name,
              country: s.country || 'xx',
              code: s.code || 'XX',
              vless: s.vless,
              ping: null
            };
          }),
          enabled: true
        };
        subs.push(newSub);
        window.API.saveSubscriptions(subs);
        toast(`Добавлена «${subName}» (${srvs.length} узлов)`);
      }

      if (addSubCard) addSubCard.hidden = true;
      pendingImport = null;
      renderSubscriptions();
      loadAllServers();
    } else if (activeUpdatingSubId) {
      const subs = window.API.getSubscriptions();
      const target = subs.find(x => x.id === activeUpdatingSubId);
      if (target) {
        target.nodesCount = srvs.length;
        target.updatedAt = Date.now();
        if (res.subscription?.expireAt) target.expireAt = res.subscription.expireAt;
        if (res.subscription?.trafficUsed) target.trafficUsed = res.subscription.trafficUsed;
        if (res.subscription?.trafficTotal) target.trafficTotal = res.subscription.trafficTotal;
        target.servers = srvs.map((rawSrv, idx) => {
          const s = normalizeServer(rawSrv);
          return {
            id: `${target.id}_${idx}`,
            name: s.name,
            country: s.country || 'xx',
            code: s.code || 'XX',
            vless: s.vless,
            ping: null
          };
        });
        window.API.saveSubscriptions(subs);
        toast(`Обновлена «${target.name}» (${srvs.length} узлов)`);
        renderSubscriptions();
        loadAllServers();
        if (!drawer?.hidden) renderServers($('#serverSearch')?.value || '');
      }
      activeUpdatingSubId = null;
    }
  });

  let activeUpdatingSubId = null;
  function refreshSingleSubscription(subId, btn) {
    const subs = window.API.getSubscriptions();
    const sub = subs.find(x => x.id === subId);
    if (!sub || !sub.url) return;
    activeUpdatingSubId = subId;
    if (btn) btn.classList.add('is-busy');
    toast(`Обновление «${sub.name}»…`);
    window.API.importSubscription(sub.url);
    setTimeout(() => { if (btn) btn.classList.remove('is-busy'); }, 2500);
  }

  async function refreshAllSubscriptions() {
    const subs = window.API.getSubscriptions().filter(s => s.url && s.url.startsWith('http'));
    if (!subs.length) { toast('Нет сетевых подписок для обновления', true); return; }
    toast(`Обновление подписок (${subs.length})…`);
    for (const sub of subs) {
      activeUpdatingSubId = sub.id;
      window.API.importSubscription(sub.url);
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  $('#refreshAllSubsBtn')?.addEventListener('click', refreshAllSubscriptions);
  $('#subRefreshBtn')?.addEventListener('click', refreshAllSubscriptions);

  /* ---------- Фильтрация базы узлов (в разделе «Узлы») и выбор локации ---------- */
  const drawer = $('#serverDrawer');
  const serverList = $('#serverList');
  const nodesServerList = $('#nodesServerList');
  const homeServerList = $('#homeServerList');
  const FILTER_KEY = 'tachyon.node_filters';

  function getCurrentSearchQuery() {
    if (!drawer?.hidden) return $('#serverSearch')?.value || '';
    if (currentView === 'subscriptions') return $('#nodesSearchInput')?.value || '';
    return $('#homeServerSearch')?.value || '';
  }

  let nodeFilters = {
    sort: 'country_ping', // 'country_ping' | 'ping' | 'sub_ping' | 'name'
    proto: 'all',         // 'all' | 'alive' | 'REALITY' | 'XHTTP' | 'TCP' | 'WS_GRPC' | 'HY2' | 'AWG' | 'SS'
    countries: [],        // выбранные ISO коды ('us', 'de', ...)
    excludedCountries: [],// исключённые ISO коды (ПКМ по чипу страны)
    dedup: true,          // убирать дубликаты по host:port
    hidePromo: true,      // скрывать инфо/рекламные записи
    excludeText: '',      // стоп-слова
    maxPing: 0            // макс. пинг в мс (0 = без лимита)
  };
  try {
    const savedF = JSON.parse(localStorage.getItem(FILTER_KEY) || 'null');
    if (savedF && typeof savedF === 'object') Object.assign(nodeFilters, savedF);
  } catch {}

  function onFiltersChanged() {
    try { localStorage.setItem(FILTER_KEY, JSON.stringify(nodeFilters)); } catch {}
    ensureValidActiveServer();
    updateAdvFilterBadge();
    updateLocCount();
    updateActiveServerDisplay();
    renderServers(getCurrentSearchQuery());
  }

  function saveNodeFilters() {
    try { localStorage.setItem(FILTER_KEY, JSON.stringify(nodeFilters)); } catch {}
    updateAdvFilterBadge();
  }

  const collapsedGroups = new Set();
  const expandedGroupsLimit = new Set();
  let lastFilteredServers = [];

  const PROMO_REGEX = /(t\.me\/|@[a-z0-9_]{3,}|осталось|трафик|подписк[аиу]|истек|expired|renew|купить|оплат|bot\b|канал|новости|0\.0\.0\.0|127\.0\.0\.1|localhost)/i;

  function isPromoOrBogusNode(s) {
    const n = s.name || '';
    const h = s.meta?.host || '';
    if (!h || h === '0.0.0.0' || h === '127.0.0.1' || h === 'localhost' || h.startsWith('127.')) return true;
    return PROMO_REGEX.test(n);
  }

  function matchProtoFilter(s, pf) {
    if (!pf || pf === 'all') return true;
    if (pf === 'alive') return s.ping != null && s.ping > 0;
    const m = s.meta || parseNodeMeta(s.vless);
    if (pf === 'REALITY') return m.sec === 'REALITY';
    if (pf === 'XHTTP') return m.trans === 'XHTTP';
    if (pf === 'TCP') return m.trans === 'TCP' && m.proto === 'VLESS';
    if (pf === 'WS_GRPC') return m.trans === 'WS' || m.trans === 'GRPC';
    return m.proto === pf;
  }

  function getBaseFilteredServers(searchQuery = '') {
    const q = searchQuery.trim().toLowerCase();
    const exTokens = (nodeFilters.excludeText || '')
      .split(/[,|;]/)
      .map(t => t.trim().toLowerCase())
      .filter(Boolean);

    const seenEndpoints = new Map();
    const out = [];

    for (const s of servers) {
      if (nodeFilters.hidePromo && isPromoOrBogusNode(s)) continue;

      if (nodeFilters.excludedCountries.includes(s.country)) continue;

      if (exTokens.length) {
        const hay = `${s.name} ${s.country} ${s.countryName} ${s.meta?.host || ''} ${s.subName || ''}`.toLowerCase();
        if (exTokens.some(tok => tok.length === 2 ? (s.country === tok || hay.includes(tok)) : hay.includes(tok))) {
          continue;
        }
      }

      if (nodeFilters.maxPing > 0 && s.ping != null && s.ping > nodeFilters.maxPing) continue;

      if (!matchProtoFilter(s, nodeFilters.proto)) continue;

      if (q) {
        const hay = `${s.name} ${s.country} ${s.countryName} ${s.code} ${(s.meta?.tags || []).join(' ')} ${s.meta?.host || ''} ${s.subName || ''}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }

      if (nodeFilters.dedup && s.endpointKey) {
        const prevIdx = seenEndpoints.get(s.endpointKey);
        if (prevIdx !== undefined) {
          const prev = out[prevIdx];
          if (s.id === activeId || (s.ping != null && (prev.ping == null || s.ping < prev.ping))) {
            out[prevIdx] = s;
          }
          continue;
        }
        seenEndpoints.set(s.endpointKey, out.length);
      }

      out.push(s);
    }
    return out;
  }

  function getStrictlyFilteredServers(searchQuery = '') {
    const base = getBaseFilteredServers(searchQuery);
    return nodeFilters.countries.length
      ? base.filter(s => nodeFilters.countries.includes(s.country))
      : base;
  }

  function renderCountryChips(baseList) {
    const bar = $('#countryChips');
    if (!bar) return;

    const counts = new Map();
    for (const s of baseList) {
      const c = s.country || 'xx';
      counts.set(c, (counts.get(c) || 0) + 1);
    }
    for (const ex of nodeFilters.excludedCountries) {
      if (!counts.has(ex)) counts.set(ex, 0);
    }

    const sortedCodes = [...counts.keys()].sort((a, b) => {
      if (a === 'xx') return 1;
      if (b === 'xx') return -1;
      return (counts.get(b) || 0) - (counts.get(a) || 0);
    });

    const allActive = nodeFilters.countries.length === 0;
    let html = `<button type="button" class="f-chip ${allActive ? 'is-active' : ''}" data-cc="all">Все <em class="chip-count">${baseList.length}</em></button>`;

    for (const code of sortedCodes) {
      const cnt = counts.get(code) || 0;
      const isSel = nodeFilters.countries.includes(code);
      const isEx = nodeFilters.excludedCountries.includes(code);
      const label = COUNTRY_NAMES[code] || code.toUpperCase();
      const flagSrc = flagFor(code);
      html += `
        <button type="button" class="f-chip ${isSel ? 'is-active' : ''} ${isEx ? 'is-excluded' : ''}" data-cc="${code}" title="ЛКМ — выбрать «${escapeHtml(label)}», ПКМ — исключить страну">
          <img class="chip-flag" src="${flagSrc}" onerror="this.onerror=null;this.src='flags/globe.svg'" alt="" />
          <span>${escapeHtml(label)}</span>
          <em class="chip-count">${cnt}</em>
        </button>
      `;
    }

    bar.innerHTML = html;

    $$('button[data-cc]', bar).forEach(btn => {
      const cc = btn.dataset.cc;
      btn.addEventListener('click', () => {
        if (cc === 'all') {
          nodeFilters.countries = [];
        } else {
          if (nodeFilters.excludedCountries.includes(cc)) {
            nodeFilters.excludedCountries = nodeFilters.excludedCountries.filter(x => x !== cc);
          }
          if (nodeFilters.countries.includes(cc)) {
            nodeFilters.countries = nodeFilters.countries.filter(x => x !== cc);
          } else {
            nodeFilters.countries.push(cc);
          }
        }
        onFiltersChanged();
      });

      btn.addEventListener('contextmenu', e => {
        e.preventDefault();
        if (cc === 'all') return;
        nodeFilters.countries = nodeFilters.countries.filter(x => x !== cc);
        if (nodeFilters.excludedCountries.includes(cc)) {
          nodeFilters.excludedCountries = nodeFilters.excludedCountries.filter(x => x !== cc);
          toast(`Страна возвращена: ${COUNTRY_NAMES[cc] || cc.toUpperCase()}`);
        } else {
          nodeFilters.excludedCountries.push(cc);
          toast(`Страна исключена: ${COUNTRY_NAMES[cc] || cc.toUpperCase()}`);
        }
        onFiltersChanged();
      });
    });
  }

  function compareByPingThenName(a, b) {
    const pa = a.ping != null && a.ping > 0 ? a.ping : 999999;
    const pb = b.ping != null && b.ping > 0 ? b.ping : 999999;
    if (pa !== pb) return pa - pb;
    return (a.name || '').localeCompare(b.name || '', 'ru', { numeric: true });
  }

  function renderServerRow(s) {
    const isAct = s.id === activeId;
    const pingStr = s.ping != null ? `${s.ping} мс` : '–';
    const pingClass = s.ping != null ? (s.ping < 120 ? 'is-good' : (s.ping < 250 ? 'is-med' : 'is-slow')) : '';
    const tags = s.meta?.tags || [detectProtocol(s.vless)];
    const badgesHtml = tags.map(t => {
      const cls = t === 'REALITY' ? 'proto-badge--reality' : (t === 'XHTTP' ? 'proto-badge--xhttp' : (t === 'HY2' || t === 'AWG' ? 'proto-badge--hy2' : ''));
      return `<span class="proto-badge ${cls}">${escapeHtml(t)}</span>`;
    }).join(' ');

    return `
      <li class="server-item ${isAct ? 'is-active' : ''}" data-id="${s.id}">
        <img class="flag-slot" src="${flagFor(s)}" onerror="this.onerror=null;this.src='flags/globe.svg'" alt="" />
        <div class="server__info">
          <span class="server__country">${escapeHtml(s.name || 'Сервер')}</span>
          <span class="server__city">${badgesHtml}</span>
        </div>
        <div class="server__right">
          <span class="server__ping ${pingClass}">${pingStr}</span>
        </div>
      </li>
    `;
  }

  function bindServerListInteractions(container) {
    if (!container) return;

    $$('.server-item[data-id]', container).forEach(el => {
      el.addEventListener('click', () => selectServer(el.dataset.id));
    });

    $$('.server-group-head[data-group]', container).forEach(head => {
      head.addEventListener('click', e => {
        if (e.target.closest('[data-ping-group]')) return;
        const g = head.dataset.group;
        if (collapsedGroups.has(g)) collapsedGroups.delete(g);
        else collapsedGroups.add(g);
        renderServers(getCurrentSearchQuery());
      });
    });

    $$('[data-ping-group]', container).forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const g = btn.dataset.pingGroup;
        const subset = lastFilteredServers.filter(s =>
          (nodeFilters.sort === 'country_ping' ? (s.country || 'xx') : (s.subName || 'Узлы')) === g
        );
        measurePingsForList(subset);
      });
    });

    $$('.server-more-btn[data-expand]', container).forEach(btn => {
      btn.addEventListener('click', () => {
        expandedGroupsLimit.add(btn.dataset.expand);
        renderServers(getCurrentSearchQuery());
      });
    });
  }

  function renderServers(q = '') {
    const clearBtn = $('#clearSearchBtn');
    if (clearBtn) clearBtn.hidden = !($('#serverSearch')?.value);
    const clearNodesBtn = $('#clearNodesSearchBtn');
    if (clearNodesBtn) clearNodesBtn.hidden = !($('#nodesSearchInput')?.value);

    const baseFiltered = getBaseFilteredServers(q);
    renderCountryChips(baseFiltered);

    const filtered = nodeFilters.countries.length
      ? baseFiltered.filter(s => nodeFilters.countries.includes(s.country))
      : baseFiltered;

    lastFilteredServers = filtered;

    const badgeText = filtered.length === servers.length
      ? `${filtered.length}`
      : `${filtered.length} / ${servers.length}`;

    const countBadge = $('#drawerCountBadge');
    if (countBadge) countBadge.textContent = badgeText;
    const nfBadge = $('#nodesFilterCountBadge');
    if (nfBadge) nfBadge.textContent = badgeText;
    const homeBadge = $('#homeServerCountBadge');
    if (homeBadge) homeBadge.textContent = badgeText;

    const isGrouped = nodeFilters.sort === 'country_ping' || nodeFilters.sort === 'sub_ping';
    const collapseBtn = $('#collapseGroupsBtn');
    if (collapseBtn) collapseBtn.hidden = !isGrouped;
    const nodesCollapseBtn = $('#nodesCollapseGroupsBtn');
    if (nodesCollapseBtn) nodesCollapseBtn.hidden = !isGrouped;

    let html = '';

    if (!filtered.length) {
      html = `<li class="server-item server--empty">Узлы не найдены. Измените параметры фильтрации выше или нажмите «Сброс».</li>`;
    } else if (!isGrouped) {
      const sorted = [...filtered].sort((a, b) => {
        if (nodeFilters.sort === 'ping') return compareByPingThenName(a, b);
        return (a.name || '').localeCompare(b.name || '', 'ru', { numeric: true });
      });
      const limit = expandedGroupsLimit.has('__flat__') ? sorted.length : 120;
      html = sorted.slice(0, limit).map(renderServerRow).join('');
      if (sorted.length > limit) {
        html += `<li class="server-more-btn" data-expand="__flat__">Показать ещё ${sorted.length - limit} узлов…</li>`;
      }
    } else {
      const groups = new Map();
      filtered.forEach(s => {
        const gKey = nodeFilters.sort === 'country_ping'
          ? (s.country || 'xx')
          : (s.subName || 'Узлы');
        if (!groups.has(gKey)) groups.set(gKey, []);
        groups.get(gKey).push(s);
      });

      const groupEntries = [...groups.entries()].map(([gKey, items]) => {
        items.sort(compareByPingThenName);
        let bestPing = null;
        for (const it of items) {
          if (it.ping != null && it.ping > 0 && (bestPing == null || it.ping < bestPing)) {
            bestPing = it.ping;
          }
        }
        return { gKey, items, bestPing };
      });

      if (nodeFilters.sort === 'country_ping') {
        groupEntries.sort((a, b) => {
          if (a.gKey === 'xx' && b.gKey !== 'xx') return 1;
          if (b.gKey === 'xx' && a.gKey !== 'xx') return -1;
          const pa = a.bestPing ?? 999999;
          const pb = b.bestPing ?? 999999;
          if (pa !== pb) return pa - pb;
          return b.items.length - a.items.length;
        });
      }

      for (const { gKey, items, bestPing } of groupEntries) {
        const isCollapsed = collapsedGroups.has(gKey);
        const title = nodeFilters.sort === 'country_ping'
          ? (COUNTRY_NAMES[gKey] || gKey.toUpperCase())
          : gKey;
        const flagHtml = nodeFilters.sort === 'country_ping'
          ? `<img class="server-group-head__flag" src="${flagFor(gKey)}" onerror="this.onerror=null;this.src='flags/globe.svg'" alt="" />`
          : '';
        const bestHtml = bestPing != null ? `<span class="server-group-head__best"><svg class="ic"><use href="#ic-bolt"/></svg>${bestPing} мс</span>` : '';

        html += `
          <li class="server-group-head ${isCollapsed ? 'is-collapsed' : ''}" data-group="${escapeHtml(gKey)}">
            <div class="server-group-head__left">
              ${flagHtml}
              <span class="server-group-head__title">${escapeHtml(title)}</span>
              <span class="server-group-head__count">${items.length}</span>
            </div>
            <div class="server-group-head__right">
              ${bestHtml}
              <button type="button" class="server-group-head__ping-btn" data-ping-group="${escapeHtml(gKey)}" title="Замерить пинг только в этой группе"><svg class="ic"><use href="#ic-bolt"/></svg><span>Пинг</span></button>
              <svg class="ic server-group-head__chev"><use href="#ic-chevron"/></svg>
            </div>
          </li>
        `;

        if (!isCollapsed) {
          const limit = expandedGroupsLimit.has(gKey) ? items.length : 60;
          html += items.slice(0, limit).map(renderServerRow).join('');
          if (items.length > limit) {
            html += `<li class="server-more-btn" data-expand="${escapeHtml(gKey)}">Показать ещё ${items.length - limit} из ${items.length}…</li>`;
          }
        }
      }
    }

    if (serverList && !drawer?.hidden) {
      serverList.innerHTML = html;
      bindServerListInteractions(serverList);
    }
    if (nodesServerList && currentView === 'subscriptions') {
      nodesServerList.innerHTML = html;
      bindServerListInteractions(nodesServerList);
    }
    if (homeServerList && currentView === 'connect') {
      homeServerList.innerHTML = html;
      bindServerListInteractions(homeServerList);
    }
  }

  function updateAdvFilterBadge() {
    const badge = $('#advFilterBadge');
    const btn = $('#openNodesFilterFromDrawerBtn');
    let count = 0;
    if (nodeFilters.proto && nodeFilters.proto !== 'all') count++;
    if (nodeFilters.countries.length) count += nodeFilters.countries.length;
    if (nodeFilters.excludedCountries.length) count += nodeFilters.excludedCountries.length;
    if (nodeFilters.excludeText.trim()) count++;
    if (nodeFilters.maxPing > 0) count++;
    if (badge) {
      badge.hidden = count === 0;
      badge.textContent = String(count);
    }
    btn?.classList.toggle('btn-act--primary', count > 0);

    const ruByBtn = $('#quickExcludeRuByBtn');
    if (ruByBtn) {
      const hasRuBy = nodeFilters.excludedCountries.includes('ru') && nodeFilters.excludedCountries.includes('by');
      ruByBtn.classList.toggle('is-active', hasRuBy);
    }
  }

  function syncFilterUiControls() {
    $$('#sortBar button[data-sort], #nodesSortBar button[data-sort]').forEach(b => {
      b.classList.toggle('is-active', b.dataset.sort === nodeFilters.sort);
    });
    $$('#protoChips button[data-proto]').forEach(b => {
      b.classList.toggle('is-active', b.dataset.proto === nodeFilters.proto);
    });
    const dedupEl = $('#dedupNodesToggle');
    if (dedupEl) dedupEl.checked = !!nodeFilters.dedup;
    const promoEl = $('#hidePromoToggle');
    if (promoEl) promoEl.checked = !!nodeFilters.hidePromo;
    const exEl = $('#excludeFilterInput');
    if (exEl) exEl.value = nodeFilters.excludeText || '';
    const mpEl = $('#maxPingInput');
    if (mpEl) mpEl.value = nodeFilters.maxPing > 0 ? String(nodeFilters.maxPing) : '';
    updateAdvFilterBadge();
  }

  function openDrawer() {
    if (!drawer) return;
    syncFilterUiControls();
    drawer.hidden = false;
    requestAnimationFrame(() => drawer.classList.add('show'));
    renderServers($('#serverSearch')?.value || '');
  }

  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove('show');
    setTimeout(() => { drawer.hidden = true; }, 280);
  }

  $('#serverPick')?.addEventListener('click', openDrawer);
  $('#drawerClose')?.addEventListener('click', closeDrawer);
  $('#drawerBackdrop')?.addEventListener('click', closeDrawer);

  $('#openNodesFilterFromDrawerBtn')?.addEventListener('click', () => {
    closeDrawer();
    go('subscriptions');
    setTimeout(() => {
      $('#nodesFilterCard')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 80);
  });

  $('#serverSearch')?.addEventListener('input', e => renderServers(e.target.value));
  $('#clearSearchBtn')?.addEventListener('click', () => {
    const inp = $('#serverSearch');
    if (inp) { inp.value = ''; inp.focus(); }
    renderServers('');
  });

  $('#nodesSearchInput')?.addEventListener('input', e => renderServers(e.target.value));
  $('#clearNodesSearchBtn')?.addEventListener('click', () => {
    const inp = $('#nodesSearchInput');
    if (inp) { inp.value = ''; inp.focus(); }
    renderServers('');
  });

  $('#homeServerSearch')?.addEventListener('input', e => renderServers(e.target.value));
  $('#homeOpenSubsViewBtn')?.addEventListener('click', () => go('subscriptions'));

  $$('#sortBar button[data-sort], #nodesSortBar button[data-sort]').forEach(b => {
    b.addEventListener('click', () => {
      nodeFilters.sort = b.dataset.sort;
      collapsedGroups.clear();
      saveNodeFilters();
      syncFilterUiControls();
      renderServers(getCurrentSearchQuery());
    });
  });

  $$('#protoChips button[data-proto]').forEach(b => {
    b.addEventListener('click', () => {
      nodeFilters.proto = b.dataset.proto;
      syncFilterUiControls();
      onFiltersChanged();
    });
  });

  function toggleAllGroupsCollapse() {
    const keys = new Set(lastFilteredServers.map(s =>
      nodeFilters.sort === 'country_ping' ? (s.country || 'xx') : (s.subName || 'Узлы')
    ));
    const allCollapsed = [...keys].every(k => collapsedGroups.has(k));
    collapsedGroups.clear();
    if (!allCollapsed) keys.forEach(k => collapsedGroups.add(k));
    const txt = allCollapsed ? 'Свернуть' : 'Развернуть';
    const b1 = $('#collapseGroupsBtn'); if (b1) b1.textContent = txt;
    const b2 = $('#nodesCollapseGroupsBtn'); if (b2) b2.textContent = txt;
    renderServers(getCurrentSearchQuery());
  }

  $('#collapseGroupsBtn')?.addEventListener('click', toggleAllGroupsCollapse);
  $('#nodesCollapseGroupsBtn')?.addEventListener('click', toggleAllGroupsCollapse);

  $('#dedupNodesToggle')?.addEventListener('change', e => {
    nodeFilters.dedup = e.target.checked;
    onFiltersChanged();
  });

  $('#hidePromoToggle')?.addEventListener('change', e => {
    nodeFilters.hidePromo = e.target.checked;
    onFiltersChanged();
  });

  $('#quickExcludeRuByBtn')?.addEventListener('click', () => {
    const targets = ['ru', 'by', 'xx'];
    const hasAll = targets.every(c => nodeFilters.excludedCountries.includes(c));
    if (hasAll) {
      nodeFilters.excludedCountries = nodeFilters.excludedCountries.filter(c => !targets.includes(c));
      toast('Локации РФ / РБ возвращены в список');
    } else {
      for (const c of targets) {
        nodeFilters.countries = nodeFilters.countries.filter(x => x !== c);
        if (!nodeFilters.excludedCountries.includes(c)) nodeFilters.excludedCountries.push(c);
      }
      toast('Узлы РФ, РБ и прочие нераспознанные локации исключены');
    }
    onFiltersChanged();
  });

  $('#excludeFilterInput')?.addEventListener('input', e => {
    nodeFilters.excludeText = e.target.value;
    onFiltersChanged();
  });

  $('#maxPingInput')?.addEventListener('input', e => {
    nodeFilters.maxPing = parseInt(e.target.value, 10) || 0;
    onFiltersChanged();
  });

  $('#resetFiltersBtn')?.addEventListener('click', () => {
    nodeFilters = {
      sort: nodeFilters.sort,
      proto: 'all',
      countries: [],
      excludedCountries: [],
      dedup: true,
      hidePromo: true,
      excludeText: '',
      maxPing: 0
    };
    const inp1 = $('#serverSearch'); if (inp1) inp1.value = '';
    const inp2 = $('#nodesSearchInput'); if (inp2) inp2.value = '';
    syncFilterUiControls();
    onFiltersChanged();
    toast('Фильтры сброшены');
  });

  /* Физическое удаление отсеянных фильтром узлов из базы подписок */
  $('#purgeFilteredNodesBtn')?.addEventListener('click', async () => {
    const kept = getStrictlyFilteredServers('');
    const removedCount = servers.length - kept.length;
    if (removedCount <= 0) {
      toast('Нет отсеянных узлов для удаления — все узлы проходят фильтр');
      return;
    }
    if (!(await confirmDialog(`Удалить из базы ${removedCount} отфильтрованных узлов и оставить только ${kept.length} активных?`))) {
      return;
    }
    const keptIds = new Set(kept.map(s => s.id));
    const subs = window.API.getSubscriptions();
    for (const sub of subs) {
      if (Array.isArray(sub.servers)) {
        sub.servers = sub.servers.filter(s => keptIds.has(s.id));
        sub.nodesCount = sub.servers.length;
      }
    }
    window.API.saveSubscriptions(subs);

    const customs = window.API.getCustomNodes();
    if (customs.length) {
      window.API.saveCustomNodes(customs.filter(c => keptIds.has(c.id)));
    }

    renderSubscriptions();
    loadAllServers();
    toast(`Удалено ${removedCount} мусорных/отфильтрованных узлов. Осталось: ${kept.length}`);
  });

  function selectServer(id) {
    const s = servers.find(x => x.id === id);
    if (!s) return;
    activeId = id;
    try { localStorage.setItem('tachyon.active_server_id', id); } catch {}
    updateActiveServerDisplay();
    if (!drawer?.hidden) closeDrawer();
    $$('.server-item').forEach(el => {
      const act = el.dataset.id === id;
      el.classList.toggle('is-active', act);
      el.classList.toggle('active', act);
    });

    if (connected) {
      toast('Узел переключён на ' + (s.name || s.country));
      applyReconnectIfActive();
    } else {
      toast('Выбран узел: ' + (s.name || s.country));
    }
  }

  /* ---------- Быстрый батч-замер пинга (СТРОГО ПО ОТФИЛЬТРОВАННЫМ УЗЛАМ) ---------- */
  let pingJobAbort = false;
  let pingJobRunning = false;

  function triggerFilteredPing() {
    if (pingJobRunning) {
      pingJobAbort = true;
      return;
    }
    const strictlyFiltered = getStrictlyFilteredServers(getCurrentSearchQuery());
    measurePingsForList(strictlyFiltered);
  }

  $('#pingAllBtn')?.addEventListener('click', triggerFilteredPing);
  $('#nodesPingFilteredBtn')?.addEventListener('click', triggerFilteredPing);
  $('#homePingBtn')?.addEventListener('click', triggerFilteredPing);

  async function measurePingsForList(targetList) {
    if (!window.API.hasNativeVpn) return;

    /* Гарантируем, что НИ ОДИН отфильтрованный (скрытый) узел не попадёт в замер пинга */
    const allowedIds = new Set(getStrictlyFilteredServers('').map(s => s.id));
    const cleanTargetList = (targetList && targetList.length ? targetList : getStrictlyFilteredServers(''))
      .filter(s => allowedIds.has(s.id));

    if (!cleanTargetList.length) {
      toast('Нет отфильтрованных узлов для замера пинга', true);
      return;
    }

    if (pingJobRunning) {
      pingJobAbort = true;
      await new Promise(r => setTimeout(r, 150));
    }

    pingJobRunning = true;
    pingJobAbort = false;
    const btn = $('#pingAllBtn');
    const lbl = $('#pingBtnLabel');
    const nodesBtn = $('#nodesPingFilteredBtn');
    const nodesLbl = $('#nodesPingBtnLabel');
    const homeBtn = $('#homePingBtn');
    const homeLbl = $('#homePingBtnTxt');
    btn?.classList.add('btn-act--primary');
    nodesBtn?.classList.add('btn-act--primary');
    homeBtn?.classList.add('btn-act--primary');

    /* Группируем отфильтрованные узлы по host:port, чтобы не пинговать одинаковые IP многократно */
    const endpointMap = new Map();
    for (const s of cleanTargetList) {
      const host = s.meta?.host || extractHost(s.vless);
      const port = s.meta?.port || 443;
      if (!host) continue;
      const key = `${host.toLowerCase()}:${port}`;
      if (!endpointMap.has(key)) endpointMap.set(key, { host, port, nodes: [] });
      endpointMap.get(key).nodes.push(s);
    }

    const tasks = [...endpointMap.values()];
    const total = tasks.length;
    let done = 0;
    let aliveCount = 0;
    let lastRender = 0;

    if (lbl) lbl.textContent = `0/${total}`;
    if (nodesLbl) nodesLbl.textContent = `0/${total}`;
    if (homeLbl) homeLbl.textContent = `0/${total}`;

    const CONCURRENCY = 16;
    let idx = 0;

    async function worker() {
      while (!pingJobAbort && idx < total) {
        const item = tasks[idx++];
        let ms = await window.API.nativeTcpPing(item.host, item.port, 2400);
        if (ms == null) {
          ms = await window.API.nativePing(item.host, 1800);
        }
        done++;
        if (ms != null && ms > 0) {
          aliveCount++;
          const key = `${item.host.toLowerCase()}:${item.port}`;
          pingCache[key] = ms;
          for (const srv of item.nodes) {
            srv.ping = ms;
            if (srv.id === activeId) $('#mPing').textContent = ms;
          }
          for (const srv of servers) {
            if (allowedIds.has(srv.id) && srv.endpointKey === key) srv.ping = ms;
          }
        }
        if (lbl) lbl.textContent = `${done}/${total}`;
        if (nodesLbl) nodesLbl.textContent = `${done}/${total}`;
        if (homeLbl) homeLbl.textContent = `${done}/${total}`;
        const now = Date.now();
        if (now - lastRender > 260 || done === total) {
          lastRender = now;
          renderServers(getCurrentSearchQuery());
        }
      }
    }

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, total) }, () => worker()));

    savePingCache();
    pingJobRunning = false;
    btn?.classList.remove('btn-act--primary');
    nodesBtn?.classList.remove('btn-act--primary');
    homeBtn?.classList.remove('btn-act--primary');
    if (lbl) lbl.textContent = 'Пинг';
    if (nodesLbl) nodesLbl.textContent = 'Пинг';
    if (homeLbl) homeLbl.textContent = 'Пинг';
    renderServers(getCurrentSearchQuery());

    if (pingJobAbort) {
      toast(`Замер остановлен (${done}/${total}, доступно: ${aliveCount})`);
    } else {
      toast(`Замер отфильтрованных завершён: ${aliveCount} из ${total} доступно`);
      if ($('#autoServerToggle')?.checked && aliveCount > 0) {
        const best = [...cleanTargetList].filter(s => s.ping != null && s.ping > 0).sort((a, b) => a.ping - b.ping)[0];
        if (best && !connected && !connecting) {
          activeId = best.id;
          try { localStorage.setItem('tachyon.active_server_id', best.id); } catch {}
          updateActiveServerDisplay();
        }
      }
    }
  }

  function extractHost(vless) {
    try {
      const m = String(vless).match(/@([^:/?#]+)/);
      return m ? m[1] : '';
    } catch { return ''; }
  }

  /* ---------- Активные соединения (Connections View) ---------- */
  let connFilterMode = 'all';
  let lastConnsData = { down: 0, up: 0, conns: [] };

  const connFilter = $('#connFilter');
  if (connFilter) {
    $$('button[data-cf]', connFilter).forEach(b => {
      b.addEventListener('click', () => {
        $$('button', connFilter).forEach(x => x.classList.remove('is-active'));
        b.classList.add('is-active');
        connFilterMode = b.dataset.cf;
        renderConnections();
      });
    });
  }

  window.API.onConnData(data => {
    lastConnsData = data || { down: 0, up: 0, conns: [] };
    if (currentView === 'connections') renderConnections();
  });

  function renderConnections() {
    const list = $('#connList');
    const empty = $('#connEmpty');
    const tot = $('#connTotals');
    if (!list) return;

    const sq = ($('#connSearchInput')?.value || '').trim().toLowerCase();
    const all = Array.isArray(lastConnsData.conns) ? lastConnsData.conns : [];
    const filtered = all.filter(c => {
      if (connFilterMode === 'desync' && !c.desync) return false;
      if (connFilterMode === 'vpn' && (c.direct || c.desync)) return false;
      if (connFilterMode === 'direct' && (!c.direct || c.desync)) return false;
      if (sq) {
        const hay = `${c.proc || ''} ${c.host || ''} ${c.ip || ''} ${c.port || ''}`.toLowerCase();
        if (!hay.includes(sq)) return false;
      }
      return true;
    });

    if (tot) tot.textContent = `${filtered.length} соед.`;

    if (!filtered.length) {
      list.innerHTML = '';
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    list.innerHTML = filtered.slice(0, 80).map((c, idx) => {
      const target = c.host || c.ip || '–';
      const proc = c.proc ? c.proc.split(/[\\/]/).pop() : 'system';
      const isDesync = !!c.desync;
      const isDirect = !!c.direct && !isDesync;
      const badgeCls = isDesync ? 'conn-b--desync' : (isDirect ? 'conn-b--direct' : 'conn-b--vpn');
      const badgeTxt = isDesync ? 'DESYNC' : (isDirect ? 'ПРЯМОЕ' : 'VPN');
      const cid = c.id || '';
      return `
        <li class="conn-row" data-conn-idx="${idx}">
          <div class="conn-row__main" data-conn-rule="${escapeHtml(target)}" data-conn-proc="${escapeHtml(proc)}" title="Нажмите, чтобы создать правило для ${escapeHtml(target)}">
            <b>${escapeHtml(proc)}</b>
            <small>${escapeHtml(target)}${c.port ? ':' + c.port : ''} · ${(c.net || 'tcp').toUpperCase()}</small>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex:none">
            <span class="conn-b ${badgeCls}">${badgeTxt}</span>
            ${cid ? `<button type="button" class="conn-close-btn" data-close-cid="${escapeHtml(cid)}" title="Принудительно закрыть соединение"><svg class="ic"><use href="#ic-close"/></svg></button>` : ''}
          </div>
        </li>
      `;
    }).join('');

    $$('[data-close-cid]', list).forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const cid = btn.dataset.closeCid;
        if (cid) {
          window.API.closeConnection(cid);
          btn.closest('.conn-row')?.remove();
        }
      });
    });

    $$('[data-conn-rule]', list).forEach(mainEl => {
      mainEl.style.cursor = 'pointer';
      mainEl.addEventListener('click', () => {
        const hostVal = mainEl.dataset.connRule;
        if (!hostVal || hostVal === '–') return;
        const cleanVal = hostVal.replace(/:\d+$/, '');
        const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(cleanVal);
        const existing = customRouteRules.find(r => r.value.toLowerCase() === cleanVal.toLowerCase());
        const nextAct = existing
          ? (existing.action === 'vpn' ? 'desync' : (existing.action === 'desync' ? 'direct' : 'vpn'))
          : 'vpn';
        if (existing) {
          existing.action = nextAct;
        } else {
          customRouteRules.unshift({ type: isIp ? 'ip' : 'domain', value: cleanVal, action: nextAct });
        }
        saveCustomRouteRules();
        renderCustomRules();
        applyReconnectIfActive();
        toast(`Правило: ${cleanVal} → ${nextAct.toUpperCase()}`);
      });
    });
  }

  /* ---------- Настройки (VPN Prefs & Rules) ---------- */
  const PREFS_KEY = 'tachyon.vpnprefs';
  let vpnPrefs = {
    mode: 'tun',
    route: 'all',
    split: 'include',
    dns: 'auto',
    dnsBootstrap: '77.88.8.8',
    fakeIp: false,
    dnsRouteMode: 'smart',
    mtu: 1400,
    allowLan: false,
    proxyTlsFragment: false,
    logLevel: 'info',
    detourNodeId: '',
    theme: 'dark'
  };
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) || 'null');
    if (saved) Object.assign(vpnPrefs, saved);
  } catch {}

  function saveVpnPrefs() {
    try { localStorage.setItem(PREFS_KEY, JSON.stringify(vpnPrefs)); } catch {}
  }

  const modeSelect = $('#modeSelect');
  if (modeSelect) {
    const btn = $('.mini-select__btn', modeSelect);
    const menu = $('.mini-select__menu', modeSelect);
    const valSpan = $('.mini-select__val', modeSelect);
    btn?.addEventListener('click', e => { e.stopPropagation(); menu.hidden = !menu.hidden; });
    document.addEventListener('click', () => { if (menu) menu.hidden = true; });

    $$('li[data-value]', menu).forEach(li => {
      li.addEventListener('click', () => {
        const v = li.dataset.value;
        vpnPrefs.mode = v;
        saveVpnPrefs();
        if (valSpan) valSpan.textContent = li.textContent;
        const hint = $('#modeRowHint');
        if (hint) hint.textContent = v === 'proxy' ? 'Локальный прокси 127.0.0.1:7897' : TUN_HINT;
        if (connected) {
          toast('Перезапуск в новом режиме…');
          window.API.vpnConnect(buildConnectOpts(activeServer()));
        }
      });
    });
  }

  const dnsSelect = $('#dnsSelect');
  if (dnsSelect) {
    const btn = $('.mini-select__btn', dnsSelect);
    const menu = $('.mini-select__menu', dnsSelect);
    const valSpan = $('.mini-select__val', dnsSelect);
    btn?.addEventListener('click', e => { e.stopPropagation(); menu.hidden = !menu.hidden; });
    document.addEventListener('click', () => { if (menu) menu.hidden = true; });

    $$('li[data-value]', menu).forEach(li => {
      li.addEventListener('click', () => {
        vpnPrefs.dns = li.dataset.value;
        saveVpnPrefs();
        if (valSpan) valSpan.textContent = li.textContent;
        if (connected) {
          toast('Применение DNS…');
          window.API.vpnConnect(buildConnectOpts(activeServer()));
        }
      });
    });
  }

  const autoConnectToggle = $('#autoConnectToggle');
  if (autoConnectToggle) {
    autoConnectToggle.checked = localStorage.getItem('tachyon.autoconnect') === '1';
    autoConnectToggle.addEventListener('change', () => {
      localStorage.setItem('tachyon.autoconnect', autoConnectToggle.checked ? '1' : '0');
    });
  }

  const killSwitchToggle = $('#killSwitchToggle');
  if (killSwitchToggle) {
    killSwitchToggle.checked = localStorage.getItem('tachyon.killswitch') === '1';
    killSwitchToggle.addEventListener('change', () => {
      const on = killSwitchToggle.checked;
      localStorage.setItem('tachyon.killswitch', on ? '1' : '0');
      window.API.setKillSwitch(on);
      toast(on ? 'Kill Switch включён' : 'Kill Switch выключен');
    });
  }

  const routeSwitch = $('#routeSwitch');
  const appRoutes = $('#appRoutes');

  /* ============================================================
     DESYNC (DPI BYPASS) И ТОЧЕЧНАЯ МАРШРУТИЗАЦИЯ (TACHYON-LISTS)
     ============================================================ */
  const DESYNC_KEY = 'tachyon.desync_prefs';
  const LISTS_STATE_KEY = 'tachyon.community_lists_v1';
  const CUSTOM_RULES_KEY = 'tachyon.custom_route_rules_v1';

  const DESYNC_PRESET_LABELS = {
    auto: 'Авто (Adaptive)',
    youtube_discord: 'YT + Discord',
    fake_split: 'Fake + Split',
    fake_disorder: 'Fake + Disorder',
    tlsrec: 'TLS Record',
    multi_split: 'Multi-Split',
    split: 'Split',
    disorder: 'Disorder',
    fake: 'Только Fake',
    oob: 'TCP OOB',
    custom: 'Свой профиль'
  };

  function getDefaultDesyncPrefs() {
    return {
      enabled: true,
      autoDirect: true,
      preset: 'auto',
      mode: 'auto',
      fooling: 'md5',
      splitPos: 'midsld',
      fakeTtl: 6,
      fakeSni: 'www.google.com',
      repeats: 2,
      splitDelayMs: 1,
      udpFake: true,
      udpRepeats: 6,
      udpFakeTtl: 6,
      blockQuic: true,
      autoTune: true
    };
  }

  let desyncPrefs = getDefaultDesyncPrefs();
  try {
    const savedD = JSON.parse(localStorage.getItem(DESYNC_KEY) || 'null');
    if (savedD && typeof savedD === 'object') {
      Object.assign(desyncPrefs, savedD);
      if (desyncPrefs.fooling === 'md5sig') desyncPrefs.fooling = 'md5';
      if (desyncPrefs.autoDirect === undefined) desyncPrefs.autoDirect = true;
    }
  } catch {}

  function saveDesyncPrefs() {
    try { localStorage.setItem(DESYNC_KEY, JSON.stringify(desyncPrefs)); } catch {}
    updateRoutingSummaryUI();
  }

  /* Полный каталог списков из репозитория https://github.com/Dushnilin/tachyon-lists */
  const TACHYON_LISTS_CATALOG = [
    {
      cat: 'ru_base',
      icon: 'ic-globe',
      title: 'Базовые РФ и обход блокировок',
      items: [
        { name: 'ru_domains', title: 'Домены РФ (.ru / .рф / .su)', desc: 'Все российские домены и популярные сервисы РФ' },
        { name: 'geoip_ru', title: 'IP-адреса РФ (GeoIP RU)', desc: 'Все подсети российских провайдеров и ЦОД' },
        { name: 'russia_inside', title: 'Внутренние сервисы РФ', desc: 'Госуслуги, банки, ФНС, маркетплейсы, РЖД (всегда напрямую)' },
        { name: 'ru_whitelist', title: 'Белый список РФ', desc: 'Критическая инфраструктура РФ, чувствительная к иностранным IP' },
        { name: 'ru_blocked', title: 'Заблокированные в РФ (ru_blocked)', desc: 'Сводный список ресурсов, заблокированных ТСПУ / РКН' },
        { name: 'antifilter', title: 'Antifilter Community', desc: 'База заблокированных доменов и IP-адресов Antifilter' },
        { name: 'reestr', title: 'Реестр запрещённых сайтов', desc: 'Выгрузка доменов из реестра блокировок' }
      ]
    },
    {
      cat: 'media',
      icon: 'ic-play',
      title: 'Видео, музыка и стриминг',
      items: [
        { name: 'youtube', title: 'YouTube и Google Video', desc: 'youtube.com, googlevideo.com (GGC-серверы), ytimg, youtu.be' },
        { name: 'twitch', title: 'Twitch', desc: 'Стриминг Twitch.tv, видео-CDN и чат' },
        { name: 'spotify', title: 'Spotify', desc: 'Музыкальный сервис Spotify, аудио-потоки и API авторизации' },
        { name: 'netflix', title: 'Netflix', desc: 'Netflix, nflxvideo.net и связанные CDN' },
        { name: 'tiktok', title: 'TikTok', desc: 'TikTok, musical.ly, bytedance CDN' },
        { name: 'soundcloud', title: 'SoundCloud', desc: 'SoundCloud и sndcdn.com' },
        { name: 'plex', title: 'Plex Media', desc: 'Сервисы Plex.tv и удалённый доступ' }
      ]
    },
    {
      cat: 'social',
      icon: 'ic-chat',
      title: 'Мессенджеры и соцсети',
      items: [
        { name: 'discord', title: 'Discord (Чат + Голос)', desc: 'discord.com, discordapp.net, discord.media, голосовые шлюзы' },
        { name: 'telegram', title: 'Telegram', desc: 'Домены и IP-подсети дата-центров Telegram Messenger' },
        { name: 'meta', title: 'Instagram / Facebook / Threads', desc: 'Все сервисы Meta, включая CDN фото и видео' },
        { name: 'twitter', title: 'X (Twitter)', desc: 'x.com, twitter.com, twimg.com, t.co' },
        { name: 'whatsapp', title: 'WhatsApp', desc: 'Серверы сообщений и звонков WhatsApp' },
        { name: 'reddit', title: 'Reddit', desc: 'reddit.com, redd.it, redditmedia.com' },
        { name: 'linkedin', title: 'LinkedIn', desc: 'linkedin.com и licdn.com' },
        { name: 'pinterest', title: 'Pinterest', desc: 'pinterest.com и pinimg.com' },
        { name: '4pda', title: '4PDA', desc: 'Форум и файловый архив 4pda.to' }
      ]
    },
    {
      cat: 'ai',
      icon: 'ic-cpu',
      title: 'AI и нейросети',
      items: [
        { name: 'ai_all', title: 'Все нейросети (AI All-in-One)', desc: 'Сводный пакет: ChatGPT, Claude, Gemini, Grok, Copilot, Perplexity и др.' },
        { name: 'openai', title: 'OpenAI (ChatGPT / Sora)', desc: 'chatgpt.com, openai.com, oaistatic.com, oaiusercontent.com' },
        { name: 'claude', title: 'Anthropic Claude', desc: 'claude.ai, anthropic.com и API' },
        { name: 'gemini', title: 'Google Gemini / AI Studio', desc: 'gemini.google.com, aistudio.google.com, NotebookLM' },
        { name: 'grok', title: 'xAI Grok', desc: 'grok.com, x.ai и связанные сервисы' },
        { name: 'perplexity', title: 'Perplexity AI', desc: 'perplexity.ai и поисковые API' },
        { name: 'copilot', title: 'Microsoft Copilot / GitHub Copilot', desc: 'copilot.microsoft.com, githubcopilot.com' },
        { name: 'cursor', title: 'Cursor & Windsurf IDE', desc: 'Серверы автодополнения и агентов Cursor.sh / Codeium' },
        { name: 'midjourney', title: 'Midjourney', desc: 'midjourney.com и CDN генераций' },
        { name: 'huggingface', title: 'Hugging Face', desc: 'huggingface.co и hf.co' }
      ]
    },
    {
      cat: 'gaming',
      icon: 'ic-gamepad',
      title: 'Игры и лаунчеры',
      items: [
        { name: 'steam', title: 'Steam', desc: 'Магазин, сообщество и игровые серверы Valve Steam' },
        { name: 'roblox', title: 'Roblox', desc: 'roblox.com, rbxcdn.com и игровые инстансы' },
        { name: 'epicgames', title: 'Epic Games / Fortnite', desc: 'Epic Games Store, Unreal Engine и Fortnite' },
        { name: 'riot', title: 'Riot Games (Valorant / LoL)', desc: 'Серверы авторизации и игр Riot Games' },
        { name: 'genshin', title: 'HoYoverse (Genshin / HSR / ZZZ)', desc: 'Игры HoYoverse / Cognosphere' },
        { name: 'battlenet', title: 'Blizzard Battle.net', desc: 'Лаунчер и игры Blizzard Entertainment' },
        { name: 'ea', title: 'EA App / Origin', desc: 'Electronic Arts, Apex Legends, Battlefield' },
        { name: 'ubisoft', title: 'Ubisoft Connect', desc: 'Сервисы и игры Ubisoft' },
        { name: 'playstation', title: 'PlayStation Network', desc: 'PSN, магазин и облачные функции Sony' },
        { name: 'xbox', title: 'Xbox Live / Game Pass', desc: 'Игровые сервисы Microsoft Xbox' }
      ]
    },
    {
      cat: 'dev',
      icon: 'ic-code',
      title: 'Разработка, облака и трекеры',
      items: [
        { name: 'github', title: 'GitHub', desc: 'github.com, githubusercontent.com, ghcr.io' },
        { name: 'docker', title: 'Docker Hub & Registries', desc: 'docker.io, docker.com, registry-1.docker.io' },
        { name: 'jetbrains', title: 'JetBrains', desc: 'Лицензии, плагины и загрузки JetBrains' },
        { name: 'figma', title: 'Figma', desc: 'figma.com и статические ассеты' },
        { name: 'notion', title: 'Notion', desc: 'notion.so и notion.site' },
        { name: 'cloudflare', title: 'Cloudflare CDN / WARP', desc: 'Сервисы и узлы сети Cloudflare' },
        { name: 'hetzner', title: 'Hetzner Cloud', desc: 'Панель и подсети Hetzner' },
        { name: 'digitalocean', title: 'DigitalOcean', desc: 'Инфраструктура DigitalOcean' },
        { name: 'torrents', title: 'Торрент-трекеры (RuTracker и др.)', desc: 'Популярные торрент-трекеры и зеркала' },
        { name: 'speedtest', title: 'Speedtest (Ookla)', desc: 'speedtest.net и серверы замера скорости' }
      ]
    },
    {
      cat: 'privacy',
      icon: 'ic-shield',
      title: 'Блокировка рекламы и телеметрии',
      items: [
        { name: 'ads_all', title: 'Рекламные сети (Ads All)', desc: 'Блокировка баннеров, трекеров и рекламных скриптов' },
        { name: 'adguard', title: 'AdGuard DNS Filter', desc: 'Базовый фильтр рекламы и аналитики AdGuard' },
        { name: 'win_telemetry', title: 'Телеметрия Windows и Office', desc: 'Отключение сбора данных Microsoft Windows' }
      ]
    }
  ];

  /* Дефолтная конфигурация списков при первом запуске:
     РФ и банки — напрямую, YouTube и Discord — через Desync */
  let communityListsState = {
    ru_domains: 'direct',
    russia_inside: 'direct',
    youtube: 'desync',
    discord: 'desync'
  };
  try {
    const savedL = JSON.parse(localStorage.getItem(LISTS_STATE_KEY) || 'null');
    if (savedL && typeof savedL === 'object') communityListsState = savedL;
  } catch {}

  function saveCommunityListsState() {
    try { localStorage.setItem(LISTS_STATE_KEY, JSON.stringify(communityListsState)); } catch {}
    updateRoutingSummaryUI();
  }

  let customRouteRules = [];
  try {
    const savedC = JSON.parse(localStorage.getItem(CUSTOM_RULES_KEY) || 'null');
    if (Array.isArray(savedC)) customRouteRules = savedC;
  } catch {}

  function saveCustomRouteRules() {
    try { localStorage.setItem(CUSTOM_RULES_KEY, JSON.stringify(customRouteRules)); } catch {}
    updateRoutingSummaryUI();
  }

  function getActiveCommunityListsArray() {
    return Object.entries(communityListsState)
      .filter(([, act]) => act && act !== 'off')
      .map(([name, action]) => ({ name, action }));
  }

  let reconnectTimer = null;
  function applyReconnectIfActive() {
    if (!connected) return;
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(() => {
      if (connected) {
        window.API.vpnConnect(buildConnectOpts(activeServer()));
      }
    }, 100);
  }

  function updateRoutingSummaryUI() {
    const activeLists = getActiveCommunityListsArray();
    const totalRules = activeLists.length + customRouteRules.length;

    const navBadge = $('#routeRulesBadge');
    if (navBadge) navBadge.textContent = String(totalRules);

    const customBadge = $('#customRulesCount');
    if (customBadge) customBadge.textContent = String(customRouteRules.length);

    const activeListsBadge = $('#activeListsCountBadge');
    if (activeListsBadge) activeListsBadge.textContent = String(activeLists.length);

    const dPill = $('#summaryDesyncPill');
    if (dPill) {
      if (desyncPrefs.enabled || vpnPrefs.route === 'desync-only') {
        const pName = DESYNC_PRESET_LABELS[desyncPrefs.preset] || 'Авто';
        dPill.textContent = `Desync: ${pName}`;
        dPill.classList.remove('is-off');
      } else {
        dPill.textContent = 'Desync: Выкл';
        dPill.classList.add('is-off');
      }
    }

    const lPill = $('#summaryListsPill');
    if (lPill) {
      lPill.textContent = `Правила: ${totalRules} акт.`;
    }

    const hint = $('#modeHint');
    if (hint) {
      if (vpnPrefs.route === 'desync-only') hint.textContent = 'Только Desync (без VPN)';
      else if (vpnPrefs.route === 'selective') hint.textContent = `Точечно (${totalRules} правил)`;
      else if (vpnPrefs.route === 'apps') hint.textContent = 'По приложениям';
      else hint.textContent = desyncPrefs.enabled ? 'Весь ПК + Desync' : 'Весь трафик ПК';
    }

    if (routeSwitch) {
      $$('button[data-route]', routeSwitch).forEach(b => {
        b.classList.toggle('is-active', b.dataset.route === vpnPrefs.route);
      });
    }
    if (appRoutes) appRoutes.hidden = vpnPrefs.route !== 'apps';

    const desyncCard = $('#desyncCard');
    const desyncToggle = $('#desyncEnableToggle');
    if (desyncToggle) desyncToggle.checked = !!desyncPrefs.enabled;
    desyncCard?.classList.toggle('is-disabled', !desyncPrefs.enabled);

    $$('#desyncPresetsBar button[data-dpreset]').forEach(b => {
      b.classList.toggle('is-active', b.dataset.dpreset === desyncPrefs.preset);
    });

    const curSni = (desyncPrefs.fakeSni || 'www.google.com').trim().toLowerCase();
    $$('#desyncSniPoolBar button[data-sni]').forEach(b => {
      b.classList.toggle('is-active', (b.dataset.sni || '').toLowerCase() === curSni);
    });

    const techSum = $('#desyncTechSummary');
    if (techSum) {
      const m = desyncPrefs.preset === 'custom' ? desyncPrefs.mode : desyncPrefs.preset;
      const q = desyncPrefs.blockQuic ? ' · Блок QUIC' : '';
      const u = desyncPrefs.udpFake ? ` · UDP Fake (×${desyncPrefs.udpRepeats || 6})` : '';
      const ad = desyncPrefs.autoDirect ? ' · Auto-Direct' : '';
      techSum.textContent = `Пресет: ${m} · ${desyncPrefs.fooling} · split:${desyncPrefs.splitPos} · TTL ${desyncPrefs.fakeTtl} · SNI ${desyncPrefs.fakeSni || 'www.google.com'}${u}${q}${ad}`;
    }

    /* Синхронизация быстрых плиток главного экрана и статус-бара */
    const qDesync = $('#quickDesyncTile');
    const qDesyncVal = $('#quickDesyncVal');
    const isDesyncActive = !!desyncPrefs.enabled || vpnPrefs.route === 'desync-only';
    qDesync?.classList.toggle('is-on', isDesyncActive);
    if (qDesyncVal) {
      qDesyncVal.textContent = isDesyncActive
        ? `Активен · ${DESYNC_PRESET_LABELS[desyncPrefs.preset] || 'Авто'}`
        : 'Выключен';
    }

    const qMode = $('#quickModeTile');
    const qModeVal = $('#quickModeVal');
    const isTun = (vpnPrefs.mode || 'tun') === 'tun';
    qMode?.classList.toggle('is-on', isTun);
    if (qModeVal) {
      qModeVal.textContent = isTun ? TUN_SHORT : 'Прокси :7897';
    }

    const qKill = $('#quickKillTile');
    const qKillVal = $('#quickKillVal');
    const isKillOn = localStorage.getItem('tachyon.killswitch') === '1';
    qKill?.classList.toggle('is-on', isKillOn);
    if (qKillVal) {
      qKillVal.textContent = isKillOn ? 'Активен' : 'Выключен';
    }

    const dnsMap = { auto: 'Авто', cloudflare: '1.1.1.1', google: '8.8.8.8', adguard: 'AdGuard' };
    const fDns = $('#footerDnsLabel');
    if (fDns) fDns.textContent = `DNS: ${dnsMap[vpnPrefs.dns || 'auto'] || 'Авто'}`;

    updateLocCount();
    updateActiveServerDisplay();
  }

  /* Обработчики быстрых плиток главного экрана */
  $('#quickDesyncTile')?.addEventListener('click', () => {
    desyncPrefs.enabled = !desyncPrefs.enabled;
    if (!desyncPrefs.enabled && vpnPrefs.route === 'desync-only') {
      vpnPrefs.route = 'all';
      saveVpnPrefs();
    }
    saveDesyncPrefs();
    updateRoutingSummaryUI();
    toast(desyncPrefs.enabled ? 'Tachyon Desync включён' : 'Tachyon Desync выключен');
    applyReconnectIfActive();
  });
  $('#quickDesyncTile')?.addEventListener('contextmenu', e => {
    e.preventDefault();
    go('desync');
  });

  $('#quickModeTile')?.addEventListener('click', () => {
    vpnPrefs.mode = (vpnPrefs.mode || 'tun') === 'tun' ? 'proxy' : 'tun';
    saveVpnPrefs();
    const valSpan = $('#modeSelect .mini-select__val');
    if (valSpan) valSpan.textContent = vpnPrefs.mode === 'proxy' ? 'Системный прокси' : 'TUN (весь ПК)';
    const hint = $('#modeRowHint');
    if (hint) hint.textContent = vpnPrefs.mode === 'proxy' ? 'Локальный прокси 127.0.0.1:7897' : TUN_HINT;
    updateRoutingSummaryUI();
    toast(vpnPrefs.mode === 'tun' ? `Режим: ${TUN_SHORT} (весь ПК)` : 'Режим: Системный прокси 127.0.0.1:7897');
    applyReconnectIfActive();
  });

  $('#quickKillTile')?.addEventListener('click', () => {
    const next = localStorage.getItem('tachyon.killswitch') !== '1';
    localStorage.setItem('tachyon.killswitch', next ? '1' : '0');
    if (killSwitchToggle) killSwitchToggle.checked = next;
    window.API.setKillSwitch(next);
    updateRoutingSummaryUI();
    toast(next ? 'Kill Switch включён' : 'Kill Switch выключен');
  });

  $('#footerLogBtn')?.addEventListener('click', () => window.API.openLog());

  if (routeSwitch) {
    $$('button[data-route]', routeSwitch).forEach(b => {
      b.addEventListener('click', () => {
        vpnPrefs.route = b.dataset.route;
        if (vpnPrefs.route === 'desync-only' && !desyncPrefs.enabled) {
          desyncPrefs.enabled = true;
          saveDesyncPrefs();
        }
        saveVpnPrefs();
        updateRoutingSummaryUI();
        applyReconnectIfActive();
      });
    });
  }

  $('#openRoutingViewBtn')?.addEventListener('click', () => go('routing'));

  /* Управление разделом Desync */
  $('#desyncEnableToggle')?.addEventListener('change', e => {
    desyncPrefs.enabled = e.target.checked;
    saveDesyncPrefs();
    toast(desyncPrefs.enabled ? 'Движок Tachyon Desync включён' : 'Движок Tachyon Desync выключен');
    applyReconnectIfActive();
  });

  $('#desyncAutoDirectToggle')?.addEventListener('change', e => {
    desyncPrefs.autoDirect = e.target.checked;
    saveDesyncPrefs();
    toast(desyncPrefs.autoDirect ? 'Авто-перехват прямых соединений включён' : 'Авто-перехват прямых соединений выключен');
    applyReconnectIfActive();
  });

  $('#resetDesyncBtn')?.addEventListener('click', () => {
    desyncPrefs = getDefaultDesyncPrefs();
    syncDesyncAdvInputs();
    saveDesyncPrefs();
    applyReconnectIfActive();
    toast('Параметры Desync сброшены к настройкам ядра по умолчанию');
  });

  $$('#desyncPresetsBar button[data-dpreset]').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = btn.dataset.dpreset;
      desyncPrefs.preset = p;
      if (p === 'auto') {
        desyncPrefs.mode = 'auto';
        desyncPrefs.fooling = 'md5';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.fakeTtl = 6;
        desyncPrefs.repeats = 2;
        desyncPrefs.splitDelayMs = 1;
        desyncPrefs.udpFake = true;
        desyncPrefs.udpRepeats = 6;
        desyncPrefs.udpFakeTtl = 6;
        desyncPrefs.blockQuic = true;
        desyncPrefs.autoTune = true;
      } else if (p === 'youtube_discord') {
        desyncPrefs.mode = 'fake_split';
        desyncPrefs.fooling = 'badseq';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.fakeTtl = 5;
        desyncPrefs.repeats = 4;
        desyncPrefs.splitDelayMs = 1;
        desyncPrefs.udpFake = true;
        desyncPrefs.udpRepeats = 6;
        desyncPrefs.udpFakeTtl = 5;
        desyncPrefs.blockQuic = true;
        desyncPrefs.autoTune = true;
      } else if (p === 'fake_split') {
        desyncPrefs.mode = 'fake_split';
        desyncPrefs.fooling = 'md5';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.fakeTtl = 6;
        desyncPrefs.repeats = 2;
        desyncPrefs.udpFake = true;
      } else if (p === 'fake_disorder') {
        desyncPrefs.mode = 'fake_disorder';
        desyncPrefs.fooling = 'badseq';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.fakeTtl = 6;
        desyncPrefs.repeats = 4;
        desyncPrefs.udpFake = true;
        desyncPrefs.blockQuic = true;
      } else if (p === 'tlsrec') {
        desyncPrefs.mode = 'tlsrec';
        desyncPrefs.splitPos = 'sni';
        desyncPrefs.blockQuic = true;
      } else if (p === 'multi_split') {
        desyncPrefs.mode = 'multi_split';
        desyncPrefs.fooling = 'md5';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.fakeTtl = 6;
        desyncPrefs.repeats = 3;
        desyncPrefs.udpFake = true;
      } else if (p === 'split') {
        desyncPrefs.mode = 'split';
        desyncPrefs.splitPos = 'midsld';
        desyncPrefs.udpFake = false;
      } else if (p === 'disorder') {
        desyncPrefs.mode = 'disorder';
        desyncPrefs.splitPos = '1';
        desyncPrefs.udpFake = false;
      } else if (p === 'fake') {
        desyncPrefs.mode = 'fake';
        desyncPrefs.fooling = 'md5';
        desyncPrefs.fakeTtl = 6;
        desyncPrefs.udpFake = true;
      } else if (p === 'oob') {
        desyncPrefs.mode = 'oob';
        desyncPrefs.splitPos = '1';
        desyncPrefs.udpFake = false;
      }
      syncDesyncAdvInputs();
      saveDesyncPrefs();
      applyReconnectIfActive();
    });
  });

  $$('#desyncSniPoolBar button[data-sni]').forEach(btn => {
    btn.addEventListener('click', () => {
      const sni = btn.dataset.sni || 'www.google.com';
      desyncPrefs.fakeSni = sni;
      const sniInp = $('#desyncFakeSniInput');
      if (sniInp) sniInp.value = sni;
      saveDesyncPrefs();
      applyReconnectIfActive();
      toast(`Подменный SNI: ${sni}`);
    });
  });

  function syncDesyncAdvInputs() {
    const ad = $('#desyncAutoDirectToggle'); if (ad) ad.checked = desyncPrefs.autoDirect !== false;
    const m = $('#desyncModeSelect'); if (m) m.value = desyncPrefs.mode || 'auto';
    const f = $('#desyncFoolingSelect'); if (f) f.value = (desyncPrefs.fooling === 'md5sig' ? 'md5' : (desyncPrefs.fooling || 'md5'));

    const rawSp = String(desyncPrefs.splitPos || 'midsld');
    const isCustomNum = /^\d+$/.test(rawSp) && rawSp !== '1' && rawSp !== '2';
    const sp = $('#desyncSplitPosSelect');
    const offField = $('#desyncCustomOffsetField');
    const offInp = $('#desyncSplitOffsetInput');
    if (sp) sp.value = isCustomNum ? 'custom_offset' : rawSp;
    if (offField) offField.hidden = !isCustomNum;
    if (offInp && isCustomNum) offInp.value = rawSp;

    const ttl = $('#desyncFakeTtlInput'); if (ttl) ttl.value = String(desyncPrefs.fakeTtl || 6);
    const sni = $('#desyncFakeSniInput'); if (sni) sni.value = desyncPrefs.fakeSni || 'www.google.com';
    const rep = $('#desyncRepeatsInput'); if (rep) rep.value = String(desyncPrefs.repeats || 2);
    const dly = $('#desyncSplitDelayInput'); if (dly) dly.value = String(desyncPrefs.splitDelayMs ?? 1);
    const uf = $('#desyncUdpFakeToggle'); if (uf) uf.checked = !!desyncPrefs.udpFake;
    const urep = $('#desyncUdpRepeatsInput'); if (urep) urep.value = String(desyncPrefs.udpRepeats || 6);
    const uttl = $('#desyncUdpFakeTtlInput'); if (uttl) uttl.value = String(desyncPrefs.udpFakeTtl || 6);
    const bq = $('#desyncBlockQuicToggle'); if (bq) bq.checked = !!desyncPrefs.blockQuic;
    const at = $('#desyncAutoTuneToggle'); if (at) at.checked = !!desyncPrefs.autoTune;
  }
  syncDesyncAdvInputs();

  function onCustomDesyncFieldChange(e) {
    const targetId = e?.target?.id || '';
    const spSelectVal = $('#desyncSplitPosSelect')?.value || 'midsld';
    const offField = $('#desyncCustomOffsetField');
    if (offField) offField.hidden = spSelectVal !== 'custom_offset';

    if (targetId === 'desyncModeSelect' || targetId === 'desyncFoolingSelect' || targetId === 'desyncSplitPosSelect' || targetId === 'desyncSplitOffsetInput') {
      desyncPrefs.preset = 'custom';
    }

    desyncPrefs.mode = $('#desyncModeSelect')?.value || 'auto';
    desyncPrefs.fooling = $('#desyncFoolingSelect')?.value || 'md5';

    if (spSelectVal === 'custom_offset') {
      const n = Math.max(1, Math.min(1400, parseInt($('#desyncSplitOffsetInput')?.value, 10) || 3));
      desyncPrefs.splitPos = String(n);
    } else {
      desyncPrefs.splitPos = spSelectVal;
    }

    desyncPrefs.fakeTtl = Math.max(1, Math.min(128, parseInt($('#desyncFakeTtlInput')?.value, 10) || 6));
    desyncPrefs.fakeSni = ($('#desyncFakeSniInput')?.value || 'www.google.com').trim() || 'www.google.com';
    desyncPrefs.repeats = Math.max(1, Math.min(100, parseInt($('#desyncRepeatsInput')?.value, 10) || 2));
    desyncPrefs.splitDelayMs = Math.max(0, Math.min(1000, parseInt($('#desyncSplitDelayInput')?.value, 10) || 0));
    desyncPrefs.udpFake = !!$('#desyncUdpFakeToggle')?.checked;
    desyncPrefs.udpRepeats = Math.max(1, Math.min(50, parseInt($('#desyncUdpRepeatsInput')?.value, 10) || 6));
    desyncPrefs.udpFakeTtl = Math.max(1, Math.min(128, parseInt($('#desyncUdpFakeTtlInput')?.value, 10) || 6));
    desyncPrefs.blockQuic = !!$('#desyncBlockQuicToggle')?.checked;
    desyncPrefs.autoTune = !!$('#desyncAutoTuneToggle')?.checked;
    saveDesyncPrefs();
    applyReconnectIfActive();
  }

  ['#desyncModeSelect', '#desyncFoolingSelect', '#desyncSplitPosSelect', '#desyncSplitOffsetInput',
   '#desyncFakeTtlInput', '#desyncFakeSniInput', '#desyncRepeatsInput', '#desyncSplitDelayInput',
   '#desyncUdpFakeToggle', '#desyncUdpRepeatsInput', '#desyncUdpFakeTtlInput',
   '#desyncBlockQuicToggle', '#desyncAutoTuneToggle'].forEach(sel => {
    $(sel)?.addEventListener('change', onCustomDesyncFieldChange);
  });

  /* Подвкладки в разделе Маршруты: Списки tachyon-lists vs Свои правила */
  $$('#routingSubtabs button[data-rtab]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#routingSubtabs button').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      const tab = btn.dataset.rtab;
      const pLists = $('#rtabLists');
      const pCustom = $('#rtabCustom');
      const pDetour = $('#rtabDetour');
      const toolbar = $('#routingListsToolbar');
      if (pLists) pLists.hidden = tab !== 'lists';
      if (pCustom) pCustom.hidden = tab !== 'custom';
      if (pDetour) pDetour.hidden = tab !== 'detour';
      if (toolbar) toolbar.hidden = tab !== 'lists';
    });
  });

  /* Кнопка сворачивания/разворачивания фильтра узлов на вкладке «Узлы» */
  $('#toggleNodeFiltersBtn')?.addEventListener('click', () => {
    const body = $('#nodeFiltersBody');
    if (!body) return;
    body.hidden = !body.hidden;
    $('#toggleNodeFiltersBtn')?.classList.toggle('btn-act--primary', !body.hidden);
  });

  /* Рендер каталога списков Dushnilin/tachyon-lists */
  let listsFilterMode = 'all'; // 'all' | 'active'
  const collapsedListCats = new Set();

  $('#collapseAllListsBtn')?.addEventListener('click', () => {
    const allCats = TACHYON_LISTS_CATALOG.map(g => g.cat);
    const allCollapsed = allCats.every(c => collapsedListCats.has(c));
    if (allCollapsed) {
      collapsedListCats.clear();
    } else {
      allCats.forEach(c => collapsedListCats.add(c));
    }
    renderCommunityLists();
  });

  $$('#listsFilterSeg button[data-lf]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#listsFilterSeg button').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      listsFilterMode = btn.dataset.lf;
      renderCommunityLists();
    });
  });

  $('#listsSearchInput')?.addEventListener('input', () => renderCommunityLists());

  function renderCommunityLists() {
    const box = $('#communityListsContainer');
    if (!box) return;
    const q = ($('#listsSearchInput')?.value || '').trim().toLowerCase();

    const collapseBtn = $('#collapseAllListsBtn');
    if (collapseBtn) {
      const allCollapsed = TACHYON_LISTS_CATALOG.every(g => collapsedListCats.has(g.cat));
      collapseBtn.textContent = allCollapsed ? 'Развернуть' : 'Свернуть';
    }

    let html = '';
    for (const group of TACHYON_LISTS_CATALOG) {
      const items = group.items.filter(it => {
        const act = communityListsState[it.name] || 'off';
        if (listsFilterMode === 'active' && act === 'off') return false;
        if (q) {
          const hay = `${it.name} ${it.title} ${it.desc}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      if (!items.length) continue;

      const activeInGroup = group.items.filter(it => (communityListsState[it.name] || 'off') !== 'off').length;
      const isCollapsed = !q && listsFilterMode !== 'active' && collapsedListCats.has(group.cat);

      html += `
        <div class="list-cat-group ${isCollapsed ? 'is-collapsed' : ''}" data-cat="${group.cat}">
          <div class="list-cat-head" data-cat-toggle="${group.cat}">
            <div class="list-cat-head__left">
              <svg class="ic"><use href="#${group.icon || 'ic-route'}"/></svg>
              <span>${escapeHtml(group.title)}</span>
            </div>
            <div class="list-cat-head__right">
              ${activeInGroup > 0 ? `<span class="core-ver-pill">${activeInGroup} акт.</span>` : `<span class="list-row__tag">${items.length}</span>`}
              <svg class="ic list-cat-head__chev"><use href="#ic-chevron"/></svg>
            </div>
          </div>
          <div class="list-cat-body">
            ${items.map(it => {
              const cur = communityListsState[it.name] || 'off';
              return `
                <div class="list-row" data-list-name="${it.name}" data-state="${cur}">
                  <div class="list-row__info">
                    <div class="list-row__title">
                      <span>${escapeHtml(it.title)}</span>
                      <span class="list-row__tag">${it.name}.trs</span>
                    </div>
                    <small class="list-row__desc" title="${escapeHtml(it.desc)}">${escapeHtml(it.desc)}</small>
                  </div>
                  <div class="act-seg" data-list="${it.name}">
                    <button type="button" class="${cur === 'off' ? 'is-active' : ''}" data-act="off" title="Не использовать список">Выкл</button>
                    <button type="button" class="${cur === 'vpn' ? 'is-active' : ''}" data-act="vpn" title="Направлять через VPN-сервер">VPN</button>
                    <button type="button" class="${cur === 'desync' ? 'is-active' : ''}" data-act="desync" title="Направлять напрямую с обходом DPI (Tachyon Desync)">Desync</button>
                    <button type="button" class="${cur === 'direct' ? 'is-active' : ''}" data-act="direct" title="Направлять напрямую в обход VPN">Прямой</button>
                    <button type="button" class="${cur === 'block' ? 'is-active' : ''}" data-act="block" title="Блокировать соединения">Блок</button>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      `;
    }

    if (!html) {
      html = `<p class="conn-empty">Списки не найдены. Попробуйте изменить запрос.</p>`;
    }

    box.innerHTML = html;

    $$('[data-cat-toggle]', box).forEach(head => {
      head.addEventListener('click', () => {
        const c = head.dataset.catToggle;
        if (collapsedListCats.has(c)) collapsedListCats.delete(c);
        else collapsedListCats.add(c);
        renderCommunityLists();
      });
    });

    $$('.act-seg[data-list] button[data-act]', box).forEach(btn => {
      btn.addEventListener('click', () => {
        const parent = btn.closest('.act-seg');
        const listName = parent.dataset.list;
        const act = btn.dataset.act;
        if (act === 'off') delete communityListsState[listName];
        else communityListsState[listName] = act;

        if (act === 'desync' && !desyncPrefs.enabled) {
          desyncPrefs.enabled = true;
          saveDesyncPrefs();
        }
        saveCommunityListsState();
        renderCommunityLists();
        applyReconnectIfActive();
      });
    });
  }

  /* Быстрые сценарии (бандлы) в 1 клик */
  function applyQuickBundle(b) {
    if (!b) return;
    if (b === 'ru_smart') {
      vpnPrefs.route = 'all';
      desyncPrefs.enabled = true;
      desyncPrefs.preset = 'youtube_discord';
      communityListsState = {
        ru_domains: 'direct',
        geoip_ru: 'direct',
        russia_inside: 'direct',
        ru_whitelist: 'direct',
        youtube: 'desync',
        discord: 'desync',
        ru_blocked: 'vpn',
        ai_all: 'vpn',
        meta: 'vpn',
        twitter: 'vpn'
      };
      toast('Сценарий: РФ мимо VPN, YouTube/Discord в Desync, остальное в VPN');
    } else if (b === 'desync_media') {
      vpnPrefs.route = 'desync-only';
      desyncPrefs.enabled = true;
      desyncPrefs.preset = 'youtube_discord';
      communityListsState = {
        youtube: 'desync',
        discord: 'desync',
        ru_blocked: 'desync',
        torrents: 'desync'
      };
      toast('Режим «Только Desync»: обход DPI без VPN-сервера');
    } else if (b === 'selective_vpn') {
      vpnPrefs.route = 'selective';
      desyncPrefs.enabled = true;
      communityListsState = {
        youtube: 'desync',
        discord: 'desync',
        ai_all: 'vpn',
        meta: 'vpn',
        twitter: 'vpn',
        ru_blocked: 'vpn'
      };
      toast('Точечный режим: только выбранные списки идут через VPN и Desync');
    } else if (b === 'adblock') {
      communityListsState.ads_all = 'block';
      communityListsState.adguard = 'block';
      communityListsState.win_telemetry = 'block';
      toast('Блокировка рекламы и телеметрии включена');
    } else if (b === 'clear') {
      communityListsState = {};
      toast('Все списки отключены');
    }
    saveVpnPrefs();
    saveDesyncPrefs();
    saveCommunityListsState();
    renderCommunityLists();
    applyReconnectIfActive();
  }

  $$('#quickBundlesBar button[data-bundle]').forEach(btn => {
    btn.addEventListener('click', () => applyQuickBundle(btn.dataset.bundle));
  });

  $('#quickBundleSelect')?.addEventListener('change', e => {
    const val = e.target.value;
    if (val) {
      applyQuickBundle(val);
      e.target.value = '';
    }
  });

  /* Обновление .trs списков из GitHub Dushnilin/tachyon-lists */
  $('#refreshListsBtn')?.addEventListener('click', () => {
    const names = Object.keys(communityListsState).filter(k => communityListsState[k] && communityListsState[k] !== 'off');
    const btn = $('#refreshListsBtn');
    const txt = $('#refreshListsTxt');
    btn?.classList.add('is-busy');
    if (txt) txt.textContent = 'Загрузка…';
    window.API.refreshLists(names);
  });

  window.API.onListsUpdate(ev => {
    const btn = $('#refreshListsBtn');
    const txt = $('#refreshListsTxt');
    if (ev.type === 'progress' && ev.info) {
      if (txt) txt.textContent = `${ev.info.done}/${ev.info.total}`;
    } else if (ev.type === 'done') {
      btn?.classList.remove('is-busy');
      if (txt) txt.textContent = 'Обновить списки';
      const ok = ev.info?.ok ?? 0;
      const tot = ev.info?.total ?? 0;
      toast(`Списки tachyon-lists обновлены (${ok} из ${tot})`);
      applyReconnectIfActive();
    } else if (ev.type === 'error') {
      btn?.classList.remove('is-busy');
      if (txt) txt.textContent = 'Обновить списки';
      toast('Ошибка обновления списков: ' + (ev.message || ''), true);
    }
  });

  /* Вкладка Б: Свои правила (Домены, IP/CIDR, Процессы) */
  function detectCustomRuleType(val, fallbackType) {
    const v = val.trim();
    if (/\.exe$/i.test(v)) return 'process';
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v) || v.includes(':')) return 'ip';
    return fallbackType || 'domain';
  }

  function renderCustomRules() {
    const list = $('#customRulesList');
    const empty = $('#customRulesEmpty');
    if (!list) return;

    if (!customRouteRules.length) {
      list.innerHTML = '';
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    const typeLabels = { domain: 'ДОМЕН', ip: 'IP/CIDR', process: 'EXE' };
    list.innerHTML = customRouteRules.map((r, idx) => `
      <li class="custom-rule-item" data-idx="${idx}">
        <div class="custom-rule-item__left">
          <span class="custom-rule-item__type">${typeLabels[r.type] || 'ДОМЕН'}</span>
          <span class="custom-rule-item__val" title="${escapeHtml(r.value)}">${escapeHtml(r.value)}</span>
        </div>
        <div class="custom-rule-item__right">
          <div class="act-seg" data-cidx="${idx}">
            <button type="button" class="${r.action === 'vpn' ? 'is-active' : ''}" data-act="vpn">VPN</button>
            <button type="button" class="${r.action === 'desync' ? 'is-active' : ''}" data-act="desync">Desync</button>
            <button type="button" class="${r.action === 'direct' ? 'is-active' : ''}" data-act="direct">Прямой</button>
            <button type="button" class="${r.action === 'block' ? 'is-active' : ''}" data-act="block">Блок</button>
          </div>
          <button type="button" class="icon-btn custom-rule-del" data-idx="${idx}" style="width:24px;height:24px;color:var(--red)" title="Удалить">
            <svg class="ic"><use href="#ic-close"/></svg>
          </button>
        </div>
      </li>
    `).join('');

    $$('.act-seg[data-cidx] button[data-act]', list).forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.closest('.act-seg').dataset.cidx, 10);
        if (!customRouteRules[idx]) return;
        customRouteRules[idx].action = btn.dataset.act;
        if (btn.dataset.act === 'desync' && !desyncPrefs.enabled) {
          desyncPrefs.enabled = true;
          saveDesyncPrefs();
        }
        saveCustomRouteRules();
        renderCustomRules();
        applyReconnectIfActive();
      });
    });

    $$('.custom-rule-del', list).forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.idx, 10);
        customRouteRules.splice(idx, 1);
        saveCustomRouteRules();
        renderCustomRules();
        applyReconnectIfActive();
      });
    });
  }

  function addCustomRuleFromBar() {
    const inp = $('#customRuleValue');
    const raw = (inp?.value || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    if (!raw) {
      toast('Введите домен, IP/CIDR или имя .exe процесса', true);
      return;
    }
    const selType = $('#customRuleType')?.value || 'domain';
    const type = detectCustomRuleType(raw, selType);
    const action = $('#customRuleAction')?.value || 'vpn';

    const existingIdx = customRouteRules.findIndex(r => r.value.toLowerCase() === raw.toLowerCase());
    if (existingIdx >= 0) {
      customRouteRules[existingIdx].action = action;
      customRouteRules[existingIdx].type = type;
    } else {
      customRouteRules.unshift({ type, value: raw, action });
    }

    if (action === 'desync' && !desyncPrefs.enabled) {
      desyncPrefs.enabled = true;
      saveDesyncPrefs();
    }

    if (inp) inp.value = '';
    saveCustomRouteRules();
    renderCustomRules();
    applyReconnectIfActive();
    toast(`Правило добавлено: ${raw} → ${action.toUpperCase()}`);
  }

  $('#addCustomRuleBtn')?.addEventListener('click', addCustomRuleFromBar);
  $('#customRuleValue')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') addCustomRuleFromBar();
  });

  $$('#quickCustomTemplates button[data-qrule]').forEach(btn => {
    btn.addEventListener('click', () => {
      const parts = (btn.dataset.qrule || '').split(':');
      if (parts.length < 3) return;
      const [type, val, action] = parts;
      const existingIdx = customRouteRules.findIndex(r => r.value.toLowerCase() === val.toLowerCase());
      if (existingIdx >= 0) {
        customRouteRules[existingIdx].action = action;
        customRouteRules[existingIdx].type = type;
      } else {
        customRouteRules.unshift({ type, value: val, action });
      }
      if (action === 'desync' && !desyncPrefs.enabled) {
        desyncPrefs.enabled = true;
        saveDesyncPrefs();
      }
      saveCustomRouteRules();
      renderCustomRules();
      applyReconnectIfActive();
      toast(`Правило добавлено: ${val} → ${action.toUpperCase()}`);
    });
  });

  const splitSwitch = $('#splitSwitch');
  if (splitSwitch) {
    $$('button[data-split]', splitSwitch).forEach(b => {
      b.addEventListener('click', () => {
        $$('button', splitSwitch).forEach(x => x.classList.remove('is-active'));
        b.classList.add('is-active');
        vpnPrefs.split = b.dataset.split;
        saveVpnPrefs();
        if (connected) window.API.vpnConnect(buildConnectOpts(activeServer()));
      });
    });
  }

  let appRules = [];
  try {
    appRules = JSON.parse(localStorage.getItem('tachyon.app_rules') || '[]');
  } catch {}

  function renderAppRules() {
    const list = $('#appList');
    if (!list) return;
    list.innerHTML = appRules.map((r, i) => `
      <li class="app-item" data-idx="${i}">
        <span class="app-item__name">${escapeHtml(r.name || r.binary)}</span>
        <button class="icon-btn app-del-btn" data-idx="${i}" style="width:22px;height:22px;color:var(--red)"><svg class="ic"><use href="#ic-close"/></svg></button>
      </li>
    `).join('');

    $$('.app-del-btn', list).forEach(b => {
      b.addEventListener('click', () => {
        appRules.splice(parseInt(b.dataset.idx, 10), 1);
        try { localStorage.setItem('tachyon.app_rules', JSON.stringify(appRules)); } catch {}
        renderAppRules();
        if (connected) window.API.vpnConnect(buildConnectOpts(activeServer()));
      });
    });
  }
  renderAppRules();

  $('#addAppBtn')?.addEventListener('click', async () => {
    const bin = await promptDialog('Имя процесса (например: chrome.exe, Discord.exe):');
    if (bin) {
      const clean = bin.trim().replace(/['"]/g, '');
      appRules.push({ binary: clean, name: clean });
      try { localStorage.setItem('tachyon.app_rules', JSON.stringify(appRules)); } catch {}
      renderAppRules();
      if (connected) window.API.vpnConnect(buildConnectOpts(activeServer()));
    }
  });

  function buildConnectOpts(s) {
    let route = vpnPrefs.route || 'all';
    if (route === 'apps') {
      route = vpnPrefs.split === 'exclude' ? 'apps-exclude' : 'apps';
    }
    const rules = appRules.map(a => `PROCESS-NAME,${a.binary}`);
    const communityLists = getActiveCommunityListsArray();

    /* Собираем extraNodes, если в правилах есть привязка вида node:<id> */
    const extraNodes = {};
    for (const item of communityLists) {
      if (item.action && item.action.startsWith('node:')) {
        const nid = item.action.slice(5);
        const srv = servers.find(x => x.id === nid);
        if (srv?.vless) extraNodes[`NODE_${nid}`] = srv.vless;
      }
    }
    for (const r of customRouteRules) {
      if (r.action && r.action.startsWith('node:')) {
        const nid = r.action.slice(5);
        const srv = servers.find(x => x.id === nid);
        if (srv?.vless) extraNodes[`NODE_${nid}`] = srv.vless;
      }
    }

    const detourSrv = vpnPrefs.detourNodeId
      ? servers.find(x => x.id === vpnPrefs.detourNodeId)
      : null;

    return {
      mode: vpnPrefs.mode || 'tun',
      route,
      rules,
      dns: vpnPrefs.dns || 'auto',
      dnsBootstrap: vpnPrefs.dnsBootstrap || '77.88.8.8',
      fakeIp: !!vpnPrefs.fakeIp,
      dnsRouteMode: vpnPrefs.dnsRouteMode || 'smart',
      mtu: Number(vpnPrefs.mtu) || 1400,
      allowLan: !!vpnPrefs.allowLan,
      proxyTlsFragment: !!vpnPrefs.proxyTlsFragment,
      logLevel: vpnPrefs.logLevel || 'info',
      detourVless: detourSrv && detourSrv.id !== s?.id ? (detourSrv.vless || '') : '',
      vless: route === 'desync-only' ? '' : (s?.vless || ''),
      desync: {
        ...desyncPrefs,
        enabled: route === 'desync-only' ? true : !!desyncPrefs.enabled
      },
      communityLists,
      customRules: customRouteRules,
      extraNodes
    };
  }

  /* ---------- Подключение VPN и Orb ---------- */
  let connected = false;
  let connecting = false;
  let sessionStart = 0;
  let timerId = null;

  const orb = $('#connectOrb');
  const orbLabel = $('#orbLabel');
  const statusChip = $('#statusChip');
  const statusText = $('#statusText');
  const heroCard = $('#heroCard');

  function setState(st) {
    orb?.classList.remove('is-on', 'is-connecting');
    statusChip?.classList.remove('is-on', 'is-connecting');
    heroCard?.classList.remove('is-on');
    $('#footerDot')?.classList.toggle('is-on', st === 'on');
    document.body.dataset.state = st === 'on' ? 'connected' : (st === 'connecting' ? 'connecting' : 'disconnected');

    const liveRateEl = $('#orbLiveRate');
    const heroPill = $('#heroModePill');
    if (heroPill) {
      heroPill.textContent = (vpnPrefs.mode || 'tun') === 'tun' ? TUN_BADGE : 'PROXY · 7897';
    }

    if (st === 'connecting') {
      orb?.classList.add('is-connecting');
      statusChip?.classList.add('is-connecting');
      if (statusText) statusText.textContent = 'Подключение…';
      if (orbLabel) orbLabel.textContent = 'Установка защищённого канала… Нажмите для отмены';
      if (liveRateEl) { liveRateEl.hidden = false; liveRateEl.textContent = 'ПОДКЛ…'; }
    } else if (st === 'on') {
      orb?.classList.add('is-on');
      statusChip?.classList.add('is-on');
      heroCard?.classList.add('is-on');
      const isDesyncOnly = vpnPrefs.route === 'desync-only' || !activeServer();
      if (statusText) statusText.textContent = isDesyncOnly ? 'Desync активен' : 'Защищено';
      if (orbLabel) orbLabel.textContent = 'Активно · Нажмите для откл.';
      $('#ipChip')?.classList.add('is-on');
      $('#ipText').textContent = isDesyncOnly ? 'DPI Bypass' : 'IP скрыт';
      if (liveRateEl) { liveRateEl.hidden = false; liveRateEl.textContent = 'ЗАЩИЩЕНО'; }
      triggerReactorShockwave();
      setTimeout(() => refreshExitNodeInfo(), 900);
    } else {
      if (statusText) statusText.textContent = 'Отключено';
      if (orbLabel) orbLabel.textContent = 'Нажмите для включения защиты';
      $('#ipChip')?.classList.remove('is-on');
      $('#ipText').textContent = 'TUN · Rust';
      if (liveRateEl) { liveRateEl.hidden = false; liveRateEl.textContent = 'ГОТОВ'; }
    }
  }

  orb?.addEventListener('click', () => {
    if (connected || connecting) disconnect();
    else connect();
  });

  function connect() {
    const s = activeServer();
    const isDesyncOnly = vpnPrefs.route === 'desync-only';

    if (!isDesyncOnly && (!s || !s.vless)) {
      if (desyncPrefs.enabled) {
        vpnPrefs.route = 'desync-only';
        saveVpnPrefs();
        updateRoutingSummaryUI();
        toast('Подписка не выбрана — запуск в режиме «Только Desync»');
      } else {
        toast('Добавьте подписку/ключ или выберите режим «Desync»', true);
        go('subscriptions');
        return;
      }
    }

    connecting = true;
    setState('connecting');
    if (vpnPrefs.route === 'desync-only' || !s) {
      toast('Запуск Tachyon Desync (DPI Bypass)…');
    } else {
      toast(`Подключение к ${s.name || s.country}…`);
    }
    window.API.vpnConnect(buildConnectOpts(s));
  }

  function disconnect() {
    connected = false;
    connecting = false;
    window.API.vpnDisconnect();
    setState('off');
    stopTimers();
    $('#mDown').textContent = '0.0';
    $('#mUp').textContent = '0.0';
    toast('Туннель отключён');
  }

  function startTimers() {
    if (timerId) return;
    sessionStart = Date.now();
    timerId = setInterval(() => {
      const sec = Math.floor((Date.now() - sessionStart) / 1000);
      const m = String(Math.floor(sec / 60)).padStart(2, '0');
      const s = String(sec % 60).padStart(2, '0');
      $('#mTime').textContent = `${m}:${s}`;
    }, 1000);
  }

  function stopTimers() {
    clearInterval(timerId);
    timerId = null;
    $('#mTime').textContent = '00:00';
  }

  /* ---------- Обработка событий ядра ---------- */
  window.API.onVpn(st => {
    if (st.state === 'connecting') {
      connecting = true;
      setState('connecting');
    } else if (st.state === 'switched') {
      connected = true;
      connecting = false;
      setState('on');
      if (!timerId) startTimers();
      setTimeout(refreshExitNodeInfo, 350);
    } else if (st.state === 'connected') {
      const wasConnected = connected;
      if (!connected) {
        connected = true;
        connecting = false;
        setState('on');
        startTimers();
      }
      if (!wasConnected && st.down == null) {
        setTimeout(refreshExitNodeInfo, 400);
      }
      if (st.ping) {
        $('#mPing').textContent = st.ping;
        pushPingSparkline(Number(st.ping) || 0);
      }
      if (st.down != null) {
        const dMB = (st.down / (1024 * 1024)).toFixed(1);
        const uMB = (st.up / (1024 * 1024)).toFixed(1);
        $('#mDown').textContent = dMB;
        $('#mUp').textContent = uMB;
        const lr = $('#orbLiveRate');
        if (lr) {
          lr.hidden = false;
          lr.textContent = `↓ ${dMB} МБ/с`;
        }
        pushChart(parseFloat(dMB), parseFloat(uMB));
      }
      if (st.totalDown != null) {
        $('#totalDown').textContent = fmtBytes(st.totalDown);
        $('#totalUp').textContent = fmtBytes(st.totalUp);
      }
    } else if (st.state === 'disconnected' || st.state === 'off' || st.state === 'idle-direct') {
      connected = false;
      connecting = false;
      setState('off');
      stopTimers();
    } else if (st.state === 'dropped') {
      connected = false;
      connecting = false;
      setState('off');
      stopTimers();
      toast('Соединение прервано (' + (st.reason || 'перезапуск') + ')', true);
    } else if (st.state === 'error') {
      connected = false;
      connecting = false;
      setState('off');
      stopTimers();
      toast('Ошибка: ' + (st.error || st.message || 'Сбой соединения'), true);
    }
  });

  function fmtBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' ГБ';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' МБ';
    return (b / 1024).toFixed(0) + ' КБ';
  }

  /* ---------- Спарклайн-график трафика ---------- */
  const cvs = $('#trafficChart');
  const ctx = cvs?.getContext('2d');
  const histD = Array(42).fill(0);
  const histU = Array(42).fill(0);

  function pushChart(d, u) {
    if (!ctx) return;
    histD.push(d); histD.shift();
    histU.push(u); histU.shift();
    drawChart();
  }

  function drawChart() {
    if (!ctx || !cvs) return;
    const w = cvs.width, h = cvs.height;
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(2, ...histD, ...histU);

    const drawArea = (data, stroke, fill) => {
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = (i / (data.length - 1)) * w;
        const y = h - (v / max) * (h - 6) - 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.lineTo(w, h);
      ctx.lineTo(0, h);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
    };

    drawArea(histD, '#60a5fa', 'rgba(96, 165, 250, 0.16)');
    drawArea(histU, '#34d399', 'rgba(52, 211, 153, 0.14)');
  }

  /* ---------- Диагностика и Логи ---------- */
  $('#openLogBtnCore')?.addEventListener('click', () => window.API.openLog());
  $('#collectLogsBtn')?.addEventListener('click', () => {
    window.API.collectLogs();
    toast('Отчёт сохранён на Рабочем столе');
  });

  $('#checkUpdBtn')?.addEventListener('click', () => {
    toast('Проверка обновлений…');
    window.API.coreUpdateCheck();
  });

  /* ---------- Обновление движка tachyon-core с GitHub ---------- */
  const coreVerBadge = $('#coreVerBadge');
  const coreUpdStatus = $('#coreUpdStatus');
  const checkCoreUpdBtn = $('#checkCoreUpdBtn');
  const installCoreUpdBtn = $('#installCoreUpdBtn');
  const installCoreUpdTxt = $('#installCoreUpdTxt');
  const coreUpdProgressWrap = $('#coreUpdProgressWrap');
  const coreUpdProgressBar = $('#coreUpdProgressBar');
  const updBar = $('#updBar');
  const updText = $('#updText');
  const updAction = $('#updAction');
  const updClose = $('#updClose');

  let pendingBannerAction = null;

  updClose?.addEventListener('click', () => { if (updBar) updBar.hidden = true; });
  updAction?.addEventListener('click', () => {
    if (typeof pendingBannerAction === 'function') pendingBannerAction();
  });

  function applyVersionBadges(ver) {
    if (!ver) return;
    const clean = String(ver).replace(/^v/i, '');
    if (coreVerBadge) coreVerBadge.textContent = 'v' + clean;
    const tb = $('.topbar__ver');
    if (tb) tb.textContent = clean;
    const ab = $('#aboutVersion');
    if (ab) ab.textContent = 'v' + clean;
    const fc = $('#footerCoreVer');
    if (fc) fc.textContent = 'tachyon-core ' + clean;
  }

  applyVersionBadges(window.__tachyonVersion || window.TACHYON_CONFIG?.version);
  window.API.onCoreVersion(ver => applyVersionBadges(ver));
  window.API.requestCoreVersion?.();

  checkCoreUpdBtn?.addEventListener('click', () => {
    if (coreUpdStatus) coreUpdStatus.textContent = 'Проверка релизов Dushnilin/tachyon-desktop…';
    checkCoreUpdBtn.classList.add('is-busy');
    window.API.coreUpdateCheck();
    setTimeout(() => checkCoreUpdBtn.classList.remove('is-busy'), 1500);
  });

  installCoreUpdBtn?.addEventListener('click', () => {
    installCoreUpdBtn.disabled = true;
    if (installCoreUpdTxt) installCoreUpdTxt.textContent = 'Загрузка…';
    if (coreUpdProgressWrap) coreUpdProgressWrap.hidden = false;
    if (coreUpdProgressBar) coreUpdProgressBar.style.width = '5%';
    window.API.coreUpdateInstall();
  });

  window.API.onCoreUpdate(ev => {
    checkCoreUpdBtn?.classList.remove('is-busy');
    if (ev.type === 'available' && ev.info) {
      const { current, latest, size } = ev.info;
      if (current) applyVersionBadges(current);
      const mb = size ? ` (${(size / (1024 * 1024)).toFixed(1)} МБ)` : '';
      if (coreUpdStatus) coreUpdStatus.textContent = `Доступна новая версия v${latest}${mb}`;
      if (installCoreUpdBtn) {
        installCoreUpdBtn.hidden = false;
        installCoreUpdBtn.disabled = false;
      }
      if (installCoreUpdTxt) installCoreUpdTxt.textContent = `Обновить до v${latest}`;

      if (updBar && updText && updAction) {
        updText.textContent = `Доступно обновление Tachyon v${latest} (установлено v${current})`;
        updAction.textContent = 'Обновить';
        updBar.hidden = false;
        pendingBannerAction = () => {
          updAction.textContent = 'Загрузка…';
          window.API.coreUpdateInstall();
        };
      }
    } else if (ev.type === 'up-to-date') {
      const ver = ev.info?.current || '';
      if (ver) applyVersionBadges(ver);
      if (coreUpdStatus) coreUpdStatus.textContent = `Установлена актуальная версия (v${ver})`;
      if (installCoreUpdBtn) installCoreUpdBtn.hidden = true;
      toast(`Tachyon v${ver} — установлена актуальная версия`);
    } else if (ev.type === 'progress') {
      if (coreUpdProgressWrap) coreUpdProgressWrap.hidden = false;
      if (coreUpdProgressBar) coreUpdProgressBar.style.width = `${ev.percent}%`;
      if (coreUpdStatus) coreUpdStatus.textContent = `Загрузка обновления… ${ev.percent}%`;
      if (updBar && !updBar.hidden && updAction) {
        updAction.textContent = `${ev.percent}%`;
      }
    } else if (ev.type === 'done') {
      const newVer = ev.info?.version || '';
      const restarting = !!ev.info?.restarting;
      if (coreUpdProgressWrap) coreUpdProgressWrap.hidden = true;
      if (installCoreUpdBtn) installCoreUpdBtn.hidden = true;
      if (updBar) updBar.hidden = true;
      if (newVer) {
        if (coreVerBadge) coreVerBadge.textContent = 'v' + newVer;
        const tb = $('.topbar__ver');
        if (tb) tb.textContent = newVer;
        const ab = $('#aboutVersion');
        if (ab) ab.textContent = 'v' + newVer;
      }
      if (coreUpdStatus) {
        coreUpdStatus.textContent = restarting
          ? `Обновлено до v${newVer} — перезапуск приложения…`
          : `Успешно обновлено до v${newVer}`;
      }
      toast(restarting ? `Обновлено до v${newVer}! Перезапуск…` : `Tachyon обновлён до v${newVer}!`);
    } else if (ev.type === 'error') {
      if (coreUpdProgressWrap) coreUpdProgressWrap.hidden = true;
      if (installCoreUpdBtn) installCoreUpdBtn.disabled = false;
      if (installCoreUpdTxt) installCoreUpdTxt.textContent = 'Повторить';
      if (coreUpdStatus) coreUpdStatus.textContent = 'Ошибка: ' + (ev.message || 'Сбой обновления');
      toast('Ошибка обновления: ' + (ev.message || ''), true);
    }
  });

  $('#githubBtn')?.addEventListener('click', () => {
    window.API.openExternal('https://github.com/Dushnilin/tachyon-desktop');
  });

  $('#selfCheckBtn')?.addEventListener('click', () => {
    const list = $('#selfCheckList');
    if (!list) return;
    list.hidden = false;
    list.innerHTML = '<li>Диагностика сетевого стека и tachyon-core…</li>';
    window.API.selfCheck({ mode: vpnPrefs.mode });
  });

  window.API.onDiagStep(step => {
    const list = $('#selfCheckList');
    if (!list) return;
    list.innerHTML += `<li><b>${escapeHtml(step.title || '')}</b>: ${escapeHtml(step.status || '')} — ${escapeHtml(step.message || '')}</li>`;
  });

  window.API.onDiagDone(() => {
    toast('Диагностика завершена');
  });

  /* ============================================================
     TACHYON POWER DIAL (ТАХИОННЫЙ РЕАКТОР НА 60 ДЕЛЕНИЙ)
     ============================================================ */
  const reactorCvs = $('#reactorCanvas');
  const reactorCtx = reactorCvs?.getContext('2d');
  let reactorAngle = 0;
  let reactorWave = 1; // 0..1 ударная волна при подключении

  function triggerReactorShockwave() {
    reactorWave = 0.01;
  }

  function renderReactorFrame() {
    if (!reactorCtx || !reactorCvs) return;
    const w = reactorCvs.width;
    const h = reactorCvs.height;
    const cx = w / 2;
    const cy = h / 2;
    reactorCtx.clearRect(0, 0, w, h);

    const isLight = document.documentElement.dataset.theme === 'light';
    const accentHex = isLight ? '#5B47C7' : '#B9A8FF';
    const warnHex = isLight ? '#9A6B00' : '#E5C07B';
    const lineHex = isLight ? '#CFCFD6' : '#2C2C34';

    reactorAngle = (reactorAngle + (connecting ? 0.045 : (connected ? 0.014 : 0.004))) % (Math.PI * 2);

    /* 1. Ударная волна (Shockwave) при подключении */
    if (reactorWave < 1) {
      reactorWave = Math.min(1, reactorWave + 0.025);
      const rWave = 48 + reactorWave * 28;
      reactorCtx.beginPath();
      reactorCtx.arc(cx, cy, rWave, 0, Math.PI * 2);
      reactorCtx.strokeStyle = isLight
        ? `rgba(91, 71, 199, ${(1 - reactorWave) * 0.45})`
        : `rgba(185, 168, 255, ${(1 - reactorWave) * 0.5})`;
      reactorCtx.lineWidth = 1.6;
      reactorCtx.stroke();
    }

    /* 2. Шкала из 60 делений (360 градусов) */
    const tickCount = 60;
    const outerR = Math.min(cx, cy) - 4;
    for (let i = 0; i < tickCount; i++) {
      const a = (i / tickCount) * Math.PI * 2 - Math.PI / 2;
      const isMajor = i % 5 === 0;
      const innerR = isMajor ? outerR - 7 : outerR - 4;

      let stroke = lineHex;
      let alpha = isMajor ? 0.85 : 0.45;
      if (connected) {
        const diff = Math.abs(Math.sin((a - reactorAngle) / 2));
        if (diff < 0.35) {
          stroke = accentHex;
          alpha = 0.95 - diff * 1.4;
        } else {
          stroke = accentHex;
          alpha = isMajor ? 0.42 : 0.2;
        }
      } else if (connecting) {
        const diff = Math.abs(Math.sin((a - reactorAngle) / 2));
        if (diff < 0.35) {
          stroke = warnHex;
          alpha = 0.95 - diff * 1.4;
        }
      }

      reactorCtx.save();
      reactorCtx.globalAlpha = Math.max(0.12, Math.min(1, alpha));
      reactorCtx.strokeStyle = stroke;
      reactorCtx.lineWidth = isMajor ? 1.5 : 1;
      reactorCtx.beginPath();
      reactorCtx.moveTo(cx + Math.cos(a) * innerR, cy + Math.sin(a) * innerR);
      reactorCtx.lineTo(cx + Math.cos(a) * outerR, cy + Math.sin(a) * outerR);
      reactorCtx.stroke();
      reactorCtx.restore();
    }

    /* 3. Орбитальное кольцо и спутник */
    const orbitR = outerR - 14;
    reactorCtx.beginPath();
    reactorCtx.arc(cx, cy, orbitR, 0, Math.PI * 2);
    reactorCtx.strokeStyle = connected ? accentHex : (connecting ? warnHex : lineHex);
    reactorCtx.globalAlpha = connected || connecting ? 0.35 : 0.25;
    reactorCtx.lineWidth = 1;
    reactorCtx.stroke();
    reactorCtx.globalAlpha = 1;

    if (connected || connecting) {
      const satX = cx + Math.cos(reactorAngle) * orbitR;
      const satY = cy + Math.sin(reactorAngle) * orbitR;
      reactorCtx.beginPath();
      reactorCtx.arc(satX, satY, 3.2, 0, Math.PI * 2);
      reactorCtx.fillStyle = connected ? accentHex : warnHex;
      reactorCtx.fill();
    }

    requestAnimationFrame(renderReactorFrame);
  }
  requestAnimationFrame(renderReactorFrame);

  /* ============================================================
     КАРТОЧКА ВЫХОДНОГО УЗЛА (EXIT NODE GEO) & PING SPARKLINE
     ============================================================ */
  const sparkCvs = $('#pingSparklineCanvas');
  const sparkCtx = sparkCvs?.getContext('2d');
  const pingHistory = Array(20).fill(0);

  function pushPingSparkline(ms) {
    if (ms > 0) {
      pingHistory.push(ms);
      if (pingHistory.length > 20) pingHistory.shift();
      const badge = $('#exitNodePingBadge');
      if (badge) badge.textContent = `${ms} мс`;
    }
    drawPingSparkline();
  }

  function drawPingSparkline() {
    if (!sparkCtx || !sparkCvs) return;
    const w = sparkCvs.width;
    const h = sparkCvs.height;
    sparkCtx.clearRect(0, 0, w, h);
    const nonZero = pingHistory.filter(v => v > 0);
    if (!nonZero.length) {
      sparkCtx.strokeStyle = 'rgba(168, 168, 173, 0.25)';
      sparkCtx.beginPath();
      sparkCtx.moveTo(0, h / 2);
      sparkCtx.lineTo(w, h / 2);
      sparkCtx.stroke();
      return;
    }
    const max = Math.max(100, ...pingHistory);
    const min = Math.max(0, Math.min(...nonZero) - 10);
    const span = Math.max(20, max - min);
    const isLight = document.documentElement.dataset.theme === 'light';
    const stroke = isLight ? '#5B47C7' : '#B9A8FF';

    sparkCtx.beginPath();
    pingHistory.forEach((v, i) => {
      const val = v > 0 ? v : nonZero[nonZero.length - 1];
      const x = (i / (pingHistory.length - 1)) * w;
      const y = h - ((val - min) / span) * (h - 6) - 3;
      if (i === 0) sparkCtx.moveTo(x, y);
      else sparkCtx.lineTo(x, y);
    });
    sparkCtx.strokeStyle = stroke;
    sparkCtx.lineWidth = 1.6;
    sparkCtx.stroke();
  }
  drawPingSparkline();

  async function refreshExitNodeInfo() {
    const ipEl = $('#exitNodeIp');
    const ccEl = $('#exitNodeCc');
    const metaEl = $('#exitNodeMeta');
    const btn = $('#refreshExitGeoBtn');
    if (btn) btn.classList.add('is-busy');
    if (ipEl) ipEl.textContent = 'Проверка…';
    try {
      const info = await window.API.checkExitGeo();
      if (info && info.ok) {
        if (ipEl) ipEl.textContent = info.ip || 'Неизвестно';
        if (ccEl) ccEl.textContent = info.countryCode || (info.latencyMs > 0 ? `${info.latencyMs} мс` : 'IP');
        const loc = [info.country, info.city, info.isp].filter(Boolean).join(' · ');
        if (metaEl) metaEl.textContent = loc || 'Маршрут проверен';
        if (info.latencyMs > 0) pushPingSparkline(info.latencyMs);
      } else {
        if (ipEl) ipEl.textContent = 'Нет ответа';
        if (ccEl) ccEl.textContent = '—';
        if (metaEl) metaEl.textContent = info?.error || 'Проверьте подключение';
      }
    } catch {
      if (ipEl) ipEl.textContent = 'Ошибка';
    } finally {
      if (btn) btn.classList.remove('is-busy');
    }
  }

  $('#refreshExitGeoBtn')?.addEventListener('click', refreshExitNodeInfo);

  /* Быстрый HTTP-тест выбранного узла на главном экране */
  $('#quickProbeBtn')?.addEventListener('click', async () => {
    const s = activeServer();
    if (!s || !s.vless) {
      toast('Сначала выберите узел', true);
      return;
    }
    const host = s.meta?.host || extractHost(s.vless);
    const port = s.meta?.port || 443;
    toast(`Проверка задержки до ${s.name}…`);
    const ms = await window.API.pingHost(host, port);
    if (ms != null && ms > 0) {
      s.ping = ms;
      $('#mPing').textContent = ms;
      pushPingSparkline(ms);
      toast(`${s.name}: отклик ${ms} мс`);
    } else {
      toast(`${s.name}: узел не ответил на TCP-пинг`, true);
    }
  });

  /* ============================================================
     МОДАЛЬНОЕ ОКНО QR-КОДА И КОПИРОВАНИЯ URI УЗЛА
     ============================================================ */
  function buildVisualQrDataUrl(text) {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 200;
    const ctxQr = canvas.getContext('2d');
    const size = 25;
    const cell = Math.floor(canvas.width / size);
    ctxQr.fillStyle = '#FFFFFF';
    ctxQr.fillRect(0, 0, canvas.width, canvas.height);
    ctxQr.fillStyle = '#131316';

    const drawFinder = (ox, oy) => {
      ctxQr.fillRect(ox * cell, oy * cell, 7 * cell, 7 * cell);
      ctxQr.fillStyle = '#FFFFFF';
      ctxQr.fillRect((ox + 1) * cell, (oy + 1) * cell, 5 * cell, 5 * cell);
      ctxQr.fillStyle = '#131316';
      ctxQr.fillRect((ox + 2) * cell, (oy + 2) * cell, 3 * cell, 3 * cell);
    };
    drawFinder(1, 1);
    drawFinder(size - 8, 1);
    drawFinder(1, size - 8);

    let hash = 2166136261;
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    for (let y = 1; y < size - 1; y++) {
      for (let x = 1; x < size - 1; x++) {
        if ((x < 9 && y < 9) || (x > size - 10 && y < 9) || (x < 9 && y > size - 10)) continue;
        hash ^= (x * 374761393 + y * 668265263 + text.charCodeAt((x + y) % Math.max(1, text.length)));
        hash = Math.imul(hash, 16777619);
        if ((Math.abs(hash) % 10) < 5) {
          ctxQr.fillRect(x * cell, y * cell, cell, cell);
        }
      }
    }
    return canvas.toDataURL('image/png');
  }

  $('#quickQrBtn')?.addEventListener('click', () => {
    const s = activeServer();
    if (!s || !s.vless) {
      toast('Нет выбранного узла для экспорта', true);
      return;
    }
    const modal = $('#qrModal');
    if (!modal) return;
    const titleEl = $('#qrNodeTitle');
    if (titleEl) titleEl.textContent = s.name || 'Узел Tachyon';
    const inpEl = $('#qrUriInput');
    if (inpEl) inpEl.value = s.vless;
    const imgEl = $('#qrImage');
    if (imgEl) imgEl.src = buildVisualQrDataUrl(s.vless);
    modal.hidden = false;
  });

  $('#qrCloseBtn')?.addEventListener('click', () => { $('#qrModal').hidden = true; });
  $('#qrBackdrop')?.addEventListener('click', () => { $('#qrModal').hidden = true; });
  $('#copyQrUriBtn')?.addEventListener('click', async () => {
    const s = activeServer();
    const val = $('#qrUriInput')?.value || s?.vless || '';
    if (val) {
      try {
        await navigator.clipboard.writeText(val);
        toast('Ключ узла скопирован в буфер обмена');
      } catch {
        toast('Не удалось скопировать ключ', true);
      }
    }
  });

  /* ============================================================
     ЦЕПОЧКА ПРОКСИ (DETOUR) И ВЫБОР УЗЛА НА ВКЛАДКЕ МАРШРУТЫ
     ============================================================ */
  function syncDetourAndRuleNodeSelects() {
    const detourSel = $('#detourNodeSelect');
    if (detourSel) {
      const cur = vpnPrefs.detourNodeId || '';
      let html = `<option value="">Выключено (напрямую к серверу)</option>`;
      for (const s of servers.slice(0, 150)) {
        html += `<option value="${escapeHtml(s.id)}" ${s.id === cur ? 'selected' : ''}>Chain → ${escapeHtml(s.name)}</option>`;
      }
      detourSel.innerHTML = html;
    }

    const ruleActSel = $('#customRuleAction');
    if (ruleActSel) {
      const curVal = ruleActSel.value || 'vpn';
      let html = `
        <option value="vpn">→ VPN</option>
        <option value="desync">→ Desync</option>
        <option value="direct">→ Прямой</option>
        <option value="block">→ Блок</option>
      `;
      for (const s of servers.slice(0, 60)) {
        const val = `node:${s.id}`;
        html += `<option value="${escapeHtml(val)}" ${val === curVal ? 'selected' : ''}>Узел: ${escapeHtml(s.name)}</option>`;
      }
      ruleActSel.innerHTML = html;
    }
  }

  $('#detourNodeSelect')?.addEventListener('change', e => {
    vpnPrefs.detourNodeId = e.target.value || '';
    saveVpnPrefs();
    toast(vpnPrefs.detourNodeId ? 'Цепочка прокси (Detour) активирована' : 'Цепочка прокси отключена');
    applyReconnectIfActive();
  });

  /* ============================================================
     ГЕНЕРАТОР CLOUDFLARE WARP (AMNEZIAWG) & БЕСПЛАТНЫЙ ПУЛ SHARD
     ============================================================ */
  $('#createWarpAwgBtn')?.addEventListener('click', async () => {
    const btn = $('#createWarpAwgBtn');
    const txt = $('#createWarpAwgTxt');
    if (btn) btn.disabled = true;
    if (txt) txt.textContent = 'WARP…';
    toast('Генерация ключей X25519 и регистрация Cloudflare WARP (AmneziaWG)…');
    try {
      const res = await window.API.createWarpAwg();
      if (res && res.ok && res.uri) {
        const customs = window.API.getCustomNodes();
        const newId = 'custom_' + Date.now();
        customs.unshift({
          id: newId,
          name: cleanServerName(res.name || 'Cloudflare WARP (AWG)'),
          country: 'us',
          code: 'US',
          vless: res.uri,
          ping: null
        });
        window.API.saveCustomNodes(customs);
        activeId = newId;
        try { localStorage.setItem('tachyon.active_server_id', newId); } catch {}
        renderSubscriptions();
        loadAllServers();
        renderServers($('#nodesSearchInput')?.value || '');
        syncDetourAndRuleNodeSelects();
        toast(`Профиль ${res.name || 'Cloudflare WARP AWG'} создан и выбран!`);
        if (connected) applyReconnectIfActive();
      } else {
        toast('Ошибка регистрации WARP: ' + (res?.error || 'Неизвестная ошибка'), true);
      }
    } catch (err) {
      toast('Ошибка генерации WARP: ' + (err?.message || ''), true);
    } finally {
      if (btn) btn.disabled = false;
      if (txt) txt.textContent = 'WARP AWG';
    }
  });

  $('#loadShardFreeBtn')?.addEventListener('click', () => {
    const freeUrl = 'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt';
    toast('Загрузка резервного пула бесплатных узлов…');
    pendingImport = { name: 'Tachyon Free Pool', input: freeUrl };
    window.API.importSubscription(freeUrl);
  });

  /* ============================================================
     ПОДВКЛАДКИ «ТРАФИК И ДИАГНОСТИКА»: СОЕДИНЕНИЯ, МАТРИЦА ТСПУ, СПИДТЕСТ, ЛОГ ЯДРА
     ============================================================ */
  let coreLogTimer = null;
  let lastRawLogText = '';
  let logFilterLevel = 'all';

  $$('#trafficSubtabs button[data-ttab]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#trafficSubtabs button').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      const tab = btn.dataset.ttab;
      const pConns = $('#ttabConns');
      const pDiag = $('#ttabDiag');
      const pLogs = $('#ttabLogs');
      if (pConns) pConns.hidden = tab !== 'conns';
      if (pDiag) pDiag.hidden = tab !== 'diag';
      if (pLogs) pLogs.hidden = tab !== 'logs';

      clearInterval(coreLogTimer);
      if (tab === 'logs') {
        window.API.requestLogTail();
        coreLogTimer = setInterval(() => window.API.requestLogTail(), 2500);
      }
    });
  });

  $('#closeAllConnsBtn')?.addEventListener('click', () => {
    window.API.closeConnection('');
    toast('Все активные соединения в ядре сброшены');
    setTimeout(() => window.API.getConnections(), 300);
  });

  $('#connSearchInput')?.addEventListener('input', () => renderConnections());

  function renderFilteredCoreLog() {
    const viewer = $('#coreLogViewer');
    if (!viewer) return;
    if (!lastRawLogText) {
      viewer.textContent = 'Лог ядра пока пуст.';
      return;
    }
    const lines = lastRawLogText.split(/\r?\n/);
    const filtered = lines.filter(l => {
      if (logFilterLevel === 'error') return /error|fatal|panic|fail/i.test(l);
      if (logFilterLevel === 'warn') return /warn|error|fatal|panic|fail/i.test(l);
      return true;
    });
    viewer.textContent = filtered.join('\n') || 'Нет записей для выбранного фильтра.';
    viewer.scrollTop = viewer.scrollHeight;
  }

  window.API.onLogTail(text => {
    lastRawLogText = text || '';
    renderFilteredCoreLog();
  });

  $$('#logLevelFilterSeg button[data-llf]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#logLevelFilterSeg button').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      logFilterLevel = btn.dataset.llf || 'all';
      renderFilteredCoreLog();
    });
  });

  $('#refreshLogTailBtn')?.addEventListener('click', () => window.API.requestLogTail());
  $('#openLogFileBtn')?.addEventListener('click', () => window.API.openLog());
  $('#copyLogTailBtn')?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('#coreLogViewer')?.textContent || '');
      toast('Журнал скопирован в буфер обмена');
    } catch {
      toast('Не удалось скопировать журнал', true);
    }
  });

  $('#runDiagMatrixBtn')?.addEventListener('click', async () => {
    const btn = $('#runDiagMatrixBtn');
    const txt = $('#runDiagMatrixTxt');
    const grid = $('#diagMatrixGrid');
    if (!grid) return;
    if (btn) btn.disabled = true;
    if (txt) txt.textContent = 'Проверка ТСПУ…';
    grid.innerHTML = `<div class="diag-empty-hint">Выполняется параллельное зондирование целей через текущий маршрут…</div>`;
    try {
      const res = await window.API.runDiagMatrix();
      const items = res?.items || res?.probes || [];
      if (!items.length) {
        grid.innerHTML = `<div class="diag-empty-hint">Нет данных от матрицы диагностики.</div>`;
      } else {
        grid.innerHTML = items.map(p => `
          <div class="diag-probe-item">
            <div class="diag-probe-item__left">
              <div class="diag-probe-item__name">${escapeHtml(p.title || p.name || p.id)}</div>
              <div class="diag-probe-item__detail">${escapeHtml(p.subtitle || p.detail || '')} · ${escapeHtml(p.status || '')}</div>
            </div>
            <span class="diag-probe-item__badge ${p.ok ? 'is-ok' : 'is-fail'}">${p.ok ? `${p.ms} мс` : 'БЛОК / ТАЙМАУТ'}</span>
          </div>
        `).join('');
        toast('Проверка матрицы доступности завершена');
      }
    } catch (e) {
      grid.innerHTML = `<div class="diag-empty-hint">Ошибка запуска матрицы: ${escapeHtml(e?.message || '')}</div>`;
    } finally {
      if (btn) btn.disabled = false;
      if (txt) txt.textContent = 'Запустить проверку';
    }
  });

  let speedtestSizeMb = parseInt(localStorage.getItem('tachyon.sp_size') || '100', 10) || 100;
  let speedtestProvider = localStorage.getItem('tachyon.sp_prov') || 'auto';
  let speedtestRunning = false;

  $$('#speedtestSizeSeg button[data-sp-mb]').forEach(btn => {
    const val = parseInt(btn.dataset.spMb, 10) || 100;
    btn.classList.toggle('is-active', val === speedtestSizeMb);
    btn.addEventListener('click', () => {
      if (speedtestRunning) return;
      speedtestSizeMb = val;
      try { localStorage.setItem('tachyon.sp_size', String(val)); } catch {}
      $$('#speedtestSizeSeg button').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
    });
  });

  const spProvSel = $('#speedtestProviderSelect');
  if (spProvSel) {
    spProvSel.value = speedtestProvider;
    spProvSel.addEventListener('change', () => {
      speedtestProvider = spProvSel.value || 'auto';
      try { localStorage.setItem('tachyon.sp_prov', speedtestProvider); } catch {}
    });
  }

  window.API.onSpeedtestProgress?.(prog => {
    if (!prog) return;
    const mbpsEl = $('#spMbpsVal');
    const peakEl = $('#spPeakVal');
    const mbsEl = $('#spMbsVal');
    const ttfbEl = $('#spTtfbVal');
    const srvBadge = $('#spServerBadge');
    const pWrap = $('#speedtestProgressWrap');
    const pTxt = $('#spProgressText');
    const pPct = $('#spProgressPct');
    const pFill = $('#spProgressFill');

    if (pWrap) pWrap.hidden = false;
    if (mbpsEl) mbpsEl.textContent = `${prog.mbps ?? 0}`;
    if (peakEl) peakEl.textContent = `${prog.peakMbps ?? prog.mbps ?? 0}`;
    if (mbsEl) mbsEl.textContent = `${prog.mbs ?? 0}`;
    if (ttfbEl) ttfbEl.textContent = `${prog.ttfbMs ?? 0} мс`;
    if (srvBadge && prog.server) srvBadge.textContent = prog.server;
    if (pTxt) pTxt.textContent = `${prog.server || 'Поток'}: ${prog.downloadedMb ?? 0} из ${prog.targetMb ?? speedtestSizeMb} МБ`;
    if (pPct) pPct.textContent = `${prog.percent ?? 0}%`;
    if (pFill) pFill.style.width = `${prog.percent ?? 0}%`;
  });

  $('#runSpeedtestBtn')?.addEventListener('click', async () => {
    if (speedtestRunning) {
      window.API.stopSpeedtest?.();
      return;
    }

    const btn = $('#runSpeedtestBtn');
    const txt = $('#runSpeedtestTxt');
    const mbpsEl = $('#spMbpsVal');
    const peakEl = $('#spPeakVal');
    const mbsEl = $('#spMbsVal');
    const ttfbEl = $('#spTtfbVal');
    const pWrap = $('#speedtestProgressWrap');
    const pTxt = $('#spProgressText');
    const pPct = $('#spProgressPct');
    const pFill = $('#spProgressFill');

    speedtestRunning = true;
    if (btn) btn.classList.add('btn-act--danger');
    if (txt) txt.textContent = 'Остановить';
    if (mbpsEl) mbpsEl.textContent = '…';
    if (peakEl) peakEl.textContent = '…';
    if (mbsEl) mbsEl.textContent = '…';
    if (ttfbEl) ttfbEl.textContent = '…';
    if (pWrap) pWrap.hidden = false;
    if (pTxt) pTxt.textContent = `Подключение к серверу (${speedtestSizeMb} МБ)…`;
    if (pPct) pPct.textContent = '0%';
    if (pFill) pFill.style.width = '0%';

    try {
      const res = await window.API.runSpeedtest({ sizeMb: speedtestSizeMb, provider: speedtestProvider });
      if (res && res.ok) {
        if (mbpsEl) mbpsEl.textContent = `${res.mbps ?? 0}`;
        if (peakEl) peakEl.textContent = `${res.peakMbps ?? res.mbps ?? 0}`;
        if (mbsEl) mbsEl.textContent = `${res.mbs ?? 0}`;
        if (ttfbEl) ttfbEl.textContent = `${res.ttfbMs ?? 0} мс`;
        const srvBadge = $('#spServerBadge');
        if (srvBadge && res.server) srvBadge.textContent = res.server;
        if (pTxt) {
          pTxt.textContent = res.stopped
            ? `Остановлено на ${res.downloadedMb ?? 0} МБ (${res.server || ''})`
            : `Завершено: ${res.downloadedMb ?? speedtestSizeMb} МБ (${res.server || ''})`;
        }
        if (pPct) pPct.textContent = res.stopped ? 'СТОП' : '100%';
        if (pFill) pFill.style.width = '100%';
        toast(`Спидтест: ${res.mbps} Мбит/с (пик ${res.peakMbps ?? res.mbps} Мбит/с, ${res.downloadedMb ?? speedtestSizeMb} МБ)`);
      } else {
        if (mbpsEl) mbpsEl.textContent = 'Ошибка';
        if (peakEl) peakEl.textContent = '—';
        if (mbsEl) mbsEl.textContent = '—';
        if (ttfbEl) ttfbEl.textContent = '—';
        if (pWrap) pWrap.hidden = true;
        toast('Ошибка спидтеста: ' + (res?.error || 'Не удалось выполнить замер'), true);
      }
    } catch {
      toast('Ошибка при выполнении спидтеста', true);
    } finally {
      speedtestRunning = false;
      if (btn) btn.classList.remove('btn-act--danger');
      if (txt) txt.textContent = 'Измерить скорость';
    }
  });

  /* ============================================================
     ОПЦИИ ИНТЕРФЕЙСА: ТЕМА (DARK/LIGHT), FAKEIP, DNS BENCHMARK, MTU, ЭКСПОРТ JSON
     ============================================================ */
  function applyTheme(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    vpnPrefs.theme = t;
    document.documentElement.dataset.theme = t;
    $$('#themeSelectSeg button[data-theme-val]').forEach(b => {
      b.classList.toggle('is-active', b.dataset.themeVal === t);
    });
    const qIcon = $('#themeQuickIcon use');
    if (qIcon) qIcon.setAttribute('href', t === 'light' ? '#ic-moon' : '#ic-sun');
    window.API.setTheme(t);
    drawPingSparkline();
  }

  $$('#themeSelectSeg button[data-theme-val]').forEach(btn => {
    btn.addEventListener('click', () => {
      applyTheme(btn.dataset.themeVal);
      saveVpnPrefs();
    });
  });

  $('#themeQuickBtn')?.addEventListener('click', () => {
    const next = (vpnPrefs.theme || 'dark') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    saveVpnPrefs();
    toast(next === 'light' ? 'Тема: Светлая' : 'Тема: Тёмная');
  });

  const dnsRouteSel = $('#dnsRouteModeSelect');
  if (dnsRouteSel) {
    dnsRouteSel.value = vpnPrefs.dnsRouteMode || 'split_ru';
    dnsRouteSel.addEventListener('change', () => {
      vpnPrefs.dnsRouteMode = dnsRouteSel.value;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  const mtuSel = $('#mtuSelect');
  if (mtuSel) {
    mtuSel.value = String(vpnPrefs.mtu || 1420);
    mtuSel.addEventListener('change', () => {
      vpnPrefs.mtu = parseInt(mtuSel.value, 10) || 1420;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  const logLevelSel = $('#logLevelSelect');
  if (logLevelSel) {
    logLevelSel.value = vpnPrefs.logLevel || 'warn';
    logLevelSel.addEventListener('change', () => {
      vpnPrefs.logLevel = logLevelSel.value;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  const fakeIpToggle = $('#fakeIpToggle');
  if (fakeIpToggle) {
    fakeIpToggle.checked = !!vpnPrefs.fakeIp;
    fakeIpToggle.addEventListener('change', () => {
      vpnPrefs.fakeIp = fakeIpToggle.checked;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  const tlsFragToggle = $('#proxyTlsFragToggle');
  if (tlsFragToggle) {
    tlsFragToggle.checked = vpnPrefs.proxyTlsFragment !== false;
    tlsFragToggle.addEventListener('change', () => {
      vpnPrefs.proxyTlsFragment = tlsFragToggle.checked;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  const allowLanToggle = $('#allowLanToggle');
  if (allowLanToggle) {
    allowLanToggle.checked = !!vpnPrefs.allowLan;
    allowLanToggle.addEventListener('change', () => {
      vpnPrefs.allowLan = allowLanToggle.checked;
      saveVpnPrefs();
      applyReconnectIfActive();
    });
  }

  /* DNS Бенчмарк (#runDnsBenchBtn + #dnsBenchList) */
  $('#runDnsBenchBtn')?.addEventListener('click', async () => {
    const btn = $('#runDnsBenchBtn');
    const txt = $('#runDnsBenchTxt');
    const list = $('#dnsBenchList');
    if (!list) return;
    if (btn) btn.disabled = true;
    if (txt) txt.textContent = 'Замер…';
    list.hidden = false;
    list.innerHTML = `<div class="conn-empty" style="grid-column:1/-1">Тестирование задержки DNS-серверов…</div>`;
    try {
      const res = await window.API.runDnsBenchmark();
      const rawItems = res?.results || res?.items || [];
      const items = [...rawItems].sort((a, b) => {
        const ma = a.ms > 0 ? a.ms : 999999;
        const mb = b.ms > 0 ? b.ms : 999999;
        return ma - mb;
      });
      if (items.length) {
        const best = items[0];
        const bestIp = best.host || best.ip || '77.88.8.8';
        vpnPrefs.dnsBootstrap = bestIp;
        if (best.id) vpnPrefs.dns = best.id;
        saveVpnPrefs();
        updateRoutingSummaryUI();
        list.innerHTML = items.map(it => {
          const ip = it.host || it.ip || '';
          const ok = it.ms > 0 && it.ms < 9000;
          return `
            <div class="dns-bench-item" data-dns-ip="${escapeHtml(ip)}" data-dns-id="${escapeHtml(it.id || '')}" title="Нажмите, чтобы выбрать ${escapeHtml(it.name)} (${escapeHtml(ip)})">
              <div>
                <span class="dns-bench-item__name">${escapeHtml(it.name)}</span>
                <span class="dns-bench-item__ip">${escapeHtml(ip)}</span>
              </div>
              <span class="dns-bench-item__ms">${ok ? `${it.ms} мс` : 'Таймаут'}</span>
            </div>
          `;
        }).join('');

        $$('[data-dns-ip]', list).forEach(el => {
          el.addEventListener('click', () => {
            vpnPrefs.dnsBootstrap = el.dataset.dnsIp;
            if (el.dataset.dnsId) vpnPrefs.dns = el.dataset.dnsId;
            saveVpnPrefs();
            updateRoutingSummaryUI();
            toast(`Выбран быстрый DNS: ${vpnPrefs.dnsBootstrap}`);
            applyReconnectIfActive();
          });
        });
        toast(`Быстрейший DNS: ${best.name} (${best.ms} мс)`);
      } else {
        list.innerHTML = `<div class="conn-empty" style="grid-column:1/-1">Нет ответа от DNS-серверов</div>`;
      }
    } catch {
      list.innerHTML = `<div class="conn-empty" style="grid-column:1/-1">Ошибка замера DNS</div>`;
    } finally {
      if (btn) btn.disabled = false;
      if (txt) txt.textContent = 'Тест задержки DNS';
    }
  });

  /* Экспорт и Импорт полной конфигурации в JSON */
  $('#exportConfigBtn')?.addEventListener('click', () => {
    const payload = {
      version: window.__tachyonVersion || window.TACHYON_CONFIG?.version || '0.3.2',
      exportedAt: new Date().toISOString(),
      vpnPrefs,
      desyncPrefs,
      communityListsState,
      customRouteRules,
      appRules,
      nodeFilters,
      subs: window.API.getSubscriptions()
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `tachyon-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Резервная копия конфигурации сохранена');
  });

  $('#importConfigBtn')?.addEventListener('click', () => {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json,application/json';
    fileInput.onchange = async e => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (data.vpnPrefs) { Object.assign(vpnPrefs, data.vpnPrefs); saveVpnPrefs(); }
        if (data.desyncPrefs) { Object.assign(desyncPrefs, data.desyncPrefs); saveDesyncPrefs(); }
        if (data.communityListsState) { communityListsState = data.communityListsState; saveCommunityListsState(); }
        if (data.customRouteRules) { customRouteRules = data.customRouteRules; saveCustomRouteRules(); }
        if (Array.isArray(data.subs)) { window.API.saveSubscriptions(data.subs); loadAllServers(); }
        applyTheme(vpnPrefs.theme || 'dark');
        updateRoutingSummaryUI();
        renderCommunityLists();
        renderCustomRules();
        syncDetourAndRuleNodeSelects();
        toast('Конфигурация успешно импортирована!');
        applyReconnectIfActive();
      } catch {
        toast('Ошибка чтения файла резервной копии JSON', true);
      }
    };
    fileInput.click();
  });

  /* ---------- Инициализация ---------- */
  applyTheme(vpnPrefs.theme || 'dark');
  loadAllServers();
  syncDetourAndRuleNodeSelects();
  updateRoutingSummaryUI();
  renderCommunityLists();
  renderCustomRules();
  setState('off');
  go('connect');
  setTimeout(refreshExitNodeInfo, 500);

  if (!window.API.getSubscriptions().length && !window.API.getCustomNodes().length && !localStorage.getItem('tachyon.default_sub_seeded')) {
    try { localStorage.setItem('tachyon.default_sub_seeded', '1'); } catch {}
    const defaultUrl = 'https://raw.githubusercontent.com/theakres/VPN/main/all';
    pendingImport = { name: 'Free', input: defaultUrl };
    setTimeout(() => window.API.importSubscription(defaultUrl), 350);
  }

  if (autoConnectToggle?.checked && activeServer()) {
    setTimeout(connect, 600);
  }
})();
