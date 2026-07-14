"use strict";

/* ---------- constants ---------- */

const FEED_LIMIT = 200;
const ARC_LIFETIME_MS = 4000;

const TYPE_LABELS = {
  connect: "Connect",
  bruteforce: "Brute force",
  login_success: "Login success",
  command: "Command exec",
  malware: "Malware / file",
  other: "Other",
};

const TYPE_COLORS = {
  connect: "#3987e5",
  bruteforce: "#e66767",
  login_success: "#008300",
  command: "#d95926",
  malware: "#d55181",
  other: "#898781",
};

const compactFmt = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });

/* ---------- helpers ---------- */

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function truncate(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function compactNumber(n) {
  return compactFmt.format(n ?? 0);
}

function flagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return "";
  const codePoints = [...countryCode.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function fmtDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function ispLabel(geo) {
  if (!geo || !geo.as_org) return "";
  return geo.asn ? `AS${geo.asn} ${geo.as_org}` : geo.as_org;
}

/* ---------- state ---------- */

let HONEYPOT = { lat: 0, lon: 0, label: "" };
const HONEYPOT_POINT = { id: "honeypot", lat: 0, lng: 0, color: "#ffffff", isHoneypot: true };

let world = null;
let timelineChart = null;
let credentialsChart = null;

let arcs = [];
let arcSeq = 0;
let points = [];
let pointSeq = 0;

/* ---------- globe ---------- */

function initGlobe() {
  const container = document.getElementById("globe-container");

  world = Globe()(container)
    .globeImageUrl("https://unpkg.com/three-globe/example/img/earth-night.jpg")
    .bumpImageUrl("https://unpkg.com/three-globe/example/img/earth-topology.png")
    .backgroundImageUrl("https://unpkg.com/three-globe/example/img/night-sky.png")
    .arcColor("color")
    .arcDashLength(0.4)
    .arcDashGap(0.15)
    .arcDashInitialGap(() => Math.random())
    .arcDashAnimateTime(1500)
    .arcStroke(0.6)
    .arcAltitudeAutoScale(0.4)
    .arcsTransitionDuration(0)
    .pointColor("color")
    .pointAltitude(0.005)
    .pointRadius((d) => (d.isHoneypot ? 0.6 : 0.3))
    .pointsMerge(false)
    .ringColor(() => (t) => `rgba(255,255,255,${1 - t})`)
    .ringMaxRadius(3.2)
    .ringPropagationSpeed(2.2)
    .ringRepeatPeriod(1400);

  // Render at the display's native resolution (capped) so the globe + textures look crisp
  // on HiDPI screens instead of the default soft upscaling.
  world.renderer().setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  world.controls().autoRotate = true;
  world.controls().autoRotateSpeed = 0.3;

  // The container can measure 0x0 on the very first synchronous read (layout not yet
  // settled), so re-measure on the next frame too, not just once at construction time.
  const resize = () => {
    world.width(container.clientWidth);
    world.height(container.clientHeight);
  };
  resize();
  requestAnimationFrame(resize);

  new ResizeObserver(resize).observe(container);
}

function refreshPoints() {
  world.pointsData([HONEYPOT_POINT, ...points]);
}

function addPoint(ev) {
  const id = pointSeq++;
  points.push({ id, lat: ev.lat, lng: ev.lon, color: ev.color });
  if (points.length > 60) points.shift();
  refreshPoints();

  setTimeout(() => {
    points = points.filter((p) => p.id !== id);
    refreshPoints();
  }, ARC_LIFETIME_MS);
}

function addArc(ev) {
  if (ev.lat == null || ev.lon == null) return;

  const id = arcSeq++;
  arcs.push({
    id,
    startLat: ev.lat,
    startLng: ev.lon,
    endLat: HONEYPOT.lat,
    endLng: HONEYPOT.lon,
    color: ev.color,
  });
  if (arcs.length > 60) arcs.shift();
  world.arcsData(arcs);

  addPoint(ev);

  setTimeout(() => {
    arcs = arcs.filter((a) => a.id !== id);
    world.arcsData(arcs);
  }, ARC_LIFETIME_MS);
}

function renderLegend() {
  const legend = document.getElementById("globe-legend");
  legend.innerHTML = Object.entries(TYPE_LABELS)
    .map(
      ([type, label]) =>
        `<span class="legend-item"><span class="legend-swatch" style="background:${TYPE_COLORS[type]}"></span>${escapeHtml(label)}</span>`
    )
    .join("");
}

/* ---------- charts ---------- */

function initCharts() {
  Chart.defaults.font.family = "system-ui, -apple-system, 'Segoe UI', sans-serif";
  Chart.defaults.color = "#898781";

  const tooltipStyle = {
    backgroundColor: "#202020",
    titleColor: "#c3c2b7",
    bodyColor: "#ffffff",
    borderColor: "#2c2c2a",
    borderWidth: 1,
    padding: 8,
    displayColors: false,
  };

  timelineChart = new Chart(document.getElementById("timeline-chart").getContext("2d"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          data: [],
          borderColor: "#3987e5",
          backgroundColor: "rgba(57,135,229,0.10)",
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: "#3987e5",
          pointHoverBorderColor: "#1a1a19",
          pointHoverBorderWidth: 2,
          fill: true,
          tension: 0.25,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false }, tooltip: tooltipStyle },
      scales: {
        x: {
          grid: { color: "#2c2c2a", drawTicks: false },
          ticks: { color: "#898781", maxTicksLimit: 8, autoSkip: true },
        },
        y: {
          beginAtZero: true,
          grid: { color: "#2c2c2a" },
          ticks: { color: "#898781", precision: 0 },
        },
      },
    },
  });

  credentialsChart = new Chart(document.getElementById("credentials-chart").getContext("2d"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          data: [],
          backgroundColor: "#3987e5",
          borderRadius: 4,
          maxBarThickness: 18,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false }, tooltip: tooltipStyle },
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: "#2c2c2a" },
          ticks: { color: "#898781", precision: 0 },
        },
        y: {
          grid: { display: false },
          ticks: { color: "#c3c2b7", font: { family: "ui-monospace, monospace", size: 11 } },
        },
      },
    },
  });
}

function renderTimeline(buckets) {
  timelineChart.data.labels = buckets.map((b) =>
    new Date(b.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
  );
  timelineChart.data.datasets[0].data = buckets.map((b) => b.count);
  timelineChart.update("none");
}

function renderCredentials(list) {
  credentialsChart.data.labels = list.map((c) => {
    const u = truncate(c.username || "(blank)", 20);
    const p = truncate(c.password || "(blank)", 20);
    return `${u} / ${p}`;
  });
  credentialsChart.data.datasets[0].data = list.map((c) => c.count);
  credentialsChart.update("none");
}

/* ---------- panel renderers ---------- */

function renderAttackerList(list) {
  const container = document.getElementById("attacker-list");
  if (!list.length) {
    container.innerHTML = `<div class="empty-state">No attackers yet</div>`;
    return;
  }
  const max = list[0].count || 1;
  container.innerHTML = list
    .map((a, i) => {
      const g = a.geo || {};
      const flag = flagEmoji(g.country_code);
      const country = escapeHtml(g.country || "Unknown");
      const isp = escapeHtml(ispLabel(g));
      const meta = [country, isp].filter(Boolean).join(" · ") || "—";
      const type = a.top_attack_type || "other";
      const color = TYPE_COLORS[type] || TYPE_COLORS.other;
      const pct = Math.max(6, (a.count / max) * 100).toFixed(0);
      return `<div class="attacker-row" data-ip="${escapeHtml(a.ip)}">
        <span class="attacker-rank">${i + 1}</span>
        <span class="attacker-main">
          <div class="attacker-ip">${flag ? flag + " " : ""}${escapeHtml(a.ip)}</div>
          <div class="attacker-meta">${meta}</div>
        </span>
        <span class="attacker-right">
          <span class="attacker-count">${a.count.toLocaleString()}</span>
          <span class="attacker-bar-track"><span class="attacker-bar-fill" style="width:${pct}%;background:${color}"></span></span>
        </span>
      </div>`;
    })
    .join("");
}

function renderCommands(list) {
  const container = document.getElementById("command-cloud");
  if (!list.length) {
    container.innerHTML = `<div class="empty-state">No commands executed yet</div>`;
    return;
  }
  const counts = list.map((c) => c.count);
  const max = Math.max(...counts);
  const min = Math.min(...counts);
  container.innerHTML = list
    .map((c) => {
      const scale = max === min ? 0.5 : (c.count - min) / (max - min);
      const size = (12 + scale * 14).toFixed(1);
      const label = truncate(c.command, 70);
      return `<span class="word-cloud-item" data-command="${escapeHtml(c.command)}" style="font-size:${size}px" title="Search: ${escapeHtml(c.command)}">${escapeHtml(label)}<span class="count">${c.count}</span></span>`;
    })
    .join("");
}

function renderGeo(list) {
  const container = document.getElementById("geo-list");
  if (!list.length) {
    container.innerHTML = `<div class="empty-state">No geolocated attacks yet</div>`;
    return;
  }
  const max = Math.max(...list.map((c) => c.count));
  container.innerHTML = list
    .map((c) => {
      const pct = Math.max(4, (c.count / max) * 100).toFixed(0);
      return `<div class="geo-row">
        <span>${flagEmoji(c.country_code)}</span>
        <span class="geo-name">${escapeHtml(c.country)}</span>
        <span class="geo-count">${c.count.toLocaleString()}</span>
        <div class="geo-bar-track"><div class="geo-bar-fill" style="width:${pct}%"></div></div>
      </div>`;
    })
    .join("");
}

/* ---------- live feed ---------- */

function feedDetailHtml(ev) {
  if (ev.eventid === "cowrie.login.failed" || ev.eventid === "cowrie.login.success") {
    return `user <span class="mono">${escapeHtml(ev.username ?? "")}</span> / pass <span class="mono">${escapeHtml(ev.password ?? "")}</span>`;
  }
  if (ev.eventid === "cowrie.command.input") {
    return `$ <span class="mono">${escapeHtml(truncate(ev.command ?? "", 80))}</span>`;
  }
  if (ev.eventid === "cowrie.session.file_download" || ev.eventid === "cowrie.session.file_upload") {
    return `download <span class="mono">${escapeHtml(truncate(ev.url ?? "", 80))}</span>`;
  }
  return `new ${escapeHtml(ev.protocol || "session")} connection`;
}

function feedRowHtml(ev) {
  const time = new Date(ev.timestamp).toLocaleTimeString([], { hour12: false });
  const flag = flagEmoji(ev.country_code);
  return `<div class="feed-row" data-ip="${escapeHtml(ev.src_ip)}">
    <span class="feed-time">${time}</span>
    <span class="feed-dot" style="background:${ev.color}"></span>
    <span class="feed-body">
      <span class="feed-ip">${flag ? `<span class="feed-flag">${flag}</span>` : ""}${escapeHtml(ev.src_ip)}</span>
      <div class="feed-detail">${feedDetailHtml(ev)}</div>
    </span>
  </div>`;
}

function prependFeed(ev) {
  const list = document.getElementById("feed-list");
  const wrapper = document.createElement("div");
  wrapper.innerHTML = feedRowHtml(ev);
  list.insertBefore(wrapper.firstElementChild, list.firstChild);
  while (list.children.length > FEED_LIMIT) {
    list.removeChild(list.lastChild);
  }
}

/* ---------- investigation drawer ---------- */

const drawerEl = document.getElementById("drawer");
const drawerScrim = document.getElementById("drawer-scrim");
const drawerTitle = document.getElementById("drawer-title");
const drawerBody = document.getElementById("drawer-body");

function openDrawer() {
  drawerEl.classList.add("open");
  drawerEl.setAttribute("aria-hidden", "false");
  drawerScrim.classList.add("open");
}

function closeDrawer() {
  drawerEl.classList.remove("open");
  drawerEl.setAttribute("aria-hidden", "true");
  drawerScrim.classList.remove("open");
}

async function openAttackerDrawer(ip) {
  openDrawer();
  drawerTitle.textContent = ip;
  drawerBody.innerHTML = `<div class="drawer-loading">Loading…</div>`;
  try {
    const res = await fetch(`/api/attacker/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error(res.status);
    drawerBody.innerHTML = renderAttackerDetail(await res.json());
  } catch {
    drawerBody.innerHTML = `<div class="drawer-empty">No details available for this IP.</div>`;
  }
}

function renderAttackerDetail(a) {
  const g = a.geo || {};
  const flag = flagEmoji(g.country_code);
  const geoKv = `
    <div class="drawer-kv"><span class="k">Country</span><span class="v">${flag ? flag + " " : ""}${escapeHtml(g.country || "Unknown")}</span></div>
    <div class="drawer-kv"><span class="k">City</span><span class="v">${escapeHtml(g.city || "—")}</span></div>
    <div class="drawer-kv"><span class="k">ISP / ASN</span><span class="v">${escapeHtml(ispLabel(g) || "—")}</span></div>
    <div class="drawer-kv"><span class="k">Events</span><span class="v">${(a.count || 0).toLocaleString()}</span></div>
    <div class="drawer-kv"><span class="k">First seen</span><span class="v">${fmtDateTime(a.first_seen)}</span></div>
    <div class="drawer-kv"><span class="k">Last seen</span><span class="v">${fmtDateTime(a.last_seen)}</span></div>`;

  const chips = (a.type_breakdown || [])
    .map(
      (t) =>
        `<span class="type-chip"><span class="dot" style="background:${TYPE_COLORS[t.attack_type] || TYPE_COLORS.other}"></span>${escapeHtml(TYPE_LABELS[t.attack_type] || t.attack_type)} · ${t.count}</span>`
    )
    .join("");

  const commands = (a.commands || []).length
    ? a.commands
        .map((c) => `<div class="drawer-list-row"><span class="label" title="${escapeHtml(c.command)}">${escapeHtml(c.command)}</span><span class="num">${c.count}</span></div>`)
        .join("")
    : `<div class="drawer-empty">No commands run (never obtained a shell).</div>`;

  const creds = (a.credentials || []).length
    ? a.credentials
        .map(
          (c) =>
            `<div class="drawer-list-row"><span class="label">${escapeHtml(c.username || "(blank)")} / ${escapeHtml(c.password || "(blank)")}</span><span class="num">${c.count}</span></div>`
        )
        .join("")
    : `<div class="drawer-empty">No login attempts recorded.</div>`;

  return `
    <div class="drawer-section"><h3>Origin</h3>${geoKv}</div>
    <div class="drawer-section"><h3>Activity</h3><div class="type-chips">${chips || '<span class="drawer-empty">—</span>'}</div></div>
    <div class="drawer-section"><h3>Commands run (${(a.commands || []).length})</h3>${commands}</div>
    <div class="drawer-section"><h3>Credentials tried (${(a.credentials || []).length})</h3>${creds}</div>`;
}

async function openCommandDrawer(query) {
  openDrawer();
  drawerTitle.textContent = `Search: "${truncate(query, 40)}"`;
  drawerBody.innerHTML = `<div class="drawer-loading">Searching…</div>`;
  try {
    const res = await fetch(`/api/commands/search?q=${encodeURIComponent(query)}`);
    drawerBody.innerHTML = renderCommandSearch(await res.json());
  } catch {
    drawerBody.innerHTML = `<div class="drawer-empty">Search failed.</div>`;
  }
}

function renderCommandSearch(data) {
  if (!data.attackers || !data.attackers.length) {
    return `<div class="drawer-empty">No attacker ran a command matching "${escapeHtml(data.query)}".</div>`;
  }
  const summary = `<div class="drawer-section">
    <div class="drawer-kv"><span class="k">Attackers</span><span class="v">${data.attackers.length.toLocaleString()}</span></div>
    <div class="drawer-kv"><span class="k">Total runs</span><span class="v">${data.total_matches.toLocaleString()}</span></div>
  </div>`;

  const rows = data.attackers
    .map((a) => {
      const g = a.geo || {};
      const flag = flagEmoji(g.country_code);
      const cmds = a.commands
        .map((c) => `<div class="mono" style="color:var(--text-muted);font-size:11px">${escapeHtml(truncate(c.command, 58))} <span style="color:var(--text-secondary)">×${c.count}</span></div>`)
        .join("");
      return `<div class="drawer-list-row drawer-attacker-row" data-ip="${escapeHtml(a.ip)}">
        <span class="label"><span class="mono" style="color:var(--text-primary)">${flag ? flag + " " : ""}${escapeHtml(a.ip)}</span>${cmds}</span>
        <span class="num">${a.match_count}</span>
      </div>`;
    })
    .join("");

  return summary + `<div class="drawer-section"><h3>Attackers who ran it (click to drill in)</h3>${rows}</div>`;
}

/* ---------- events / wiring ---------- */

function wireInteractions() {
  // Attacker rows, feed rows -> attacker drawer (event delegation)
  document.getElementById("attacker-list").addEventListener("click", (e) => {
    const row = e.target.closest("[data-ip]");
    if (row) openAttackerDrawer(row.dataset.ip);
  });
  document.getElementById("feed-list").addEventListener("click", (e) => {
    const row = e.target.closest("[data-ip]");
    if (row) openAttackerDrawer(row.dataset.ip);
  });

  // Command cloud -> command search drawer
  document.getElementById("command-cloud").addEventListener("click", (e) => {
    const item = e.target.closest("[data-command]");
    if (item) openCommandDrawer(item.dataset.command);
  });

  // Command-search results -> click an attacker to switch into attacker mode (bidirectional)
  drawerBody.addEventListener("click", (e) => {
    const row = e.target.closest(".drawer-attacker-row[data-ip]");
    if (row) openAttackerDrawer(row.dataset.ip);
  });

  // Drawer close affordances
  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  drawerScrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });

  // Search bar (debounced) + Enter for immediate search
  const searchInput = document.getElementById("search-input");
  let searchTimer = null;
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (q.length < 2) return;
    searchTimer = setTimeout(() => openCommandDrawer(q), 250);
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      clearTimeout(searchTimer);
      const q = searchInput.value.trim();
      if (q) openCommandDrawer(q);
    }
  });

  // Scroll cue -> analytics
  document.getElementById("scroll-cue").addEventListener("click", () => {
    document.getElementById("analytics").scrollIntoView({ behavior: "smooth" });
  });
}

/* ---------- websocket ---------- */

let ws = null;
let reconnectDelay = 1000;

function setWsStatus(connected) {
  document.getElementById("ws-dot").classList.toggle("connected", connected);
  document.getElementById("ws-text").textContent = connected ? "live" : "reconnecting…";
}

function connectWS() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${protocol}://${location.host}/ws`);

  ws.onopen = () => {
    setWsStatus(true);
    reconnectDelay = 1000;
  };
  ws.onclose = () => {
    setWsStatus(false);
    setTimeout(connectWS, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (msg) => {
    const payload = JSON.parse(msg.data);
    if (payload.type === "event") handleEvent(payload.data);
    else if (payload.type === "stats") handleStats(payload.data);
  };
}

function handleEvent(ev) {
  prependFeed(ev);
  addArc(ev);
}

function handleStats(stats) {
  document.getElementById("stat-total").textContent = compactNumber(stats.total_events);
  document.getElementById("stat-attackers").textContent = compactNumber(stats.unique_attackers);
  const lastBucket = stats.timeline[stats.timeline.length - 1];
  document.getElementById("stat-per-min").textContent = lastBucket ? lastBucket.count : 0;

  renderAttackerList(stats.top_attackers);
  renderCredentials(stats.top_credentials);
  renderCommands(stats.top_commands);
  renderGeo(stats.top_countries);
  renderTimeline(stats.timeline);
}

/* ---------- init ---------- */

async function applySnapshot(snapshot) {
  HONEYPOT = snapshot.honeypot;
  document.getElementById("honeypot-label").textContent = `→ ${HONEYPOT.label}`;
  HONEYPOT_POINT.lat = HONEYPOT.lat;
  HONEYPOT_POINT.lng = HONEYPOT.lon;

  world.pointOfView({ lat: HONEYPOT.lat, lng: HONEYPOT.lon, altitude: 2.2 }, 0);
  world.ringsData([{ lat: HONEYPOT.lat, lng: HONEYPOT.lon }]);
  refreshPoints();

  const feedList = document.getElementById("feed-list");
  feedList.innerHTML = snapshot.feed.map(feedRowHtml).join("");

  handleStats(snapshot);

  snapshot.feed
    .slice(0, 15)
    .reverse()
    .forEach((ev, i) => setTimeout(() => addArc(ev), i * 150));
}

async function init() {
  initGlobe();
  initCharts();
  renderLegend();
  wireInteractions();

  const snapshot = await fetch("/api/snapshot").then((r) => r.json());
  await applySnapshot(snapshot);

  connectWS();
}

document.addEventListener("DOMContentLoaded", init);
