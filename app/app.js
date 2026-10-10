import WebBleConnection from "./vendor/meshcore/connection/web_ble_connection.js";
import WebSerialConnection from "./vendor/meshcore/connection/web_serial_connection.js";
import Constants from "./vendor/meshcore/constants.js";

const DET_SVC = "4d575400-7f3a-4c1e-9b2d-6a1f0c0de001";
const DET_TX = "4d575401-7f3a-4c1e-9b2d-6a1f0c0de001";
const DET_RX = "4d575402-7f3a-4c1e-9b2d-6a1f0c0de001";

const CATS = [
  { key: "flock", name: "Flock" },
  { key: "raven", name: "Raven" },
  { key: "axon", name: "Axon" },
  { key: "tracker", name: "Trackers" },
  { key: "glasses", name: "Glasses" },
  { key: "deauth", name: "Deauth" },
  { key: "beacon", name: "Beacons" },
  { key: "meshcore", name: "MeshCore" },
  { key: "rogueap", name: "Rogue AP" },
  { key: "attack", name: "Attack" },
  { key: "skimmer", name: "Skimmer" },
  { key: "camera", name: "Cameras" },
  { key: "drone", name: "Drones" },
  { key: "canary", name: "Canary" },
];
const ACTIVE_MS = 60000;
const MAX_MSGS = 300;
const MAX_LOG = 500;
const MAX_TEXT_BYTES = 140;
const FWD_GAP_MS = 20000;       // spacing between forwarded alerts (airtime)
const FOLLOW_METERS = 500;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "style") n.style.cssText = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n[k] = v;
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
}

function load(key, fallback) {
  try {
    const v = localStorage.getItem("mw." + key);
    return v ? JSON.parse(v) : fallback;
  } catch {
    return fallback;
  }
}
function save(key, value) {
  try {
    localStorage.setItem("mw." + key, JSON.stringify(value));
  } catch { /* storage full or blocked: keep running in memory */ }
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const clock = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 90) return s + "s ago";
  if (s < 5400) return Math.round(s / 60) + "m ago";
  return Math.round(s / 3600) + "h ago";
}

let toastTimer;
function toast(text, alert = false) {
  const t = $("toast");
  t.textContent = text;
  t.className = alert ? "alert" : "";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), alert ? 6000 : 3500);
}

// ---------------------------------------------------------------- settings
const cfg = Object.assign(
  { fwdOn: false, fwdTo: "ch:0", fwdConf: 3, fwdCool: 10,
    fwdCats: ["flock", "raven", "axon", "deauth", "tracker"],
    geoOn: false, vibOn: true, hidden: ["beacon"] },
  load("cfg", {}));
const saveCfg = () => save("cfg", cfg);

// ------------------------------------------------------------------- radio
const radio = { conn: null, self: null, contacts: [], channels: [] };
const convs = load("convs", {});       // key -> { name, kind, msgs: [], unread }
let openKey = null;
const pendingAcks = new Map();          // expectedAckCrc -> message

// The library's request helpers share response listeners, so requests must
// not overlap. Everything goes through this queue.
let chain = Promise.resolve();
function radioOp(fn, ms = 10000) {
  const run = () => Promise.race([
    fn(),
    new Promise((_, rej) => setTimeout(() => rej(new Error("radio timed out")), ms)),
  ]);
  const p = chain.then(run, run);
  chain = p.catch(() => {});
  return p;
}

function setLink(id, state, info) {
  const b = $(id);
  b.classList.toggle("on", state === "on");
  b.classList.toggle("busy", state === "busy");
  b.querySelector("small").textContent = info;
}

async function connectRadio(e) {
  if (radio.conn) {
    await radio.conn.close();
    if (radio.conn) onRadioDown();
    return;
  }
  const useSerial = !navigator.bluetooth || (navigator.serial && e?.shiftKey);
  if (!navigator.bluetooth && !navigator.serial) {
    toast("This browser has no Web Bluetooth. Use Chrome or Edge (Android, desktop) or Bluefy on iOS.", true);
    return;
  }
  let conn;
  try {
    setLink("radioLink", "busy", "pairing");
    conn = useSerial ? await WebSerialConnection.open() : await WebBleConnection.open();
  } catch (e) {
    setLink("radioLink", "off", "connect");
    if (e.name !== "NotFoundError") toast("Radio: " + e.message, true);
    return;
  }
  if (!conn) return setLink("radioLink", "off", "connect");
  radio.conn = conn;
  conn.on("connected", onRadioUp);
  conn.on("disconnected", onRadioDown);
  conn.on(Constants.PushCodes.MsgWaiting, drainMessages);
  conn.on(Constants.PushCodes.SendConfirmed, ({ ackCode }) => {
    const m = pendingAcks.get(ackCode);
    if (!m) return;
    pendingAcks.delete(ackCode);
    m.state = "delivered";
    save("convs", convs);
    renderThread();
  });
}

async function onRadioUp() {
  const conn = radio.conn;
  setLink("radioLink", "busy", "syncing");
  try {
    radio.self = await radioOp(() => conn.getSelfInfo());
    await radioOp(() => conn.syncDeviceTime()).catch(() => {});
    radio.contacts = await radioOp(() => conn.getContacts(), 30000);
    radio.channels = [];
    for (let i = 0; i < 16; i++) {
      try {
        const ch = await radioOp(() => conn.getChannel(i), 3000);
        if (ch.name) radio.channels.push(ch);
      } catch {
        break;
      }
    }
    for (const ch of radio.channels) conv("ch:" + ch.channelIdx, ch.name, "channel");
    for (const c of radio.contacts) {
      if (c.type === Constants.AdvType.Chat || c.type === Constants.AdvType.Room) {
        conv("c:" + hex(c.publicKey.slice(0, 6)), c.advName || "(unnamed)", "contact");
      }
    }
    const mhz = (radio.self.radioFreq / 1000).toFixed(3);
    setLink("radioLink", "on", `${radio.self.name} · ${mhz} MHz`);
    renderConvs();
    renderForwardTargets();
    await drainMessages();
  } catch (e) {
    toast("Radio sync failed: " + (e?.message || "no response"), true);
    setLink("radioLink", "on", "connected, sync failed");
  }
}

function onRadioDown() {
  radio.conn = null;
  radio.self = null;
  setLink("radioLink", "off", "connect");
  renderThread();
}

function conv(key, name, kind) {
  const c = convs[key] || (convs[key] = { msgs: [], unread: 0 });
  if (name) c.name = name;
  if (kind) c.kind = kind;
  return c;
}

function addMsg(key, msg) {
  const c = conv(key);
  c.msgs.push(msg);
  if (c.msgs.length > MAX_MSGS) c.msgs.splice(0, c.msgs.length - MAX_MSGS);
  const visible = openKey === key && !$("tab-messages").hidden && !document.hidden;
  if (!msg.me && !visible) c.unread = (c.unread || 0) + 1;
  save("convs", convs);
  renderConvs();
  if (openKey === key) renderThread();
}

let draining = false;
async function drainMessages() {
  if (draining || !radio.conn) return;
  draining = true;
  try {
    for (;;) {
      const m = await radioOp(() => radio.conn.syncNextMessage());
      if (!m) break;
      if (m.contactMessage) {
        const key = "c:" + hex(m.contactMessage.pubKeyPrefix);
        if (!convs[key]) conv(key, key.slice(2), "contact");
        addMsg(key, { text: m.contactMessage.text, at: Date.now(), snr: m.contactMessage.snr });
      } else if (m.channelMessage) {
        const idx = m.channelMessage.channelIdx;
        const key = "ch:" + idx;
        if (!convs[key]) conv(key, "Channel " + idx, "channel");
        // Channel texts arrive as "Sender: text"
        const raw = m.channelMessage.text;
        const cut = raw.indexOf(": ");
        const from = cut > 0 && cut <= 32 ? raw.slice(0, cut) : null;
        addMsg(key, { from, text: from ? raw.slice(cut + 2) : raw, at: Date.now(),
                      snr: m.channelMessage.snr, hops: m.channelMessage.pathLen });
      }
    }
  } catch (e) {
    console.warn("message sync failed", e);
  } finally {
    draining = false;
  }
}

function clip(text) {
  let out = text;
  while (enc.encode(out).length > MAX_TEXT_BYTES) out = out.slice(0, -1);
  return out;
}

async function sendTo(key, text, alert = false) {
  if (!radio.conn) throw new Error("radio not connected");
  text = clip(text);
  const msg = { me: true, text, at: Date.now(), state: "sending", alert };
  addMsg(key, msg);
  try {
    if (key.startsWith("ch:")) {
      await radioOp(() => radio.conn.sendChannelTextMessage(Number(key.slice(3)), text));
      msg.state = "sent";
    } else {
      const contact = radio.contacts.find((c) => hex(c.publicKey.slice(0, 6)) === key.slice(2));
      if (!contact) throw new Error("contact is not on the radio");
      const res = await radioOp(() => radio.conn.sendTextMessage(contact.publicKey, text));
      msg.state = "sent";
      pendingAcks.set(res.expectedAckCrc, msg);
    }
  } catch (e) {
    msg.state = "failed";
    throw e;
  } finally {
    save("convs", convs);
    if (openKey === key) renderThread();
  }
}

// ---------------------------------------------------------------- messages UI
function renderConvs() {
  const box = $("convs");
  box.replaceChildren();
  let unread = 0;
  for (const [kind, title] of [["channel", "Channels"], ["contact", "Contacts"]]) {
    const keys = Object.keys(convs).filter((k) => convs[k].kind === kind);
    if (!keys.length) continue;
    keys.sort((a, b) => (convs[b].msgs.at(-1)?.at || 0) - (convs[a].msgs.at(-1)?.at || 0));
    box.append(el("h3", {}, title));
    for (const key of keys) {
      const c = convs[key];
      const last = c.msgs.at(-1);
      unread += c.unread || 0;
      box.append(el("button", { class: "conv" + (key === openKey ? " on" : ""), onclick: () => openConv(key) },
        el("span", { class: "avatar" }, kind === "channel" ? "#" : (c.name || "?").slice(0, 1).toUpperCase()),
        el("span", { class: "who" },
          el("div", {}, c.name || key),
          el("small", {}, last ? (last.me ? "You: " : last.from ? last.from + ": " : "") + last.text : "No messages yet")),
        c.unread ? el("span", { class: "badge" }, String(c.unread)) : null));
    }
  }
  if (!box.children.length) {
    box.append(el("div", { class: "empty" }, el("b", {}, "No radio connected"),
      "Tap Radio above to pair your MeshCore companion radio over Bluetooth. Shift-click to use USB serial instead."));
  }
  $("unreadBadge").hidden = !unread;
  $("unreadBadge").textContent = unread;
}

function openConv(key) {
  openKey = key;
  if (key) convs[key].unread = 0;
  save("convs", convs);
  $("tab-messages").classList.toggle("open", !!key);
  renderConvs();
  renderThread(true);
}

function renderThread(jump = false) {
  const c = openKey && convs[openKey];
  $("threadEmpty").hidden = !!c;
  $("threadHead").hidden = $("msgs").hidden = $("sendForm").hidden = !c;
  if (!c) return;
  $("threadName").textContent = (c.kind === "channel" ? "# " : "") + (c.name || openKey);
  $("threadSub").textContent = c.kind === "channel" ? "channel" : "direct";
  const box = $("msgs");
  const pinned = jump || box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  box.replaceChildren();
  for (const m of c.msgs) {
    let meta = clock(m.at);
    if (m.me) meta += " · " + m.state;
    else {
      if (m.hops != null && m.hops !== 255) meta += ` · ${m.hops} hop${m.hops === 1 ? "" : "s"}`;
      if (m.snr != null) meta += ` · SNR ${m.snr}`;
    }
    box.append(el("div", { class: "msg" + (m.me ? " me" : "") + (m.alert ? " alert" : "") + (m.state === "failed" ? " failed" : "") },
      m.from ? el("div", { class: "from" }, m.from) : null,
      el("div", {}, m.text),
      el("div", { class: "meta" }, meta)));
  }
  if (pinned) box.scrollTop = box.scrollHeight;
  $("sendBtn").disabled = !radio.conn;
  $("sendText").placeholder = radio.conn ? "Message" : "Radio not connected";
}

$("sendForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("sendText").value.trim();
  if (!text || !openKey) return;
  $("sendText").value = "";
  try {
    await sendTo(openKey, text);
  } catch (err) {
    toast("Not sent: " + (err?.message || "radio rejected the message"), true);
  }
});
$("back").addEventListener("click", () => openConv(null));

// ---------------------------------------------------------------- detector
const det = { device: null, rx: null, status: null, buf: "" };
const log = load("log", {});            // "cat|mac" -> detection record
const lastFwd = load("fwd", {});        // "cat|mac" -> ms
const fwdQueue = [];
let geo = null;
let unseenThreats = 0;

async function connectDetector() {
  if (det.device) return det.device.gatt.disconnect();
  if (!navigator.bluetooth) {
    toast("This browser has no Web Bluetooth. Use Chrome or Edge (Android, desktop) or Bluefy on iOS.", true);
    return;
  }
  try {
    setLink("detLink", "busy", "pairing");
    const device = await navigator.bluetooth.requestDevice({ filters: [{ services: [DET_SVC] }] });
    device.addEventListener("gattserverdisconnected", () => {
      det.device = det.rx = det.status = null;
      setLink("detLink", "off", "connect");
      renderDetections();
    });
    const gatt = await device.gatt.connect();
    const svc = await gatt.getPrimaryService(DET_SVC);
    const tx = await svc.getCharacteristic(DET_TX);
    det.rx = await svc.getCharacteristic(DET_RX);
    det.buf = "";
    tx.addEventListener("characteristicvaluechanged", (e) => onDetBytes(e.target.value));
    await tx.startNotifications();
    det.device = device;
    setLink("detLink", "on", device.name || "connected");
    await detCmd("list");
  } catch (e) {
    det.device = null;
    setLink("detLink", "off", "connect");
    if (e.name !== "NotFoundError") toast("Detector: " + e.message, true);
  }
}

async function detCmd(cmd) {
  if (!det.rx) return;
  try {
    await det.rx.writeValue(enc.encode(cmd));
  } catch (e) {
    console.warn("detector command failed", e);
  }
}

const dec = new TextDecoder();
function onDetBytes(view) {
  det.buf += dec.decode(view, { stream: true });
  let nl;
  while ((nl = det.buf.indexOf("\n")) >= 0) {
    const line = det.buf.slice(0, nl).trim();
    det.buf = det.buf.slice(nl + 1);
    if (!line) continue;
    try {
      onDetEvent(JSON.parse(line));
    } catch {
      console.warn("bad line from detector", line);
    }
  }
}

function meters(a, b) {
  const rad = Math.PI / 180;
  const x = (b.lon - a.lon) * rad * Math.cos(((a.lat + b.lat) / 2) * rad);
  const y = (b.lat - a.lat) * rad;
  return Math.hypot(x, y) * 6371000;
}

function onDetEvent(ev) {
  if (ev.t === "st") {
    const wasDemo = det.status?.demo;
    det.status = ev;
    $("muteOn").checked = !!ev.mute;
    if (ev.demo && !wasDemo) toast("Emulator ON — these detections are simulated", true);
    return renderDetections();
  }
  if (ev.t === "demo") {
    if (ev.on) toast("Emulator ON — these detections are simulated", true);
    return;
  }
  if (ev.t === "convoy") {
    toast(`CONVOY — ${ev.n} units may be tailing you`, true);
    if (cfg.vibOn && navigator.vibrate) navigator.vibrate([200, 80, 200, 80, 200]);
    if ($("tab-detections").hidden) unseenThreats++;
    return;
  }
  if (ev.t !== "det") return;
  const key = ev.cat + "|" + ev.mac;
  const last = Date.now() - ev.age * 1000;
  const r = log[key] || (log[key] = { cat: ev.cat, mac: ev.mac, first: last - ev.dur * 1000 });
  Object.assign(r, { lbl: ev.lbl, m: ev.m, rssi: ev.rssi, pk: Math.max(ev.pk, r.pk ?? -127),
                     conf: Math.max(ev.conf, r.conf || 0), d: ev.d || r.d, last,
                     persist: !!ev.persist || !!r.persist, rot: !!ev.rot || !!r.rot });
  if (geo && ev.age < 10) {
    r.pos = geo;
    r.pos0 = r.pos0 || geo;
    if (r.cat === "tracker" && !r.moving && meters(r.pos0, geo) > FOLLOW_METERS) r.moving = true;
  }
  trimLog();
  save("log", log);

  const following = r.cat === "tracker" && (r.persist || r.moving);
  const threat = r.cat === "tracker" ? following : !["beacon", "meshcore"].includes(r.cat) && r.conf >= 3;
  if (ev.ev !== "list" && threat && !r.alerted) {
    r.alerted = true;
    toast(`${following ? "Tracker may be following you" : r.lbl} · ${r.rssi} dBm`, true);
    if (cfg.vibOn && navigator.vibrate) navigator.vibrate([120, 60, 120]);
    if ($("tab-detections").hidden) unseenThreats++;
  }
  if (ev.ev !== "list") maybeForward(key, r, following);
  renderDetections();
}

function trimLog() {
  const keys = Object.keys(log);
  if (keys.length <= MAX_LOG) return;
  keys.sort((a, b) => log[a].last - log[b].last);
  for (const k of keys.slice(0, keys.length - MAX_LOG)) delete log[k];
}

function maybeForward(key, r, following) {
  if (!cfg.fwdOn || !radio.conn || !cfg.fwdCats.includes(r.cat)) return;
  if (r.cat === "tracker" ? !following : r.conf < cfg.fwdConf) return;
  if (Date.now() - (lastFwd[key] || 0) < cfg.fwdCool * 60000) return;
  lastFwd[key] = Date.now();
  save("fwd", lastFwd);
  let text = `[MW] ${following ? "Tracker following? " + r.lbl : r.lbl} c${r.conf} ${r.rssi}dBm ${r.mac}`;
  if (r.d && r.cat !== "tracker") text += " " + r.d.slice(0, 24);
  if (cfg.geoOn && r.pos) text += ` @${r.pos.lat.toFixed(5)},${r.pos.lon.toFixed(5)}`;
  fwdQueue.push(text);
}

setInterval(async () => {
  if (!fwdQueue.length || !radio.conn) return;
  const text = fwdQueue.shift();
  try {
    await sendTo(cfg.fwdTo, text, true);
  } catch (e) {
    toast("Alert not forwarded: " + (e?.message || "radio rejected it"), true);
  }
}, FWD_GAP_MS);

// --------------------------------------------------------------- detections UI
function renderDetections() {
  const now = Date.now();
  const records = Object.values(log);
  const tiles = $("tiles");
  tiles.replaceChildren();
  for (const c of CATS) {
    const n = records.filter((r) => r.cat === c.key && now - r.last < ACTIVE_MS).length;
    tiles.append(el("button", {
      class: "tile" + (cfg.hidden.includes(c.key) ? " off" : ""), style: `--c: var(--${c.key})`,
      title: "Show or hide " + c.name,
      onclick: () => {
        cfg.hidden = cfg.hidden.includes(c.key) ? cfg.hidden.filter((k) => k !== c.key) : [...cfg.hidden, c.key];
        saveCfg();
        renderDetections();
      },
    }, el("b", {}, String(n)), el("small", {}, c.name)));
  }

  const s = det.status;
  $("detStat").textContent = s
    ? `detector fw ${s.fw} · battery ${s.bat}% · up ${Math.round(s.up / 60)} min · ${s.mute ? "muted" : "sound on"}`
    : det.device ? "Waiting for detector status..." : "Detector not connected. Showing saved log.";

  const shown = records.filter((r) => !cfg.hidden.includes(r.cat)).sort((a, b) => b.last - a.last).slice(0, 150);
  const list = $("detList");
  list.replaceChildren();
  for (const r of shown) {
    const conf = el("span", { class: "conf", title: `confidence ${r.conf}/4` });
    for (let i = 1; i <= 4; i++) conf.append(el("i", { class: i <= r.conf ? "f" : "" }));
    const following = r.cat === "tracker" && (r.persist || r.moving);
    const sub = [r.mac, r.m, r.d, `peak ${r.pk} dBm`, `first ${clock(r.first)}`, ago(r.last)];
    if (r.pos) sub.push(`${r.pos.lat.toFixed(5)},${r.pos.lon.toFixed(5)}`);
    list.append(el("div", { class: "det" + (now - r.last > ACTIVE_MS ? " stale" : ""), style: `--c: var(--${r.cat})` },
      el("div", { class: "lbl" }, r.lbl, el("em", {}, r.cat.toUpperCase()), conf),
      el("div", { class: "rssi" }, r.rssi + " dBm"),
      following ? el("div", { class: "sub flag" }, r.moving ? "Seen in places over 500 m apart: may be travelling with you"
                                                              : "In range for 10+ minutes") : null,
      el("div", { class: "sub" }, sub.filter(Boolean).join(" · "))));
  }
  $("detEmpty").hidden = shown.length > 0;
  $("threatBadge").hidden = !unseenThreats;
  $("threatBadge").textContent = unseenThreats;
}
setInterval(() => { if (!$("tab-detections").hidden) renderDetections(); }, 5000);

// ---------------------------------------------------------------- settings UI
function renderForwardTargets() {
  const sel = $("fwdTo");
  sel.replaceChildren();
  for (const [key, c] of Object.entries(convs)) {
    sel.append(el("option", { value: key }, (c.kind === "channel" ? "# " : "") + (c.name || key)));
  }
  if (!sel.children.length) sel.append(el("option", { value: cfg.fwdTo }, "Connect the radio first"));
  sel.value = cfg.fwdTo;
  if (sel.value !== cfg.fwdTo) sel.selectedIndex = 0;
}

function renderForwardCats() {
  const box = $("fwdCats");
  box.replaceChildren();
  for (const c of CATS.filter((c) => c.key !== "beacon" && c.key !== "meshcore")) {
    box.append(el("button", {
      class: "chip" + (cfg.fwdCats.includes(c.key) ? " on" : ""), style: `--c: var(--${c.key})`,
      onclick: () => {
        cfg.fwdCats = cfg.fwdCats.includes(c.key) ? cfg.fwdCats.filter((k) => k !== c.key) : [...cfg.fwdCats, c.key];
        saveCfg();
        renderForwardCats();
      },
    }, c.name));
  }
}

let geoWatch = null;
function applyGeo() {
  if (geoWatch != null) navigator.geolocation.clearWatch(geoWatch);
  geoWatch = null;
  geo = null;
  if (!cfg.geoOn || !navigator.geolocation) return;
  geoWatch = navigator.geolocation.watchPosition(
    (p) => (geo = { lat: p.coords.latitude, lon: p.coords.longitude }),
    (e) => {
      toast("Location unavailable: " + e.message, true);
      cfg.geoOn = false;
      $("geoOn").checked = false;
      saveCfg();
    },
    { enableHighAccuracy: true, maximumAge: 10000 });
}

function bindCheck(id, key, after) {
  $(id).checked = !!cfg[key];
  $(id).addEventListener("change", (e) => {
    cfg[key] = e.target.checked;
    saveCfg();
    after?.();
  });
}
bindCheck("fwdOn", "fwdOn");
bindCheck("geoOn", "geoOn", applyGeo);
bindCheck("vibOn", "vibOn");
$("fwdConf").value = cfg.fwdConf;
$("fwdConf").addEventListener("change", (e) => { cfg.fwdConf = Number(e.target.value); saveCfg(); });
$("fwdCool").value = cfg.fwdCool;
$("fwdCool").addEventListener("change", (e) => { cfg.fwdCool = Math.max(1, Number(e.target.value) || 10); saveCfg(); });
$("fwdTo").addEventListener("change", (e) => { cfg.fwdTo = e.target.value; saveCfg(); });
$("muteOn").addEventListener("change", (e) => detCmd(e.target.checked ? "mute 1" : "mute 0"));

$("canarySsid").value = cfg.canary || "";
$("canarySet").addEventListener("click", async () => {
  const name = $("canarySsid").value.trim();
  if (!name) return toast("Enter a bait name first", true);
  if (!det.rx) return toast("Connect the detector first", true);
  cfg.canary = name; saveCfg();
  await detCmd("canary " + name);
  toast("Canary armed: " + name);
});
$("canaryClear").addEventListener("click", async () => {
  cfg.canary = ""; saveCfg();
  $("canarySsid").value = "";
  await detCmd("canary");
  toast("Canary disarmed");
});

$("exportLog").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(Object.values(log), null, 1));
    toast("Detection log copied");
  } catch {
    toast("Clipboard blocked by the browser", true);
  }
});
$("clearLog").addEventListener("click", () => {
  for (const k of Object.keys(log)) delete log[k];
  save("log", log);
  detCmd("clear");
  renderDetections();
  toast("Detection log cleared");
});
$("clearMsgs").addEventListener("click", () => {
  for (const c of Object.values(convs)) { c.msgs = []; c.unread = 0; }
  save("convs", convs);
  renderConvs();
  renderThread();
  toast("Message history cleared");
});

// --------------------------------------------------------------------- shell
for (const b of document.querySelectorAll("nav button")) {
  b.addEventListener("click", () => {
    for (const o of document.querySelectorAll("nav button")) o.classList.toggle("on", o === b);
    for (const name of ["messages", "detections", "settings"]) $("tab-" + name).hidden = name !== b.dataset.tab;
    if (b.dataset.tab === "detections") { unseenThreats = 0; renderDetections(); }
    if (b.dataset.tab === "settings") renderForwardTargets();
    if (b.dataset.tab === "messages" && openKey) openConv(openKey);
  });
}
$("radioLink").addEventListener("click", connectRadio);
$("detLink").addEventListener("click", connectDetector);

renderConvs();
renderThread();
renderDetections();
renderForwardTargets();
renderForwardCats();
applyGeo();
