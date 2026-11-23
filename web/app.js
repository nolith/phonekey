// phonekey approval app. The page asks the passkey for a PRF output, derives
// an ed25519 key from it, signs what the user approves, and forgets the key
// (unless a grant keeps it for a few seconds).

import { authorizedKey, b64url, enc, fingerprint, fromB64, fromB64url, sshsigSign, text } from "./sshsig.js";
import { chooseImpl, deriveSeed, onWebCryptoFallback, selfTest } from "./ed25519.js";

const $ = (id) => document.getElementById(id);

const state = {
  config: null,
  pending: [],
  selected: new Set(),
  highlight: new URLSearchParams(location.search).get("req"),
  impl: null,
  grant: null,
  events: null,
};

// Small DOM helper: never builds HTML from strings, so request content can't
// inject markup.
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k in el && typeof v !== "string") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

function show(id, visible) {
  $(id).hidden = !visible;
}

function setError(err) {
  const msg = err ? String(err.message ?? err) : "";
  $("error").textContent = msg;
  show("error", !!msg);
  if (err) console.error(err);
}

function pref(key, fallback) {
  try {
    return localStorage.getItem("phonekey." + key) ?? fallback;
  } catch {
    return fallback;
  }
}

function setPref(key, value) {
  try {
    localStorage.setItem("phonekey." + key, value);
  } catch {}
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error || msg;
    } catch {}
    const e = new Error(msg);
    e.status = res.status;
    throw e;
  }
  return res.status === 204 || res.status === 202 ? null : res.json();
}

// Passkey + PRF

function rpId() {
  return state.config.rp_id || location.hostname;
}

function salt() {
  return enc.encode(state.config.salt);
}

function random(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function prfResult(cred) {
  const r = cred.getClientExtensionResults().prf;
  return r?.results?.first ? new Uint8Array(r.results.first) : null;
}

// getPRF asks an existing passkey for its PRF output. allow restricts the
// picker to registered credentials when we know them.
async function getPRF(allow = []) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId: rpId(),
      userVerification: "required",
      allowCredentials: allow.map((id) => ({ type: "public-key", id: fromB64url(id) })),
      extensions: { prf: { eval: { first: salt() } } },
    },
  });
  const prf = prfResult(cred);
  if (!prf) throw new Error("This passkey didn't return a PRF result. The provider may not support the PRF extension.");
  return { prf, credentialId: b64url(new Uint8Array(cred.rawId)) };
}

async function createPRF(label) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId(), name: state.config.rp_name },
      user: { id: random(16), name: label, displayName: label },
      challenge: random(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salt() } } },
    },
  });
  const credentialId = b64url(new Uint8Array(cred.rawId));
  const ext = cred.getClientExtensionResults().prf;
  if (!ext?.enabled && !ext?.results) {
    throw new Error("The passkey was created but the provider doesn't support the PRF extension.");
  }
  // Some providers only evaluate PRF on get(); that costs a second prompt.
  const prf = prfResult(cred);
  if (prf) return { prf, credentialId };
  return getPRF([credentialId]);
}

async function keyFromPRF(prf) {
  const seed = await deriveSeed(prf, state.config.hkdf_info);
  const key = await state.impl.fromSeed(seed);
  seed.fill(0);
  prf.fill(0);
  key.authorized = authorizedKey(key.pub);
  key.fingerprint = await fingerprint(key.pub);
  return key;
}

async function unlock() {
  const allow = (state.config.keys || []).map((k) => k.credential_id).filter(Boolean);
  const { prf, credentialId } = await getPRF(allow);
  const key = await keyFromPRF(prf);
  key.credentialId = credentialId;
  return key;
}

async function signedNonce(key) {
  const { nonce } = await api("POST", "/api/web/nonce", {});
  const sig = await key.sign(enc.encode("phonekey-auth-v1\n" + nonce));
  return { nonce, signature: btoaBytes(sig) };
}

function btoaBytes(bytes) {
  let s = "";
  for (const c of bytes) s += String.fromCharCode(c);
  return btoa(s);
}

// Flows

async function pair(create) {
  const code = $("pair-code").value.trim();
  const label = $("pair-label").value.trim() || "passkey";
  if (!code && !state.config.logged_in) throw new Error("Enter the pairing code from `phonekeyd pair-code`.");
  const { prf, credentialId } = create ? await createPRF(label) : await getPRF();
  const key = await keyFromPRF(prf);
  await api("POST", "/api/web/pair", {
    code,
    label,
    public_key: key.authorized,
    credential_id: credentialId,
    ...(await signedNonce(key)),
  });
  $("paired-key-text").textContent = key.authorized + " " + label.replace(/\s+/g, "_");
  await loadConfig();
  render();
  show("pair", false);
  show("paired-key", true);
}

async function login() {
  const key = await unlock();
  await api("POST", "/api/web/login", { public_key: key.authorized, ...(await signedNonce(key)) });
  await loadConfig();
  render();
}

function signable(req, key) {
  if (req.public_key !== key.authorized) {
    return `This request is for ${req.fingerprint}, but the passkey you used derives ${key.fingerprint}.`;
  }
  const data = fromB64(req.data);
  if (text(data.slice(0, 13)) === "phonekey-auth") return "Refusing to sign a login message.";
  if (req.details.kind !== "userauth" && req.details.kind !== "sshsig") return "Refusing to sign unrecognized data.";
  return null;
}

async function signRequest(req, key, grant = false) {
  const problem = signable(req, key);
  if (problem) throw new Error(problem);
  const sig = await key.sign(fromB64(req.data));
  await api("POST", `/api/web/requests/${req.id}/signature`, { signature: btoaBytes(sig), grant });
}

async function approve() {
  const reqs = state.pending.filter((r) => state.selected.has(r.id));
  if (!reqs.length) return;
  const key = await unlock();
  const errors = [];
  for (const r of reqs) {
    try {
      await signRequest(r, key);
      state.selected.delete(r.id);
    } catch (e) {
      errors.push(`${r.summary}: ${e.message}`);
    }
  }
  const seconds = grantSeconds();
  const scopes = reqs.map((r) => r.context.scope).filter(Boolean);
  if (seconds > 0 && scopes.length && !errors.length) startGrant(key, scopes, seconds, reqs.map((r) => r.id));
  if (errors.length) throw new Error(errors.join("\n"));
}

async function deny() {
  const ids = [...state.selected];
  for (const id of ids) {
    await api("POST", `/api/web/requests/${id}/deny`, {});
    state.selected.delete(id);
  }
}

// Grants: keep the derived key in memory briefly and sign requests from the
// same process tree as they arrive. Ends on timeout, when the page is hidden,
// or when the user taps End.

function grantSeconds() {
  const max = state.config?.max_grant_seconds ?? 0;
  return Math.min(Number(pref("grant", "30")), max);
}

// done lists requests already signed, which the pending list may still show
// until the next event arrives.
function startGrant(key, scopes, seconds, done) {
  endGrant();
  const g = { key, scopes: new Set(scopes), until: Date.now() + seconds * 1000, signed: [], busy: new Set(done) };
  g.timer = setInterval(() => (Date.now() >= g.until ? endGrant() : renderGrant()), 500);
  state.grant = g;
  renderGrant();
  runGrant();
}

function endGrant() {
  const g = state.grant;
  if (!g) return;
  clearInterval(g.timer);
  g.key = null;
  state.grant = null;
  renderGrant();
}

async function runGrant() {
  const g = state.grant;
  if (!g) return;
  for (const r of state.pending) {
    if (state.grant !== g || Date.now() >= g.until) return;
    if (!g.scopes.has(r.context.scope) || g.busy.has(r.id) || signable(r, g.key)) continue;
    g.busy.add(r.id);
    try {
      await signRequest(r, g.key, true);
      g.signed.push(r.summary);
      renderGrant();
    } catch (e) {
      setError(e);
    }
  }
}

function renderGrant() {
  const g = state.grant;
  show("grant", !!g);
  if (!g) return;
  const left = Math.max(0, Math.ceil((g.until - Date.now()) / 1000));
  const signed = g.signed.length ? ` · signed ${g.signed.length}: ${g.signed.join("; ")}` : "";
  $("grant-info").textContent = `${left}s left, same process tree only${signed}`;
}

// Live updates

function connectEvents() {
  if (state.events) state.events.close();
  const es = new EventSource("/api/web/events");
  state.events = es;
  es.addEventListener("requests", (ev) => {
    $("conn").textContent = "live";
    state.pending = JSON.parse(ev.data);
    const ids = new Set(state.pending.map((r) => r.id));
    for (const id of state.selected) if (!ids.has(id)) state.selected.delete(id);
    // Preselect arrivals only when nothing else was pending, so a request
    // that shows up while the user is about to approve another one isn't
    // swept into the same approval.
    const nothingWasPending = !state.seen?.size;
    for (const r of state.pending) {
      if (!state.seen?.has(r.id) && (nothingWasPending || r.id === state.highlight)) state.selected.add(r.id);
    }
    state.seen = ids;
    renderRequests();
    runGrant();
    closeNotifications(ids);
  });
  es.onerror = () => {
    $("conn").textContent = "reconnecting…";
  };
}

async function closeNotifications(live) {
  const reg = await navigator.serviceWorker?.getRegistration();
  if (!reg) return;
  for (const n of await reg.getNotifications()) {
    if (n.tag && !live.has(n.tag)) n.close();
  }
}

// Push

async function enablePush() {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    throw new Error("Push isn't available here. On iOS, add phonekey to the Home Screen and open it from there.");
  }
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error(`Notification permission: ${perm}`);
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: fromB64url(state.config.vapid_public_key),
    });
  }
  await api("POST", "/api/web/push/subscribe", sub.toJSON());
  await renderPushState();
}

async function renderPushState() {
  let s = "Not supported in this context.";
  if ("serviceWorker" in navigator && "PushManager" in window) {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = await reg?.pushManager.getSubscription();
    s = `Permission: ${Notification.permission}. ${sub ? "Subscribed on this device." : "Not subscribed on this device."}`;
  }
  $("push-state").textContent = s;
}

// Rendering

function kv(pairs) {
  const items = pairs.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length));
  if (!items.length) return null;
  return h("dl", { class: "kv" }, items.map(([k, v]) => [h("dt", {}, k), h("dd", {}, Array.isArray(v) ? v.join(", ") : v)]));
}

function keyLabel(fp) {
  const k = (state.config.keys || []).find((k) => k.fingerprint === fp);
  return k ? `${k.label} (${fp})` : fp;
}

function renderDetails(r) {
  const d = r.details;
  if (d.kind === "userauth") {
    return kv([
      ["Type", "SSH login"],
      ["User", d.user],
      ["Service", d.service],
      ["Method", d.method],
      ["Server key", d.host_key_fingerprint],
      ["Key", keyLabel(r.fingerprint)],
    ]);
  }
  if (d.kind === "sshsig") {
    return kv([
      ["Type", "File signature (SSHSIG)"],
      ["Namespace", d.namespace],
      ["Hash", `${d.hash_algorithm}:${d.hash.slice(0, 16)}…`],
      ["Key", keyLabel(r.fingerprint)],
    ]);
  }
  return kv([["Type", `unrecognized, ${d.length} bytes`]]);
}

function renderContext(c) {
  const sb = c.session_bind;
  const g = c.git_object;
  const chain = (c.processes || []).map((p) => p.command).join(" ← ");
  const parts = [
    kv([
      ["Dev box", c.host],
      ["Action", c.action],
      ["Remote", c.remote],
      ["Server", sb && (sb.host_names?.length ? sb.host_names : "unknown host")],
      ["Server key", sb?.host_key_fingerprint],
      ["Forwarded", sb?.forwarding ? "yes, via a forwarded agent" : null],
      ["Processes", chain],
    ]),
  ];
  if (g) {
    parts.push(
      kv([
        [g.type === "tag" ? "Tag" : "Commit", g.subject],
        ["Tag name", g.tag],
        ["Author", g.author],
        ["Committer", g.committer !== g.author ? g.committer : null],
        ["Tagger", g.tagger],
        ["Parents", g.parents > 1 ? String(g.parents) : null],
      ]),
    );
    if (g.body) parts.push(h("pre", { class: "commit-body" }, g.body));
  }
  return h("div", { class: "unverified" }, h("div", { class: "block-label" }, "Dev box says (not verified)"), parts);
}

function renderRequests() {
  const list = $("request-list");
  list.replaceChildren();
  const now = Date.now() / 1000;
  for (const r of state.pending) {
    const left = Math.max(0, Math.round(r.expires_at - now));
    const checkbox = h("input", {
      type: "checkbox",
      checked: state.selected.has(r.id),
      "aria-label": "Select",
      onchange: (e) => {
        e.target.checked ? state.selected.add(r.id) : state.selected.delete(r.id);
        renderActions();
      },
    });
    list.append(
      h(
        "li",
        { class: "card" + (r.id === state.highlight ? " highlight" : "") },
        h(
          "div",
          { class: "card-head" },
          checkbox,
          h("div", {}, h("div", { class: "card-title" }, r.summary), h("div", { class: "card-meta", "data-expires": r.expires_at }, `${r.devbox} · ${left}s left`)),
        ),
        h("div", { class: "block-label" }, "Signed data"),
        renderDetails(r),
        renderContext(r.context),
      ),
    );
  }
  show("empty", !state.pending.length);
  renderActions();
}

function renderActions() {
  const n = state.pending.filter((r) => state.selected.has(r.id)).length;
  show("actions", state.pending.length > 0);
  $("approve").textContent = n > 1 ? `Approve ${n}` : "Approve";
  $("deny").textContent = n > 1 ? `Deny ${n}` : "Deny";
  $("approve").disabled = $("deny").disabled = n === 0;
}

function tickCountdowns() {
  const now = Date.now() / 1000;
  for (const el of document.querySelectorAll("[data-expires]")) {
    const left = Math.max(0, Math.round(Number(el.dataset.expires) - now));
    el.textContent = el.textContent.replace(/\d+s left$/, `${left}s left`);
  }
}

function renderKeys() {
  $("keys").replaceChildren(
    ...(state.config.keys || []).map((k) => h("li", {}, h("strong", {}, k.label), " ", h("code", {}, k.fingerprint))),
  );
}

function renderGrantOptions() {
  const sel = $("grant-seconds");
  const max = state.config.max_grant_seconds;
  const opts = [0, 15, 30, 60, 120].filter((s) => s <= max);
  sel.replaceChildren(...opts.map((s) => h("option", { value: String(s) }, s ? `${s} seconds` : "Off")));
  sel.value = String(grantSeconds());
  sel.disabled = max === 0;
}

async function renderHistory() {
  if (!state.config.logged_in) return;
  const items = await api("GET", "/api/web/history");
  $("history").replaceChildren(
    ...items.map((r) =>
      h(
        "li",
        {},
        h("span", { class: "st" }, r.status + (r.via_grant ? " (grant)" : "")),
        r.summary,
        h("div", { class: "card-meta" }, `${r.devbox} · ${new Date(r.created_at * 1000).toLocaleString()}`),
      ),
    ),
  );
}

function render() {
  const c = state.config;
  const loggedIn = c.logged_in;
  $("status").textContent = loggedIn ? `${(c.keys || []).length} key(s)` : "not logged in";
  show("pair", !loggedIn);
  show("requests", loggedIn);
  show("setup", loggedIn);
  show("history-section", loggedIn);
  $("pair-label").placeholder = /iPhone|iPad/.test(navigator.userAgent) ? "iPhone (iCloud Keychain)" : "passkey";
  if (loggedIn) {
    renderKeys();
    renderGrantOptions();
    renderPushState();
    if (!state.events) connectEvents();
  }
}

async function renderEnv() {
  const caps = (await PublicKeyCredential?.getClientCapabilities?.().catch(() => null)) || {};
  const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  const [wc, nb] = await Promise.all([selfTest("webcrypto"), selfTest("noble")]);
  const fmt = (t) => (t.ok ? "passes RFC 8032 vectors" : `fails: ${t.error}`);
  $("env").replaceChildren(
    ...[
      ["Origin", location.origin],
      ["RP ID", rpId()],
      ["PRF salt", state.config.salt],
      ["Home-screen app", standalone ? "yes" : "no"],
      ["PRF capability", caps["extension:prf"] === undefined ? "not reported" : String(caps["extension:prf"])],
      ["WebCrypto Ed25519", fmt(wc)],
      ["noble-ed25519", fmt(nb)],
      ["In use", state.impl.name],
      ["User agent", navigator.userAgent],
    ].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
  );
}

async function diagDerive() {
  const { prf } = await getPRF();
  const key = await keyFromPRF(prf);
  const out = $("diag-out");
  out.textContent = `${key.authorized}\n${key.fingerprint}\nimplementation: ${key.impl}`;
  out.hidden = false;
}

async function diagSign() {
  const { prf } = await getPRF();
  const key = await keyFromPRF(prf);
  const message = `phonekey test ${new Date().toISOString()}`;
  const armored = await sshsigSign(key.sign, key.pub, enc.encode(message), "phonekey-test");
  const out = $("diag-out");
  out.textContent = [
    "# Verify on any machine with OpenSSH:",
    `echo 'phonekey ${key.authorized}' > allowed_signers`,
    "cat > msg.sig <<'EOF'",
    armored.trimEnd(),
    "EOF",
    `printf '%s' '${message}' | ssh-keygen -Y verify -f allowed_signers -I phonekey -n phonekey-test -s msg.sig`,
    "",
    `# implementation: ${key.impl}`,
  ].join("\n");
  out.hidden = false;
}

// Wiring

function action(id, fn) {
  $(id).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err);
    } finally {
      btn.disabled = false;
      if (id === "approve" || id === "deny") renderActions();
    }
  });
}

async function loadConfig() {
  state.config = await api("GET", "/api/web/config");
}

async function main() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch((e) => console.warn("service worker", e));
  }
  onWebCryptoFallback(() => setError("WebCrypto produced an invalid Ed25519 signature; fell back to noble-ed25519 for it."));
  state.impl = await chooseImpl(pref("impl", "auto"));
  $("impl-pref").value = pref("impl", "auto");
  await loadConfig();
  render();
  renderEnv();

  action("pair-create", () => pair(true));
  action("pair-existing", () => pair(false));
  action("add-key", () => {
    show("pair", true);
    $("pair-code").value = "";
    $("pair-code").placeholder = "not needed while logged in";
  });
  action("login", login);
  action("approve", approve);
  action("deny", deny);
  action("grant-end", async () => endGrant());
  action("push-enable", enablePush);
  action("push-test", () => api("POST", "/api/web/push/test", {}));
  action("logout", async () => {
    await api("POST", "/api/web/logout", {});
    state.events?.close();
    state.events = null;
    await loadConfig();
    render();
  });
  action("paired-key-copy", () => navigator.clipboard.writeText($("paired-key-text").textContent));
  action("paired-key-done", async () => show("paired-key", false));
  action("diag-derive", diagDerive);
  action("diag-sign", diagSign);
  $("grant-seconds").addEventListener("change", (e) => setPref("grant", e.target.value));
  $("impl-pref").addEventListener("change", async (e) => {
    setPref("impl", e.target.value);
    state.impl = await chooseImpl(e.target.value);
    renderEnv();
  });
  $("history-details").addEventListener("toggle", (e) => e.target.open && renderHistory().catch(setError));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) endGrant();
  });
  setInterval(tickCountdowns, 1000);
}

main().catch(setError);
