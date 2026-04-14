use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::State,
    response::Html,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

// ── Constants ─────────────────────────────────────────────────────────────────

const PNET_ADDR_DEFAULT: &str = "127.0.0.1:7777";
const TOKEN_FILE: &str = "pnet_token.bin";
/// Port that pnet pushes received app packets to (registered with pnet).
const PUSH_PORT: u16 = 8888;
/// Port used for control requests (register, get-data) and their replies.
/// Separate from PUSH_PORT so the background push loop never races with replies.
const CTRL_PORT: u16 = 8889;
const HTTP_PORT: u16 = 3000;
const APP_ALIAS: &str = "deliverer";
const APP_PROTOCOL: &str = "text/plain";

// pnet op bytes
const OP_REGISTER: u8 = 0x00;
const OP_GET_DATA: u8 = 0x02;
const OP_SEND: u8 = 0x03;
const OP_PUSH: u8 = 0x04;
const STATUS_OK: u8 = 0x00;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
struct AppInfo {
    id: u16,
    alias: String,
    approved: bool,
}

#[derive(Clone, Debug, Serialize)]
struct Destination {
    device_uuid: Vec<u8>,
    app_id: u16,
    label: String,
}

#[derive(Clone, Debug, Serialize)]
struct Message {
    sender: String,
    text: String,
    timestamp: u64,
}

struct Inner {
    token: Option<[u8; 16]>,
    app_info: Option<AppInfo>,
    destinations: Vec<Destination>,
    /// sender_app_id → display label
    app_labels: HashMap<u16, String>,
    messages: Vec<Message>,
    last_fetch_ok: Option<u64>,
}

struct AppState {
    /// Receives op 0x04 pushes from pnet. Background loop owns this.
    push_socket: Arc<UdpSocket>,
    /// Sends registration/get-data/send requests; receives their replies.
    ctrl_socket: Arc<UdpSocket>,
    pnet_addr: SocketAddr,
    inner: Mutex<Inner>,
}

// ── Binary helpers ────────────────────────────────────────────────────────────

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let s = std::str::from_utf8(data.get(*pos..*pos + len)?).ok()?.to_string();
    *pos += len;
    Some(s)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_be_bytes(data.get(*pos..*pos + 2)?.try_into().ok()?);
    *pos += 2;
    Some(v)
}

fn read_bytes<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let arr: [u8; N] = data.get(*pos..*pos + N)?.try_into().ok()?;
    *pos += N;
    Some(arr)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── pnet protocol ─────────────────────────────────────────────────────────────

fn build_register() -> Vec<u8> {
    let mut buf = vec![OP_REGISTER];
    push_str(&mut buf, APP_ALIAS);
    buf.extend_from_slice(&PUSH_PORT.to_be_bytes()); // push delivery port
    push_str(&mut buf, APP_PROTOCOL);
    buf
}

fn build_get_data(token: &[u8; 16]) -> Vec<u8> {
    let mut buf = vec![OP_GET_DATA];
    buf.extend_from_slice(token);
    buf
}

fn build_send(token: &[u8; 16], dest_device_uuid: &[u8], dest_app_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_SEND];
    buf.extend_from_slice(token);
    buf.extend_from_slice(dest_device_uuid);
    buf.extend_from_slice(&dest_app_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Parse op 0x02 response and update shared state.
fn parse_get_data(reply: &[u8], inner: &mut Inner) {
    let mut pos = 1usize; // skip OK byte

    // App's own data.
    let Some(app_id) = read_u16(reply, &mut pos) else { return };
    let Some(alias) = read_str(reply, &mut pos) else { return };
    pos += 6; // ip(4) + port(2)
    let Some(&approved_byte) = reply.get(pos) else { return };
    pos += 1;
    pos += 16; // token
    let Some(local_device_uuid) = read_bytes::<16>(reply, &mut pos) else { return };

    inner.app_info = Some(AppInfo {
        id: app_id,
        alias,
        approved: approved_byte != 0,
    });

    // Owner alias + uuid.
    let Some(_owner_alias) = read_str(reply, &mut pos) else { return };
    pos += 16;

    let mut destinations: Vec<Destination> = Vec::new();
    let mut app_labels: HashMap<u16, String> = HashMap::new();

    // Own devices.
    let Some(&device_count) = reply.get(pos) else { return };
    pos += 1;
    for _ in 0..device_count {
        let Some(dev_uuid) = read_bytes::<16>(reply, &mut pos) else { return };
        let Some(dev_alias) = read_str(reply, &mut pos) else { return };
        pos += 1 + 1 + 4 + 2; // grade + sg_rank + ip + port
        let Some(&app_count) = reply.get(pos) else { return };
        pos += 1;
        for _ in 0..app_count {
            let Some(aid) = read_u16(reply, &mut pos) else { return };
            let Some(app_alias) = read_str(reply, &mut pos) else { return };
            pos += 4 + 2 + 1; // ip + port + user_approved
            let label = format!("{dev_alias} / {app_alias}");
            app_labels.insert(aid, label.clone());
            // Exclude only the specific app instance that is this deliverer
            // (same device AND same app ID).  App IDs are device-scoped, so
            // two devices can each have an app with id=1; comparing only the
            // numeric ID would incorrectly drop apps on other devices.
            if !(dev_uuid == local_device_uuid && aid == app_id) {
                destinations.push(Destination {
                    device_uuid: dev_uuid.to_vec(),
                    app_id: aid,
                    label,
                });
            }
        }
    }

    // Contacts.
    let Some(&contact_count) = reply.get(pos) else { return };
    pos += 1;
    for _ in 0..contact_count {
        let Some(contact_alias) = read_str(reply, &mut pos) else { return };
        pos += 16; // contact uuid
        let Some(&device_count) = reply.get(pos) else { return };
        pos += 1;
        for _ in 0..device_count {
            let Some(dev_uuid) = read_bytes::<16>(reply, &mut pos) else { return };
            let Some(dev_alias) = read_str(reply, &mut pos) else { return };
            pos += 1 + 1 + 4 + 2; // grade + sg_rank + ip + port
            let Some(&app_count) = reply.get(pos) else { return };
            pos += 1;
            for _ in 0..app_count {
                // Contact apps: only approved, no ip/port in response
                let Some(aid) = read_u16(reply, &mut pos) else { return };
                let Some(app_alias) = read_str(reply, &mut pos) else { return };
                let label = format!("{contact_alias} / {dev_alias} / {app_alias}");
                app_labels.insert(aid, label.clone());
                destinations.push(Destination {
                    device_uuid: dev_uuid.to_vec(),
                    app_id: aid,
                    label,
                });
            }
        }
    }

    inner.destinations = destinations;
    inner.app_labels = app_labels;
}

// ── Token persistence ─────────────────────────────────────────────────────────

fn load_token() -> Option<[u8; 16]> {
    let bytes = std::fs::read(TOKEN_FILE).ok()?;
    bytes.as_slice().try_into().ok()
}

fn save_token(token: &[u8; 16]) {
    if let Err(e) = std::fs::write(TOKEN_FILE, token) {
        eprintln!("[token] failed to save: {e}");
    }
}

// ── Registration ──────────────────────────────────────────────────────────────

async fn register(ctrl: &UdpSocket, pnet_addr: SocketAddr) -> Option<[u8; 16]> {
    ctrl.send_to(&build_register(), pnet_addr).await.ok()?;

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctrl.recv_from(&mut buf),
    )
    .await
    .ok()?
    .ok()?;

    let reply = &buf[..len];
    if reply.len() < 17 || reply[0] != STATUS_OK {
        eprintln!("[register] failed: {:?}", &reply[..reply.len().min(4)]);
        return None;
    }
    Some(reply[1..17].try_into().unwrap())
}

async fn fetch_data(ctrl: &UdpSocket, pnet_addr: SocketAddr, token: &[u8; 16], inner: &Mutex<Inner>) {
    if ctrl.send_to(&build_get_data(token), pnet_addr).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 4096];
    let Ok(Ok((len, _))) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctrl.recv_from(&mut buf),
    )
    .await
    else {
        eprintln!("[fetch_data] timeout or error");
        return;
    };

    let reply = &buf[..len];
    if reply.is_empty() || reply[0] != STATUS_OK {
        eprintln!("[fetch_data] bad reply: {:?}", &reply[..reply.len().min(4)]);
        return;
    }

    let mut guard = inner.lock().unwrap();
    parse_get_data(reply, &mut guard);
    if guard.app_info.is_some() {
        guard.last_fetch_ok = Some(now_secs());
    }
}

// ── UDP push receive loop ─────────────────────────────────────────────────────

async fn push_receive_loop(state: Arc<AppState>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _) = match state.push_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { eprintln!("[push_recv] {e}"); continue; }
        };

        let data = &buf[..len];
        if data.len() < 3 || data[0] != OP_PUSH {
            continue;
        }

        let sender_id = u16::from_be_bytes([data[1], data[2]]);
        let text = String::from_utf8_lossy(&data[3..]).into_owned();

        let mut inner = state.inner.lock().unwrap();
        let sender = inner.app_labels.get(&sender_id)
            .cloned()
            .unwrap_or_else(|| format!("app#{sender_id}"));
        eprintln!("[recv] from {sender}: {text}");
        inner.messages.push(Message { sender, text, timestamp: now_secs() });
    }
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

async fn handle_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Serialize)]
struct ApiState {
    approved: bool,
    app_info: Option<AppInfo>,
    destinations: Vec<Destination>,
    messages: Vec<Message>,
    last_fetch_ok: Option<u64>,
}

async fn handle_state(State(state): State<Arc<AppState>>) -> Json<ApiState> {
    let inner = state.inner.lock().unwrap();
    Json(ApiState {
        approved: inner.app_info.as_ref().map(|a| a.approved).unwrap_or(false),
        app_info: inner.app_info.clone(),
        destinations: inner.destinations.clone(),
        messages: inner.messages.clone(),
        last_fetch_ok: inner.last_fetch_ok,
    })
}

#[derive(Deserialize)]
struct SendRequest {
    dest_index: usize,
    text: String,
}

#[derive(Serialize)]
struct SendResponse {
    ok: bool,
    error: Option<String>,
}

async fn handle_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendRequest>,
) -> Json<SendResponse> {
    let (token, dest) = {
        let inner = state.inner.lock().unwrap();
        let Some(token) = inner.token else {
            return Json(SendResponse { ok: false, error: Some("not registered".into()) });
        };
        let Some(dest) = inner.destinations.get(req.dest_index).cloned() else {
            return Json(SendResponse { ok: false, error: Some("invalid destination index".into()) });
        };
        (token, dest)
    };

    let pkt = build_send(&token, &dest.device_uuid, dest.app_id, req.text.as_bytes());
    match state.ctrl_socket.send_to(&pkt, state.pnet_addr).await {
        Ok(_) => Json(SendResponse { ok: true, error: None }),
        Err(e) => Json(SendResponse { ok: false, error: Some(e.to_string()) }),
    }
}

async fn handle_refresh(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let token = state.inner.lock().unwrap().token;
    if let Some(token) = token {
        fetch_data(&state.ctrl_socket, state.pnet_addr, &token, &state.inner).await;
    }
    Json(serde_json::json!({ "ok": true }))
}

// ── Background data refresh loop ─────────────────────────────────────────────

async fn data_refresh_loop(state: Arc<AppState>) {
    loop {
        let connected = state.inner.lock().unwrap().app_info.is_some();
        let delay_secs = if connected { 30 } else { 5 };
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

        let token = state.inner.lock().unwrap().token;
        if let Some(token) = token {
            fetch_data(&state.ctrl_socket, state.pnet_addr, &token, &state.inner).await;
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let pnet_addr_str = std::env::var("PNET_ADDR").unwrap_or_else(|_| PNET_ADDR_DEFAULT.to_string());
    let pnet_addr: SocketAddr = pnet_addr_str.parse().expect("invalid PNET_ADDR");

    let push_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{PUSH_PORT}"))
            .await
            .expect("failed to bind push UDP socket"),
    );
    let ctrl_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{CTRL_PORT}"))
            .await
            .expect("failed to bind ctrl UDP socket"),
    );

    eprintln!("[startup] push port {PUSH_PORT}, ctrl port {CTRL_PORT}");

    const STARTUP_RETRIES: u32 = 4;
    const STARTUP_RETRY_DELAY_SECS: u64 = 2;

    // Try to reuse a saved token before registering fresh.
    let token = if let Some(saved) = load_token() {
        eprintln!("[startup] found saved token {}, verifying...", hex(&saved));
        let inner_tmp = Mutex::new(Inner {
            token: Some(saved),
            app_info: None,
            destinations: Vec::new(),
            app_labels: HashMap::new(),
            messages: Vec::new(),
            last_fetch_ok: None,
        });
        let mut verified = false;
        for attempt in 1..=STARTUP_RETRIES + 1 {
            fetch_data(&ctrl_socket, pnet_addr, &saved, &inner_tmp).await;
            if inner_tmp.lock().unwrap().app_info.is_some() {
                verified = true;
                break;
            }
            if attempt <= STARTUP_RETRIES {
                eprintln!("[startup] fetch attempt {attempt} failed, retrying in {STARTUP_RETRY_DELAY_SECS}s...");
                tokio::time::sleep(std::time::Duration::from_secs(STARTUP_RETRY_DELAY_SECS)).await;
            }
        }
        if verified {
            eprintln!("[startup] saved token is valid");
        } else {
            eprintln!("[startup] could not reach pnet — will keep retrying in background");
            eprintln!("[startup] if the token is invalid, delete {TOKEN_FILE} to re-register");
        }
        saved
    } else {
        eprintln!("[startup] no saved token, registering with pnet at {pnet_addr}...");
        match register(&ctrl_socket, pnet_addr).await {
            Some(t) => { save_token(&t); eprintln!("[startup] token = {}", hex(&t)); t }
            None => {
                eprintln!("[startup] registration failed — is pnet running on {pnet_addr}?");
                std::process::exit(1);
            }
        }
    };

    let state = Arc::new(AppState {
        push_socket,
        ctrl_socket,
        pnet_addr,
        inner: Mutex::new(Inner {
            token: Some(token),
            app_info: None,
            destinations: Vec::new(),
            app_labels: HashMap::new(),
            messages: Vec::new(),
            last_fetch_ok: None,
        }),
    });

    fetch_data(&state.ctrl_socket, pnet_addr, &token, &state.inner).await;

    let approved = state.inner.lock().unwrap().app_info.as_ref().map(|a| a.approved).unwrap_or(false);
    if approved {
        eprintln!("[startup] app is approved");
    } else {
        eprintln!("[startup] app is NOT approved — visit the pnet admin UI to approve it");
    }

    tokio::spawn(push_receive_loop(state.clone()));
    tokio::spawn(data_refresh_loop(state.clone()));

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/api/state", get(handle_state))
        .route("/api/send", post(handle_send))
        .route("/api/refresh", post(handle_refresh))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{HTTP_PORT}"))
        .await
        .expect("failed to bind HTTP port");

    eprintln!("[startup] HTTP UI at http://127.0.0.1:{HTTP_PORT}");
    axum::serve(listener, app).await.unwrap();
}

// ── Embedded HTML UI ──────────────────────────────────────────────────────────

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>pnet Deliverer</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; max-width: 800px; margin: 0 auto; }
    h1 { color: #7ec8e3; margin-bottom: 16px; }
    h2 { color: #a0c8a0; margin-bottom: 8px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
    .status { background: #2a2a2a; border: 1px solid #444; padding: 10px 14px; border-radius: 4px; margin-bottom: 20px; }
    .status.approved { border-color: #5a8a5a; }
    .status.pending  { border-color: #8a7a3a; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; margin-left: 8px; }
    .badge.ok   { background: #2a5a2a; color: #80e080; }
    .badge.warn { background: #5a4a1a; color: #e0c060; }
    .panel { background: #2a2a2a; border: 1px solid #444; border-radius: 4px; padding: 14px; margin-bottom: 20px; }
    .messages { max-height: 320px; overflow-y: auto; }
    .msg { border-bottom: 1px solid #333; padding: 8px 0; }
    .msg:last-child { border-bottom: none; }
    .msg .sender { color: #7ec8e3; font-size: 0.85em; }
    .msg .text   { margin-top: 4px; white-space: pre-wrap; word-break: break-word; }
    .msg .time   { color: #666; font-size: 0.75em; float: right; }
    .empty { color: #666; font-style: italic; }
    .send-form { display: flex; flex-direction: column; gap: 10px; }
    select, textarea, button { font-family: monospace; font-size: 0.9em; }
    select   { background: #1a1a1a; color: #e0e0e0; border: 1px solid #555; padding: 6px 8px; border-radius: 3px; width: 100%; }
    textarea { background: #1a1a1a; color: #e0e0e0; border: 1px solid #555; padding: 6px 8px; border-radius: 3px; width: 100%; resize: vertical; min-height: 60px; }
    button { background: #2a4a6a; color: #7ec8e3; border: 1px solid #4a7aaa; padding: 8px 18px; border-radius: 3px; cursor: pointer; }
    button:hover { background: #3a5a7a; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    .refresh-btn { float: right; font-size: 0.8em; padding: 4px 10px; }
    .error { color: #e08080; margin-top: 6px; font-size: 0.85em; }
  </style>
</head>
<body>
  <h1>pnet Deliverer</h1>

  <div id="status" class="status">Connecting...</div>

  <div class="panel">
    <h2>Received Messages <button class="refresh-btn" onclick="refresh()">Refresh</button></h2>
    <div id="messages" class="messages"><span class="empty">No messages yet.</span></div>
  </div>

  <div class="panel">
    <h2>Send Message</h2>
    <div class="send-form">
      <select id="dest"><option value="">-- select destination --</option></select>
      <textarea id="text" placeholder="Type your message..."></textarea>
      <div>
        <button id="send-btn" onclick="sendMsg()">Send</button>
        <span id="send-error" class="error"></span>
      </div>
    </div>
  </div>

  <script>
    function fmtTime(ts) {
      return new Date(ts * 1000).toLocaleTimeString();
    }

    function escHtml(s) {
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    async function loadState() {
      let s;
      try {
        const r = await fetch('/api/state');
        s = await r.json();
      } catch (e) {
        return;
      }

      const statusEl = document.getElementById('status');
      const syncLine = s.last_fetch_ok
        ? `<small style="color:#888;margin-top:4px;display:block">Last synced: ${new Date(s.last_fetch_ok * 1000).toLocaleTimeString()}</small>`
        : `<small style="color:#c08020;margin-top:4px;display:block">Last synced: never — waiting for pnet\u2026</small>`;
      if (s.app_info) {
        const badge = s.approved
          ? '<span class="badge ok">APPROVED</span>'
          : '<span class="badge warn">PENDING APPROVAL</span>';
        statusEl.className = 'status ' + (s.approved ? 'approved' : 'pending');
        statusEl.innerHTML = `<strong>${escHtml(s.app_info.alias)}</strong> (id ${s.app_info.id}) ${badge}`;
        if (!s.approved) {
          statusEl.innerHTML += '<br><small style="color:#888;margin-top:4px;display:block">Approve this app in the pnet admin UI, then click Refresh.</small>';
        }
        statusEl.innerHTML += syncLine;
      } else {
        statusEl.className = 'status pending';
        statusEl.innerHTML = 'Not registered.' + syncLine;
      }

      const msgEl = document.getElementById('messages');
      if (s.messages.length === 0) {
        msgEl.innerHTML = '<span class="empty">No messages yet.</span>';
      } else {
        msgEl.innerHTML = s.messages.slice().reverse().map(m =>
          `<div class="msg">
            <span class="time">${fmtTime(m.timestamp)}</span>
            <div class="sender">${escHtml(m.sender)}</div>
            <div class="text">${escHtml(m.text)}</div>
          </div>`
        ).join('');
      }

      const destEl = document.getElementById('dest');
      const prev = destEl.value;
      destEl.innerHTML = '<option value="">-- select destination --</option>';
      s.destinations.forEach((d, i) => {
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = d.label;
        destEl.appendChild(opt);
      });
      if (prev !== '') destEl.value = prev;

      document.getElementById('send-btn').disabled = !s.approved;
    }

    async function refresh() {
      await fetch('/api/refresh', { method: 'POST' });
      await loadState();
    }

    async function sendMsg() {
      const destIdx = document.getElementById('dest').value;
      const text = document.getElementById('text').value.trim();
      const errEl = document.getElementById('send-error');
      errEl.textContent = '';

      if (destIdx === '') { errEl.textContent = 'Select a destination.'; return; }
      if (!text) { errEl.textContent = 'Enter a message.'; return; }

      const r = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dest_index: parseInt(destIdx), text }),
      });
      const result = await r.json();
      if (result.ok) {
        document.getElementById('text').value = '';
      } else {
        errEl.textContent = result.error || 'Send failed.';
      }
    }

    loadState();
    setInterval(loadState, 2000);
  </script>
</body>
</html>
"#;
