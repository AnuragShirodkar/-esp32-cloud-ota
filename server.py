"""
ESP32 Cloud OTA — Complete Server with Monitoring
==================================================
Day 4 complete version with:
- MAC based device management
- API key + login security
- Activity logging
- Per device statistics
- Registration page
- 15 minute offline alert

API Key  : ESP32-OTA-1ar0922ec
Dashboard: #ironman@099
"""

import os
import json
import hashlib
import functools
from datetime import datetime
from flask import (Flask, request, jsonify, send_file,
                   render_template_string, session, redirect, url_for)

app = Flask(__name__)
app.secret_key = "OTA-SESSION-KEY-anurag-2024"

# ── Security ──────────────────────────────────────

API_KEY            = "ESP32-OTA-1ar0922ec"
DASHBOARD_PASSWORD = "#ironman@099"

# ── Paths ─────────────────────────────────────────

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
FIRMWARE_DIR  = os.path.join(BASE_DIR, "firmware")
BIN_PATH      = os.path.join(FIRMWARE_DIR, "firmware.bin")
META_PATH     = os.path.join(FIRMWARE_DIR, "meta.json")
DEVICES_PATH  = os.path.join(FIRMWARE_DIR, "devices.json")
REGISTRY_PATH = os.path.join(FIRMWARE_DIR, "registry.json")
LOGS_PATH     = os.path.join(FIRMWARE_DIR, "logs.json")
STATS_PATH    = os.path.join(FIRMWARE_DIR, "stats.json")

os.makedirs(FIRMWARE_DIR, exist_ok=True)

# ── JSON Helpers ──────────────────────────────────

def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_meta():     return load_json(META_PATH,     {"version": "none", "history": []})
def load_devices():  return load_json(DEVICES_PATH,  {})
def load_registry(): return load_json(REGISTRY_PATH, {})
def load_logs():     return load_json(LOGS_PATH,      [])
def load_stats():    return load_json(STATS_PATH,     {})

def save_meta(d):     save_json(META_PATH,     d)
def save_devices(d):  save_json(DEVICES_PATH,  d)
def save_registry(d): save_json(REGISTRY_PATH, d)
def save_logs(d):     save_json(LOGS_PATH,      d)
def save_stats(d):    save_json(STATS_PATH,     d)

def md5_of_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ── Time ──────────────────────────────────────────

def now_utc():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Device Name Lookup ────────────────────────────

def get_device_name(mac):
    return load_registry().get(mac, mac)

# ── Logging ───────────────────────────────────────

def add_log(mac, event, detail="", status="info"):
    logs = load_logs()
    logs.insert(0, {
        "mac":    mac,
        "name":   get_device_name(mac),
        "event":  event,
        "detail": detail,
        "status": status,
        "time":   now_utc()
    })
    save_logs(logs[:500])

# ── Stats ─────────────────────────────────────────

def update_stats(mac, event):
    stats = load_stats()
    if mac not in stats:
        stats[mac] = {
            "total_checkins":     0,
            "successful_updates": 0,
            "failed_updates":     0,
            "last_update":        None,
            "last_failure":       None
        }
    if event == "checkin":
        stats[mac]["total_checkins"] += 1
    elif event == "update_success":
        stats[mac]["successful_updates"] += 1
        stats[mac]["last_update"] = now_utc()
    elif event == "update_failed":
        stats[mac]["failed_updates"] += 1
        stats[mac]["last_failure"] = now_utc()
    save_stats(stats)

# ── Device Registration ───────────────────────────

def register_device(req):
    mac     = req.headers.get("X-Device-MAC", "unknown")
    version = req.headers.get("X-FW-Version",  "unknown")
    if mac == "unknown":
        return mac, version
    devices  = load_devices()
    registry = load_registry()
    devices[mac] = {
        "mac":       mac,
        "name":      registry.get(mac, None),
        "version":   version,
        "last_seen": now_utc(),
        "ip":        req.remote_addr or "unknown"
    }
    save_devices(devices)
    return mac, version

# ── Security Decorators ───────────────────────────

def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key:
            return jsonify({"error": "API key missing"}), 401
        if key != API_KEY:
            return jsonify({"error": "Invalid API key"}), 403
        return f(*args, **kwargs)
    return decorated

def require_login(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Auth ──────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Cloud OTA - Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0d0f0e;--surface:#141714;--border:#232623;--accent:#39ff8a;--text:#e8ede9;--muted:#5a6b5c;--danger:#ff4f4f;--mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:380px}
  .logo{font-family:var(--display);font-size:22px;font-weight:800;margin-bottom:8px}
  .logo span{color:var(--accent)}
  .sub{color:var(--muted);font-size:12px;margin-bottom:32px}
  label{font-size:11px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);display:block;margin-bottom:8px}
  input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:12px 14px;outline:none;transition:border-color .2s;margin-bottom:20px}
  input:focus{border-color:var(--accent)}
  button{width:100%;background:var(--accent);color:#000;border:none;border-radius:6px;font-family:var(--display);font-size:15px;font-weight:700;padding:12px;cursor:pointer;transition:opacity .2s}
  button:hover{opacity:.85}
  .error{background:#1a0a0a;border:1px solid var(--danger);border-radius:6px;padding:10px 14px;color:var(--danger);font-size:12px;margin-bottom:20px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">ESP32 <span>Cloud</span> OTA</div>
  <div class="sub">Enter password to access dashboard</div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter dashboard password" autofocus>
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>"""

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == DASHBOARD_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Wrong password. Try again."
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── ESP32 Endpoints ───────────────────────────────

@app.route("/checkin", methods=["POST"])
@require_api_key
def checkin():
    mac, version = register_device(request)
    add_log(mac, "check-in", f"v{version}", "info")
    update_stats(mac, "checkin")
    return jsonify({"ok": True})

@app.route("/version")
@require_api_key
def get_version():
    mac, version = register_device(request)
    meta         = load_meta()
    server_ver   = meta["version"]
    if server_ver != "none" and server_ver != version:
        add_log(mac, "update available",
                f"device v{version} to server v{server_ver}", "warning")
    return jsonify({"version": server_ver})

@app.route("/firmware")
def get_firmware():
    key = request.headers.get("X-API-Key") or request.args.get("key")
    mac = request.headers.get("X-Device-MAC", "unknown")
    if not key:
        return jsonify({"error": "API key missing"}), 401
    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403
    if not os.path.exists(BIN_PATH):
        return jsonify({"error": "No firmware uploaded yet"}), 404
    add_log(mac, "firmware download", "downloading binary", "info")
    return send_file(BIN_PATH, mimetype="application/octet-stream",
                     as_attachment=True, download_name="firmware.bin")

@app.route("/update/success", methods=["POST"])
@require_api_key
def update_success():
    mac     = request.headers.get("X-Device-MAC", "unknown")
    version = request.headers.get("X-FW-Version",  "unknown")
    add_log(mac, "update success", f"now running v{version}", "success")
    update_stats(mac, "update_success")
    return jsonify({"ok": True})

@app.route("/update/failed", methods=["POST"])
@require_api_key
def update_failed():
    mac    = request.headers.get("X-Device-MAC", "unknown")
    reason = request.headers.get("X-Error", "unknown error")
    add_log(mac, "update failed", reason, "error")
    update_stats(mac, "update_failed")
    return jsonify({"ok": True})

# ── Browser Endpoints ─────────────────────────────

@app.route("/upload", methods=["POST"])
@require_login
def upload_firmware():
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400
    file    = request.files["file"]
    version = request.form.get("version", "").strip()
    if not file.filename.endswith(".bin"):
        return jsonify({"error": "Only .bin files are accepted"}), 400
    if not version:
        return jsonify({"error": "Version string is required"}), 400
    file.save(BIN_PATH)
    size_kb = round(os.path.getsize(BIN_PATH) / 1024, 1)
    md5     = md5_of_file(BIN_PATH)
    meta    = load_meta()
    meta["version"] = version
    meta["history"].insert(0, {
        "version":  version,
        "filename": file.filename,
        "size_kb":  size_kb,
        "md5":      md5,
        "uploaded": now_utc()
    })
    meta["history"] = meta["history"][:20]
    save_meta(meta)
    add_log("dashboard", "firmware uploaded",
            f"v{version} - {size_kb} KB", "success")
    print(f"[OTA] New firmware uploaded - v{version} ({size_kb} KB)")
    return jsonify({"ok": True, "version": version,
                    "size_kb": size_kb, "md5": md5})

@app.route("/history")
@require_login
def get_history():
    return jsonify(load_meta().get("history", []))

@app.route("/devices/named")
@require_login
def get_named_devices():
    devices  = load_devices()
    registry = load_registry()
    stats    = load_stats()
    return jsonify([
        {**d, "name": registry[mac], "stats": stats.get(mac, {})}
        for mac, d in devices.items() if mac in registry
    ])

@app.route("/devices/unnamed")
@require_login
def get_unnamed_devices():
    devices  = load_devices()
    registry = load_registry()
    return jsonify([d for mac, d in devices.items() if mac not in registry])

@app.route("/devices/register", methods=["POST"])
@require_login
def register_device_name():
    data = request.get_json()
    mac  = data.get("mac", "").strip()
    name = data.get("name", "").strip()
    if not mac or not name:
        return jsonify({"error": "MAC and name required"}), 400
    registry      = load_registry()
    registry[mac] = name
    save_registry(registry)
    devices = load_devices()
    if mac in devices:
        devices[mac]["name"] = name
        save_devices(devices)
    add_log(mac, "device registered", f"named: {name}", "success")
    return jsonify({"ok": True, "mac": mac, "name": name})

@app.route("/devices/rename", methods=["POST"])
@require_login
def rename_device():
    data     = request.get_json()
    mac      = data.get("mac", "").strip()
    name     = data.get("name", "").strip()
    if not mac or not name:
        return jsonify({"error": "MAC and name required"}), 400
    registry = load_registry()
    old_name = registry.get(mac, mac)
    registry[mac] = name
    save_registry(registry)
    devices = load_devices()
    if mac in devices:
        devices[mac]["name"] = name
        save_devices(devices)
    add_log(mac, "device renamed", f"{old_name} to {name}", "info")
    return jsonify({"ok": True})

@app.route("/logs")
@require_login
def get_logs():
    logs   = load_logs()
    status = request.args.get("status")
    limit  = int(request.args.get("limit", 100))
    if status:
        logs = [l for l in logs if l["status"] == status]
    return jsonify(logs[:limit])

@app.route("/stats")
@require_login
def get_stats():
    stats    = load_stats()
    registry = load_registry()
    return jsonify([
        {"mac": mac, "name": registry.get(mac, mac), **s}
        for mac, s in stats.items()
    ])

# ── Registration Page ─────────────────────────────

REGISTER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Device Registration</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0d0f0e;--surface:#141714;--border:#232623;--accent:#39ff8a;--accent2:#00c8ff;--text:#e8ede9;--muted:#5a6b5c;--danger:#ff4f4f;--radius:10px;--mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;min-height:100vh;padding:40px 24px}
  header{display:flex;align-items:center;justify-content:space-between;margin-bottom:40px;padding-bottom:20px;border-bottom:1px solid var(--border)}
  .logo{font-family:var(--display);font-size:26px;font-weight:800}
  .logo span{color:var(--accent)}
  .back-btn{background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-family:var(--mono);font-size:12px;padding:6px 14px;cursor:pointer;text-decoration:none;transition:border-color .2s,color .2s}
  .back-btn:hover{border-color:var(--accent);color:var(--accent)}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:16px}
  .card-label{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);margin-bottom:16px}
  .device-row{display:flex;align-items:center;gap:12px;padding:16px 0;border-bottom:1px solid var(--border)}
  .device-row:last-child{border-bottom:none}
  .mac{font-size:14px;color:var(--accent2);min-width:180px}
  .ver{color:var(--muted);font-size:11px;min-width:60px}
  .last{color:var(--muted);font-size:11px;flex:1}
  .name-input{background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:13px;padding:8px 12px;outline:none;transition:border-color .2s;width:200px}
  .name-input:focus{border-color:var(--accent)}
  .name-input::placeholder{color:var(--muted)}
  .save-btn{background:var(--accent);color:#000;border:none;border-radius:6px;font-family:var(--display);font-size:13px;font-weight:700;padding:8px 16px;cursor:pointer;transition:opacity .2s;white-space:nowrap}
  .save-btn:hover{opacity:.85}
  .empty{color:var(--muted);text-align:center;padding:32px}
  .toast{display:none;position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;font-weight:600;z-index:999}
  .toast.success{background:var(--accent);color:#000;display:block}
  .toast.error{background:var(--danger);color:#fff;display:block}
  .count-badge{font-family:var(--display);font-size:32px;font-weight:800;color:var(--accent2);line-height:1;margin-bottom:4px}
  .count-sub{color:var(--muted);font-size:11px;margin-bottom:20px}
</style>
</head>
<body>
<header>
  <div class="logo">ESP32 <span>Cloud</span> OTA</div>
  <a href="/" class="back-btn">Back to dashboard</a>
</header>
<div class="card">
  <div class="card-label">Unregistered devices</div>
  <div class="count-badge" id="count">-</div>
  <div class="count-sub">devices waiting to be named</div>
  <div id="devices-list"><div class="empty">Loading...</div></div>
</div>
<div class="toast" id="toast"></div>
<script>
function loadDevices(){
  fetch('/devices/unnamed').then(r=>r.json()).then(devices=>{
    const list=document.getElementById('devices-list');
    document.getElementById('count').textContent=devices.length;
    if(!devices.length){list.innerHTML='<div class="empty">No unregistered devices - all devices are named</div>';return}
    list.innerHTML=devices.map(d=>`
      <div class="device-row" id="row-${d.mac.replace(/:/g,'')}">
        <div class="mac">${d.mac}</div>
        <div class="ver">v${d.version}</div>
        <div class="last">Last seen: ${d.last_seen}</div>
        <input class="name-input" id="inp-${d.mac.replace(/:/g,'')}"
               placeholder="Enter device name..."
               onkeydown="if(event.key==='Enter')saveName('${d.mac}')">
        <button class="save-btn" onclick="saveName('${d.mac}')">Register</button>
      </div>`).join('');
  });
}
function saveName(mac){
  const id=mac.replace(/:/g,'');
  const name=document.getElementById('inp-'+id).value.trim();
  if(!name){toast('Enter a device name','error');return}
  fetch('/devices/register',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mac,name})}).then(r=>r.json()).then(d=>{
    if(d.ok){
      toast(name+' registered','success');
      document.getElementById('row-'+id).remove();
      const c=document.getElementById('count');
      c.textContent=parseInt(c.textContent)-1;
    } else toast(d.error||'Failed','error');
  });
}
function toast(msg,type){
  const t=document.getElementById('toast');t.textContent=msg;t.className='toast '+type;
  clearTimeout(t._t);t._t=setTimeout(()=>t.className='toast',3500);
}
loadDevices();
</script>
</body>
</html>"""

@app.route("/register")
@require_login
def register_page():
    return render_template_string(REGISTER_HTML)

# ── Main Dashboard ────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Cloud OTA</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0d0f0e;--surface:#141714;--border:#232623;--accent:#39ff8a;--accent2:#00c8ff;--text:#e8ede9;--muted:#5a6b5c;--danger:#ff4f4f;--warning:#f5a623;--radius:10px;--mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;min-height:100vh;padding:40px 24px}
  header{display:flex;align-items:center;justify-content:space-between;margin-bottom:40px;padding-bottom:20px;border-bottom:1px solid var(--border)}
  .logo{font-family:var(--display);font-size:26px;font-weight:800;letter-spacing:-.5px}
  .logo span{color:var(--accent)}
  .header-right{display:flex;align-items:center;gap:12px}
  .cloud-badge{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:6px 14px;font-size:12px;color:var(--muted)}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .logout-btn{background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-family:var(--mono);font-size:12px;padding:6px 14px;cursor:pointer;text-decoration:none;transition:border-color .2s,color .2s}
  .logout-btn:hover{border-color:var(--danger);color:var(--danger)}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}
  @media(max-width:900px){.grid3{grid-template-columns:1fr 1fr}}
  @media(max-width:600px){.grid3{grid-template-columns:1fr}}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:16px}
  .card-label{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);margin-bottom:10px}
  .stat-num{font-family:var(--display);font-size:40px;font-weight:800;line-height:1}
  .stat-sub{color:var(--muted);font-size:11px;margin-top:6px}
  .version-display{font-family:var(--display);font-size:48px;font-weight:800;color:var(--accent);line-height:1;letter-spacing:-1px}
  .drop-zone{border:2px dashed var(--border);border-radius:var(--radius);padding:36px;text-align:center;cursor:pointer;transition:border-color .2s,background .2s;margin-bottom:16px}
  .drop-zone.dragover{border-color:var(--accent);background:#0d1f13}
  .drop-zone input{display:none}
  .drop-icon{font-size:32px;margin-bottom:10px;display:block;filter:grayscale(1);transition:filter .2s}
  .drop-zone.has-file .drop-icon{filter:none}
  .drop-title{font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:4px}
  .drop-sub{color:var(--muted);font-size:12px}
  .file-info{display:none;margin-top:10px;padding:8px 14px;background:var(--bg);border-radius:6px;border:1px solid var(--accent);color:var(--accent);font-size:12px}
  .drop-zone.has-file .file-info{display:block}
  .upload-row{display:flex;gap:12px;align-items:center}
  .ver-input{flex:1;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:10px 14px;outline:none;transition:border-color .2s}
  .ver-input:focus{border-color:var(--accent)}
  .ver-input::placeholder{color:var(--muted)}
  .upload-btn{background:var(--accent);color:#000;border:none;border-radius:6px;font-family:var(--display);font-size:14px;font-weight:700;padding:10px 24px;cursor:pointer;transition:opacity .2s;white-space:nowrap}
  .upload-btn:hover{opacity:.85}
  .upload-btn:disabled{opacity:.4;cursor:not-allowed}
  .toast{display:none;position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;font-weight:600;z-index:999}
  .toast.success{background:var(--accent);color:#000;display:block}
  .toast.error{background:var(--danger);color:#fff;display:block}
  .progress-wrap{display:none;height:4px;background:var(--border);border-radius:2px;margin-top:12px;overflow:hidden}
  .progress-bar{height:100%;background:var(--accent);width:0%;transition:width .3s}
  .progress-wrap.active{display:block}
  .device-table{width:100%;border-collapse:collapse}
  .device-table th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)}
  .device-table td{padding:12px;border-bottom:1px solid var(--border);vertical-align:middle}
  .device-table tr:last-child td{border-bottom:none}
  .device-name{font-family:var(--display);font-size:15px;font-weight:700}
  .device-mac{color:var(--muted);font-size:11px;margin-top:3px}
  .s-online{display:inline-flex;align-items:center;gap:6px;color:var(--accent);font-size:12px}
  .s-offline{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:12px}
  .s-missing{display:inline-flex;align-items:center;gap:6px;color:var(--danger);font-size:12px}
  .sdot{width:7px;height:7px;border-radius:50%}
  .sdot.on{background:var(--accent);animation:pulse 2s infinite}
  .sdot.off{background:var(--muted)}
  .sdot.miss{background:var(--danger)}
  .ver-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px}
  .utd{background:#0e3a2a;color:var(--accent)}
  .old{background:#2a1a0e;color:var(--warning)}
  .last-seen{color:var(--muted);font-size:11px}
  .rename-btn{background:transparent;border:1px solid var(--border);border-radius:4px;color:var(--muted);font-family:var(--mono);font-size:11px;padding:3px 8px;cursor:pointer;transition:border-color .2s}
  .rename-btn:hover{border-color:var(--accent2);color:var(--accent2)}
  .empty{color:var(--muted);text-align:center;padding:24px}
  .reg-alert{display:none;background:#1a2e3a;border:1px solid var(--accent2);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:12px;color:var(--accent2)}
  .reg-alert a{color:var(--accent2);font-weight:600}
  .sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
  .refresh-btn{background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-family:var(--mono);font-size:11px;padding:4px 12px;cursor:pointer;transition:border-color .2s}
  .refresh-btn:hover{border-color:var(--accent2);color:var(--accent2)}
  .log-filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
  .fb{background:transparent;border:1px solid var(--border);border-radius:4px;color:var(--muted);font-family:var(--mono);font-size:11px;padding:4px 10px;cursor:pointer;transition:all .2s}
  .fb.active{border-color:var(--accent);color:var(--accent)}
  .log-entry{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)}
  .log-entry:last-child{border-bottom:none}
  .ldot{width:8px;height:8px;border-radius:50%;margin-top:4px;flex-shrink:0}
  .ldot.info{background:var(--accent2)}
  .ldot.success{background:var(--accent)}
  .ldot.warning{background:var(--warning)}
  .ldot.error{background:var(--danger)}
  .log-name{color:var(--text);font-weight:600;font-size:12px}
  .log-event{color:var(--muted);font-size:11px}
  .log-detail{color:var(--muted);font-size:11px;margin-top:2px}
  .log-time{color:var(--muted);font-size:10px;margin-left:auto;white-space:nowrap}
  .log-box{max-height:400px;overflow-y:auto}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
  .scard{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px}
  .scard-name{font-family:var(--display);font-size:14px;font-weight:700;margin-bottom:12px}
  .srow{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;font-size:12px}
  .slabel{color:var(--muted)}
  .sval{font-weight:600}
  .sval.g{color:var(--accent)}
  .sval.r{color:var(--danger)}
  .sval.y{color:var(--warning);font-size:10px}
  .htable{width:100%;border-collapse:collapse}
  .htable th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)}
  .htable td{padding:10px 12px;border-bottom:1px solid var(--border)}
  .htable tr:last-child td{border-bottom:none}
  .htable tr:first-child td{color:var(--accent)}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;background:#0e3a2a;color:var(--accent)}
</style>
</head>
<body>
<header>
  <div class="logo">ESP32 <span>Cloud</span> OTA</div>
  <div class="header-right">
    <div class="cloud-badge"><div class="dot"></div>Secured - Online 24/7</div>
    <a href="/logout" class="logout-btn">Logout</a>
  </div>
</header>

<div id="reg-alert" class="reg-alert">
  New device(s) detected - <span id="unreg-count">0</span> unregistered
  <a href="/register"> Register now</a>
</div>

<div class="grid3">
  <div class="card">
    <div class="card-label">Current firmware</div>
    <div class="version-display" id="ver-display">-</div>
    <div style="color:var(--muted);margin-top:8px;font-size:11px" id="ver-sub">Fetching...</div>
  </div>
  <div class="card">
    <div class="card-label">Devices</div>
    <div class="stat-num" id="total-devices" style="color:var(--accent2)">-</div>
    <div class="stat-sub" id="online-count">- online</div>
  </div>
  <div class="card">
    <div class="card-label">Total check-ins</div>
    <div class="stat-num" id="total-checkins" style="color:var(--accent)">-</div>
    <div class="stat-sub">across all devices</div>
  </div>
</div>

<div class="card">
  <div class="sec-hdr">
    <div class="card-label" style="margin-bottom:0">Named devices</div>
    <div style="display:flex;gap:8px">
      <a href="/register" style="background:transparent;border:1px solid var(--accent2);border-radius:6px;color:var(--accent2);font-family:var(--mono);font-size:11px;padding:4px 12px;text-decoration:none">+ Register</a>
      <button class="refresh-btn" onclick="loadDevices()">Refresh</button>
    </div>
  </div>
  <div id="devices-container"><div class="empty">Loading...</div></div>
</div>

<div class="card">
  <div class="card-label">Device statistics</div>
  <div class="stats-grid" id="stats-container"><div class="empty">Loading...</div></div>
</div>

<div class="card">
  <div class="sec-hdr">
    <div class="card-label" style="margin-bottom:0">Activity log</div>
    <button class="refresh-btn" onclick="loadLogs()">Refresh</button>
  </div>
  <div class="log-filters">
    <button class="fb active" onclick="filterLogs('all',this)">All</button>
    <button class="fb" onclick="filterLogs('success',this)">Success</button>
    <button class="fb" onclick="filterLogs('warning',this)">Updates</button>
    <button class="fb" onclick="filterLogs('error',this)">Errors</button>
    <button class="fb" onclick="filterLogs('info',this)">Info</button>
  </div>
  <div class="log-box" id="log-box"><div class="empty">Loading...</div></div>
</div>

<div class="card">
  <div class="card-label">Upload new firmware</div>
  <div class="drop-zone" id="drop-zone" onclick="document.getElementById('fi').click()">
    <input type="file" id="fi" accept=".bin">
    <span class="drop-icon">&#128230;</span>
    <div class="drop-title">Drop .bin file here or click to browse</div>
    <div class="drop-sub">Only compiled Arduino .bin files</div>
    <div class="file-info" id="file-info"></div>
  </div>
  <div class="upload-row">
    <input class="ver-input" id="ver-in" type="text" placeholder="Version - e.g. 1.0.1">
    <button class="upload-btn" id="up-btn" onclick="doUpload()">Upload</button>
  </div>
  <div class="progress-wrap" id="pw"><div class="progress-bar" id="pb"></div></div>
</div>

<div class="card">
  <div class="card-label">Upload history</div>
  <div id="history"><div class="empty">No uploads yet</div></div>
</div>

<div class="toast" id="toast"></div>
<script>
  let file=null,logFilter='all';
  const zone=document.getElementById('drop-zone'),fi=document.getElementById('fi');
  zone.addEventListener('dragover',e=>{e.preventDefault();zone.classList.add('dragover')});
  zone.addEventListener('dragleave',()=>zone.classList.remove('dragover'));
  zone.addEventListener('drop',e=>{e.preventDefault();zone.classList.remove('dragover');if(e.dataTransfer.files[0])setFile(e.dataTransfer.files[0])});
  fi.addEventListener('change',()=>{if(fi.files[0])setFile(fi.files[0])});
  function setFile(f){
    if(!f.name.endsWith('.bin')){toast('Only .bin files accepted','error');return}
    file=f;zone.classList.add('has-file');
    document.getElementById('file-info').textContent=f.name+' - '+(f.size/1024).toFixed(1)+' KB';
  }
  function doUpload(){
    const v=document.getElementById('ver-in').value.trim();
    if(!file){toast('Select a .bin file','error');return}
    if(!v){toast('Enter a version number','error');return}
    const btn=document.getElementById('up-btn');
    btn.disabled=true;btn.textContent='Uploading...';
    document.getElementById('pw').classList.add('active');
    const fd=new FormData();fd.append('file',file);fd.append('version',v);
    const xhr=new XMLHttpRequest();
    xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('pb').style.width=Math.round(e.loaded/e.total*100)+'%'};
    xhr.onload=()=>{
      btn.disabled=false;btn.textContent='Upload';
      document.getElementById('pw').classList.remove('active');
      document.getElementById('pb').style.width='0%';
      if(xhr.status===200){
        const r=JSON.parse(xhr.responseText);
        toast('v'+r.version+' uploaded - '+r.size_kb+' KB','success');
        file=null;zone.classList.remove('has-file');
        document.getElementById('file-info').textContent='';
        document.getElementById('ver-in').value='';fi.value='';
        loadAll();
      } else toast(JSON.parse(xhr.responseText).error||'Upload failed','error');
    };
    xhr.onerror=()=>{btn.disabled=false;btn.textContent='Upload';toast('Network error','error')};
    xhr.open('POST','/upload');xhr.send(fd);
  }
  function loadVer(){
    fetch('/version',{headers:{'X-API-Key':'ESP32-OTA-1ar0922ec'}}).then(r=>r.json()).then(d=>{
      const el=document.getElementById('ver-display'),sub=document.getElementById('ver-sub');
      if(d.version==='none'){el.textContent='-';sub.textContent='No firmware uploaded yet'}
      else{el.textContent='v'+d.version;sub.textContent='Ready to serve worldwide'}
    });
  }
  function loadDevices(){
    const sv=document.getElementById('ver-display').textContent.replace('v','');
    fetch('/devices/unnamed').then(r=>r.json()).then(u=>{
      const a=document.getElementById('reg-alert');
      document.getElementById('unreg-count').textContent=u.length;
      a.style.display=u.length>0?'block':'none';
    });
    fetch('/devices/named').then(r=>r.json()).then(devices=>{
      document.getElementById('total-devices').textContent=devices.length;
      const on=devices.filter(d=>Math.floor((new Date()-new Date(d.last_seen))/60000)<5).length;
      document.getElementById('online-count').textContent=on+' online';
      const c=document.getElementById('devices-container');
      if(!devices.length){c.innerHTML='<div class="empty">No named devices - <a href="/register" style="color:var(--accent2)">register devices</a></div>';return}
      c.innerHTML='<table class="device-table"><thead><tr><th>Device</th><th>Status</th><th>Firmware</th><th>Check-ins</th><th>Last seen</th><th></th></tr></thead><tbody>'+
        devices.map(d=>{
          const diff=Math.floor((new Date()-new Date(d.last_seen))/60000);
          const on=diff<5,miss=diff>=15,utd=d.version===sv;
          const ci=d.stats?d.stats.total_checkins||0:0;
          const st=on?'<span class="s-online"><span class="sdot on"></span>Online</span>':miss?'<span class="s-missing"><span class="sdot miss"></span>Missing</span>':'<span class="s-offline"><span class="sdot off"></span>Offline</span>';
          return '<tr><td><div class="device-name">'+d.name+'</div><div class="device-mac">'+d.mac+'</div></td><td>'+st+'</td><td><span class="ver-badge '+(utd?'utd':'old')+'">v'+d.version+' '+(utd?'':'update available')+'</span></td><td style="color:var(--muted)">'+ci+'</td><td class="last-seen">'+d.last_seen+'</td><td><button class="rename-btn" onclick="renameDevice(\''+d.mac+'\',\''+d.name+'\')">Rename</button></td></tr>';
        }).join('')+'</tbody></table>';
    });
  }
  function loadStats(){
    fetch('/stats').then(r=>r.json()).then(stats=>{
      document.getElementById('total-checkins').textContent=stats.reduce((s,d)=>s+(d.total_checkins||0),0);
      const c=document.getElementById('stats-container');
      if(!stats.length){c.innerHTML='<div class="empty">No stats yet</div>';return}
      c.innerHTML=stats.map(s=>'<div class="scard"><div class="scard-name">'+s.name+'</div>'+
        '<div class="srow"><span class="slabel">Total check-ins</span><span class="sval">'+(s.total_checkins||0)+'</span></div>'+
        '<div class="srow"><span class="slabel">Successful updates</span><span class="sval g">'+(s.successful_updates||0)+'</span></div>'+
        '<div class="srow"><span class="slabel">Failed updates</span><span class="sval r">'+(s.failed_updates||0)+'</span></div>'+
        '<div class="srow"><span class="slabel">Last update</span><span class="sval y">'+(s.last_update?s.last_update.slice(0,16).replace('T',' '):'never')+'</span></div></div>').join('');
    });
  }
  function loadLogs(f){
    if(f)logFilter=f;
    const url=logFilter==='all'?'/logs':'/logs?status='+logFilter;
    fetch(url).then(r=>r.json()).then(logs=>{
      const c=document.getElementById('log-box');
      if(!logs.length){c.innerHTML='<div class="empty">No logs yet</div>';return}
      c.innerHTML=logs.map(l=>'<div class="log-entry"><div class="ldot '+l.status+'"></div><div style="flex:1"><div style="display:flex;align-items:center;gap:8px"><span class="log-name">'+l.name+'</span><span class="log-event">'+l.event+'</span></div>'+(l.detail?'<div class="log-detail">'+l.detail+'</div>':'')+'</div><div class="log-time">'+l.time.replace('T',' ').replace('Z','')+'</div></div>').join('');
    });
  }
  function filterLogs(f,btn){
    document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');loadLogs(f);
  }
  function renameDevice(mac,cur){
    const name=prompt('Rename (current: '+cur+'):',cur);
    if(!name||name===cur)return;
    fetch('/devices/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac,name})}).then(r=>r.json()).then(d=>{
      if(d.ok){toast('Renamed to '+name,'success');loadDevices()}
      else toast(d.error||'Failed','error');
    });
  }
  function loadHistory(){
    fetch('/history').then(r=>r.json()).then(rows=>{
      const c=document.getElementById('history');
      if(!rows.length){c.innerHTML='<div class="empty">No uploads yet</div>';return}
      c.innerHTML='<table class="htable"><thead><tr><th>Version</th><th>File</th><th>Size</th><th>MD5</th><th>Uploaded</th></tr></thead><tbody>'+
        rows.map((r,i)=>'<tr><td><span class="badge">'+r.version+'</span>'+(i===0?' current':'')+' </td><td>'+r.filename+'</td><td>'+r.size_kb+' KB</td><td style="font-size:11px;color:var(--muted)">'+r.md5.slice(0,12)+'</td><td style="color:var(--muted)">'+r.uploaded+'</td></tr>').join('')+'</tbody></table>';
    });
  }
  function toast(msg,type){
    const t=document.getElementById('toast');t.textContent=msg;t.className='toast '+type;
    clearTimeout(t._t);t._t=setTimeout(()=>t.className='toast',3500);
  }
  function loadAll(){loadVer();loadDevices();loadStats();loadLogs();loadHistory()}
  loadAll();setInterval(loadAll,30000);
</script>
</body>
</html>"""

@app.route("/")
@require_login
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ── Run ───────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
