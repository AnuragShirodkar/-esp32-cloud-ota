"""
ESP32 Cloud OTA Update Server
==============================
Deployed on Render.com — runs 24/7 from the cloud.
ESP32 devices can update from anywhere in the world.

Endpoints:
  GET  /          → Web dashboard
  GET  /version   → Returns current version (ESP32 polls this)
  GET  /firmware  → Serves the .bin file (ESP32 downloads this)
  POST /upload    → Browser uploads new .bin + version
  GET  /history   → Returns upload history as JSON
"""

import os
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template_string

app = Flask(__name__)

# ── Config ────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FIRMWARE_DIR = os.path.join(BASE_DIR, "firmware")
BIN_PATH     = os.path.join(FIRMWARE_DIR, "firmware.bin")
META_PATH    = os.path.join(FIRMWARE_DIR, "meta.json")

os.makedirs(FIRMWARE_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────

def load_meta():
    if not os.path.exists(META_PATH):
        return {"version": "none", "history": []}
    with open(META_PATH) as f:
        return json.load(f)

def save_meta(meta):
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

def md5_of_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ── ESP32 Endpoints ───────────────────────────────

@app.route("/version")
def get_version():
    meta = load_meta()
    return jsonify({"version": meta["version"]})

@app.route("/firmware")
def get_firmware():
    if not os.path.exists(BIN_PATH):
        return jsonify({"error": "No firmware uploaded yet"}), 404
    return send_file(BIN_PATH, mimetype="application/octet-stream",
                     as_attachment=True, download_name="firmware.bin")

# ── Browser Endpoints ─────────────────────────────

@app.route("/upload", methods=["POST"])
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
    meta = load_meta()
    meta["version"] = version
    meta["history"].insert(0, {
        "version":  version,
        "filename": file.filename,
        "size_kb":  size_kb,
        "md5":      md5,
        "uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    meta["history"] = meta["history"][:20]
    save_meta(meta)
    print(f"[OTA] New firmware uploaded — v{version} ({size_kb} KB)")
    return jsonify({"ok": True, "version": version, "size_kb": size_kb, "md5": md5})

@app.route("/history")
def get_history():
    meta = load_meta()
    return jsonify(meta.get("history", []))

# ── Dashboard ─────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Cloud OTA</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0d0f0e; --surface:#141714; --border:#232623; --accent:#39ff8a; --accent2:#00c8ff; --text:#e8ede9; --muted:#5a6b5c; --danger:#ff4f4f; --radius:10px; --mono:'JetBrains Mono',monospace; --display:'Syne',sans-serif; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:var(--mono); font-size:13px; min-height:100vh; padding:40px 24px; }
  header { display:flex; align-items:flex-end; justify-content:space-between; margin-bottom:40px; padding-bottom:20px; border-bottom:1px solid var(--border); }
  .logo { font-family:var(--display); font-size:26px; font-weight:800; letter-spacing:-0.5px; }
  .logo span { color:var(--accent); }
  .cloud-badge { display:flex; align-items:center; gap:8px; background:var(--surface); border:1px solid var(--border); border-radius:999px; padding:6px 14px; font-size:12px; color:var(--muted); }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--accent); animation:pulse 2s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
  @media(max-width:700px){.grid{grid-template-columns:1fr}}
  .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:24px; }
  .card-label { font-size:10px; text-transform:uppercase; letter-spacing:2px; color:var(--muted); margin-bottom:10px; }
  .version-display { font-family:var(--display); font-size:48px; font-weight:800; color:var(--accent); line-height:1; letter-spacing:-1px; }
  .endpoint-list { display:flex; flex-direction:column; gap:8px; }
  .endpoint { display:flex; align-items:center; gap:10px; padding:8px 12px; background:var(--bg); border-radius:6px; border:1px solid var(--border); }
  .method { font-size:10px; font-weight:600; padding:2px 6px; border-radius:4px; min-width:36px; text-align:center; }
  .get { background:#0e3a2a; color:var(--accent); }
  .post { background:#1a2e3a; color:var(--accent2); }
  .ep-desc { color:var(--muted); margin-left:auto; font-size:11px; }
  .full { grid-column:1/-1; }
  .drop-zone { border:2px dashed var(--border); border-radius:var(--radius); padding:36px; text-align:center; cursor:pointer; transition:border-color .2s,background .2s; margin-bottom:16px; }
  .drop-zone.dragover { border-color:var(--accent); background:#0d1f13; }
  .drop-zone input { display:none; }
  .drop-icon { font-size:32px; margin-bottom:10px; display:block; filter:grayscale(1); transition:filter .2s; }
  .drop-zone.has-file .drop-icon { filter:none; }
  .drop-title { font-family:var(--display); font-size:16px; font-weight:700; margin-bottom:4px; }
  .drop-sub { color:var(--muted); font-size:12px; }
  .file-info { display:none; margin-top:10px; padding:8px 14px; background:var(--bg); border-radius:6px; border:1px solid var(--accent); color:var(--accent); font-size:12px; }
  .drop-zone.has-file .file-info { display:block; }
  .upload-row { display:flex; gap:12px; align-items:center; }
  .ver-input { flex:1; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-family:var(--mono); font-size:14px; padding:10px 14px; outline:none; transition:border-color .2s; }
  .ver-input:focus { border-color:var(--accent); }
  .ver-input::placeholder { color:var(--muted); }
  .upload-btn { background:var(--accent); color:#000; border:none; border-radius:6px; font-family:var(--display); font-size:14px; font-weight:700; padding:10px 24px; cursor:pointer; transition:opacity .2s,transform .1s; white-space:nowrap; }
  .upload-btn:hover { opacity:.85; }
  .upload-btn:disabled { opacity:.4; cursor:not-allowed; }
  .toast { display:none; position:fixed; bottom:24px; right:24px; padding:12px 20px; border-radius:8px; font-size:13px; font-weight:600; z-index:999; }
  .toast.success { background:var(--accent); color:#000; display:block; }
  .toast.error { background:var(--danger); color:#fff; display:block; }
  .history-table { width:100%; border-collapse:collapse; }
  .history-table th { text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:2px; color:var(--muted); padding:8px 12px; border-bottom:1px solid var(--border); }
  .history-table td { padding:10px 12px; border-bottom:1px solid var(--border); }
  .history-table tr:last-child td { border-bottom:none; }
  .history-table tr:first-child td { color:var(--accent); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; background:#0e3a2a; color:var(--accent); }
  .empty { color:var(--muted); text-align:center; padding:24px; }
  .progress-wrap { display:none; height:4px; background:var(--border); border-radius:2px; margin-top:12px; overflow:hidden; }
  .progress-bar { height:100%; background:var(--accent); width:0%; transition:width .3s; }
  .progress-wrap.active { display:block; }
  .url-card { grid-column:1/-1; background:#0e3a2a; border:1px solid var(--accent); }
  .url-display { font-size:14px; color:var(--accent); margin-top:8px; word-break:break-all; }
</style>
</head>
<body>
<header>
  <div class="logo">ESP32 <span>Cloud</span> OTA</div>
  <div class="cloud-badge"><div class="dot"></div>Cloud — Online 24/7</div>
</header>
<div class="grid">
  <div class="card url-card">
    <div class="card-label">Your cloud URL — paste this in your ESP32 sketch</div>
    <div class="url-display" id="server-url"></div>
  </div>
  <div class="card">
    <div class="card-label">Current firmware version</div>
    <div class="version-display" id="ver-display">—</div>
    <div style="color:var(--muted);margin-top:12px;font-size:11px" id="ver-sub">Fetching...</div>
  </div>
  <div class="card">
    <div class="card-label">ESP32 endpoints</div>
    <div class="endpoint-list">
      <div class="endpoint"><span class="method get">GET</span><span>/version</span><span class="ep-desc">Version check</span></div>
      <div class="endpoint"><span class="method get">GET</span><span>/firmware</span><span class="ep-desc">Download .bin</span></div>
      <div class="endpoint"><span class="method post">POST</span><span>/upload</span><span class="ep-desc">Upload firmware</span></div>
    </div>
  </div>
  <div class="card full">
    <div class="card-label">Upload new firmware</div>
    <div class="drop-zone" id="drop-zone" onclick="document.getElementById('fi').click()">
      <input type="file" id="fi" accept=".bin">
      <span class="drop-icon">📦</span>
      <div class="drop-title">Drop .bin file here or click to browse</div>
      <div class="drop-sub">Only compiled Arduino .bin files</div>
      <div class="file-info" id="file-info"></div>
    </div>
    <div class="upload-row">
      <input class="ver-input" id="ver-in" type="text" placeholder="Version — e.g. 1.0.1">
      <button class="upload-btn" id="up-btn" onclick="doUpload()">Upload</button>
    </div>
    <div class="progress-wrap" id="pw"><div class="progress-bar" id="pb"></div></div>
  </div>
  <div class="card full">
    <div class="card-label">Upload history</div>
    <div id="history"><div class="empty">No uploads yet</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
  document.getElementById('server-url').textContent = window.location.origin;
  let file = null;
  const zone = document.getElementById('drop-zone');
  const fi = document.getElementById('fi');
  zone.addEventListener('dragover', e=>{e.preventDefault();zone.classList.add('dragover')});
  zone.addEventListener('dragleave', ()=>zone.classList.remove('dragover'));
  zone.addEventListener('drop', e=>{e.preventDefault();zone.classList.remove('dragover');if(e.dataTransfer.files[0])setFile(e.dataTransfer.files[0])});
  fi.addEventListener('change', ()=>{if(fi.files[0])setFile(fi.files[0])});
  function setFile(f){
    if(!f.name.endsWith('.bin')){toast('Only .bin files accepted','error');return}
    file=f;zone.classList.add('has-file');
    document.getElementById('file-info').textContent=`${f.name} · ${(f.size/1024).toFixed(1)} KB`;
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
        toast(`v${r.version} uploaded — ${r.size_kb} KB`,'success');
        file=null;zone.classList.remove('has-file');
        document.getElementById('file-info').textContent='';
        document.getElementById('ver-in').value='';fi.value='';
        loadVer();loadHistory();
      } else toast(JSON.parse(xhr.responseText).error||'Upload failed','error');
    };
    xhr.onerror=()=>{btn.disabled=false;btn.textContent='Upload';toast('Network error','error')};
    xhr.open('POST','/upload');xhr.send(fd);
  }
  function loadVer(){
    fetch('/version').then(r=>r.json()).then(d=>{
      const el=document.getElementById('ver-display');
      const sub=document.getElementById('ver-sub');
      if(d.version==='none'){el.textContent='—';sub.textContent='No firmware uploaded yet'}
      else{el.textContent='v'+d.version;sub.textContent='Ready to serve to ESP32 devices worldwide'}
    });
  }
  function loadHistory(){
    fetch('/history').then(r=>r.json()).then(rows=>{
      const c=document.getElementById('history');
      if(!rows.length){c.innerHTML='<div class="empty">No uploads yet</div>';return}
      c.innerHTML=`<table class="history-table"><thead><tr><th>Version</th><th>File</th><th>Size</th><th>MD5</th><th>Uploaded</th></tr></thead><tbody>${rows.map((r,i)=>`<tr><td><span class="badge">${r.version}</span>${i===0?' ← current':''}</td><td>${r.filename}</td><td>${r.size_kb} KB</td><td style="font-size:11px;color:var(--muted)">${r.md5.slice(0,12)}…</td><td style="color:var(--muted)">${r.uploaded}</td></tr>`).join('')}</tbody></table>`;
    });
  }
  function toast(msg,type){
    const t=document.getElementById('toast');t.textContent=msg;t.className='toast '+type;
    clearTimeout(t._t);t._t=setTimeout(()=>t.className='toast',3500);
  }
  loadVer();loadHistory();
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ── Run ───────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
