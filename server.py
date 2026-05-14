"""
server.py - Flask server with HMAC-SHA256 request validation
Demonstrates server-side integrity verification for HTTP POST requests.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac
import hashlib

app = Flask(__name__)
CORS(app)

SECRET_KEY = "Shrihari_23BCI0083"


def generate_hmac(message: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(message: str, provided_hmac: str) -> bool:
    expected_hmac = generate_hmac(message)
    return hmac.compare_digest(expected_hmac, provided_hmac)


# ─── Web UI ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HMAC Integrity Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #0f1117;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 32px 16px;
    }

    .page { max-width: 860px; margin: 0 auto; }

    header {
      text-align: center;
      margin-bottom: 40px;
    }
    header h1 {
      font-size: 1.9rem;
      font-weight: 700;
      color: #fff;
      letter-spacing: -0.5px;
    }
    header p {
      margin-top: 6px;
      font-size: 0.9rem;
      color: #64748b;
    }
    .tag {
      display: inline-block;
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      font-size: 0.75rem;
      padding: 2px 10px;
      border-radius: 20px;
      margin-top: 10px;
    }

    /* Cards */
    .card {
      background: #1a1f2e;
      border: 1px solid #2d3748;
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 24px;
    }
    .card-title {
      font-size: 1rem;
      font-weight: 600;
      color: #93c5fd;
      margin-bottom: 18px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card-title .badge {
      background: #1d4ed8;
      color: #bfdbfe;
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 10px;
      font-weight: 500;
    }

    /* Form fields */
    .field { margin-bottom: 14px; }
    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    input[type="text"], input[type="number"] {
      width: 100%;
      background: #0f1117;
      border: 1px solid #334155;
      color: #e2e8f0;
      font-size: 0.92rem;
      padding: 9px 12px;
      border-radius: 7px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #3b82f6; }

    /* Toggle */
    .toggle-row {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
    }
    .toggle-label { font-size: 0.85rem; color: #94a3b8; }
    .switch { position: relative; display: inline-block; width: 40px; height: 22px; }
    .switch input { display: none; }
    .slider {
      position: absolute; inset: 0;
      background: #374151; border-radius: 22px;
      cursor: pointer; transition: 0.3s;
    }
    .slider::before {
      content: '';
      position: absolute;
      width: 16px; height: 16px;
      left: 3px; top: 3px;
      background: #fff; border-radius: 50%;
      transition: 0.3s;
    }
    input:checked + .slider { background: #3b82f6; }
    input:checked + .slider::before { transform: translateX(18px); }

    /* HMAC display */
    .hmac-box {
      background: #0f1117;
      border: 1px solid #334155;
      border-radius: 7px;
      padding: 10px 12px;
      font-family: 'Courier New', monospace;
      font-size: 0.78rem;
      color: #34d399;
      word-break: break-all;
      min-height: 38px;
      margin-bottom: 14px;
    }
    .hmac-box.empty { color: #374151; }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 10px 20px;
      border-radius: 8px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: opacity 0.2s, transform 0.1s;
    }
    .btn:active { transform: scale(0.97); }
    .btn-primary { background: #2563eb; color: #fff; }
    .btn-secondary { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
    .btn-danger { background: #7f1d1d; color: #fca5a5; }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }

    /* Response panel */
    .response-panel {
      margin-top: 18px;
      border-radius: 8px;
      overflow: hidden;
      display: none;
    }
    .response-panel.show { display: block; }
    .response-header {
      padding: 10px 14px;
      font-size: 0.82rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .response-header.success { background: #064e3b; color: #6ee7b7; }
    .response-header.error   { background: #7f1d1d; color: #fca5a5; }
    .response-header.warn    { background: #78350f; color: #fcd34d; }
    .response-body {
      background: #0f1117;
      border: 1px solid #1f2937;
      border-top: none;
      padding: 12px 14px;
      font-family: 'Courier New', monospace;
      font-size: 0.8rem;
      color: #d1d5db;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* Demo 3 scenarios */
    .scenarios { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 18px; }
    @media (max-width: 600px) { .scenarios { grid-template-columns: 1fr; } }
    .scenario-btn {
      padding: 14px 10px;
      border-radius: 8px;
      border: 1px solid #334155;
      background: #1e293b;
      color: #e2e8f0;
      cursor: pointer;
      font-size: 0.82rem;
      text-align: center;
      transition: border-color 0.2s, background 0.2s;
    }
    .scenario-btn:hover { border-color: #3b82f6; background: #1e3a5f; }
    .scenario-btn .s-title { font-weight: 600; margin-bottom: 4px; }
    .scenario-btn .s-desc { color: #64748b; font-size: 0.75rem; }

    /* Info box */
    .info-box {
      background: #0c1a2e;
      border: 1px solid #1e3a5f;
      border-radius: 8px;
      padding: 14px 16px;
      font-size: 0.82rem;
      color: #7dd3fc;
      margin-bottom: 18px;
      line-height: 1.6;
    }

    /* Divider */
    hr { border: none; border-top: 1px solid #1f2937; margin: 8px 0 20px; }

    .spinner {
      display: inline-block;
      width: 14px; height: 14px;
      border: 2px solid #ffffff44;
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
<div class="page">

  <header>
    <h1>🔐 HMAC Request Integrity Demo</h1>
    <p>Cryptography &amp; Network Security Lab — Flask Server</p>
    <span class="tag">Shrihari V &nbsp;|&nbsp; 23BCI0083</span>
  </header>

  <!-- ── CARD 1: Generate HMAC ── -->
  <div class="card">
    <div class="card-title">
      ⚙️ Generate HMAC
      <span class="badge">STEP 1</span>
    </div>
    <div class="info-box">
      Enter a message below to compute its HMAC-SHA256 using the shared secret key.
      The generated value must be included in the request so the server can verify integrity.
    </div>
    <div class="field">
      <label>Message (e.g. transfer=5000&amp;account=B)</label>
      <input type="text" id="gen-msg" value="transfer=5000&account=B" oninput="autoGenHmac()"/>
    </div>
    <label>Generated HMAC-SHA256</label>
    <div class="hmac-box" id="gen-hmac-out">—</div>
    <div class="btn-row">
      <button class="btn btn-primary" onclick="generateHmac()">Generate HMAC</button>
      <button class="btn btn-secondary" onclick="copyHmac()">Copy</button>
    </div>
  </div>

  <!-- ── CARD 2: Send Request ── -->
  <div class="card">
    <div class="card-title">
      📤 Send Transfer Request
      <span class="badge">STEP 2</span>
    </div>
    <div class="field">
      <label>Transfer Amount</label>
      <input type="text" id="req-transfer" value="5000"/>
    </div>
    <div class="field">
      <label>Account</label>
      <input type="text" id="req-account" value="B"/>
    </div>
    <div class="toggle-row">
      <label class="switch">
        <input type="checkbox" id="use-hmac" checked onchange="toggleHmacField()"/>
        <span class="slider"></span>
      </label>
      <span class="toggle-label">Include HMAC in request</span>
    </div>
    <div id="hmac-field-wrap">
      <div class="field">
        <label>HMAC Value <span style="color:#64748b;font-size:0.75rem">(paste from Step 1, or generate automatically)</span></label>
        <input type="text" id="req-hmac" placeholder="Paste HMAC here…"/>
      </div>
    </div>
    <div class="toggle-row" style="margin-top:4px">
      <label class="switch">
        <input type="checkbox" id="use-secure" checked/>
        <span class="slider"></span>
      </label>
      <span class="toggle-label">Use secure endpoint <code style="color:#64748b;font-size:0.8rem">/transfer</code> (toggle off for insecure)</span>
    </div>
    <div class="btn-row" style="margin-top:12px">
      <button class="btn btn-primary" id="send-btn" onclick="sendRequest()">Send Request</button>
      <button class="btn btn-secondary" onclick="fillFromGenerator()">↑ Use HMAC from Step 1</button>
    </div>

    <div class="response-panel" id="resp-panel">
      <div class="response-header" id="resp-header"></div>
      <div class="response-body" id="resp-body"></div>
    </div>
  </div>

  <!-- ── CARD 3: Quick Scenarios ── -->
  <div class="card">
    <div class="card-title">⚡ Quick Demo Scenarios</div>
    <div class="info-box">
      Click a scenario to auto-fill and run it instantly. These replicate the three key outcomes from the project.
    </div>
    <div class="scenarios">
      <div class="scenario-btn" onclick="runScenario('legit')">
        <div class="s-title">✅ Legitimate</div>
        <div class="s-desc">Valid HMAC, correct values — should be accepted (200)</div>
      </div>
      <div class="scenario-btn" onclick="runScenario('tampered')">
        <div class="s-title">❌ Tampered</div>
        <div class="s-desc">Modified amount, stale HMAC — should be rejected (403)</div>
      </div>
      <div class="scenario-btn" onclick="runScenario('insecure')">
        <div class="s-title">⚠️ No HMAC</div>
        <div class="s-desc">Tampered value, insecure endpoint — accepted blindly (200)</div>
      </div>
    </div>
    <div class="response-panel" id="quick-panel">
      <div class="response-header" id="quick-header"></div>
      <div class="response-body" id="quick-body"></div>
    </div>
  </div>

</div>

<script>
  // ── HMAC generation (client-side, matches server logic) ──
  async function computeHmac(message) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode('Shrihari_23BCI0083'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  let lastGeneratedHmac = '';

  async function generateHmac() {
    const msg = document.getElementById('gen-msg').value.trim();
    if (!msg) return;
    const h = await computeHmac(msg);
    lastGeneratedHmac = h;
    document.getElementById('gen-hmac-out').textContent = h;
    document.getElementById('gen-hmac-out').classList.remove('empty');
  }

  async function autoGenHmac() {
    const msg = document.getElementById('gen-msg').value.trim();
    if (!msg) { document.getElementById('gen-hmac-out').textContent = '—'; return; }
    const h = await computeHmac(msg);
    lastGeneratedHmac = h;
    document.getElementById('gen-hmac-out').textContent = h;
  }

  function copyHmac() {
    const txt = document.getElementById('gen-hmac-out').textContent;
    if (txt && txt !== '—') navigator.clipboard.writeText(txt);
  }

  function fillFromGenerator() {
    document.getElementById('req-hmac').value = lastGeneratedHmac;
  }

  function toggleHmacField() {
    const wrap = document.getElementById('hmac-field-wrap');
    wrap.style.display = document.getElementById('use-hmac').checked ? 'block' : 'none';
  }

  // ── Send request ──
  async function sendRequest() {
    const transfer = document.getElementById('req-transfer').value.trim();
    const account  = document.getElementById('req-account').value.trim();
    const useHmac  = document.getElementById('use-hmac').checked;
    const useSecure = document.getElementById('use-secure').checked;
    const hmacVal  = document.getElementById('req-hmac').value.trim();

    const endpoint = useSecure ? '/transfer' : '/transfer-no-hmac';
    let params = `transfer=${encodeURIComponent(transfer)}&account=${encodeURIComponent(account)}`;
    if (useHmac && useSecure) params += `&hmac=${encodeURIComponent(hmacVal)}`;

    const btn = document.getElementById('send-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Sending…';

    try {
      const res = await fetch(`${endpoint}?${params}`, { method: 'POST' });
      const data = await res.json();
      showResponse('resp-panel', 'resp-header', 'resp-body', res.status, data);
    } catch(e) {
      showResponse('resp-panel', 'resp-header', 'resp-body', 0, { error: e.message });
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Send Request';
    }
  }

  // ── Quick scenarios ──
  async function runScenario(type) {
    let transfer, account, hmacVal, endpoint, params;

    if (type === 'legit') {
      transfer = '5000'; account = 'B';
      hmacVal = await computeHmac(`transfer=${transfer}&account=${account}`);
      endpoint = '/transfer';
      params = `transfer=${transfer}&account=${account}&hmac=${hmacVal}`;
    } else if (type === 'tampered') {
      const originalHmac = await computeHmac('transfer=5000&account=B');
      transfer = '9000'; account = 'B'; // tampered amount
      endpoint = '/transfer';
      params = `transfer=${transfer}&account=${account}&hmac=${originalHmac}`;
    } else {
      transfer = '9000'; account = 'B';
      endpoint = '/transfer-no-hmac';
      params = `transfer=${transfer}&account=${account}`;
    }

    try {
      const res = await fetch(`${endpoint}?${params}`, { method: 'POST' });
      const data = await res.json();
      showResponse('quick-panel', 'quick-header', 'quick-body', res.status, data);
    } catch(e) {
      showResponse('quick-panel', 'quick-header', 'quick-body', 0, { error: e.message });
    }
  }

  function showResponse(panelId, headerId, bodyId, status, data) {
    const panel  = document.getElementById(panelId);
    const header = document.getElementById(headerId);
    const body   = document.getElementById(bodyId);

    panel.classList.add('show');

    let cls, icon, label;
    if (status === 200) {
      cls = data.message && data.message.includes('NO integrity') ? 'warn' : 'success';
      icon = cls === 'warn' ? '⚠️' : '✅';
      label = `${status} OK`;
    } else if (status === 403) {
      cls = 'error'; icon = '❌'; label = `${status} Forbidden — Tamper detected`;
    } else if (status === 400) {
      cls = 'error'; icon = '⚠️'; label = `${status} Bad Request`;
    } else {
      cls = 'error'; icon = '⚠️'; label = `Error`;
    }

    header.className = `response-header ${cls}`;
    header.innerHTML = `${icon} &nbsp; ${label}`;
    body.textContent = JSON.stringify(data, null, 2);
  }

  // Auto-generate HMAC on load
  autoGenHmac();
</script>
</body>
</html>"""


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/transfer", methods=["POST"])
def transfer():
    transfer_amount = request.args.get("transfer")
    account = request.args.get("account")
    provided_hmac = request.args.get("hmac")

    if not all([transfer_amount, account, provided_hmac]):
        return jsonify({
            "status": "error",
            "message": "Missing parameters. Required: transfer, account, hmac"
        }), 400

    message = f"transfer={transfer_amount}&account={account}"

    if verify_hmac(message, provided_hmac):
        return jsonify({
            "status": "success",
            "message": "Request accepted. HMAC verified — data integrity confirmed.",
            "data": {"transfer": transfer_amount, "account": account}
        }), 200
    else:
        return jsonify({
            "status": "rejected",
            "message": "Request rejected. HMAC mismatch — possible tampering detected.",
            "provided_hmac": provided_hmac,
            "expected_hmac": generate_hmac(f"transfer={transfer_amount}&account={account}")
        }), 403


@app.route("/transfer-no-hmac", methods=["POST"])
def transfer_no_hmac():
    transfer_amount = request.args.get("transfer")
    account = request.args.get("account")

    if not all([transfer_amount, account]):
        return jsonify({
            "status": "error",
            "message": "Missing parameters."
        }), 400

    return jsonify({
        "status": "success",
        "message": "Request accepted (NO integrity check — vulnerable endpoint).",
        "data": {"transfer": transfer_amount, "account": account}
    }), 200


if __name__ == "__main__":
    print("Starting HMAC verification server on http://127.0.0.1:5000")
    print(f"Secret key in use: {SECRET_KEY}")
    app.run(debug=True)