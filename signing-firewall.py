#!/usr/bin/env python3
"""
Signing Firewall - a real policy proxy that sits between a payout app
and the thing that actually signs / sends money.

What it does, for real (not a UI animation):
  * Every transfer is a real API request to this server.
  * The firewall REJECTS requests that fail policy: unknown destination,
    single approval for a large transfer, velocity breach, or a frozen system.
  * Large transfers wait out a timelock before they can be released.
  * The Watchtower polls a real Ethereum RPC with eth_getCode and, if a
    watched wallet delegates (EIP-7702) to an address that is not allowlisted,
    it freezes the whole system and writes it to the hash-chained audit log.
  * It never holds private keys and never signs anything itself.

Usage:
  python signing-firewall.py serve
  python signing-firewall.py serve --port 8765
  python signing-firewall.py dashboard
  python signing-firewall.py dashboard --once
  python signing-firewall.py watchtower --address 0x28C6c06298d514Db089934071355E5743bf21d60

Web app:  http://127.0.0.1:8765/  (when serve is running)
Terminal: python signing-firewall.py dashboard  (works in Terminal, cmd, PowerShell)

Python 3.9+ only, standard library only. No pip packages required.
This works on Linux, macOS and Windows.
"""
import argparse
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.0"
DEFAULT_PORT = 8765
DEFAULT_RPC = "https://ethereum.publicnode.com"

DEFAULT_CONFIG = {
    "port": DEFAULT_PORT,
    "host": "127.0.0.1",
    "dual_approval_threshold": 10000,
    "timelock_threshold": 100000,
    "timelock_seconds": 60,
    "velocity_limit": 50000,
    "velocity_window_seconds": 600,
    "allowlist": ["vendor-001", "payroll-001", "ops-001"],
    "allowed_delegations": [],
    "rpc_url": DEFAULT_RPC,
    "watch_interval_seconds": 60,
    "watched_addresses": [],
}


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_config(path, overrides):
    cfg = dict(DEFAULT_CONFIG)
    cfg["allowlist"] = list(DEFAULT_CONFIG["allowlist"])
    cfg["allowed_delegations"] = list(DEFAULT_CONFIG["allowed_delegations"])
    cfg["watched_addresses"] = list(DEFAULT_CONFIG["watched_addresses"])
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        for k, v in loaded.items():
            cfg[k] = v
    for k, v in overrides.items():
        if v is not None:
            cfg[k] = v
    return cfg


class State:
    def __init__(self, config, data_dir=None):
        self.config = config
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.started_at = now_iso()
        self.transfers = {}
        self.next_id = 1
        self.frozen = False
        self.freeze_reason = ""
        self.audit = []
        self.approved_in_window = []  # list of (epoch, amount)
        self.watch = {}  # address -> dict
        for addr in config.get("watched_addresses", []):
            self.watch[addr] = {
                "address": addr, "status": "NOT_CHECKED", "code": "",
                "delegated_to": "", "last_checked": "", "error": "",
            }
        if data_dir:
            try:
                os.makedirs(data_dir, exist_ok=True)
            except OSError:
                pass

    def audit_log(self, kind, detail):
        prev = self.audit[-1]["hash"] if self.audit else "0" * 64
        payload = json.dumps({"prev": prev, "kind": kind, "detail": detail},
                             sort_keys=True)
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry = {"time": now_iso(), "kind": kind, "detail": detail,
                 "prev_hash": prev, "hash": h}
        self.audit.append(entry)
        if self.data_dir:
            try:
                with open(os.path.join(self.data_dir, "audit.log"), "a",
                          encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError:
                pass
        return entry

    def velocity_sum(self):
        now = time.time()
        window = self.config["velocity_window_seconds"]
        self.approved_in_window = [(t, a) for (t, a) in self.approved_in_window
                                   if now - t <= window]
        return sum(a for _, a in self.approved_in_window)


def verify_audit_chain(audit):
    prev = "0" * 64
    for entry in audit:
        payload = json.dumps({"prev": prev, "kind": entry["kind"],
                              "detail": entry["detail"]}, sort_keys=True)
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != entry["hash"]:
            return False
        if entry["prev_hash"] != prev:
            return False
        prev = entry["hash"]
    return True


# ---------------- Policy engine (this is the real gate) ----------------

def propose_transfer(state, from_account, to_account, amount):
    with state.lock:
        if state.frozen:
            state.audit_log("BLOCKED_FROZEN", {"to": to_account, "amount": amount})
            return None, "system is frozen: " + state.freeze_reason
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return None, "amount must be a number"
        if amount <= 0:
            return None, "amount must be positive"
        if to_account not in state.config["allowlist"]:
            state.audit_log("BLOCKED_ALLOWLIST", {"to": to_account, "amount": amount})
            return None, "destination is not allowlisted"
        tid = "TF-%04d" % state.next_id
        state.next_id += 1
        required = 1 if amount < state.config["dual_approval_threshold"] else 2
        timelock_until = ""
        if amount >= state.config["timelock_threshold"]:
            timelock_until = datetime.fromtimestamp(
                time.time() + state.config["timelock_seconds"],
                tz=timezone.utc).isoformat().replace("+00:00", "Z")
        tr = {
            "id": tid, "from": from_account, "to": to_account, "amount": amount,
            "status": "PENDING", "approvals": [], "required_approvals": required,
            "timelock_until": timelock_until, "created_at": now_iso(),
        }
        state.transfers[tid] = tr
        state.audit_log("PROPOSED", {"id": tid, "to": to_account, "amount": amount})
        return tr, ""


def _try_approve_locked(state, tr):
    """Assumes state.lock is held. Returns (ok, message)."""
    if tr["timelock_until"]:
        # Compare ISO timestamps lexicographically; both are UTC Z format.
        if now_iso() < tr["timelock_until"]:
            tr["status"] = "WAITING_TIMELOCK"
            return False, "timelock has not expired yet: " + tr["timelock_until"]
    vel = state.velocity_sum() + tr["amount"]
    if vel > state.config["velocity_limit"]:
        tr["status"] = "BLOCKED_VELOCITY"
        state.frozen = True
        state.freeze_reason = "velocity limit breached by " + tr["id"]
        state.audit_log("VELOCITY_FREEZE", {"id": tr["id"], "velocity": vel,
                                            "limit": state.config["velocity_limit"]})
        return False, "velocity limit breached, system frozen"
    tr["status"] = "APPROVED"
    state.approved_in_window.append((time.time(), tr["amount"]))
    state.audit_log("APPROVED", {"id": tr["id"], "to": tr["to"], "amount": tr["amount"]})
    return True, "approved"


def approve_transfer(state, tid, approver):
    with state.lock:
        if state.frozen:
            return None, "system is frozen: " + state.freeze_reason
        tr = state.transfers.get(tid)
        if not tr:
            return None, "transfer not found"
        if tr["status"] in ("APPROVED", "BLOCKED_VELOCITY", "BLOCKED_ALLOWLIST"):
            return None, "transfer is already " + tr["status"]
        if approver in tr["approvals"]:
            return None, "approver has already approved this transfer"
        tr["approvals"].append(approver)
        if len(tr["approvals"]) < tr["required_approvals"]:
            tr["status"] = "PENDING"
            state.audit_log("APPROVAL", {"id": tid, "approver": approver,
                                         "count": len(tr["approvals"])})
            return tr, "approval recorded, waiting for more approvals"
        ok, msg = _try_approve_locked(state, tr)
        if not ok and tr["status"] != "BLOCKED_VELOCITY":
            state.audit_log("APPROVAL", {"id": tid, "approver": approver,
                                         "count": len(tr["approvals"])})
        return tr, msg


def release_transfer(state, tid):
    with state.lock:
        tr = state.transfers.get(tid)
        if not tr:
            return None, "transfer not found"
        if tr["status"] != "WAITING_TIMELOCK":
            return None, "transfer is not waiting for timelock"
        if state.frozen:
            return None, "system is frozen: " + state.freeze_reason
        if len(tr["approvals"]) < tr["required_approvals"]:
            return None, "not enough approvals yet"
        ok, msg = _try_approve_locked(state, tr)
        return tr, msg


def set_frozen(state, frozen, reason):
    with state.lock:
        state.frozen = frozen
        state.freeze_reason = reason if frozen else ""
        state.audit_log("FROZEN" if frozen else "UNFROZEN", {"reason": reason})
        return True


# ---------------- Watchtower: real EIP-7702 delegation detection ----------------

def parse_delegation(code):
    """Return delegated address, or '' if not delegated, or 'OTHER_CODE'."""
    if not code or code in ("0x", "0X"):
        return ""
    c = code.lower()
    if c.startswith("0xef0100") and len(c) == 48:
        return "0x" + c[8:]
    return "OTHER_CODE"


def rpc_get_code(rpc_url, address):
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
        "params": [address, "latest"],
    }).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Signing-Firewall/" + VERSION})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if "error" in data and data["error"]:
        raise ValueError(str(data["error"]))
    return data.get("result", "")


def check_watchtower(state, rpc_func=None):
    """Check every watched address. On unauthorised delegation, freeze.
    rpc_func(address) -> code, injectable for tests. Returns list of results."""
    func = rpc_func or (lambda addr: rpc_get_code(state.config["rpc_url"], addr))
    allowed = {a.lower() for a in state.config.get("allowed_delegations", [])}
    results = []
    with state.lock:
        addrs = list(state.watch.keys())
    for addr in addrs:
        try:
            code = func(addr)
            delegated = parse_delegation(code)
            status = "OK"
            if delegated == "OTHER_CODE":
                status = "CODE_PRESENT"
            elif delegated and delegated.lower() not in allowed:
                status = "ALERT_UNAUTHORISED_DELEGATION"
            entry = {"address": addr, "status": status, "code": code,
                     "delegated_to": delegated if delegated != "OTHER_CODE" else "",
                     "last_checked": now_iso(), "error": ""}
            with state.lock:
                state.watch[addr] = entry
            if status == "ALERT_UNAUTHORISED_DELEGATION":
                set_frozen(state, True,
                           "watchtower: unauthorised delegation on " + addr)
                with state.lock:
                    state.audit_log("WATCHTOWER_ALERT",
                                    {"address": addr, "delegated_to": delegated})
            results.append(entry)
        except Exception as exc:  # network/RPC failure: report, do NOT freeze
            entry = {"address": addr, "status": "ERROR", "code": "",
                     "delegated_to": "", "last_checked": now_iso(),
                     "error": str(exc)}
            with state.lock:
                state.watch[addr] = entry
            results.append(entry)
    return results


def watchtower_loop(state, interval, stop_event):
    while not stop_event.is_set():
        try:
            check_watchtower(state)
        except Exception:
            pass
        stop_event.wait(interval)


# ---------------- Web app (served by the same server, no dependencies) ----------------

WEB_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signing Firewall</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
header{background:#111827;padding:18px 22px;border-bottom:3px solid #22c55e}
h1{margin:0;font-size:22px} p.sub{margin:4px 0 0;color:#94a3b8}
main{max-width:1100px;margin:0 auto;padding:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:#1e293b;border-radius:12px;padding:14px}
.card b{font-size:22px;display:block}
.card span{color:#94a3b8;font-size:13px}
section{background:#1e293b;border-radius:12px;padding:16px;margin-top:14px}
h2{margin-top:0;font-size:17px}
table{width:100%;border-collapse:collapse;font-size:14px} th,td{text-align:left;padding:6px;border-bottom:1px solid #334155}
input,button{padding:8px 10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;margin:3px}
button{background:#22c55e;color:#052e16;border:none;font-weight:700;cursor:pointer}
button.danger{background:#ef4444;color:#fff}
.bar{height:14px;background:#334155;border-radius:7px;overflow:hidden}
.bar div{height:100%;background:#22c55e}
.frozen{background:#7f1d1d!important;border-color:#ef4444!important}
code{word-break:break-all}
small{color:#94a3b8}
</style></head><body>
<header><h1>Signing Firewall</h1><p class="sub">Policy proxy in front of your signer. It can say no, in real time. No private keys are held here.</p></header>
<main>
<div id="status"></div>
<div class="cards" id="cards"></div>
<section><h2>Velocity (last window)</h2><div class="bar"><div id="velbar"></div></div><p id="veltext"></p>
<small>When velocity is breached, the system freezes and stays frozen until an admin unfreezes it with a reason.</small></section>
<section><h2>Propose a transfer</h2>
<input id="from" placeholder="From account" value="ops-001">
<input id="to" placeholder="To (allowlisted)" value="vendor-001">
<input id="amount" type="number" placeholder="Amount" value="5000">
<button onclick="propose()">Propose</button><span id="proposeMsg"></span>
<small><br>Default allowlist: vendor-001, payroll-001, ops-001. Edit config.json to change it.</small></section>
<section><h2>Pending / waiting transfers</h2><div id="pending"></div>
<input id="approver" placeholder="Approver name" value="alice">
<small>Large transfers need 2 different approvers. Very large transfers also wait out a timelock, then use Release.</small></section>
<section><h2>Freeze control</h2>
<input id="freezeReason" placeholder="Reason" value="manual review">
<button class="danger" onclick="freezeIt()">Freeze all</button>
<button onclick="unfreezeIt()">Unfreeze</button><span id="freezeMsg"></span></section>
<section><h2>Watchtower (EIP-7702)</h2>
<input id="watchAddr" placeholder="0x wallet address" size="46">
<button onclick="addWatch()">Watch address</button>
<button onclick="checkWatch()">Check now</button><div id="watch"></div>
<small>Watchtower uses a real public RPC (eth_getCode). A delegated wallet has code starting 0xef0100. An unauthorised delegation freezes the system. RPC errors do not freeze, they are reported.</small></section>
<section><h2>Recent audit events (hash-chained)</h2><div id="events"></div></section>
<section><h2>About / limits</h2><p><small>
This tool only helps if it is deployed separately from the app that requests transfers, with separate credentials. It does not replace an HSM, threshold signing, or a cold wallet. Once a valid signature is broadcast on-chain it cannot be un-signed, which is why timelocks and pre-signing policy matter. Start on testnet / with test accounts, never with mainnet keys.</small></p></section>
</main>
<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return r.json()}
async function refresh(){
 const s=await api('/api/state');
 document.getElementById('status').innerHTML='<section class="'+(s.frozen?'frozen':'')+'"><b>Status: '+(s.frozen?'FROZEN - '+esc(s.freeze_reason):'LIVE')+'</b></section>';
 document.getElementById('cards').innerHTML=
  '<div class="card"><b>'+s.counts.total+'</b><span>Total transfers</span></div>'+
  '<div class="card"><b>'+s.counts.approved+'</b><span>Approved</span></div>'+
  '<div class="card"><b>'+s.counts.pending+'</b><span>Pending / waiting</span></div>'+
  '<div class="card"><b>'+s.counts.blocked+'</b><span>Blocked</span></div>'+
  '<div class="card"><b>'+Object.keys(s.watch).length+'</b><span>Watched wallets</span></div>';
 const pct=Math.min(100,Math.round(s.velocity.value/s.velocity.limit*100));
 document.getElementById('velbar').style.width=pct+'%';
 document.getElementById('veltext').textContent=s.velocity.value+' / '+s.velocity.limit+' in the last '+s.velocity.window_seconds+'s ('+pct+'%)';
 document.getElementById('pending').innerHTML='<table><tr><th>ID</th><th>From -&gt; To</th><th>Amount</th><th>Approvals</th><th>Status</th><th>Action</th></tr>'+
  s.transfers.map(t=>'<tr><td>'+esc(t.id)+'</td><td>'+esc(t.from)+' -&gt; '+esc(t.to)+'</td><td>'+esc(t.amount)+'</td><td>'+t.approvals.length+' / '+t.required_approvals+'</td><td>'+esc(t.status)+'</td><td><button onclick="approve(\''+t.id+'\')">Approve</button> '+(t.status==='WAITING_TIMELOCK'?'<button onclick="releaseIt(\''+t.id+'\')">Release</button>':'')+'</td></tr>').join('')+'</table>';
 document.getElementById('watch').innerHTML='<table><tr><th>Address</th><th>Status</th><th>Delegated to</th><th>Last checked</th></tr>'+
  Object.values(s.watch).map(w=>'<tr><td><code>'+esc(w.address)+'</code></td><td>'+esc(w.status)+'</td><td><code>'+esc(w.delegated_to)+'</code></td><td>'+esc(w.last_checked)+'</td></tr>').join('')+'</table>';
 document.getElementById('events').innerHTML=s.audit.slice(-12).reverse().map(e=>'<div><code>'+esc(e.time)+'</code> <b>'+esc(e.kind)+'</b> '+esc(JSON.stringify(e.detail))+'</div>').join('');
}
async function propose(){const r=await api('/api/transfers',{from_account:document.getElementById('from').value,to_account:document.getElementById('to').value,amount:parseFloat(document.getElementById('amount').value)});document.getElementById('proposeMsg').textContent=r.error||('Created '+r.transfer.id);refresh()}
async function approve(id){const a=document.getElementById('approver').value||'alice';const r=await api('/api/transfers/'+id+'/approve',{approver:a});if(r.error)alert(r.error);refresh()}
async function releaseIt(id){const r=await api('/api/transfers/'+id+'/release',{});if(r.error)alert(r.error);refresh()}
async function freezeIt(){await api('/api/freeze',{reason:document.getElementById('freezeReason').value});refresh()}
async function unfreezeIt(){await api('/api/unfreeze',{reason:document.getElementById('freezeReason').value});refresh()}
async function addWatch(){const r=await api('/api/watchtower',{address:document.getElementById('watchAddr').value});if(r.error)alert(r.error);refresh()}
async function checkWatch(){await api('/api/watchtower/check',{});refresh()}
refresh(); setInterval(refresh,1000);
</script></body></html>
"""


def state_to_json(state):
    with state.lock:
        transfers = sorted(state.transfers.values(), key=lambda t: t["id"])
        counts = {
            "total": len(transfers),
            "approved": sum(1 for t in transfers if t["status"] == "APPROVED"),
            "pending": sum(1 for t in transfers if t["status"] in ("PENDING", "WAITING_TIMELOCK")),
            "blocked": sum(1 for t in transfers if t["status"].startswith("BLOCKED")),
        }
        vel = state.velocity_sum()
        return {
            "version": VERSION, "started_at": state.started_at,
            "frozen": state.frozen, "freeze_reason": state.freeze_reason,
            "counts": counts, "transfers": transfers,
            "velocity": {"value": vel, "limit": state.config["velocity_limit"],
                         "window_seconds": state.config["velocity_window_seconds"]},
            "watch": state.watch, "audit": state.audit[-50:],
            "config": {"dual_approval_threshold": state.config["dual_approval_threshold"],
                       "timelock_threshold": state.config["timelock_threshold"],
                       "timelock_seconds": state.config["timelock_seconds"],
                       "allowlist": state.config["allowlist"],
                       "rpc_url": state.config["rpc_url"]},
        }


class Handler(BaseHTTPRequestHandler):
    state = None

    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = WEB_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/state":
            self._json(state_to_json(self.state))
        elif self.path == "/api/health":
            self._json({"ok": True, "version": VERSION})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        body = self._read_json()
        st = self.state
        if self.path == "/api/transfers":
            tr, err = propose_transfer(st, body.get("from_account", ""),
                                       body.get("to_account", ""), body.get("amount"))
            if err:
                self._json({"error": err}, 403)
            else:
                self._json({"transfer": tr})
        elif self.path.startswith("/api/transfers/") and self.path.endswith("/approve"):
            tid = self.path.split("/")[3]
            tr, msg = approve_transfer(st, tid, body.get("approver", ""))
            if tr is None:
                self._json({"error": msg}, 403)
            else:
                self._json({"transfer": tr, "message": msg})
        elif self.path.startswith("/api/transfers/") and self.path.endswith("/release"):
            tid = self.path.split("/")[3]
            tr, msg = release_transfer(st, tid)
            if tr is None:
                self._json({"error": msg}, 403)
            else:
                self._json({"transfer": tr, "message": msg})
        elif self.path == "/api/freeze":
            set_frozen(st, True, body.get("reason", "manual"))
            self._json({"frozen": True})
        elif self.path == "/api/unfreeze":
            set_frozen(st, False, body.get("reason", "manual"))
            self._json({"frozen": False})
        elif self.path == "/api/watchtower":
            addr = (body.get("address") or "").strip()
            if not addr:
                self._json({"error": "address required"}, 400)
            else:
                with st.lock:
                    st.watch[addr] = {"address": addr, "status": "NOT_CHECKED",
                                      "code": "", "delegated_to": "",
                                      "last_checked": "", "error": ""}
                self._json({"watched": addr})
        elif self.path == "/api/watchtower/check":
            results = check_watchtower(st)
            self._json({"results": results, "frozen": st.frozen})
        else:
            self._json({"error": "not found"}, 404)


def run_server(config, data_dir):
    state = State(config, data_dir=data_dir)
    Handler.state = state
    server = ThreadingHTTPServer((config["host"], config["port"]), Handler)
    stop = threading.Event()
    watch_thread = None
    if config.get("watch_interval_seconds"):
        watch_thread = threading.Thread(target=watchtower_loop,
                                        args=(state, config["watch_interval_seconds"], stop),
                                        daemon=True)
        watch_thread.start()
    print("Signing Firewall %s" % VERSION)
    print("Web app:  http://%s:%s/" % (config["host"], config["port"]))
    print("Terminal: python signing-firewall.py dashboard --url http://%s:%s"
          % (config["host"], config["port"]))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.shutdown()


# ---------------- Terminal dashboard (Terminal / cmd / PowerShell) ----------------

def _bar(pct, width=40):
    filled = int(max(0, min(1, pct)) * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def render_terminal(state_json, no_color=False):
    def c(code, text):
        return text if no_color else ("\033[%sm%s\033[0m" % (code, text))
    frozen = state_json.get("frozen")
    counts = state_json.get("counts", {})
    vel = state_json.get("velocity", {})
    pct = (vel.get("value", 0) / vel["limit"]) if vel.get("limit") else 0
    lines = []
    lines.append("=" * 78)
    lines.append("  SIGNING FIREWALL  -  live terminal dashboard  (v%s)" % VERSION)
    lines.append("=" * 78)
    status = "FROZEN - " + state_json.get("freeze_reason", "") if frozen else "LIVE"
    lines.append("  Status : " + c("31" if frozen else "32", status))
    lines.append("  Started: %s" % state_json.get("started_at", ""))
    lines.append("")
    lines.append("  Transfers: total %s | approved %s | pending %s | blocked %s" % (
        counts.get("total", 0), counts.get("approved", 0),
        counts.get("pending", 0), counts.get("blocked", 0)))
    lines.append("  Velocity: %s %s %s%%  (%s / %s per %ss)" % (
        _bar(pct), "", int(pct * 100), vel.get("value", 0), vel.get("limit", 0),
        vel.get("window_seconds", 0)))
    lines.append("")
    lines.append("  PENDING / WAITING TRANSFERS")
    lines.append("  " + "-" * 74)
    pending = [t for t in state_json.get("transfers", [])
               if t["status"] in ("PENDING", "WAITING_TIMELOCK")]
    if not pending:
        lines.append("  (none)")
    for t in pending:
        lines.append("  %s  %s -> %s  %s  approvals %d/%d  %s" % (
            t["id"], t["from"], t["to"], t["amount"],
            len(t["approvals"]), t["required_approvals"], t["status"]))
    lines.append("")
    lines.append("  WATCHTOWER (EIP-7702)")
    lines.append("  " + "-" * 74)
    watch = state_json.get("watch", {})
    if not watch:
        lines.append("  (no wallets watched yet - add one in the web app or API)")
    for w in watch.values():
        lines.append("  %s  %s  delegated=%s  %s" % (
            w["address"][:20] + "...", w["status"],
            w.get("delegated_to") or "-", w.get("last_checked", "")))
    lines.append("")
    lines.append("  RECENT AUDIT EVENTS")
    lines.append("  " + "-" * 74)
    for e in state_json.get("audit", [])[-8:]:
        lines.append("  %s  %-28s  %s" % (
            e["time"][11:19], e["kind"], json.dumps(e["detail"])[:70]))
    lines.append("")
    lines.append("  Press Ctrl+C to exit. This dashboard polls the live server every second.")
    lines.append("=" * 78)
    return "\n".join(lines)


def fetch_state(url):
    url = url.rstrip("/") + "/api/state"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_dashboard(url, interval, once, no_color):
    if os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass
    if once:
        try:
            print(render_terminal(fetch_state(url), no_color=no_color))
        except Exception as exc:
            print("Could not reach server at %s : %s" % (url, exc))
            print("Start it first: python signing-firewall.py serve")
            return 1
        return 0
    while True:
        try:
            if os.name == "nt":
                os.system("cls")
            else:
                sys.stdout.write("\033[2J\033[H")
            print(render_terminal(fetch_state(url), no_color=no_color))
        except KeyboardInterrupt:
            print("\nDashboard stopped.")
            return 0
        except Exception as exc:
            print("Waiting for server at %s : %s" % (url, exc))
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nDashboard stopped.")
            return 0


# ---------------- CLI ----------------

def main(argv=None):
    parser = argparse.ArgumentParser(prog="signing-firewall",
                                     description="Signing Firewall - policy proxy + EIP-7702 Watchtower")
    parser.add_argument("--version", action="store_true", help="print version")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="start web app + API server")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--config", default=None)
    p_serve.add_argument("--data-dir", default="signing-firewall-data")
    p_serve.add_argument("--rpc-url", default=None)
    p_serve.add_argument("--watch-interval", type=int, default=None)
    p_serve.add_argument("--no-watch", action="store_true")

    p_dash = sub.add_parser("dashboard", help="terminal dashboard (Terminal/cmd/PowerShell)")
    p_dash.add_argument("--url", default="http://127.0.0.1:8765")
    p_dash.add_argument("--interval", type=float, default=1.0)
    p_dash.add_argument("--once", action="store_true", help="print one frame and exit")
    p_dash.add_argument("--no-color", action="store_true")

    p_watch = sub.add_parser("watchtower", help="one-shot EIP-7702 check for real wallets")
    p_watch.add_argument("--address", action="append", required=True)
    p_watch.add_argument("--rpc-url", default=None)
    p_watch.add_argument("--allowed-delegation", action="append", default=[])

    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    if args.cmd == "serve":
        overrides = {"host": args.host, "port": args.port, "rpc_url": args.rpc_url}
        if args.watch_interval is not None:
            overrides["watch_interval_seconds"] = args.watch_interval
        if args.no_watch:
            overrides["watch_interval_seconds"] = 0
        config = load_config(args.config, overrides)
        run_server(config, args.data_dir)
        return 0
    if args.cmd == "dashboard":
        return run_dashboard(args.url, args.interval, args.once, args.no_color)
    if args.cmd == "watchtower":
        cfg = dict(DEFAULT_CONFIG)
        cfg["rpc_url"] = args.rpc_url or DEFAULT_RPC
        cfg["allowed_delegations"] = args.allowed_delegation
        state = State(cfg)
        for addr in args.address:
            state.watch[addr] = {"address": addr, "status": "NOT_CHECKED",
                                 "code": "", "delegated_to": "",
                                 "last_checked": "", "error": ""}
        results = check_watchtower(state)
        alert = False
        for r in results:
            print("%s  %s  delegated_to=%s  %s" % (
                r["address"], r["status"], r.get("delegated_to") or "-",
                r.get("error") or ""))
            if r["status"] == "ALERT_UNAUTHORISED_DELEGATION":
                alert = True
        return 1 if alert else 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
