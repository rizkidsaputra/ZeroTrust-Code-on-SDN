#!/usr/bin/env python3
"""
ZTNA Policy Engine (PDP) — versi ONOS.
Berjalan di VM1 bersama ONOS controller.

Perbedaan utama vs versi OpenDaylight:
  * REST endpoint  : http://<onos>:8181/onos/v1/flows/{deviceId}
  * Auth           : onos / rocks
  * Device id      : of:0000000000000001  (bukan openflow:1)
  * Flow JSON      : selector/criteria + treatment/instructions (bukan MD-SAL)
  * Flow id        : dibuat ONOS, dibaca dari header Location pada response POST
  * PENTING        : app org.onosproject.fwd (reactive forwarding) HARUS
                     dinonaktifkan, kalau tidak deny-by-default bocor —
                     ini masalah yang sama dengan odl-l2switch di versi ODL.

Run:   pip install flask requests
       sudo python3 pdp_onos.py
Test:  python3 pdp_onos.py --dry-run
"""

import argparse
import ipaddress
import time
import uuid
from datetime import datetime

import requests
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
ONOS_HOST = "192.168.13.5"
ONOS_PORT = 8181
ONOS_AUTH = ("onos", "rocks")
ONOS_BASE = f"http://{ONOS_HOST}:{ONOS_PORT}/onos/v1"
APP_ID    = "org.onosproject.rest"   # appId pemilik flow yang kita push

PDP_IP      = "192.168.13.5"
DATA_SUBNET = "10.0.0.0/24"
ALLOWED_HOURS = range(0, 24)

W_R, W_C, W_B = 0.5, 0.3, 0.2
TIER_FULL, TIER_LIMITED = 70, 40

R_BY_ROLE = {"research": 80, "server": 95, "iot": 50, "guest": 30, "security": 90}

USERS = {
    "alice":  {"password": "research123", "role": "research"},
    "bob":    {"password": "guest123",    "role": "guest"},
    "sensor": {"password": "iot123",      "role": "iot"},       # demo IoT -> log
}

# ---------------------------------------------------------------------------
# TOPOLOGY — FULL MESH 5 switch (K5), host di port 1 switch-nya sendiri.
#   s1 Research | s2 Server | s3 IoT | s4 Guest | s5 Security (log collector)
#
# Skema port HARUS identik dengan ztna_net_onos_mesh.py:
#   port ke switch lain = 2 + index switch tujuan di daftar switch lainnya
#   contoh  s1: ->s2=2 ->s3=3 ->s4=4 ->s5=5
#           s5: ->s1=2 ->s2=3 ->s3=4 ->s4=5
# device id ONOS = of: + dpid 16 hex digit
# ---------------------------------------------------------------------------
SWITCH_IDS = [1, 2, 3, 4, 5]
SW = {i: "of:%016x" % i for i in SWITCH_IDS}


def _others(i):
    return [j for j in SWITCH_IDS if j != i]


def _port_to(i, j):
    return 2 + _others(i).index(j)


HOST = {  # ip -> (segment, mac, device-id)
    "10.0.0.1": ("research", "00:00:00:00:00:01", SW[1]),
    "10.0.0.2": ("server",   "00:00:00:00:00:02", SW[2]),
    "10.0.0.3": ("iot",      "00:00:00:00:00:03", SW[3]),
    "10.0.0.4": ("guest",    "00:00:00:00:00:04", SW[4]),
    "10.0.0.5": ("security", "00:00:00:00:00:05", SW[5]),
}
SEG_IP = {seg: ip for ip, (seg, _, _) in HOST.items()}
HOST_PORT = 1

# full mesh: setiap switch bertetangga dengan semua switch lain
ADJ = {SW[i]: [SW[j] for j in _others(i)] for i in SWITCH_IDS}
LINK_PORT = {(SW[i], SW[j]): _port_to(i, j)
             for i in SWITCH_IDS for j in _others(i)}

# ---------------------------------------------------------------------------
# POLICY  (segmen -> {segmen-tujuan: [tcp dst port yang diizinkan]})
#
# Catatan desain:
#   * Guest terisolasi penuh (tidak boleh ke mana pun).
#   * Server tidak menginisiasi ke segmen data (no lateral movement),
#     kecuali mengirim log ke Security.
#   * Security bersifat RECEIVE-ONLY: entitlement-nya kosong. Host monitoring
#     yang bisa menjangkau semua segmen justru jadi titik pivot paling empuk
#     bagi penyerang, jadi ia hanya boleh menerima, tidak pernah memulai.
# ---------------------------------------------------------------------------
PORT_SYSLOG = 514      # kanal pengiriman log ke Security

POLICY = {
    "research": {"server": [8080, 9000, 22], "iot": [80], "security": [PORT_SYSLOG]},
    "iot":      {"server": [9000], "security": [PORT_SYSLOG]},
    "server":   {"security": [PORT_SYSLOG]},
    "guest":    {},
    "security": {},                       # receive-only
}
MIN_SCORE = {
    "server":   TIER_FULL,
    "iot":      TIER_LIMITED,
    "guest":    TIER_LIMITED,
    "security": TIER_FULL,                # kanal log hanya untuk sesi tepercaya
}
LIMITED_PORTS = {80, 8080}

# ---------------------------------------------------------------------------
app = Flask(__name__)
SESSION = requests.Session()
SESSIONS = {}          # token -> dict(user, role, ip, mac, flows=[(device, flowId)])
DRY_RUN = False


# ---------- trust scoring --------------------------------------------------
def context_score(ip, reported_mac):
    score, reasons = 100, []
    try:
        in_subnet = ipaddress.ip_address(ip) in ipaddress.ip_network(DATA_SUBNET)
    except ValueError:
        in_subnet = False
    if not in_subnet:
        score -= 40; reasons.append("ip outside data subnet")
    if datetime.now().hour not in ALLOWED_HOURS:
        score -= 30; reasons.append("outside allowed hours")
    expected_mac = HOST.get(ip, (None, None, None))[1]
    if expected_mac and reported_mac and reported_mac.lower() != expected_mac.lower():
        score -= 50; reasons.append("mac/ip binding mismatch")
    return max(0, score), reasons


def behaviour_score(failed_logins):
    return max(0, 100 - min(failed_logins * 15, 60))


def trust_score(role, ip, mac, failed_logins):
    R = R_BY_ROLE.get(role, 0)
    C, reasons = context_score(ip, mac)
    B = behaviour_score(failed_logins)
    T = round(W_R * R + W_C * C + W_B * B, 1)
    tier = "FULL" if T >= TIER_FULL else "LIMITED" if T >= TIER_LIMITED else "DENIED"
    return T, tier, {"R": R, "C": C, "B": B, "reasons": reasons}


# ---------- path + flow building (format ONOS) -----------------------------
def shortest_path(src_sw, dst_sw):
    from collections import deque
    q, seen = deque([[src_sw]]), {src_sw}
    while q:
        p = q.popleft()
        if p[-1] == dst_sw:
            return p
        for nb in ADJ[p[-1]]:
            if nb not in seen:
                seen.add(nb); q.append(p + [nb])
    return None


def _flow_json(device, priority, smac, sip, dip, port, out_port, is_return=False):
    """Flow rule dalam format ONOS REST (selector/treatment)."""
    criteria = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "ETH_SRC",  "mac": smac},            # ikat identitas (anti-spoof)
        {"type": "IPV4_SRC", "ip": f"{sip}/32"},
        {"type": "IPV4_DST", "ip": f"{dip}/32"},
        {"type": "IP_PROTO", "protocol": 6},
        {"type": "TCP_SRC" if is_return else "TCP_DST", "tcpPort": port},
    ]
    return {
        "priority": priority,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": device,
        "tableId": 0,
        "selector": {"criteria": criteria},
        "treatment": {"instructions": [
            {"type": "OUTPUT", "port": str(out_port)}
        ]},
    }


def _post_flow(device, body):
    """POST flow ke ONOS; return flowId (dibaca dari header Location)."""
    url = f"{ONOS_BASE}/flows/{device}?appId={APP_ID}"
    if DRY_RUN:
        import json
        print(f"POST {url}\n{json.dumps(body, indent=2)}\n")
        return "dry-run"
    try:
        r = SESSION.post(url, json=body, auth=ONOS_AUTH,
                         headers={"Content-Type": "application/json"}, timeout=5)
    except requests.RequestException as e:
        print(f"  [POST {device}] ERROR {e}")
        return None
    if r.status_code not in (200, 201, 204):
        print(f"  [POST {device}] {r.status_code} {r.text[:200]}")
        return None
    # ONOS balas: Location: /onos/v1/flows/of:0000...0001/<flowId>
    loc = r.headers.get("Location", "")
    flow_id = loc.rstrip("/").split("/")[-1] if loc else None
    if not flow_id:
        try:
            flow_id = str(r.json().get("flows", [{}])[0].get("flowId"))
        except Exception:
            flow_id = None
    return flow_id


def _delete_flow(device, flow_id):
    if DRY_RUN or not flow_id:
        print(f"DELETE {ONOS_BASE}/flows/{device}/{flow_id}")
        return True
    try:
        SESSION.delete(f"{ONOS_BASE}/flows/{device}/{flow_id}",
                       auth=ONOS_AUTH, timeout=5)
    except requests.RequestException:
        pass
    return True


def _install_along(path, dst_sw, smac, sip, dip, port, is_return):
    installed = []
    for i, device in enumerate(path):
        out_port = HOST_PORT if device == dst_sw else LINK_PORT[(device, path[i + 1])]
        body = _flow_json(device, 50, smac, sip, dip, port, out_port, is_return)
        fid = _post_flow(device, body)
        if fid:
            installed.append((device, fid))
    return installed


def provision_session(client_ip, res_ip, port):
    c_sw, r_sw = HOST[client_ip][2], HOST[res_ip][2]
    path = shortest_path(c_sw, r_sw)
    fwd = _install_along(path, r_sw, HOST[client_ip][1],
                         client_ip, res_ip, port, is_return=False)
    ret = _install_along(path[::-1], c_sw, HOST[res_ip][1],
                         res_ip, client_ip, port, is_return=True)
    return fwd + ret, path


# ---------- decision -------------------------------------------------------
def evaluate(role, ip, mac, T, tier):
    granted = {}
    for dst_seg, ports in POLICY.get(role, {}).items():
        if T < MIN_SCORE.get(dst_seg, TIER_FULL):
            continue
        allow = ports if tier == "FULL" else [p for p in ports if p in LIMITED_PORTS]
        if not allow:
            continue
        granted[dst_seg] = {"ports": allow}
    return granted


# ---------- HTTP -----------------------------------------------------------
FAILED = {}


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    user = data.get("username", "")
    pw   = data.get("password", "")
    mac  = data.get("mac", "")
    ip   = request.remote_addr
    if ip not in HOST:
        ip = data.get("ip", ip)

    rec = USERS.get(user)
    if not rec or rec["password"] != pw:
        FAILED[user] = FAILED.get(user, 0) + 1
        return jsonify(ok=False, error="invalid credentials"), 401

    role = rec["role"]
    T, tier, parts = trust_score(role, ip, mac, FAILED.get(user, 0))
    if tier == "DENIED":
        return jsonify(ok=False, tier=tier, trust=T, detail=parts,
                       error="trust below threshold"), 403

    granted = evaluate(role, ip, mac, T, tier)
    token = uuid.uuid4().hex[:12]
    flows = []
    t0 = time.time()
    for dst_seg, info in granted.items():
        dst_ip = SEG_IP[dst_seg]
        path = None
        for port in info["ports"]:
            session_flows, path = provision_session(ip, dst_ip, port)
            flows += session_flows
        info["path"] = path
    print(f"[login] {user} ({role}) T={T} {tier} -> {len(flows)} flows in "
          f"{time.time() - t0:.1f}s : {', '.join(granted) or 'none'}")
    SESSIONS[token] = {"user": user, "role": role, "ip": ip, "mac": mac,
                       "flows": flows, "ts": time.time()}
    return jsonify(ok=True, token=token, role=role, trust=T, tier=tier,
                   detail=parts, granted=granted)


@app.route("/logout", methods=["POST"])
def logout():
    data = request.get_json(force=True, silent=True) or {}
    sess = SESSIONS.pop(data.get("token", ""), None)
    if not sess:
        return jsonify(ok=False, error="unknown token"), 404
    for device, fid in sess["flows"]:
        _delete_flow(device, fid)
    return jsonify(ok=True, revoked=len(sess["flows"]))


@app.route("/health")
def health():
    """Sekalian cek konektivitas ke ONOS."""
    onos_ok, devices = False, []
    if not DRY_RUN:
        try:
            r = SESSION.get(f"{ONOS_BASE}/devices", auth=ONOS_AUTH, timeout=5)
            onos_ok = r.status_code == 200
            devices = [d["id"] for d in r.json().get("devices", [])] if onos_ok else []
        except requests.RequestException:
            pass
    return jsonify(ok=True, sessions=len(SESSIONS),
                   onos_reachable=onos_ok, devices=devices)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="cetak JSON REST ONOS tanpa memanggil controller")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    DRY_RUN = args.dry_run
    app.run(host="0.0.0.0", port=args.port)