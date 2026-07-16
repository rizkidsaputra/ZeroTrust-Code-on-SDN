#!/usr/bin/env python3
"""
ZTNA CLI client — run INSIDE a Mininet host:  mininet> h1 python3 pep_client.py

Authenticates to the PDP, which computes a trust score and provisions ring
flows for the resources this role is entitled to. Stdlib only (no pip needed
in the host namespace).
"""

import getpass
import json
import subprocess
import sys
import urllib.request

PDP_URL = "http://192.168.13.4:5000"


def local_identity():
    """Best-effort read of this namespace's data-plane IP and MAC."""
    ip = mac = None
    out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "10.0.0." in line and "inet " in line:
            ip = line.split("inet ")[1].split("/")[0]
            dev = line.split()[1]
            link = subprocess.run(["cat", f"/sys/class/net/{dev}/address"],
                                  capture_output=True, text=True).stdout.strip()
            mac = link or mac
            break
    return ip, mac


def post(path, payload):
    req = urllib.request.Request(PDP_URL + path,
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except urllib.error.URLError as e:
        return None, {"error": f"cannot reach PDP: {e.reason}"}


def main():
    ip, mac = local_identity()
    print(f"== ZTNA login ==  (this host: {ip} / {mac})")
    user = input("username: ").strip()
    pw = getpass.getpass("password: ")

    status, res = post("/login", {"username": user, "password": pw, "ip": ip, "mac": mac})
    if status is None:
        print("!", res["error"]); return
    if not res.get("ok"):
        print(f"DENIED ({status}): {res.get('error')}  "
              f"[tier={res.get('tier')} trust={res.get('trust')}]")
        if res.get("detail", {}).get("reasons"):
            print("  reasons:", ", ".join(res["detail"]["reasons"]))
        return

    print(f"\nGRANTED  role={res['role']}  trust={res['trust']}  tier={res['tier']}")
    for resource, info in res["granted"].items():
        ports = ",".join(str(p) for p in info["ports"])
        path = " -> ".join(n.split(":")[1] for n in info["path"])
        print(f"  {resource:8s} ports [{ports}]   path s{path}")
    if not res["granted"]:
        print("  (no resources granted for this role/tier)")

    token = res["token"]
    print(f"\nsession token: {token}")
    print("flows stay active until you revoke them:")
    print(f"    python3 pep_client.py --logout {token}")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--logout":
        s, r = post("/logout", {"token": sys.argv[2]})
        print("logged out (flows revoked)" if r.get("ok") else f"logout failed: {r}")
    else:
        main()