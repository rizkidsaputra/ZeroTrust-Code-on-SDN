#!/usr/bin/env python3
"""
ZTNA data plane — versi ONOS, topologi FULL MESH 5 switch.

    s1 Research | s2 Server | s3 IoT | s4 Guest | s5 Security
    Semua pasangan switch terhubung langsung (K5, 10 link).
    h5 (Security) = kolektor log / SIEM, bersifat RECEIVE-ONLY.

Perubahan dari versi ring:
  * 5 switch full mesh, SEMUA switch punya host. s5 menaungi h5 (Security),
    segmen monitoring yang memetakan supporting component NIST SP 800-207
    (Activity Logs / SIEM) ke testbed. s5 tetap bisa dipakai sebagai jalur
    transit untuk path-aware routing di tahap lanjutan.
  * Port di-set EKSPLISIT. Topologi mesh yang pakai addLink() tanpa nomor
    port menghasilkan penomoran yang tidak deterministik, sedangkan PDP
    memakai static map. Skema:
        semua : port 1 = host
        semua : port ke switch lain = 2 + index switch tujuan di daftar
                switch lainnya (urut menaik)
        contoh s1: ->s2=2, ->s3=3, ->s4=4, ->s5=5
                s5: ->s1=2, ->s2=3, ->s3=4, ->s4=5
  * Mesh = banyak loop. Aman karena static ARP (nol broadcast) + default
    drop + tidak ada app flooding di controller.

Run:  sudo python3 ztna_net_onos_mesh.py
"""

import base64
import json
import time
import urllib.request

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel

ONOS_IP   = "192.168.13.5"
ONOS_PORT = 8181
ONOS_AUTH = ("onos", "rocks")
APP_ID    = "org.onosproject.rest"
OF_PORT   = 6653
GW_IP     = "10.0.0.254"

SWITCHES = [1, 2, 3, 4, 5]

HOSTS = {
    "h1": ("10.0.0.1", "00:00:00:00:00:01", "research"),
    "h2": ("10.0.0.2", "00:00:00:00:00:02", "server"),
    "h3": ("10.0.0.3", "00:00:00:00:00:03", "iot"),
    "h4": ("10.0.0.4", "00:00:00:00:00:04", "guest"),
    "h5": ("10.0.0.5", "00:00:00:00:00:05", "security"),
}


def others(i):
    return [j for j in SWITCHES if j != i]


def port_to(i, j):
    """Port di switch si yang menuju sj. Harus identik dengan PDP."""
    return 2 + others(i).index(j)


class MeshTopo(Topo):
    def build(self):
        sw = {}
        for i in SWITCHES:
            # dpid eksplisit -> device id ONOS = of:000000000000000<i>
            sw[i] = self.addSwitch("s%d" % i, protocols="OpenFlow13",
                                   dpid="%016x" % i)
        # host di port 1 switch-nya sendiri (semua switch)
        for i in SWITCHES:
            name = "h%d" % i
            ip, mac, _ = HOSTS[name]
            h = self.addHost(name, ip="%s/24" % ip, mac=mac)
            self.addLink(h, sw[i], port1=0, port2=1)
        # full mesh, port eksplisit di kedua ujung
        for a in range(len(SWITCHES)):
            for b in range(a + 1, len(SWITCHES)):
                i, j = SWITCHES[a], SWITCHES[b]
                self.addLink(sw[i], sw[j],
                             port1=port_to(i, j), port2=port_to(j, i))


# ---------------------------------------------------------------------------
# REST helper (stdlib saja)
# ---------------------------------------------------------------------------
def _auth_header():
    return "Basic " + base64.b64encode(("%s:%s" % ONOS_AUTH).encode()).decode()


def onos_post_flow(device, body):
    url = ("http://%s:%d/onos/v1/flows/%s?appId=%s"
           % (ONOS_IP, ONOS_PORT, device, APP_ID))
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    req.add_header("Authorization", _auth_header())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201, 204)
    except Exception as e:
        print("  [REST %s] ERROR %s" % (device, e))
        return False


def wait_for_devices(expected=5, timeout=60):
    url = "http://%s:%d/onos/v1/devices" % (ONOS_IP, ONOS_PORT)
    deadline = time.time() + timeout
    while time.time() < deadline:
        req = urllib.request.Request(url)
        req.add_header("Authorization", _auth_header())
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                avail = [d["id"] for d in json.load(r).get("devices", [])
                         if d.get("available")]
                if len(avail) >= expected:
                    print("[onos] %d device terdaftar: %s"
                          % (len(avail), ", ".join(sorted(avail))))
                    return True
        except Exception:
            pass
        time.sleep(2)
    print("[onos] WARNING: device belum lengkap setelah %ds" % timeout)
    return False


def install_pdp_carveout_rest(nat_port):
    """Carveout h1 <-> PDP di s1, via REST supaya tidak dihapus ONOS."""
    dev = "of:%016x" % 1
    out = {
        "priority": 200, "timeout": 0, "isPermanent": True,
        "deviceId": dev, "tableId": 0,
        "selector": {"criteria": [
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IPV4_DST", "ip": "%s/32" % ONOS_IP},
        ]},
        "treatment": {"instructions": [{"type": "OUTPUT", "port": str(nat_port)}]},
    }
    back = {
        "priority": 200, "timeout": 0, "isPermanent": True,
        "deviceId": dev, "tableId": 0,
        "selector": {"criteria": [
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IPV4_SRC", "ip": "%s/32" % ONOS_IP},
        ]},
        "treatment": {"instructions": [{"type": "OUTPUT", "port": "1"}]},
    }
    ok = onos_post_flow(dev, out) and onos_post_flow(dev, back)
    print("[carveout] h1 <-> PDP (%s) via s1 port %s  [%s]"
          % (ONOS_IP, nat_port, "OK" if ok else "GAGAL"))


# ---------------------------------------------------------------------------
def s1_port_to_node(net, node):
    s1 = net.get("s1")
    for intf in s1.intfList():
        if intf.link:
            peer = intf.link.intf1 if intf.link.intf2 is intf else intf.link.intf2
            if peer.node is node:
                return s1.ports[intf]
    return None


def setup_static_arp(net, nat):
    gw_mac = nat.MAC()
    for name, (ip, mac, _) in HOSTS.items():
        h = net.get(name)
        for oname, (oip, omac, _) in HOSTS.items():
            if oname != name:
                h.cmd("arp -s %s %s" % (oip, omac))
        h.cmd("arp -s %s %s" % (GW_IP, gw_mac))
        nat.cmd("arp -s %s %s" % (ip, mac))


def start_services(net):
    net.get("h2").cmd("python3 -m http.server 8080 >/tmp/h2-8080.log 2>&1 &")
    net.get("h2").cmd("python3 -m http.server 9000 >/tmp/h2-9000.log 2>&1 &")
    net.get("h2").cmd("python3 -m http.server 22   >/tmp/h2-22.log   2>&1 &")
    net.get("h3").cmd("python3 -m http.server 80   >/tmp/h3-80.log   2>&1 &")
    # h5 = kolektor log Security (port 514). Hanya menerima, tidak menginisiasi.
    net.get("h5").cmd("python3 -m http.server 514  >/tmp/h5-514.log  2>&1 &")


def print_port_map():
    print("\n=== Peta port (harus sama dengan LINK_PORT di pdp_onos.py) ===")
    for i in SWITCHES:
        seg = HOSTS["h%d" % i][2]
        m = "  ".join("->s%d=%d" % (j, port_to(i, j)) for j in others(i))
        print("  s%d  h%d/%-9s host=1  %s" % (i, i, seg, m))
    print()


def main():
    setLogLevel("info")
    net = Mininet(topo=MeshTopo(), switch=OVSSwitch, controller=None,
                  autoSetMacs=False, build=False)
    net.addController("c0", controller=RemoteController, ip=ONOS_IP, port=OF_PORT)
    net.build()
    s1 = net.get("s1")
    nat = net.addNAT(name="nat0", ip=GW_IP + "/24", connect=s1)
    net.start()

    for i in SWITCHES:
        net.get("s%d" % i).cmd("ovs-vsctl set-fail-mode s%d secure" % i)

    nat.configDefault()
    nat.setIP(GW_IP + "/24")
    for name in HOSTS:
        net.get(name).cmd("ip route replace default via %s" % GW_IP)

    setup_static_arp(net, nat)
    start_services(net)
    print_port_map()

    nat_port = s1_port_to_node(net, nat)
    if nat_port is None:
        print("[carveout] ERROR: link s1<->nat0 tidak ketemu")
    else:
        wait_for_devices(expected=5)
        install_pdp_carveout_rest(nat_port)

    print("\nnat0: ip=%s mac=%s  (s1 port %s)" % (GW_IP, nat.MAC(), nat_port))
    print("Sanity:  mininet> h1 ping -c2 %s" % ONOS_IP)
    print("Login :  mininet> h1 python3 pep_client.py\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()