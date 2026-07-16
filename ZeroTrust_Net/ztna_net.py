#!/usr/bin/env python3
"""
ZTNA data plane — runs on VM2 (Mininet/OVS).

4-switch ring, one host per switch:
    h1 Research | h2 Server | h3 IoT | h4 Guest
A NAT node on s1 gives hosts a route to the PDP (VM1, 192.168.13.4) so the
research host can log in; masquerade handles the return path (no route needed
on VM1). Static ARP everywhere => no ARP broadcast => ring stays loop-free.
Default-drop is provided by odl-l2switch (priority-0 drop + LLDP-to-controller,
verified in Week 2); the PDP installs the only allow-flows on top.

Run:  sudo python3 ztna_net.py
Then: mininet> h1 python3 pep_client.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel

ODL_IP  = "192.168.13.4"       # VM1 (OpenDaylight + PDP)
OF_PORT = 6653
GW_IP   = "10.0.0.254"         # NAT gateway on s1 (data-plane side)

HOSTS = {  # name: (ip, mac, segment)
    "h1": ("10.0.0.1", "00:00:00:00:00:01", "research"),
    "h2": ("10.0.0.2", "00:00:00:00:00:02", "server"),
    "h3": ("10.0.0.3", "00:00:00:00:00:03", "iot"),
    "h4": ("10.0.0.4", "00:00:00:00:00:04", "guest"),
}


class RingTopo(Topo):
    def build(self):
        sw = []
        for i in range(1, 5):
            s = self.addSwitch("s%d" % i, protocols="OpenFlow13")
            name = "h%d" % i
            ip, mac, _ = HOSTS[name]
            h = self.addHost(name, ip="%s/24" % ip, mac=mac)
            self.addLink(h, s, port1=0, port2=1)          # host on switch port 1
            sw.append(s)
        for i in range(4):                                # ring s1-s2-s3-s4-s1
            self.addLink(sw[i], sw[(i + 1) % 4], port1=2, port2=3)


def s1_port_to(net, node):
    """Return the s1 port number whose link goes to `node` (e.g. nat0)."""
    s1 = net.get("s1")
    for intf in s1.intfList():
        if intf.link:
            peer = intf.link.intf1 if intf.link.intf2 is intf else intf.link.intf2
            if peer.node is node:
                return s1.ports[intf]
    return None


def setup_static_arp(net, nat):
    """No ARP on the wire -> no broadcast -> no ring loop."""
    gw_mac = nat.MAC()
    for name, (ip, mac, _) in HOSTS.items():
        h = net.get(name)
        for oname, (oip, omac, _) in HOSTS.items():
            if oname != name:
                h.cmd("arp -s %s %s" % (oip, omac))
        h.cmd("arp -s %s %s" % (GW_IP, gw_mac))           # gateway to PDP
        nat.cmd("arp -s %s %s" % (ip, mac))               # gateway knows each host


def start_services(net):
    """Simple TCP listeners so 'Limited' vs 'Full' ports are testable."""
    net.get("h2").cmd("python3 -m http.server 8080 >/tmp/h2-8080.log 2>&1 &")
    net.get("h2").cmd("python3 -m http.server 9000 >/tmp/h2-9000.log 2>&1 &")
    net.get("h2").cmd("python3 -m http.server 22   >/tmp/h2-22.log   2>&1 &")
    net.get("h3").cmd("python3 -m http.server 80   >/tmp/h3-80.log   2>&1 &")
    # h4 (guest) intentionally offers nothing


def install_pdp_carveout(net, nat):
    """Two high-priority flows on s1 so h1 can always reach the PDP portal."""
    nat_port = s1_port_to(net, nat)
    if nat_port is None:
        print("[carveout] ERROR: could not find s1<->nat0 link"); return
    s1 = net.get("s1")
    s1.dpctl("add-flow", "priority=200,ip,nw_dst=%s,actions=output:%d" % (ODL_IP, nat_port))
    s1.dpctl("add-flow", "priority=200,ip,nw_src=%s,actions=output:1" % ODL_IP)
    print("[carveout] h1 <-> PDP (%s) via s1 port %d" % (ODL_IP, nat_port))


def main():
    setLogLevel("info")
    net = Mininet(topo=RingTopo(), switch=OVSSwitch, controller=None,
                  autoSetMacs=False, build=False)
    net.addController("c0", controller=RemoteController, ip=ODL_IP, port=OF_PORT)
    net.build()
    s1 = net.get("s1")
    nat = net.addNAT(name="nat0", ip=GW_IP + "/24", connect=s1)   # auto-links to s1
    net.start()
    for sname in ("s1", "s2", "s3", "s4"):               # deny-by-default, no NORMAL fallback
        s = net.get(sname)
        s.cmd("ovs-vsctl set-fail-mode %s secure" % sname)
        s.dpctl("add-flow", "priority=0,actions=drop")
    nat.configDefault()                                          # host default routes + masquerade
    nat.setIP(GW_IP + "/24")                                     # pin the gateway IP
    for name in HOSTS:
        net.get(name).cmd("ip route replace default via %s" % GW_IP)

    setup_static_arp(net, nat)
    start_services(net)
    install_pdp_carveout(net, nat)

    print("\nnat0: ip=%s mac=%s" % (GW_IP, nat.MAC()))
    print("Ready. Log in from the research host:\n"
          "  mininet> h1 python3 pep_client.py\n"
          "Sanity:  mininet> h1 ping -c1 %s   (should reach the PDP host)\n" % ODL_IP)
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()