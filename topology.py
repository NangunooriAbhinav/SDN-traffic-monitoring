#!/usr/bin/env python3
"""
mpclient/topology.py

Mininet topology script for a small demo network used in the SDN-based
traffic monitoring & mitigation project.

Topology:
  h1 (attacker, 10.0.0.1)  \
                             \
                              s1 (Open vSwitch)
                             /
  h2 (victim,  10.0.0.2)  /
                          \
                           h3 (benign, 10.0.0.3)

Usage examples:
  # Use the built-in Mininet controller (for quick demos)
  sudo python3 mpclient/topology.py --controller local

  # Use a remote Ryu controller running on localhost:6633 (recommended)
  sudo python3 mpclient/topology.py --controller remote --ryu-ip 127.0.0.1 --ryu-port 6633

  # Customize link bandwidth and delay
  sudo python3 mpclient/topology.py --bw 100 --delay 5ms

Notes:
  - Run this script with root privileges (sudo) because Mininet needs them.
  - If you plan to use the remote controller option, start your Ryu app
    before running this script:
      ryu-manager path/to/your_ryu_app.py
  - Traffic helper scripts (e.g., iperf/hping commands) are provided separately.
"""

import argparse

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController


def build_network(
    controller_type="local", ryu_ip="127.0.0.1", ryu_port=6633, bw=10, delay="0ms"
):
    """
    Build and return a Mininet network object configured with:
      - 1 OVS switch
      - 3 hosts: attacker (h1), victim (h2), benign/background (h3)
      - Links configured with TCLink using provided bandwidth and delay
    """
    info("=== Creating Mininet network\n")
    if controller_type == "remote":
        info("Using remote controller at %s:%s\n" % (ryu_ip, ryu_port))
        controller = RemoteController("c0", ip=ryu_ip, port=int(ryu_port))
        net = Mininet(
            controller=controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True
        )
    else:
        info("Using local (built-in) controller\n")
        net = Mininet(
            controller=Controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True
        )

    info("Adding controller\n")
    # For Mininet when passing controller class, an instance is created automatically on start.
    # If remote controller instance is wanted in the Mininet object, it was passed above.

    info("Adding switch s1\n")
    s1 = net.addSwitch("s1")

    info("Adding hosts\n")
    # IPs chosen for clarity; Mininet can auto-assign but keep explicit mapping here.
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # attacker
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # victim
    h3 = net.addHost("h3", ip="10.0.0.3/24")  # benign/background

    info("Creating links (bw=%s Mbps, delay=%s)\n" % (bw, delay))
    # Use TCLink to impose bandwidth and delay constraints on the links.
    net.addLink(h1, s1, bw=float(bw), delay=delay)
    net.addLink(h2, s1, bw=float(bw), delay=delay)
    net.addLink(h3, s1, bw=float(bw), delay=delay)

    return net


def start_network(net, controller_type="local"):
    """Start the Mininet network and print quick instructions for demo runs."""
    info("=== Starting network\n")
    net.start()

    info("\n=== Hosts and interfaces:\n")
    for host in net.hosts:
        info("  %s: %s\n" % (host.name, host.IP()))

    info(
        """
Quick demo commands (run these from the Mininet CLI or in parallel terminals):

  1) Start iperf server on victim (h2):
       h2 iperf -s &

  2) Start a benign iperf client from h3 -> h2:
       h3 iperf -c 10.0.0.2 -t 60 &

  3) From attacker (h1) simulate an attack (examples below):
       # UDP flood using hping3 (if installed in hosts)
       h1 hping3 --udp --flood --rand-source -p 80 10.0.0.2
       # TCP SYN flood
       h1 hping3 --flood -S -p 80 10.0.0.2
       # ICMP flood (ping flood)
       h1 ping -f 10.0.0.2

  4) Useful checks:
       # Show OVS flows on switch s1 (on the VM host):
       sudo ovs-ofctl dump-flows s1
       # From Mininet CLI:
       s1 ovs-ofctl dump-flows s1

Notes:
  - If you are using a remote Ryu controller, start your controller before running this script.
  - If hping3 is not available inside Mininet hosts, you can install it in the VM image or use scapy scripts as an alternative.
"""
    )

    info("=== Dropping into Mininet CLI. Use 'exit' or Ctrl-D to stop the network.\n")
    CLI(net)

    info("=== Stopping network\n")
    net.stop()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Mininet demo topology for SDN monitoring project"
    )
    parser.add_argument(
        "--controller",
        choices=["local", "remote"],
        default="remote",
        help="Controller type to use. 'remote' is Ryu (default), 'local' uses Mininet's built-in controller.",
    )
    parser.add_argument(
        "--ryu-ip",
        default="127.0.0.1",
        help="IP address of remote Ryu controller (if remote selected).",
    )
    parser.add_argument(
        "--ryu-port",
        default=6633,
        help="Port of remote Ryu controller (if remote selected).",
    )
    parser.add_argument(
        "--bw",
        type=float,
        default=10.0,
        help="Link bandwidth in Mbps for each host-to-switch link (TCLink).",
    )
    parser.add_argument(
        "--delay", default="0ms", help="Link delay to apply (e.g., '5ms')."
    )
    return parser.parse_args()


def main():
    setLogLevel("info")
    args = parse_args()
    net = build_network(
        controller_type=args.controller,
        ryu_ip=args.ryu_ip,
        ryu_port=args.ryu_port,
        bw=args.bw,
        delay=args.delay,
    )
    try:
        start_network(net, controller_type=args.controller)
    except Exception as e:
        info("Error encountered during network run: %s\n" % e)
        net.stop()


if __name__ == "__main__":
    main()
