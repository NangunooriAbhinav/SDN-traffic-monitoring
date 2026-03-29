#!/usr/bin/env bash
###############################################################################
# traffic/benign.sh
#
# Generate normal/benign traffic between hosts in the Mininet topology.
# Run these commands from the Mininet CLI or source this script.
#
# Usage (from Mininet CLI):
#   source traffic/benign.sh          # prints instructions
#   OR run commands individually as shown below
#
# Usage (standalone — not typical, only for reference):
#   bash traffic/benign.sh [duration_seconds]
###############################################################################

set -euo pipefail

DURATION="${1:-60}"       # default 60 seconds
VICTIM_IP="10.0.0.2"

cat <<EOF
========================================================================
  Benign Traffic Generation — Mininet Commands
========================================================================

  Run these in the Mininet CLI (mininet>):

  1) Start iperf server on the victim (h2):
       h2 iperf -s -u &

  2) Start TCP iperf from benign host (h3 -> h2, ${DURATION}s):
       h3 iperf -c ${VICTIM_IP} -t ${DURATION} &

  3) Start UDP iperf from benign host (h3 -> h2, 1 Mbps, ${DURATION}s):
       h3 iperf -c ${VICTIM_IP} -u -b 1M -t ${DURATION} &

  4) Periodic ping from h3 -> h2 (1 ping/sec, ${DURATION} pings):
       h3 ping -c ${DURATION} ${VICTIM_IP} &

  5) Periodic ping from h1 -> h2 (normal, non-flood, 1 ping/sec):
       h1 ping -c ${DURATION} ${VICTIM_IP} &

  6) Check connectivity (all-to-all ping test):
       pingall

  Notes:
    - The '&' runs each command in the background so you can start
      multiple streams simultaneously.
    - Adjust DURATION by passing it as an argument or changing the
      variable above.
    - These traffic patterns are designed to stay well below the
      anomaly detection threshold configured in the Ryu controller.
========================================================================
EOF

echo ""
echo "[benign.sh] To auto-run a basic benign scenario, paste these into Mininet CLI:"
echo ""
echo "  h2 iperf -s -u &"
echo "  h3 iperf -c ${VICTIM_IP} -t ${DURATION} &"
echo "  h3 ping -c ${DURATION} ${VICTIM_IP} &"
echo "  h1 ping -c ${DURATION} ${VICTIM_IP} &"
echo ""
