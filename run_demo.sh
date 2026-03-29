#!/usr/bin/env bash
###############################################################################
# run_demo.sh
#
# Master orchestration script for the SDN traffic monitoring & mitigation demo.
#
# This script:
#   1. Checks that all required tools are installed.
#   2. Creates the logs/ directory if needed.
#   3. Starts the Ryu controller in the background.
#   4. Waits for the controller to be ready.
#   5. Launches the Mininet topology (drops into interactive CLI).
#   6. Cleans up on exit.
#
# Usage:
#   sudo bash run_demo.sh [--controller-only | --topology-only]
#
# Options:
#   --controller-only   Only start the Ryu controller (no Mininet).
#   --topology-only     Only start Mininet (assumes controller is already running).
#   (no option)         Start both controller and Mininet.
#
# Prerequisites:
#   - Ubuntu (18.04 / 20.04 / 22.04)
#   - sudo / root access
#   - mininet, openvswitch-switch, ryu-manager, iperf installed
#   - hping3 (optional, for TCP/UDP flood attacks)
###############################################################################

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
CONTROLLER_SCRIPT="${SCRIPT_DIR}/ryu_controller.py"
TOPOLOGY_SCRIPT="${SCRIPT_DIR}/topology.py"
CONTROLLER_LOG="${LOG_DIR}/controller_$(date +%Y%m%d_%H%M%S).log"
CONTROLLER_PORT=6633
CONTROLLER_PID=""
MODE="${1:-full}"

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Cleanup handler ---
cleanup() {
    echo ""
    info "Cleaning up..."

    if [[ -n "${CONTROLLER_PID}" ]] && kill -0 "${CONTROLLER_PID}" 2>/dev/null; then
        info "Stopping Ryu controller (PID ${CONTROLLER_PID})..."
        kill "${CONTROLLER_PID}" 2>/dev/null || true
        wait "${CONTROLLER_PID}" 2>/dev/null || true
    fi

    # Clean up Mininet state
    info "Running Mininet cleanup..."
    mn -c 2>/dev/null || true

    info "Done. Logs are in: ${LOG_DIR}/"
}
trap cleanup EXIT

# --- Prerequisite checks ---
check_prerequisites() {
    info "Checking prerequisites..."
    local missing=()

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)."
        exit 1
    fi

    # Required tools
    for tool in python3 ovs-vsctl mn iperf; do
        if ! command -v "${tool}" &>/dev/null; then
            missing+=("${tool}")
        fi
    done

    # Check ryu-manager
    if ! command -v ryu-manager &>/dev/null; then
        # Try python module
        if ! python3 -c "import ryu" 2>/dev/null; then
            missing+=("ryu-manager (pip install ryu)")
        else
            warn "ryu-manager not in PATH, but ryu module found. Will use 'python3 -m ryu.cmd.manager'."
        fi
    fi

    # Optional tools
    if ! command -v hping3 &>/dev/null; then
        warn "hping3 not found. TCP/UDP flood attacks will require scapy fallback."
        warn "Install with: sudo apt-get install hping3"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install them with:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install -y mininet openvswitch-switch iperf python3-pip"
        echo "  pip3 install ryu"
        exit 1
    fi

    # Check that our scripts exist
    if [[ ! -f "${CONTROLLER_SCRIPT}" ]]; then
        error "Controller script not found: ${CONTROLLER_SCRIPT}"
        exit 1
    fi
    if [[ ! -f "${TOPOLOGY_SCRIPT}" ]]; then
        error "Topology script not found: ${TOPOLOGY_SCRIPT}"
        exit 1
    fi

    info "All prerequisites satisfied."
}

# --- Start Ryu controller ---
start_controller() {
    info "Starting Ryu controller..."
    mkdir -p "${LOG_DIR}"

    # Determine how to invoke ryu-manager
    local ryu_cmd
    if command -v ryu-manager &>/dev/null; then
        ryu_cmd="ryu-manager"
    else
        ryu_cmd="python3 -m ryu.cmd.manager"
    fi

    # Start in background, log to file
    ${ryu_cmd} "${CONTROLLER_SCRIPT}" \
        --ofp-tcp-listen-port "${CONTROLLER_PORT}" \
        > "${CONTROLLER_LOG}" 2>&1 &
    CONTROLLER_PID=$!

    info "Ryu controller started (PID ${CONTROLLER_PID})"
    info "Controller log: ${CONTROLLER_LOG}"

    # Wait for controller to be ready
    info "Waiting for controller to be ready..."
    local retries=0
    local max_retries=15
    while ! ss -tlnp 2>/dev/null | grep -q ":${CONTROLLER_PORT}" ; do
        if ! kill -0 "${CONTROLLER_PID}" 2>/dev/null; then
            error "Controller process died. Check log: ${CONTROLLER_LOG}"
            tail -20 "${CONTROLLER_LOG}" 2>/dev/null || true
            exit 1
        fi
        retries=$((retries + 1))
        if [[ ${retries} -ge ${max_retries} ]]; then
            error "Controller did not start listening on port ${CONTROLLER_PORT} after ${max_retries}s."
            error "Check log: ${CONTROLLER_LOG}"
            tail -20 "${CONTROLLER_LOG}" 2>/dev/null || true
            exit 1
        fi
        sleep 1
    done

    info "Controller is listening on port ${CONTROLLER_PORT}."
}

# --- Start Mininet topology ---
start_topology() {
    info "Starting Mininet topology..."
    echo ""
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}  SDN Traffic Monitoring & Mitigation Demo${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
    echo -e "  ${GREEN}Benign traffic:${NC}"
    echo "    h2 iperf -s -u &"
    echo "    h3 iperf -c 10.0.0.2 -t 60 &"
    echo "    h3 ping -c 60 10.0.0.2 &"
    echo ""
    echo -e "  ${RED}Attack traffic:${NC}"
    echo "    h1 ping -f 10.0.0.2 &              # ICMP flood"
    echo "    h1 hping3 --flood -S -p 80 10.0.0.2 &  # TCP SYN flood"
    echo ""
    echo -e "  ${YELLOW}Monitoring:${NC}"
    echo "    s1 ovs-ofctl dump-flows s1          # Show OVS flows"
    echo "    Watch controller log: tail -f ${CONTROLLER_LOG}"
    echo ""
    echo -e "  ${CYAN}Stop:${NC} Type 'exit' or Ctrl-D in Mininet CLI"
    echo ""
    echo -e "${CYAN}======================================================================${NC}"
    echo ""

    # Launch Mininet with remote controller
    python3 "${TOPOLOGY_SCRIPT}" --controller remote --ryu-port "${CONTROLLER_PORT}"
}

# --- Main ---
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     SDN Traffic Monitoring & Mitigation — Demo Runner       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_prerequisites

    case "${MODE}" in
        --controller-only)
            start_controller
            info "Controller is running. Press Ctrl-C to stop."
            wait "${CONTROLLER_PID}"
            ;;
        --topology-only)
            start_topology
            ;;
        full|*)
            start_controller
            start_topology
            ;;
    esac
}

main
