# MPClient — Demo README

This repository contains a lightweight SDN-based traffic monitoring and mitigation demo. The goal is to provide a reproducible demo you can run locally (recommended on an Ubuntu VM) that shows detection of high-volume anomalous traffic and automatic mitigation using OpenFlow rules pushed by a Ryu controller.

This README explains what is included, how to run the demo, what to expect, and next steps.

---

## What I will deliver (files you should see)
- `mpclient/topology.py` — Mininet topology script (attacker, victim, background hosts).
- `mpclient/ryu_controller.py` — Ryu controller application that polls flow stats, runs threshold detection with EMA + hysteresis, and installs drop flows when needed.
- `mpclient/traffic/benign.sh` — Helper instructions to generate normal traffic (iperf, ping).
- `mpclient/traffic/attack.sh` — Helper instructions to generate attack traffic (hping3, ping flood).
- `mpclient/disc.md` — Project approach and client-facing breakdown.
- `mpclient/README.md` — (this file) instructions to run and reproduce the demo.

---

## High-level steps to run the demo
1. Prepare an Ubuntu VM (or a native Ubuntu machine) with root privileges.
2. Install dependencies (Mininet, Open vSwitch, Ryu, iperf, hping3). See "Prerequisites" below for minimal guidance.
3. Start the Ryu controller and the Mininet topology.
4. Generate benign traffic, observe statistics, then run the attack script and observe detection + mitigation.
5. Collect logs and review plots/metrics.

---

## Prerequisites (minimum)
- Ubuntu (18.04 / 20.04 / 22.04 recommended)
- Root (or `sudo`) access to install packages and run Mininet
- Packages/tools:
  - Mininet
  - Open vSwitch
  - Ryu (Python-based SDN controller framework)
  - `iperf` (traffic generation)
  - `hping3` (for attack traffic; optional if you use `ping` floods)
  - Python 3 and `pip` for Ryu app dependencies

Notes:
- If you prefer, I can provide a Dockerfile or VM snapshot with dependencies pre-installed.
- Mininet typically requires running as root (or using the included `sudo` helper).

---

## Example (manual) commands you will run
- Start the controller (in a terminal on the VM):
  - e.g., run the Ryu app: `ryu-manager mpclient/ryu_controller.py`
- Start the Mininet topology (in another terminal, run as root):
  - e.g., `sudo python3 mpclient/topology.py`
- From the Mininet CLI, start benign traffic (example):
  - `h2 iperf -s &` (start server on victim)
  - `h3 iperf -c 10.0.0.2 -t 60 &` (start client)
- From the Mininet CLI, run an attack (example with hping3):
  - `h1 hping3 --udp --flood --rand-source -p 80 10.0.0.2` (UDP flood)
  - or `h1 hping3 --flood -S -p 80 10.0.0.2` (TCP SYN flood)
  - or `h1 ping -f 10.0.0.2` (ICMP flood)

Important: Replace hostnames/IPs with those defined in the topology if different.

---

## What the controller does (brief)
- Periodically polls Open vSwitch flow statistics.
- Computes per-source packet/byte rates using a sliding window and an exponential moving average (EMA) to smooth noise.
- Applies hysteresis to avoid rapid toggling (flapping) of mitigation state.
- On confirmed sustained threshold violation, installs a high-priority OpenFlow drop rule that prevents the offending source from reaching the victim.
- Installs timeouts / automatic expiry on mitigation rules so that blocks are not permanent unless re-triggered.

---

## Expected demonstration behavior
- During benign traffic runs you will see normal throughput/latency with no mitigations.
- When an attack is launched that exceeds configured thresholds, the controller will:
  - Detect the anomaly (a detection log entry appears).
  - Install a drop rule (mitigation log entry appears).
  - The victim's incoming traffic from the offending source will fall to near-zero.
- The demo collects logs for:
  - Detection timestamps
  - Mitigation timestamps
  - Flow stats over time (packets/sec and bytes/sec)
  - Simple CSVs suitable for plotting

---

## Configuration & tuning
Key parameters you can adjust (in `mpclient/ryu_controller.py` or a config file):
- `poll_interval` — how often the controller polls flow stats (e.g., 1s).
- `aggregation_window` — how many seconds to aggregate before decision (e.g., 5s).
- `threshold` — packets/sec or bytes/sec limit used to flag anomalies.
- `ema_alpha` — smoothing factor for EMA.
- `hysteresis` — amount to reduce false unblocks/flaps (e.g., require N consecutive windows to trigger).
- `mitigation_timeout` — how long the installed drop flow persists (or choose manual unblocking).

I will provide sensible defaults and a short calibration routine to pick thresholds from baseline runs.

---

## Reproducibility and logs
- All demo runs should be reproducible with the included topology and traffic scripts.
- I will include example commands and a short `run_demo.sh` in the repo (or provide the commands in `mpclient/README.md`) that perform:
  1. Start the controller.
  2. Start Mininet topology.
  3. Run baseline traffic for calibration.
  4. Run attack scenario(s) and collect logs.
- Logs are saved as timestamped CSVs under `mpclient/logs/` (or printed to the controller terminal).

---

## Troubleshooting tips
- If the controller does not connect to the switch:
  - Ensure the Mininet topology is configured to use the controller IP/port used by `ryu-manager`.
- If `hping3` is not available in Mininet hosts:
  - Install it in the VM image or use `ping -f` as an alternative.
- If throughput seems low compared to real networks:
  - This is expected: Mininet is a simulator and CPU limits in the VM affect absolute numbers. Use relative comparisons and detection timing.

---

## Safety and ethics
- These scripts generate high-volume traffic within a controlled local simulation. Do NOT run attack commands (`hping3 --flood`, `ping -f`) against real production networks or outside an isolated lab. The demo is intended for controlled experimentation only.

---

## Next steps I will take (if you confirm)
- Populate the repository with:
  - The topology script (`mpclient/topology.py`)
  - The Ryu controller (`mpclient/ryu_controller.py`)
  - A small `run_demo.sh` to orchestrate a sample run
  - Example traffic scripts and a short calibration guide
- Run a sample calibration in my environment, tune default thresholds, and include sample output plots.
- Provide a one-page client summary you can use for presentations.

Please confirm you want me to proceed with the implementation (I will begin with a controller-only mitigation approach as recommended). If you prefer the hybrid option (controller + `iptables`), tell me now and I will include host-level blocking support.