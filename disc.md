# Discussion / Project Approach Breakdown

This document explains the optimal, client-facing approach I will take to implement an SDN-based traffic monitoring and mitigation prototype using a Mininet simulation. It is written so you can review scope, components, expected outcomes, and a clear delivery plan.

## Goal
Build a lightweight, reproducible system that detects high-volume anomalous traffic (e.g., flooding/DoS patterns) and automatically mitigates it in a simulated SDN environment. The solution prioritizes clarity, repeatability, and measurable evaluation.

## High-level approach (one sentence)
Simulate a small network with Mininet + Open vSwitch, collect flow statistics via a Ryu controller app, detect anomalies with a threshold-based detector (with smoothing and per-source scope), and mitigate by installing OpenFlow drop rules or applying host-level firewall rules.

## System components
- Environment: Ubuntu VM (specify version), Mininet for topology emulation.
- Switching: Open vSwitch (OVS) used as programmable switches.
- Controller: Ryu controller application (Python) implementing monitoring, detection, and mitigation logic.
- Traffic: `iperf` and `ping` for baseline traffic; `hping3` or scripted `scapy` for attack traffic.
- Mitigation options:
  - Preferred: Controller pushes OpenFlow drop rules to the switch.
  - Alternative / hybrid: Execute `iptables` on a host to block offending IPs.
- Logging & analysis: CSV logs, simple plotting scripts (matplotlib) for figures.

## Workflow (detailed)
1. Network simulation
   - Create a reproducible Mininet topology (small hub-and-spoke or linear) with attacker(s), victim(s), and background hosts.
   - Document topology and Mininet command to reproduce.

2. Traffic generation
   - Define baseline traffic profiles (e.g., continuous iperf streams, periodic pings).
   - Define attack scenarios (UDP/TCP/ICMP floods) with configurable rates and durations.

3. Monitoring
   - Controller polls OVS flow statistics every configurable interval (e.g., 1–5s).
   - Metrics captured: packets/sec, bytes/sec, per-flow packet/byte counters, optional SYN/ACK counts for TCP.

4. Detection
   - Primary method: threshold-based detector applied per-source IP.
   - Stability improvements:
     - Sliding window aggregation (e.g., 5s window).
     - Exponential moving average (EMA) for noise reduction.
     - Hysteresis before toggling mitigation state to avoid flapping.
   - Thresholds:
     - Chosen empirically from benign runs (e.g., set as baseline mean + k * std or fixed absolute value).
     - Configurable per-experiment.

5. Mitigation
   - On confirmed anomaly, controller installs a high-priority drop flow targeting the offending source (or source+port).
   - Flow timeouts or explicit unblocking policy to restore connectivity after a safe interval.
   - If using `iptables`, apply drop rules and log blocking actions.

6. Evaluation
   - Metrics to report:
     - Detection rate (TP / total attacks)
     - False positive rate (benign traffic flagged)
     - Detection latency (time from attack start to detection)
     - Mitigation latency (time from detection to successful blocking)
     - Impact on legitimate traffic (throughput loss)
   - Experiments:
     - Vary attack intensity, duration, and mixed background traffic.
     - Compare controller-driven flow drops vs iptables in terms of latency and collateral impact.

## Safety and limitations
- Mininet is a simulation; absolute throughput and timing differ from production—use relative measurements.
- Threshold-based detection is simple and explainable but vulnerable to low-rate/stealthy attacks; list as future improvement (adaptive baselines or ML).
- Controller polling overhead increases with experiment scale; limit topology size or optimize collection interval.

## Deliverables
- Mininet topology script(s) with instructions.
- Ryu controller app implementing monitoring, detection, and mitigation.
- Traffic scripts for benign and attack scenarios.
- CSV logs and plotting scripts for experiment figures.
- Short operations README containing exact commands to reproduce experiments.

## Timeline (estimate)
- Prototype (basic detection + drop rule): 1–3 days.
- Experiments + plotting + write-up: additional 3–7 days depending on number of scenarios and refinement.

## Next steps (I will do)
- Produce the Mininet topology and Ryu app skeleton.
- Provide exact commands to run experiments and a sample run producing plots.
- Tune thresholds with a small calibration run and document chosen values.

If you want, I’ll now populate the repository with the topology script and controller skeleton or produce the client-facing one-page summary for your presentation. Tell me which you prefer.