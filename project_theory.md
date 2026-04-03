# Project Theory: SDN-Based Traffic Monitoring & Anomaly Mitigation

This document explains the overarching theory of Software-Defined Networking (SDN) used in this project, and how the core mechanics interact to monitor, detect, and mitigate anomalous network spikes.

## 1. What is Software-Defined Networking (SDN)?

Traditional networking couples the **Control Plane** (the logic of where traffic goes) and the **Data Plane** (the physical forwarding of packets) inside hardware switches. Configuration has to be done switch-by-switch.

SDN separates these planes:
- **Data Plane (Forwarding):** Resides in the switch (Open vSwitch in this project). It simply forwards packets according to a table of rules.
- **Control Plane (Logic):** Resides in a centralized software controller (a Ryu/OS-Ken Python application). The controller dictates what rules are placed into the switches using a protocol (OpenFlow 1.3).

This centralization allows the controller to have a holistic view of network traffic and proactively secure it by rewriting rules in real time.

## 2. Project Architecture Overview

The topology represents a basic targeted attack scenario:
- **Switch 1 (`s1`):** An Open vSwitch acting as the middleman.
- **Controller:** Runs `ryu_controller.py`, polls `s1` for traffic data repeatedly, and programs routing/drop rules.
- **`h1` (Attacker):** Initiates denial-of-service (DoS) or flood attacks.
- **`h2` (Victim):** The target server or host for the attack.
- **`h3` (Benign):** Represents normal, underlying network behavior.

## 3. Core Mechanisms

The project relies on a loop of three phases: **Monitoring**, **Detection**, and **Mitigation**.

### A. Monitoring
The controller continually queries the switch for "Flow Statistics" per connected IP address at a strict rate (`POLL_INTERVAL`, default 1.0s). This provides a snapshot in time of exactly how many packets each distinct sender has transmitted.

### B. Detection Algorithm
Rather than looking strictly at instant packet volume—which is prone to false positives from sudden benign bursts—the logic applies smoothed statistical anomaly detection.

1. **Exponential Moving Average (EMA):** 
   A smoothing technique where recent values are weighted heavier than older ones using an `EMA_ALPHA` factor.
   - *Advantage:* If a benign host sends a massive singular burst, the EMA will curve upwards gradually, preventing immediate panic. However, an attacker sustaining high output will quickly push the EMA over the anomaly line.

2. **Hysteresis / Sustained Windows:** 
   Even if the EMA crosses the threshold (e.g., `500 pkt/s`), the rule won't fire instantly. The EMA must stay above that threshold for consecutive polling cycles (e.g., `SUSTAINED_WINDOWS` = 3).
   - *Advantage:* Avoids mitigating harmless micro-bursts, ensuring absolute certainty before dropping traffic.

### C. Mitigation & Recovery
Once the sustained condition is met, the system reacts:
1. **Drop Rule Enforcement:** The controller uses OpenFlow to push a high-priority drop rule specifically targeting the misbehaving source IP into the switch limit tables.
2. **Auto-Recovery (`idle_timeout`):** Hard bans are brittle. The OpenFlow drop rule is accompanied by an `idle_timeout` (e.g., `30s`). If the attacker quits trying to flood the network, the rule sees zero hits for 30 seconds and automatically disappears, returning the network state back to normal without manual intervention.

## 4. Understanding the Project Structure

Below is an outline of what each file accomplishes in serving the greater architecture:

- **`ryu_controller.py`:** The brain. Contains the logic for the L2 Ethernet Switch learning, requests the flow stats, computes the EMA, and initiates the mitigation OpenFlow drop flow overrides.
- **`topology.py`:** The Mininet blueprint. It translates our concept of 3 Hosts and 1 Switch into actual virtual Ethernet interfaces inside the OS.
- **`run_demo.sh`:** The orchestrator. Launching complex SDN environments entails tricky sequence timings. This manages the safe start-up and shutdown of the python controller, processes, and topologies.
- **`launch_controller.py`:** An invocation wrapper that manages differences between using raw `ryu-manager` and `osken-manager`, passing down configurations neatly.
- **`traffic/`:** Houses bash scripts for producing predetermined streams of network traffic for testing (`benign.sh` and `attack.sh`). 
- **`analysis/`:** Takes the `.csv` dumps exported by the controller loggers and visualizes the math. `plot_stats.py` draws Matplotlib graphs of EMA vs Threshold, while `evaluate.py` judges how fast the code noticed the flood start and drop.
