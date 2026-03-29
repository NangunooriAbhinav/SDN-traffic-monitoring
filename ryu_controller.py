#!/usr/bin/env python3
"""
Ryu controller app: monitoring, threshold-based anomaly detection, and mitigation.

Overview
- Polls flow stats from connected switches (OpenFlow 1.3).
- Computes per-source (IPv4) packet rate using delta and an EMA smoother.
- Triggers mitigation (installing a high-priority drop flow) when EMA exceeds a configurable threshold
  for a sustained number of consecutive windows (hysteresis).
- Drop rules include an idle timeout so mitigation is automatically lifted after a configurable period.

Notes
- Designed as a compact, readable starting point for the project. You can tune constants below.
- This app assumes IPv4 traffic; ARP/other traffic are ignored for detection purposes.
- Test and run in a Mininet topology with Open vSwitch and use the Ryu manager:
    ryu-manager mpclient/ryu_controller.py
"""

import time
import logging
import csv
import os
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp

LOG = logging.getLogger("ryu_controller")
LOG.setLevel(logging.INFO)


# ---------------------------
# Configuration (tune as needed)
# ---------------------------
POLL_INTERVAL = 1.0          # seconds between flow stats polls
EMA_ALPHA = 0.4              # EMA smoothing factor (0 < alpha <= 1)
DETECTION_THRESHOLD = 500.0  # packets/sec EMA threshold to consider anomalous
SUSTAINED_WINDOWS = 3        # number of consecutive windows above threshold to trigger mitigation
MITIGATION_IDLE_TIMEOUT = 30 # seconds: drop flow idle timeout (auto-unblock)
DROP_FLOW_PRIORITY = 200     # priority for drop rules
FLOW_STATS_TABLE = 0         # table to request stats from

# Logging paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
# ---------------------------


class SimpleSDNMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSDNMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}   # dpid -> datapath object
        self.mac_to_port = {}  # dpid -> {mac_addr -> port_no} (L2 learning table)
        # per-datapath, per-src statistics:
        # stats[dpid][ipv4_src] = {
        #   'last_packets': int,
        #   'last_time': float,
        #   'ema': float,
        #   'sustain_count': int
        # }
        self.stats = {}
        # keep a set of currently blocked (dpid, src_ip) tuples
        self.blocked = set()

        # --- CSV logging setup ---
        os.makedirs(LOG_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Flow stats CSV: periodic per-source metrics
        self.stats_csv_path = os.path.join(LOG_DIR, f"flow_stats_{ts}.csv")
        self._stats_csv_file = open(self.stats_csv_path, "w", newline="")
        self._stats_writer = csv.writer(self._stats_csv_file)
        self._stats_writer.writerow(
            ["timestamp", "dpid", "src_ip", "packet_count", "pkt_rate", "ema", "sustain_count", "action"]
        )

        # Events CSV: detection and mitigation events
        self.events_csv_path = os.path.join(LOG_DIR, f"events_{ts}.csv")
        self._events_csv_file = open(self.events_csv_path, "w", newline="")
        self._events_writer = csv.writer(self._events_csv_file)
        self._events_writer.writerow(
            ["timestamp", "dpid", "src_ip", "event_type", "ema", "threshold", "detail"]
        )

        LOG.info("CSV logging → stats: %s", self.stats_csv_path)
        LOG.info("CSV logging → events: %s", self.events_csv_path)

        # start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    # ---------------------------
    # Datapath lifecycle handlers
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = datapath.id
        state = ev.state

        if state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.datapaths[dpid] = datapath
                self.stats.setdefault(dpid, {})
                LOG.info("Datapath %s connected", dpid)
        elif state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                del self.datapaths[dpid]
                if dpid in self.stats:
                    del self.stats[dpid]
                LOG.info("Datapath %s disconnected", dpid)

    # ---------------------------
    # Switch feature config (optional default flows)
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry (low priority) to send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)
        LOG.info("Installed table-miss flow on datapath %s", datapath.id)

    # ---------------------------
    # L2 Learning Switch — PacketIn handler
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP packets (used by SDN for topology discovery)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Initialize per-switch MAC table
        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC → port mapping
        self.mac_to_port[dpid][src] = in_port

        # Lookup destination: use learned port or flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If we know the destination port, install a flow to avoid future PacketIn
        if out_port != ofproto.OFPP_FLOOD:
            # Build match — include eth_type and IP fields for IPv4 so flow stats
            # can be used by the anomaly detector
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            pkt_arp = pkt.get_protocol(arp.arp)

            if pkt_ipv4:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    eth_dst=dst,
                    eth_src=src,
                    ipv4_src=pkt_ipv4.src,
                    ipv4_dst=pkt_ipv4.dst,
                )
            elif pkt_arp:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0806,
                    eth_dst=dst,
                    eth_src=src,
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src,
                )

            # Priority 1 (above table-miss at 0, below drop rules at 200)
            # Set SEND_FLOW_REM flag so we get notified if the flow is removed
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst,
                idle_timeout=60,
                hard_timeout=0,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
            )
            datapath.send_msg(mod)

        # Send the buffered/received packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # ---------------------------
    # Monitoring loop
    # ---------------------------
    def _monitor(self):
        while True:
            for dpid, dp in list(self.datapaths.items()):
                try:
                    self._request_flow_stats(dp)
                except Exception as e:
                    LOG.exception("Error requesting flow stats from %s: %s", dpid, e)
            hub.sleep(POLL_INTERVAL)

    def _request_flow_stats(self, datapath):
        """
        Send an OFPFlowStatsRequest to the datapath.
        We request all flows in the chosen table.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Request stats for table 0 (or FLOW_STATS_TABLE)
        req = parser.OFPFlowStatsRequest(datapath, table_id=FLOW_STATS_TABLE)
        datapath.send_msg(req)

    # ---------------------------
    # Flow stats reply handler
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        body = ev.msg.body
        now = time.time()

        for stat in body:
            # We are only interested in IPv4 flows (eth_type = 0x0800) and flows with ipv4_src
            match = getattr(stat, "match", None)
            if match is None:
                continue

            ipv4_src = None
            # Safe extraction: match may be a dict-like or object; handle common cases
            try:
                # many Ryu examples allow indexing like a dict
                if "ipv4_src" in match:
                    ipv4_src = match["ipv4_src"]
            except Exception:
                # fallback: attempt to iterate items
                try:
                    for k, v in getattr(match, "items", lambda: [])():
                        if k == "ipv4_src":
                            ipv4_src = v
                            break
                except Exception:
                    # try to_jsondict (less common)
                    try:
                        j = match.to_jsondict()
                        # j -> {'OFPMatch': {'oxm_fields': [...]}}
                        # This is more involved to parse; skip for compactness
                        ipv4_src = None
                    except Exception:
                        ipv4_src = None

            if not ipv4_src:
                # not an IPv4-matched flow or no src field present; skip
                continue

            # initialize per-src stats if missing
            dp_stats = self.stats.setdefault(dpid, {})
            entry = dp_stats.get(ipv4_src)
            if entry is None:
                entry = {
                    "last_packets": stat.packet_count,
                    "last_time": now,
                    "ema": 0.0,
                    "sustain_count": 0,
                }
                dp_stats[ipv4_src] = entry
                # Nothing to compute on first sighting
                continue

            # compute packet rate
            dt = now - entry["last_time"]
            if dt <= 0:
                dt = POLL_INTERVAL
            delta_pkts = stat.packet_count - entry["last_packets"]
            if delta_pkts < 0:
                # counters may wrap or reset; reset baseline
                delta_pkts = stat.packet_count

            pkt_rate = float(delta_pkts) / dt

            # update EMA
            prev_ema = entry["ema"]
            ema = EMA_ALPHA * pkt_rate + (1.0 - EMA_ALPHA) * prev_ema if prev_ema > 0 else pkt_rate
            entry["ema"] = ema
            entry["last_packets"] = stat.packet_count
            entry["last_time"] = now

            LOG.debug(
                "DPID %s SRC %s pkt_rate=%.1f ema=%.1f sustain=%d",
                dpid,
                ipv4_src,
                pkt_rate,
                ema,
                entry["sustain_count"],
            )

            # detection logic with hysteresis
            key = (dpid, ipv4_src)
            action = "normal"
            if ema >= DETECTION_THRESHOLD:
                entry["sustain_count"] += 1
                LOG.info(
                    "Potential anomaly: dpid=%s src=%s ema=%.1f sustain=%d",
                    dpid,
                    ipv4_src,
                    ema,
                    entry["sustain_count"],
                )
                if entry["sustain_count"] >= SUSTAINED_WINDOWS:
                    if key not in self.blocked:
                        action = "mitigate"
                        LOG.info("Trigger mitigation for %s on dpid %s (ema=%.1f)", ipv4_src, dpid, ema)
                        self._mitigate(datapath, ipv4_src)
                        self.blocked.add(key)
                        self._log_event(dpid, ipv4_src, "mitigation", ema,
                                        "drop flow installed")
                    else:
                        action = "blocked"
                else:
                    action = "anomaly"
                    self._log_event(dpid, ipv4_src, "anomaly_detected", ema,
                                    f"sustain={entry['sustain_count']}/{SUSTAINED_WINDOWS}")
            else:
                # below threshold: decay sustain counter
                if entry["sustain_count"] > 0:
                    entry["sustain_count"] = max(0, entry["sustain_count"] - 1)
                if key in self.blocked and ema < (DETECTION_THRESHOLD * 0.6):
                    action = "unblocked"
                    LOG.info("Heuristic unblocking candidate: %s on dpid %s (ema=%.1f)", ipv4_src, dpid, ema)
                    self.blocked.discard(key)
                    self._log_event(dpid, ipv4_src, "unblock_heuristic", ema,
                                    "ema dropped below 60% threshold")

            # Write per-poll stats row
            self._stats_writer.writerow([
                datetime.now().isoformat(), dpid, ipv4_src,
                stat.packet_count, f"{pkt_rate:.2f}", f"{ema:.2f}",
                entry["sustain_count"], action
            ])
            self._stats_csv_file.flush()

    # ---------------------------
    # CSV event helper
    # ---------------------------
    def _log_event(self, dpid, src_ip, event_type, ema, detail=""):
        """Write a row to the events CSV."""
        self._events_writer.writerow([
            datetime.now().isoformat(), dpid, src_ip,
            event_type, f"{ema:.2f}", f"{DETECTION_THRESHOLD:.2f}", detail
        ])
        self._events_csv_file.flush()

    # ---------------------------
    # Mitigation: install drop flow
    # ---------------------------
    def _mitigate(self, datapath, src_ip):
        """
        Install a high-priority flow that drops traffic from src_ip (IPv4).
        Uses idle_timeout so it expires automatically after MITIGATION_IDLE_TIMEOUT seconds of inactivity.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match IPv4 src; include eth_type to ensure IPv4 match
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        # No actions => drop
        instructions = []

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=FLOW_STATS_TABLE,
            priority=DROP_FLOW_PRIORITY,
            match=match,
            instructions=instructions,
            idle_timeout=MITIGATION_IDLE_TIMEOUT,
            hard_timeout=0,
            command=ofproto_v1_3.OFPFC_ADD,
        )
        datapath.send_msg(mod)
        LOG.info("Installed drop flow on dpid=%s for src=%s (idle_timeout=%ds)", datapath.id, src_ip, MITIGATION_IDLE_TIMEOUT)

    # ---------------------------
    # Optional: flow removal / cleanup handlers (log)
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        match = getattr(msg, "match", None)
        src = None
        try:
            if "ipv4_src" in match:
                src = match["ipv4_src"]
        except Exception:
            try:
                for k, v in getattr(match, "items", lambda: [])():
                    if k == "ipv4_src":
                        src = v
                        break
            except Exception:
                src = None

        if src:
            key = (datapath.id, src)
            if key in self.blocked:
                LOG.info("Drop flow expired/removed for %s on dpid %s", src, datapath.id)
                self.blocked.discard(key)
                self._log_event(datapath.id, src, "flow_removed", 0.0,
                                f"reason={msg.reason}")

# End of file
