#!/usr/bin/env python3
"""
analysis/evaluate.py

Compute evaluation metrics from the controller's CSV log files.

Metrics computed:
  1. Detection latency   — time from first anomaly detection to mitigation (per source)
  2. Mitigation latency  — time from attack start (first elevated EMA) to drop flow install
  3. False positive rate  — % of non-attacker IPs that were flagged/mitigated
  4. False negative rate  — % of attacker IPs that were NOT mitigated
  5. Recovery time        — time from mitigation to flow removal (unblock)
  6. Summary statistics   — total events, per-source breakdowns

Usage:
  python3 analysis/evaluate.py                          # auto-find latest CSVs
  python3 analysis/evaluate.py --stats logs/flow_stats_*.csv --events logs/events_*.csv
  python3 analysis/evaluate.py --attacker 10.0.0.1      # specify known attacker IP

Output:
  Prints metrics to stdout and saves a summary to logs/evaluation_report.txt
"""

import argparse
import csv
import glob
import os
import sys
from datetime import datetime
from collections import defaultdict

# ---------------------------
# Defaults
# ---------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_LOG_DIR = os.path.join(PROJECT_DIR, "logs")

# Default attacker IP (h1 in our topology)
DEFAULT_ATTACKER_IP = "10.0.0.1"


def find_latest_csv(log_dir, prefix):
    """Find the most recently modified CSV file matching the prefix."""
    pattern = os.path.join(log_dir, f"{prefix}_*.csv")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def parse_stats_csv(filepath):
    """Parse flow_stats CSV into a list of dicts."""
    rows = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                row["timestamp"] = datetime.fromisoformat(row["timestamp"])
                row["pkt_rate"] = float(row["pkt_rate"])
                row["ema"] = float(row["ema"])
                row["packet_count"] = int(row["packet_count"])
                row["sustain_count"] = int(row["sustain_count"])
                row["dpid"] = int(row["dpid"])
                rows.append(row)
            except (ValueError, KeyError):
                continue
    return rows


def parse_events_csv(filepath):
    """Parse events CSV into a list of dicts."""
    rows = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                row["timestamp"] = datetime.fromisoformat(row["timestamp"])
                row["ema"] = float(row["ema"])
                row["threshold"] = float(row["threshold"])
                row["dpid"] = int(row["dpid"])
                rows.append(row)
            except (ValueError, KeyError):
                continue
    return rows


def compute_metrics(stats_rows, events_rows, attacker_ips):
    """Compute all evaluation metrics."""
    results = {
        "per_source": {},
        "global": {},
    }

    # --- Group events by source IP ---
    events_by_src = defaultdict(list)
    for ev in events_rows:
        events_by_src[ev["src_ip"]].append(ev)

    # --- Group stats by source IP ---
    stats_by_src = defaultdict(list)
    for row in stats_rows:
        stats_by_src[row["src_ip"]].append(row)

    all_sources = set(stats_by_src.keys()) | set(events_by_src.keys())

    for src_ip in sorted(all_sources):
        src_events = sorted(events_by_src.get(src_ip, []), key=lambda e: e["timestamp"])
        src_stats = sorted(stats_by_src.get(src_ip, []), key=lambda s: s["timestamp"])

        info = {
            "is_attacker": src_ip in attacker_ips,
            "total_stats_samples": len(src_stats),
            "total_events": len(src_events),
            "first_seen": src_stats[0]["timestamp"] if src_stats else None,
            "last_seen": src_stats[-1]["timestamp"] if src_stats else None,
            "max_pkt_rate": max((s["pkt_rate"] for s in src_stats), default=0),
            "max_ema": max((s["ema"] for s in src_stats), default=0),
            "avg_ema": sum(s["ema"] for s in src_stats) / len(src_stats) if src_stats else 0,
        }

        # Find key event timestamps
        first_anomaly = None
        first_mitigation = None
        first_unblock = None
        first_flow_removed = None

        for ev in src_events:
            if ev["event_type"] == "anomaly_detected" and first_anomaly is None:
                first_anomaly = ev["timestamp"]
            elif ev["event_type"] == "mitigation" and first_mitigation is None:
                first_mitigation = ev["timestamp"]
            elif ev["event_type"] == "unblock_heuristic" and first_unblock is None:
                first_unblock = ev["timestamp"]
            elif ev["event_type"] == "flow_removed" and first_flow_removed is None:
                first_flow_removed = ev["timestamp"]

        info["first_anomaly_time"] = first_anomaly
        info["first_mitigation_time"] = first_mitigation
        info["first_unblock_time"] = first_unblock
        info["first_flow_removed_time"] = first_flow_removed

        # Detection latency: first anomaly → first mitigation
        if first_anomaly and first_mitigation:
            info["detection_latency_s"] = (first_mitigation - first_anomaly).total_seconds()
        else:
            info["detection_latency_s"] = None

        # Mitigation latency: first elevated sample (above threshold) → mitigation
        first_elevated = None
        for s in src_stats:
            if s["action"] in ("anomaly", "mitigate"):
                first_elevated = s["timestamp"]
                break
        if first_elevated and first_mitigation:
            info["mitigation_latency_s"] = (first_mitigation - first_elevated).total_seconds()
        else:
            info["mitigation_latency_s"] = None

        # Recovery time: mitigation → flow removed (or unblock)
        recovery_end = first_flow_removed or first_unblock
        if first_mitigation and recovery_end:
            info["recovery_time_s"] = (recovery_end - first_mitigation).total_seconds()
        else:
            info["recovery_time_s"] = None

        # Action distribution
        action_counts = defaultdict(int)
        for s in src_stats:
            action_counts[s["action"]] += 1
        info["action_counts"] = dict(action_counts)

        # Was this source mitigated?
        info["was_mitigated"] = first_mitigation is not None

        results["per_source"][src_ip] = info

    # --- Global metrics ---
    mitigated_sources = {ip for ip, info in results["per_source"].items() if info["was_mitigated"]}
    attacker_set = set(attacker_ips)
    benign_set = all_sources - attacker_set

    # True/false positive/negative
    true_positives = mitigated_sources & attacker_set
    false_positives = mitigated_sources & benign_set
    false_negatives = attacker_set - mitigated_sources
    true_negatives = benign_set - mitigated_sources

    results["global"] = {
        "total_sources": len(all_sources),
        "total_stats_samples": len(stats_rows),
        "total_events": len(events_rows),
        "attacker_ips": sorted(attacker_ips),
        "true_positives": sorted(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "true_negatives": sorted(true_negatives),
        "tp_count": len(true_positives),
        "fp_count": len(false_positives),
        "fn_count": len(false_negatives),
        "tn_count": len(true_negatives),
    }

    # Rates (avoid division by zero)
    total_actual_positive = len(attacker_set) or 1
    total_actual_negative = len(benign_set) or 1
    total_predicted_positive = len(mitigated_sources) or 1

    results["global"]["detection_rate"] = len(true_positives) / total_actual_positive
    results["global"]["false_positive_rate"] = len(false_positives) / total_actual_negative
    results["global"]["false_negative_rate"] = len(false_negatives) / total_actual_positive
    results["global"]["precision"] = len(true_positives) / total_predicted_positive
    results["global"]["recall"] = len(true_positives) / total_actual_positive

    # Average detection latency (across attackers that were detected)
    latencies = [
        results["per_source"][ip]["detection_latency_s"]
        for ip in true_positives
        if results["per_source"][ip]["detection_latency_s"] is not None
    ]
    results["global"]["avg_detection_latency_s"] = (
        sum(latencies) / len(latencies) if latencies else None
    )

    return results


def format_report(results):
    """Format evaluation results as a readable text report."""
    lines = []
    sep = "=" * 70

    lines.append(sep)
    lines.append("  SDN ANOMALY DETECTION — EVALUATION REPORT")
    lines.append(sep)
    lines.append("")

    g = results["global"]

    # --- Summary ---
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total source IPs observed:  {g['total_sources']}")
    lines.append(f"  Total stats samples:        {g['total_stats_samples']}")
    lines.append(f"  Total events logged:        {g['total_events']}")
    lines.append(f"  Known attacker IPs:         {', '.join(g['attacker_ips']) or 'none specified'}")
    lines.append("")

    # --- Classification ---
    lines.append("CLASSIFICATION RESULTS")
    lines.append("-" * 40)
    lines.append(f"  True Positives  (TP): {g['tp_count']}  {g['true_positives']}")
    lines.append(f"  False Positives (FP): {g['fp_count']}  {g['false_positives']}")
    lines.append(f"  False Negatives (FN): {g['fn_count']}  {g['false_negatives']}")
    lines.append(f"  True Negatives  (TN): {g['tn_count']}  {g['true_negatives']}")
    lines.append("")
    lines.append(f"  Detection Rate (Recall): {g['recall']:.2%}")
    lines.append(f"  Precision:               {g['precision']:.2%}")
    lines.append(f"  False Positive Rate:     {g['false_positive_rate']:.2%}")
    lines.append(f"  False Negative Rate:     {g['false_negative_rate']:.2%}")
    lines.append("")

    # --- Latencies ---
    lines.append("LATENCY METRICS")
    lines.append("-" * 40)
    avg_lat = g["avg_detection_latency_s"]
    lines.append(f"  Avg detection latency:  {avg_lat:.2f}s" if avg_lat is not None else "  Avg detection latency:  N/A")
    lines.append("")

    # --- Per-source ---
    lines.append("PER-SOURCE BREAKDOWN")
    lines.append("-" * 40)

    for src_ip, info in sorted(results["per_source"].items()):
        role = "ATTACKER" if info["is_attacker"] else "BENIGN"
        status = "MITIGATED" if info["was_mitigated"] else "not mitigated"
        lines.append(f"\n  [{role}] {src_ip} — {status}")
        lines.append(f"    Samples: {info['total_stats_samples']}, Events: {info['total_events']}")
        lines.append(f"    Max pkt rate: {info['max_pkt_rate']:.1f} pkt/s, Max EMA: {info['max_ema']:.1f}")
        lines.append(f"    Avg EMA: {info['avg_ema']:.1f}")

        if info["detection_latency_s"] is not None:
            lines.append(f"    Detection latency: {info['detection_latency_s']:.2f}s")
        if info["mitigation_latency_s"] is not None:
            lines.append(f"    Mitigation latency: {info['mitigation_latency_s']:.2f}s")
        if info["recovery_time_s"] is not None:
            lines.append(f"    Recovery time: {info['recovery_time_s']:.2f}s")

        actions = info["action_counts"]
        if actions:
            parts = [f"{k}={v}" for k, v in sorted(actions.items())]
            lines.append(f"    Actions: {', '.join(parts)}")

    lines.append("")
    lines.append(sep)
    lines.append(f"  Report generated: {datetime.now().isoformat()}")
    lines.append(sep)
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Evaluate SDN anomaly detection performance.")
    parser.add_argument("--stats", help="Path to flow_stats CSV file")
    parser.add_argument("--events", help="Path to events CSV file")
    parser.add_argument("--logdir", default=DEFAULT_LOG_DIR, help="Directory containing CSV logs")
    parser.add_argument("--attacker", nargs="+", default=[DEFAULT_ATTACKER_IP],
                        help=f"Known attacker IP(s) (default: {DEFAULT_ATTACKER_IP})")
    parser.add_argument("--outfile", default=None,
                        help="Output report file (default: logs/evaluation_report.txt)")
    args = parser.parse_args()

    # Resolve paths
    stats_file = args.stats or find_latest_csv(args.logdir, "flow_stats")
    events_file = args.events or find_latest_csv(args.logdir, "events")

    if not stats_file or not os.path.isfile(stats_file):
        print(f"[evaluate] ERROR: No flow_stats CSV found in {args.logdir}")
        print("  Run the demo first to generate data, or specify --stats <path>")
        sys.exit(1)

    print(f"[evaluate] Stats CSV:    {stats_file}")
    print(f"[evaluate] Events CSV:   {events_file or '(none)'}")
    print(f"[evaluate] Attacker IPs: {args.attacker}")
    print()

    # Parse
    stats_rows = parse_stats_csv(stats_file)
    events_rows = parse_events_csv(events_file) if events_file else []

    if not stats_rows:
        print("[evaluate] No stats data found. Exiting.")
        sys.exit(0)

    # Compute
    results = compute_metrics(stats_rows, events_rows, set(args.attacker))

    # Format & print
    report = format_report(results)
    print(report)

    # Save to file
    outfile = args.outfile or os.path.join(args.logdir, "evaluation_report.txt")
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    with open(outfile, "w") as f:
        f.write(report)
    print(f"[evaluate] Report saved: {outfile}")


if __name__ == "__main__":
    main()
