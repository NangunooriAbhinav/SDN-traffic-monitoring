#!/usr/bin/env python3
"""
analysis/plot_stats.py

Generate visualisation charts from the controller's CSV log files.

Produces:
  1. Packet rate & EMA over time per source IP (with detection threshold line)
  2. Event timeline (anomaly detections, mitigations, unblocks)
  3. Per-source action breakdown (bar chart)

Usage:
  python3 analysis/plot_stats.py                          # auto-find latest CSVs in logs/
  python3 analysis/plot_stats.py --stats logs/flow_stats_*.csv --events logs/events_*.csv
  python3 analysis/plot_stats.py --outdir results/        # save PNGs to custom dir

Output:
  PNG figures saved to logs/ (or --outdir) directory.
"""

import argparse
import csv
import glob
import os
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # non-interactive backend (no display needed)
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Patch

# ---------------------------
# Defaults
# ---------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_LOG_DIR = os.path.join(PROJECT_DIR, "logs")

# Colors
COLORS = {
    "pkt_rate": "#4FC3F7",   # light blue
    "ema": "#FF7043",        # orange-red
    "threshold": "#EF5350",  # red dashed line
    "anomaly_detected": "#FFA726",    # orange
    "mitigation": "#EF5350",          # red
    "unblock_heuristic": "#66BB6A",   # green
    "flow_removed": "#AB47BC",        # purple
    "normal": "#78909C",     # grey
    "anomaly": "#FFA726",    # orange
    "mitigate": "#EF5350",   # red
    "blocked": "#E53935",    # dark red
    "unblocked": "#66BB6A",  # green
}


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


def plot_rates(stats_rows, events_rows, threshold, outdir):
    """
    Plot 1: Packet rate and EMA over time, per source IP.
    One subplot per unique src_ip.
    """
    # Group by src_ip
    sources = {}
    for row in stats_rows:
        src = row["src_ip"]
        sources.setdefault(src, []).append(row)

    if not sources:
        print("[plot_stats] No flow stats data to plot.")
        return

    n = len(sources)
    fig, axes = plt.subplots(n, 1, figsize=(14, 4 * n), sharex=True, squeeze=False)
    fig.suptitle("Packet Rate & EMA Over Time", fontsize=16, fontweight="bold", y=0.98)

    for idx, (src_ip, rows) in enumerate(sorted(sources.items())):
        ax = axes[idx, 0]
        times = [r["timestamp"] for r in rows]
        rates = [r["pkt_rate"] for r in rows]
        emas = [r["ema"] for r in rows]

        ax.plot(times, rates, color=COLORS["pkt_rate"], alpha=0.5, linewidth=1,
                label="Packet Rate (raw)")
        ax.plot(times, emas, color=COLORS["ema"], linewidth=2,
                label="EMA (smoothed)")
        ax.axhline(y=threshold, color=COLORS["threshold"], linestyle="--",
                   linewidth=1.5, alpha=0.8, label=f"Threshold ({threshold:.0f} pkt/s)")

        # Mark mitigation events as vertical lines
        if events_rows:
            for ev in events_rows:
                if ev["src_ip"] == src_ip and ev["event_type"] == "mitigation":
                    ax.axvline(x=ev["timestamp"], color=COLORS["mitigation"],
                               linestyle=":", linewidth=1.5, alpha=0.7)

        ax.set_ylabel("Packets/sec", fontsize=11)
        ax.set_title(f"Source: {src_ip}", fontsize=12, fontweight="bold")
        ax.legend(loc="upper right", fontsize=9)
        ax.grid(True, alpha=0.3)
        ax.set_ylim(bottom=0)

    axes[-1, 0].set_xlabel("Time", fontsize=11)
    axes[-1, 0].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    fig.autofmt_xdate(rotation=30)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    outpath = os.path.join(outdir, "packet_rate_ema.png")
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot_stats] Saved: {outpath}")


def plot_event_timeline(events_rows, outdir):
    """
    Plot 2: Event timeline — scatter plot of events over time, colored by type.
    """
    if not events_rows:
        print("[plot_stats] No events data to plot.")
        return

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.suptitle("Detection & Mitigation Event Timeline", fontsize=16, fontweight="bold")

    # Assign y-positions per src_ip
    src_ips = sorted(set(ev["src_ip"] for ev in events_rows))
    y_map = {ip: i for i, ip in enumerate(src_ips)}

    for ev in events_rows:
        etype = ev["event_type"]
        color = COLORS.get(etype, "#78909C")
        marker = {"anomaly_detected": "^", "mitigation": "X",
                   "unblock_heuristic": "o", "flow_removed": "s"}.get(etype, "D")
        ax.scatter(ev["timestamp"], y_map[ev["src_ip"]], c=color,
                   marker=marker, s=80, edgecolors="black", linewidths=0.5,
                   zorder=3)

    ax.set_yticks(range(len(src_ips)))
    ax.set_yticklabels(src_ips, fontsize=11)
    ax.set_ylabel("Source IP", fontsize=11)
    ax.set_xlabel("Time", fontsize=11)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.grid(True, alpha=0.3)

    # Legend
    legend_items = [
        Patch(facecolor=COLORS["anomaly_detected"], label="Anomaly Detected"),
        Patch(facecolor=COLORS["mitigation"], label="Mitigation (Drop)"),
        Patch(facecolor=COLORS["unblock_heuristic"], label="Unblocked"),
        Patch(facecolor=COLORS["flow_removed"], label="Flow Removed"),
    ]
    ax.legend(handles=legend_items, loc="upper right", fontsize=9)

    fig.autofmt_xdate(rotation=30)
    plt.tight_layout()

    outpath = os.path.join(outdir, "event_timeline.png")
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot_stats] Saved: {outpath}")


def plot_action_breakdown(stats_rows, outdir):
    """
    Plot 3: Stacked bar chart showing action counts per source IP.
    """
    if not stats_rows:
        return

    # Count actions per source
    action_counts = {}  # src_ip -> {action -> count}
    for row in stats_rows:
        src = row["src_ip"]
        action = row["action"]
        action_counts.setdefault(src, {}).setdefault(action, 0)
        action_counts[src][action] += 1

    if not action_counts:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.suptitle("Action Breakdown Per Source IP", fontsize=16, fontweight="bold")

    sources = sorted(action_counts.keys())
    all_actions = sorted(set(a for counts in action_counts.values() for a in counts))
    x = range(len(sources))
    bar_width = 0.6

    bottom = [0] * len(sources)
    for action in all_actions:
        values = [action_counts[s].get(action, 0) for s in sources]
        color = COLORS.get(action, "#78909C")
        ax.bar(x, values, bar_width, bottom=bottom, label=action, color=color,
               edgecolor="white", linewidth=0.5)
        bottom = [b + v for b, v in zip(bottom, values)]

    ax.set_xticks(x)
    ax.set_xticklabels(sources, fontsize=11)
    ax.set_xlabel("Source IP", fontsize=11)
    ax.set_ylabel("Number of Poll Samples", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()

    outpath = os.path.join(outdir, "action_breakdown.png")
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot_stats] Saved: {outpath}")


def main():
    parser = argparse.ArgumentParser(description="Plot SDN flow stats and detection events.")
    parser.add_argument("--stats", help="Path to flow_stats CSV file (auto-detects latest if omitted)")
    parser.add_argument("--events", help="Path to events CSV file (auto-detects latest if omitted)")
    parser.add_argument("--logdir", default=DEFAULT_LOG_DIR, help="Directory containing CSV logs")
    parser.add_argument("--outdir", default=None, help="Output directory for PNG charts (default: same as logdir)")
    parser.add_argument("--threshold", type=float, default=500.0,
                        help="Detection threshold line to draw (default: 500)")
    args = parser.parse_args()

    # Resolve file paths
    stats_file = args.stats or find_latest_csv(args.logdir, "flow_stats")
    events_file = args.events or find_latest_csv(args.logdir, "events")
    outdir = args.outdir or args.logdir

    if not stats_file or not os.path.isfile(stats_file):
        print(f"[plot_stats] ERROR: No flow_stats CSV found in {args.logdir}")
        print("  Run the demo first to generate data, or specify --stats <path>")
        sys.exit(1)

    os.makedirs(outdir, exist_ok=True)

    print(f"[plot_stats] Stats CSV:  {stats_file}")
    print(f"[plot_stats] Events CSV: {events_file or '(none)'}")
    print(f"[plot_stats] Output dir: {outdir}")
    print()

    # Parse
    stats_rows = parse_stats_csv(stats_file)
    events_rows = parse_events_csv(events_file) if events_file else []

    print(f"[plot_stats] Loaded {len(stats_rows)} stats rows, {len(events_rows)} event rows.")

    if not stats_rows:
        print("[plot_stats] No data to plot. Exiting.")
        sys.exit(0)

    # Generate plots
    plot_rates(stats_rows, events_rows, args.threshold, outdir)
    plot_event_timeline(events_rows, outdir)
    plot_action_breakdown(stats_rows, outdir)

    print()
    print(f"[plot_stats] Done! Charts saved to: {outdir}/")


if __name__ == "__main__":
    main()
