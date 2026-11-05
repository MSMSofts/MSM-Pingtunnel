#!/usr/bin/env python3
"""Low-overhead, secret-free Linux PingTunnel long-session sampler.

Runs locally on EACH VPS. Never opens config.json or copies pairing keys.
Security/performance JSON is allowlisted to numeric counters and state only.
Kernel /proc/net UDP counters are host-wide, not PingTunnel-specific.
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

SECURITY_NAMES = {
    "state", "last_valid_age_seconds", "recoveries", "replay_drops",
    "authentication_failures", "pending_packets", "expired_or_overflow_packets",
}
SECURITY_PREFIXES = ("icmp_", "reverse_", "smart_", "auto_", "direct_")
PERF_NAMES = {
    "profile", "rtt_samples", "rtt_ms", "jitter_ms", "probe_loss_estimate",
    "recent_rtt_samples", "recent_rtt_ms", "recent_jitter_ms",
    "last_rtt_sample_age_seconds", "next_tcp_resend_ms", "next_tcp_window",
}
SNMP_NAMES = {
    "Udp": {"InDatagrams", "InErrors", "RcvbufErrors", "SndbufErrors", "OutDatagrams"},
    "Ip": {"InDiscards", "InReceives"},
    "Icmp": {"InErrors", "OutErrors"},
}


def safe_json(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, PermissionError, ValueError, OSError):
        return {}


def numerical_fields(source, names=None, prefixes=()):
    result = {}
    for key, value in source.items():
        if not isinstance(key, str):
            continue
        if (names is not None and key not in names) and not key.startswith(prefixes):
            continue
        if type(value) in (int, float, bool) or key in ("state", "profile", "icmp_direction") and isinstance(value, str):
            result[key] = value
    return result


def read_snmp(path="/proc/net/snmp"):
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    found = {}
    for header, values in zip(lines[::2], lines[1::2]):
        h, v = header.split(), values.split()
        if not h or not v or h[0] != v[0]:
            continue
        protocol = h[0].rstrip(":")
        for key, raw in zip(h[1:], v[1:]):
            if key in SNMP_NAMES.get(protocol, set()):
                try:
                    found[protocol + "_" + key] = int(raw)
                except ValueError:
                    pass
    return found


def main_pid():
    try:
        call = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "--value", "pingtunnel.service"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, check=False, timeout=2,
        )
        pid = int(call.stdout.strip())
        return pid if pid > 0 else None
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return None


def process_metrics(pid):
    if pid is None:
        return {}
    proc = Path("/proc") / str(pid)
    try:
        raw = (proc / "stat").read_text(encoding="utf-8")
        # The executable name in parentheses can contain spaces.
        fields = raw.rsplit(") ", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])  # utime + stime
        metrics = {"cpu_ticks": ticks}
        for line in (proc / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                metrics["rss_kb"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                metrics["threads"] = int(line.split()[1])
        metrics["open_fds"] = len(list((proc / "fd").iterdir()))
        return metrics
    except (OSError, ValueError, IndexError):
        return {}


def sample(label, previous):
    instant = time.monotonic()
    pid = main_pid()
    proc = process_metrics(pid)
    cpu_percent = None
    if previous and pid == previous.get("pid") and "cpu_ticks" in proc:
        elapsed = instant - previous["clock"]
        if elapsed > 0:
            cpu_percent = round(
                (proc["cpu_ticks"] - previous["ticks"])
                * 100.0 / os.sysconf("SC_CLK_TCK") / elapsed, 2,
            )
    record = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "monotonic_s": round(instant, 3), "label": label, "pid": pid,
        "process": {k: v for k, v in proc.items() if k != "cpu_ticks"},
        "cpu_percent_of_one_core": cpu_percent,
        "security": numerical_fields(
            safe_json("/run/pingtunnel-security.json"),
            SECURITY_NAMES, SECURITY_PREFIXES,
        ),
        "performance": numerical_fields(
            safe_json("/run/pingtunnel-performance.json"), PERF_NAMES,
        ),
        "kernel_host_wide": read_snmp(),
    }
    tick_state = {"pid": pid, "clock": instant, "ticks": proc.get("cpu_ticks", 0)}
    return record, tick_state


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered)-1, max(0, int((len(ordered)-1)*pct+0.999999)))
    return round(ordered[index], 2)


def numeric_series(records, section, key):
    out = []
    for rec in records:
        value = rec.get(section, {}).get(key)
        if type(value) in (int, float):
            out.append(float(value))
    return out


def report(path):
    records = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    if not records:
        raise SystemExit("No samples in input file")
    start, end = records[0], records[-1]
    elapsed = end["monotonic_s"]-start["monotonic_s"]
    print("Samples:", len(records), "duration_sec:", round(elapsed),
          "label:", start.get("label"))
    for section, keys in (
        ("performance", ("recent_rtt_ms", "recent_jitter_ms", "probe_loss_estimate")),
        ("security", ("reverse_p95_delivery_delay_ms", "reverse_oldest_queue_age_ms",
                      "reverse_queue_packets", "icmp_userspace_pps")),
        ("process", ("rss_kb", "threads", "open_fds")),
    ):
        for key in keys:
            values = numeric_series(records, section, key)
            if values:
                print(section + "." + key, "median:", percentile(values, .50),
                      "p95:", percentile(values, .95), "peak:", max(values))
    cpus = [r["cpu_percent_of_one_core"] for r in records
            if type(r.get("cpu_percent_of_one_core")) in (int, float)]
    if cpus:
        print("CPU % of one core: median", percentile(cpus, .50),
              "p95", percentile(cpus, .95), "peak", max(cpus))
    for section, keys in (
        ("security", ("replay_drops", "authentication_failures",
                      "reverse_queue_drops", "icmp_write_failures",
                      "icmp_fragment_drops", "recoveries")),
        ("kernel_host_wide", ("Udp_InErrors", "Udp_RcvbufErrors",
                              "Udp_SndbufErrors", "Ip_InDiscards")),
    ):
        for key in keys:
            valid = numeric_series(records, section, key)
            if len(valid) >= 2:
                print(section + "." + key + "_delta", int(valid[-1]-valid[0]))
    window = max(2, len(records)//10)
    for section, key in (("process", "rss_kb"), ("performance", "recent_rtt_ms"),
                         ("security", "reverse_p95_delivery_delay_ms")):
        first = numeric_series(records[:window], section, key)
        last = numeric_series(records[-window:], section, key)
        if first and last:
            print(section + "." + key + " early_median",
                  round(statistics.median(first), 2), "late_median",
                  round(statistics.median(last), 2))
    print("NOTE: /proc/net/snmp counters include all processes on the VPS.")
    print("NOTE: ICMP userspace writes are not end-to-end delivery guarantees.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=7200, help="seconds (1..86400)")
    parser.add_argument("--interval", type=int, default=5, help="seconds (1..60)")
    parser.add_argument("--label", default="peer", choices=("iran", "foreign", "peer"))
    parser.add_argument("--output", default="/tmp/pingtunnel-long-session.jsonl")
    parser.add_argument("--analyze", metavar="PATH", help="summarize an existing JSONL")
    args = parser.parse_args()
    if args.analyze:
        report(args.analyze)
        return
    if not 1 <= args.duration <= 86400 or not 1 <= args.interval <= 60:
        parser.error("duration must be 1..86400, interval must be 1..60")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    deadline = time.monotonic() + args.duration
    previous = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            print("Recording local counters:", args.output, "label:", args.label)
            while True:
                rec, previous = sample(args.label, previous)
                out.write(json.dumps(rec, separators=(",", ":"), sort_keys=True)+"\n")
                out.flush()
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(args.interval, remaining))
    except KeyboardInterrupt:
        print("Interrupted; samples saved.")
    print("Summary: python3", __file__, "--analyze", args.output)


if __name__ == "__main__":
    main()
