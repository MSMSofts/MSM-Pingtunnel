#!/usr/bin/env python3
"""Regression tests for a secret-free, bounded long-session PingTunnel probe."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "long_session_probe.py"
spec = importlib.util.spec_from_file_location("long_session_probe", MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LongSessionProbeTests(unittest.TestCase):
    def test_allowlist_never_copies_pairing_keys_or_addresses(self):
        original = {
            "pair_key": "TOP-SECRET", "peer_ip": "192.0.2.20",
            "region": "iran", "reverse_queue_packets": 19,
            "replay_drops": 42, "udp_dispatch_overflow_drops": 3,
            "state": "authenticated", "auto_fallback_reason": "secret-raw",
            "reverse_p95_delivery_delay_ms": 150, "icmp_userspace_pps": 91,
        }
        safe = probe.numerical_fields(original,probe.SECURITY_NAMES,probe.SECURITY_PREFIXES)
        self.assertEqual(safe["replay_drops"],42)
        self.assertEqual(safe["state"],"authenticated")
        self.assertEqual(safe["udp_dispatch_overflow_drops"],3)
        self.assertNotIn("pair_key",safe)
        self.assertNotIn("peer_ip",safe)
        self.assertNotIn("region",safe)
        self.assertNotIn("auto_fallback_reason",safe)

    def test_kernel_udp_counters_parse_as_host_wide(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/"snmp"
            path.write_text(
                "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n"
                "Udp: 400 12 6 900 4 2\n"
                "Ip: InReceives InDiscards\n"
                "Ip: 2000 3\n",
                encoding="utf-8")
            counters = probe.read_snmp(path)
        self.assertEqual(counters["Udp_RcvbufErrors"],4)
        self.assertEqual(counters["Udp_SndbufErrors"],2)
        self.assertEqual(counters["Ip_InDiscards"],3)
        self.assertNotIn("Udp_NoPorts", counters)

    def test_summary_uses_delta_and_median_without_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/"samples.jsonl"
            records = []
            for i in range(8):
                records.append({
                    "utc": "2026-11-05T12:00:00Z", "label": "iran",
                    "monotonic_s": float(i*5),
                    "pid":123, "cpu_percent_of_one_core":20+i,
                    "process":{"rss_kb":12000+i*10,"threads":10,"open_fds":15},
                    "security":{
                        "replay_drops":10+i, "reverse_queue_drops":i,
                        "udp_dispatch_overflow_drops":i,
                        "reverse_p95_delivery_delay_ms": 5+i,
                    },
                    "performance":{"recent_rtt_ms":80+i,"recent_jitter_ms":3+i},
                    "kernel_host_wide":{"Udp_RcvbufErrors":100+i},
                })
            path.write_text(
                "".join(json.dumps(x)+"\n" for x in records),
                encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                probe.report(path)
            result = output.getvalue()
        self.assertIn("Samples: 8",result)
        self.assertIn("replay_drops_delta 7",result)
        self.assertIn("Udp_RcvbufErrors_delta 7",result)
        self.assertIn("p95",result)


if __name__ == "__main__":
    unittest.main()
