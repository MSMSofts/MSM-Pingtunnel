#!/usr/bin/env python3
"""Compare two simultaneous tcpdump PCAPs of a Reverse ICMP tunnel.

Read-only, stdlib-only analysis. No cryptographic keys, sockets or daemon
changes. Packet identity: ICMP type/code + Echo ID/sequence + full payload
(SHA-256, deliberately omitting IP TTL/checksums). Reflections: the same
full Echo ID/sequence/payload irrespective of request/reply type.

Use tcpdump -s 0 -w on both physical eth0 interfaces, then copy both PCAPs
to one machine. Missing packets are *capture-to-capture nonmatches*, not
proof of packet loss without checking tcpdump kernel-drop counters.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
import statistics
import struct
import sys
from typing import Dict, List, Tuple

NS = 1_000_000_000
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}

@dataclass(frozen=True)
class Frame:
    ns: int
    direction: str  # "F8", "I8", "F0", or "I0": observing HOST and ICMP type
    marker: str
    key: bytes
    echo_key: bytes

@dataclass
class Capture:
    frames: List[Frame]
    start_ns: int
    end_ns: int
    all_records: int = 0
    relevant: int = 0
    truncated: int = 0
    fragments: int = 0
    unsupported: int = 0
    unrelated: int = 0
    repeated: int = 0

def ipv4_at(frame: bytes, linktype: int):
    if linktype == 1:  # Ethernet (optionally with 802.1Q/802.1ad tags)
        if len(frame) < 14:
            return None
        proto = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        for _ in range(2):
            if proto not in (0x8100, 0x88a8, 0x9100):
                break
            if len(frame) < offset + 4:
                return None
            proto = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        return offset if proto == 0x0800 else None
    if linktype == 113:  # Linux cooked SLL v1 (the protocol is at +14)
        return 16 if len(frame) >= 16 and frame[14:16] == b"\x08\x00" else None
    if linktype == 276:  # Linux cooked SLL v2 (the protocol is at +0)
        return 20 if len(frame) >= 20 and frame[:2] == b"\x08\x00" else None
    if linktype == 101:  # Raw IPv4
        return 0
    raise ValueError(f"unsupported pcap linktype {linktype}; capture with tcpdump -i eth0")

def parse_icmp(record: bytes, linktype: int, foreign: bytes, iran: bytes):
    offset = ipv4_at(record, linktype)
    if offset is None:
        return None, "unrelated"
    ip = record[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None, "unrelated"
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl:
        return None, "truncated"
    src, dst = ip[12:16], ip[16:20]
    if src not in (iran, foreign) or dst not in (iran, foreign) or src == dst or ip[9] != 1:
        return None, "unrelated"
    # Offsets >0 are a subsequent IPv4 fragment: cannot identify ICMP Echo
    # until full reassembly. MF-first fragments are likewise incomplete.
    frag = struct.unpack_from("!H", ip, 6)[0]
    if frag & 0x3fff:
        return None, "fragment"
    iplen = struct.unpack_from("!H", ip, 2)[0]
    if iplen < ihl + 8 or len(ip) < iplen:
        return None, "truncated"
    icmp = ip[ihl:iplen]
    if len(icmp) < 8 or icmp[0] not in (0, 8) or icmp[1] != 0:
        return None, "unrelated"
    marker = icmp[8:12].decode("ascii", errors="replace") if len(icmp) >= 12 else ""
    if marker not in ("PTD4", "PTR4", "PTH4"):
        marker = "other"
    # Wire identity is stable across the path, including TTL decrements;
    # omitting ICMP checksum avoids checksum offload quirks.
    key = hashlib.sha256(icmp[0:2] + icmp[4:]).digest()
    echo_key = hashlib.sha256(icmp[4:]).digest()
    host_and_type = ("F" if src == foreign else "I") + str(icmp[0])
    return Frame(0, host_and_type, marker, key, echo_key), "ok"

def read_pcap(path: str, foreign: bytes, iran: bytes) -> Capture:
    if not os.path.isfile(path):
        raise ValueError(f"pcap does not exist: {path}")
    frames = []
    stats = Counter()
    first = last = None
    seen = set()
    with open(path, "rb") as stream:
        head = stream.read(24)
        if len(head) != 24 or head[:4] not in PCAP_MAGICS:
            raise ValueError(f"{path}: expected classic tcpdump PCAP (-w), not pcapng")
        endian, ns_per_frac = PCAP_MAGICS[head[:4]]
        _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", head)
        if major != 2 or minor != 4:
            raise ValueError(f"{path}: unsupported PCAP version {major}.{minor}")
        if linktype not in (1, 101, 113, 276):
            raise ValueError(f"{path}: unsupported link-layer type {linktype}")
        while True:
            hdr = stream.read(16)
            if not hdr:
                break
            if len(hdr) < 16:
                raise ValueError(f"{path}: truncated packet header")
            sec, frac, size, original = struct.unpack(endian + "IIII", hdr)
            if size > 16_777_216 or size > snaplen or size > original:
                raise ValueError(f"{path}: invalid PCAP captured size {size}")
            raw = stream.read(size)
            if len(raw) != size:
                raise ValueError(f"{path}: incomplete PCAP packet")
            ns = sec * NS + frac * ns_per_frac
            first = ns if first is None else min(ns, first)
            last = ns if last is None else max(ns, last)
            stats["all_records"] += 1
            if size < original:
                stats["truncated"] += 1
                continue
            candidate, why = parse_icmp(raw, linktype, foreign, iran)
            if candidate is None:
                stats[why] += 1
                continue
            packet = Frame(ns, candidate.direction, candidate.marker, candidate.key, candidate.echo_key)
            if (packet.direction, packet.key) in seen:
                stats["repeated"] += 1
            seen.add((packet.direction, packet.key))
            stats["relevant"] += 1
            frames.append(packet)
    if first is None or last is None or last - first < 10 * NS:
        raise ValueError(f"{path}: fewer than 10 seconds of captured packets; make a 60-second capture")
    return Capture(frames, first, last, **{key: stats[key] for key in
        ("all_records", "relevant", "truncated", "fragments", "unsupported", "unrelated", "repeated")})

def by_source(capture: Capture, label: str):
    return {f.key: f for f in capture.frames if f.direction == label}

def percentile(values, share):
    if not values:
        return None
    data = sorted(values)
    index = round((len(data) - 1) * share)
    return data[index]

def estimate_skew(foreign: Capture, iran: Capture):
    # Iran clock - Foreign clock; add this to a Foreign timestamp to get
    # approximately the Iran clock. Cross-host path delay cancels in the
    # paired low-quantile one-way samples, assuming roughly symmetric delay.
    i8, f0 = by_source(iran, "F8"), by_source(foreign, "I0")
    f8, i0 = by_source(foreign, "F8"), by_source(iran, "I0")
    forward = [(i8[k].ns - f8[k].ns) for k in i8.keys() & f8.keys()]
    backward = [(f0[k].ns - i0[k].ns) for k in f0.keys() & i0.keys()]
    if len(forward) < 10 or len(backward) < 10:
        return 0, False, len(forward), len(backward)
    a = percentile(forward, 0.1)
    b = percentile(backward, 0.1)
    return (a - b) // 2, True, len(forward), len(backward)

def cohorts(foreign: Capture, iran: Capture, skew: int, guard_s: float):
    guard = int(guard_s * NS)
    groups = {
        "foreign_requests": [f for f in foreign.frames if f.direction == "F8"],
        "iran_requests": [f for f in iran.frames if f.direction == "F8"],
        "iran_replies": [f for f in iran.frames if f.direction == "I0"],
        "foreign_replies": [f for f in foreign.frames if f.direction == "I0"],
    }
    # Restrict sender cohorts to the two overlapping capture intervals with
    # a guard at every edge. Sender timestamps are mapped to the other VPS.
    def eligible(packet, sender, receiver, add_offset):
        if packet.ns < sender.start_ns + guard or packet.ns > sender.end_ns - guard:
            return False
        adjusted = packet.ns + add_offset
        return receiver.start_ns + guard <= adjusted <= receiver.end_ns - guard
    fsend = {f.key: f for f in groups["foreign_requests"]
             if eligible(f, foreign, iran, skew)}
    isend = {f.key: f for f in groups["iran_replies"]
             if eligible(f, iran, foreign, -skew)}
    irecv = by_source(iran, "F8")
    frecv = by_source(foreign, "I0")
    return fsend, irecv, isend, frecv, groups

def pretty(result):
    pct = "n/a" if result["unmatched_pct"] is None else f'{result["unmatched_pct"]:.2f}%'
    return (f'{result["name"]:<35} {result["sent"]:>8} '
            f'{result["received"]:>9} {result["missing"]:>8} {pct:>9}')

def seconds(t):
    return datetime.fromtimestamp(t / NS, tz=timezone.utc).strftime("%H:%M:%S")

def report_foreign_buckets(result, receiver, size=5):
    records = result["records"]
    if not records:
        return []
    baseline = min(p.ns for p in records)
    buckets = defaultdict(lambda: [0, 0])
    for p in records:
        slot = ((p.ns - baseline) // (size * NS))
        buckets[slot][0] += 1
        buckets[slot][1] += (p.key not in receiver)
    return [(seconds(baseline + slot * size * NS), totals[0], totals[1])
            for slot, totals in sorted(buckets.items())]

def analyze(foreign: Capture, iran: Capture, guard: float):
    skew, calibrated, forward_matches, backward_matches = estimate_skew(foreign, iran)
    sent_f, recv_i, sent_i, recv_f, all_groups = cohorts(foreign, iran, skew, guard)
    # Explicit signatures from all foreign outgoing PTD4 (not just the
    # guard-trimmed cohort) permit identifying the Iran kernel's Type-0
    # mirror independently from true Iran->Foreign encrypted DATA/ACK.
    foreign_ciphertexts = {p.echo_key for p in all_groups["foreign_requests"] if p.marker == "PTD4"}
    results = []
    def add(label, src, dst, marker, predicate=None):
        records = [p for p in src.values() if p.marker == marker and (predicate is None or predicate(p))]
        matched = sum(p.key in dst for p in records)
        result = {"name": label, "sent": len(records), "received": matched,
                  "missing": len(records) - matched,
                  "unmatched_pct": 100 * (len(records)-matched)/len(records) if records else None,
                  "records": records}
        results.append(result)
        return result
    downlink = add("Foreign -> Iran encrypted PTD4", sent_f, recv_i, "PTD4")
    polls = add("Foreign -> Iran signed PTR4 polls", sent_f, recv_i, "PTR4")
    add("Foreign -> Iran handshakes PTH4", sent_f, recv_i, "PTH4")
    uplink = add("Iran -> Foreign genuine PTD4", sent_i, recv_f, "PTD4",
                 lambda p: p.echo_key not in foreign_ciphertexts)
    add("Iran -> Foreign reflected PTD4", sent_i, recv_f, "PTD4",
        lambda p: p.echo_key in foreign_ciphertexts)
    add("Iran -> Foreign PTR4 kernel echoes", sent_i, recv_f, "PTR4")
    add("Iran -> Foreign handshakes PTH4", sent_i, recv_f, "PTH4")
    return {"skew_ns": skew, "calibrated": calibrated, "skew_forward_samples": forward_matches,
            "skew_backward_samples": backward_matches, "results": results,
            "downlink_buckets": report_foreign_buckets(downlink, recv_i),
            "uplink_buckets": report_foreign_buckets(uplink, recv_f),
            "guard_s": guard, "foreign": foreign, "iran": iran}

def render(report):
    foreign, iran = report["foreign"], report["iran"]
    print("Reverse ICMP PCAP comparison (matched full ICMP IDs, seq and ciphertext)")
    print(f"Foreign capture: {foreign.all_records} records, {foreign.relevant} relevant,"
          f" {foreign.truncated} truncated, {foreign.fragments} fragmented,"
          f" {foreign.repeated} duplicates")
    print(f"Iran capture:    {iran.all_records} records, {iran.relevant} relevant,"
          f" {iran.truncated} truncated, {iran.fragments} fragmented,"
          f" {iran.repeated} duplicates")
    if report["calibrated"]:
        print(f'Clock offset estimate (Iran minus Foreign): {report["skew_ns"]/NS:+.3f} sec '
              f'({report["skew_forward_samples"]} forward, '
              f'{report["skew_backward_samples"]} reverse matches)')
    else:
        print("WARNING: insufficient packet matches for two-way clock alignment;"
              " clocks assumed synchronized. Capture both at the same time.")
    print(f'Comparisons use only overlapping windows, trimmed by {report["guard_s"]:.0f}s.'
          " Percentages are *capture-to-capture unmatched*, not guaranteed network loss.")
    print()
    print(f'{"Traffic class":<35} {"Sent":>8} {"Matched":>9} {"Missing":>8} {"Missing %":>9}')
    print("-" * 75)
    for result in report["results"]:
        print(pretty(result))
    print()
    for label, key in (("Foreign -> Iran PTD4 (5-second sender buckets)", "downlink_buckets"),
                       ("Iran -> Foreign genuine PTD4 (5-second sender buckets)", "uplink_buckets")):
        print(label)
        rows = report[key]
        if not rows:
            print("  no samples")
        else:
            for when, total, missing in rows:
                print(f"  {when} UTC: {total:>5} sent, {missing:>5} unmatched"
                      f" ({100*missing/total:5.1f}%)")
    if any(c.truncated or c.fragments for c in (foreign, iran)):
        print("WARNING: truncated/fragmented packets were excluded; "
              "verify -s 0 and MTU before interpreting unmatched rates.")
    print("IMPORTANT: check tcpdump's 'packets dropped by kernel' on BOTH VPSs;"
          " nonzero local capture drops can mimic network loss.")
    print("A zero-PING-auth-error status does NOT prove zero PTD4 carrier loss.")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--foreign", required=True, help="foreign-VPS tcpdump .pcap")
    parser.add_argument("--iran", required=True, help="Iran-VPS tcpdump .pcap")
    parser.add_argument("--foreign-ip", required=True)
    parser.add_argument("--iran-ip", required=True)
    parser.add_argument("--trim-seconds", type=float, default=3.0,
        help="exclude first/last N seconds of each capture (default: 3)")
    args = parser.parse_args(argv)
    if args.trim_seconds < 0 or args.trim_seconds > 20:
        parser.error("--trim-seconds must be between 0 and 20")
    try:
        foreign_ip = ipaddress.IPv4Address(args.foreign_ip).packed
        iran_ip = ipaddress.IPv4Address(args.iran_ip).packed
        if foreign_ip == iran_ip:
            parser.error("the peer IPs must be different")
        foreign = read_pcap(args.foreign, foreign_ip, iran_ip)
        iran = read_pcap(args.iran, foreign_ip, iran_ip)
        result = analyze(foreign, iran, args.trim_seconds)
        render(result)
    except (ValueError, OSError) as error:
        parser.exit(2, f"ERROR: {error}\n")

if __name__ == "__main__":
    main()
