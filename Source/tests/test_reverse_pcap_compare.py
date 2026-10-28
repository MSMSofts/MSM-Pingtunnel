#!/usr/bin/env python3
"""Synthetic integration tests for paired ICMP Reverse carrier capture analysis."""
import importlib.util
from ipaddress import IPv4Address
from pathlib import Path
import struct
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "reverse_pcap_compare.py"
spec = importlib.util.spec_from_file_location("reverse_pcap_compare", MODULE)
compare = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = compare
spec.loader.exec_module(compare)

F = IPv4Address("198.51.100.2").packed
I = IPv4Address("198.51.100.3").packed
SEC = 1_000_000_000
EPOCH = 1_700_000_000 * SEC
SKEW = 4 * SEC
PROP = 42_000_000  # 42ms each way

def packet(src, dst, typ, number, payload):
    # Include a valid IPv4 total-length field. Checksums deliberately zero:
    # only the full ICMP type+id+seq+payload is used for wire identity.
    echo = struct.pack("!BBHHH", typ, 0, 0, 0x42a5, number) + payload
    total = 20 + len(echo)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, number,
                     0x4000, 64, 1, 0, src, dst)
    return b"\xaa"*12 + struct.pack("!H", 0x0800) + ip + echo

def write_pcap(path, records, snap=262144):
    with open(path, "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, snap, 1))
        for ts, data in sorted(records, key=lambda x: x[0]):
            micros = (ts % SEC) // 1000
            output.write(struct.pack("<IIII", ts // SEC, micros, len(data), len(data)))
            output.write(data)

def simulate():
    # A common capture with 4s absolute clock offset, ten observed Linux
    # ciphertext reflections, 45/50 delivered Foreign->Iran PTD4 DATA,
    # 48/60 polls, 17/20 delivered authentic Iran->Foreign PTD4 DATA.
    foreign, iran = [], []
    def sent_foreign(n, time_s, magic, payload, arrives=True):
        b = packet(F, I, 8, n, magic + payload)
        when = EPOCH + int(time_s * SEC)
        foreign.append((when, b))
        if arrives:
            iran.append((when + SKEW + PROP, b))
        return b
    def sent_iran(n, time_s, magic, payload, arrives=True):
        b = packet(I, F, 0, n, magic + payload)
        when = EPOCH + SKEW + int(time_s * SEC)
        iran.append((when, b))
        if arrives:
            foreign.append((when - SKEW + PROP, b))
        return b
    # Full capture spans 70s, and actual comparison cohort is safely 5..60s.
    foreign.extend([(EPOCH, packet(F,I,3,1,b"edge")),
                    (EPOCH+70*SEC,packet(F,I,3,2,b"edge"))])
    iran.extend([(EPOCH+SKEW,packet(I,F,3,1,b"edge")),
                 (EPOCH+SKEW+70*SEC,packet(I,F,3,2,b"edge"))])
    data = []
    for n in range(50):
        b = sent_foreign(100+n, 10+n*0.1, b"PTD4",bytes([n])*48, n%10!=0)
        data.append(b)
    for n in range(60):
        sent_foreign(300+n, 20+n*0.1,b"PTR4",bytes([n])*32,n%5!=0)
    for n in range(20):
        sent_iran(500+n, 25+n*0.1,b"PTD4",bytes([n+80])*48, n%7!=0)
    # Of 10 kernel PTD4 mirror Echo Replies, nine arrive at Foreign. Since
    # Echo type differs from outbound F8, match by ICMP ID/seq/ciphertext.
    for n,b in enumerate(data[:10]):
        echo = bytearray(b)
        echo[14+20] = 0  # ICMP Echo Reply, keep exact ID/seq/payload
        iran.append((EPOCH+SKEW+(30+n*0.1)*SEC,bytes(echo)))
        if n>0:
            foreign.append((EPOCH+(30+n*0.1)*SEC+PROP,bytes(echo)))
    # Kernel responses to some outbound PTR4 polls.
    for n in range(15):
        b = packet(I,F,0,300+n,b"PTR4"+bytes([n])*32)
        iran.append((EPOCH+SKEW+(40+n*0.1)*SEC,b))
        foreign.append((EPOCH+(40+n*0.1)*SEC+PROP,b))
    return foreign, iran

class CompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.foreign = Path(self.temp.name)/"foreign.pcap"
        self.iran = Path(self.temp.name)/"iran.pcap"
        fo, ir = simulate()
        write_pcap(self.foreign, fo)
        write_pcap(self.iran, ir)
    def tearDown(self):
        self.temp.cleanup()
    def get(self):
        f = compare.read_pcap(str(self.foreign),F,I)
        i = compare.read_pcap(str(self.iran),F,I)
        return compare.analyze(f,i,3)

    def test_matching_real_encrypted_frames_and_mirror_echoes(self):
        report = self.get()
        self.assertTrue(report["calibrated"])
        self.assertAlmostEqual(report["skew_ns"]/SEC,4,places=2)
        by_name = {r["name"]:r for r in report["results"]}
        expected = {
            "Foreign -> Iran encrypted PTD4": (50,45,5),
            "Foreign -> Iran signed PTR4 polls": (60,48,12),
            "Iran -> Foreign genuine PTD4": (20,17,3),
            "Iran -> Foreign reflected PTD4": (10,9,1),
            "Iran -> Foreign PTR4 kernel echoes": (15,15,0),
        }
        for name,counts in expected.items():
            data = by_name[name]
            self.assertEqual((data["sent"],data["received"],data["missing"]),
                             counts,msg=name)
        self.assertTrue(report["downlink_buckets"])
        self.assertTrue(report["uplink_buckets"])
        self.assertEqual(sum(x[2] for x in report["downlink_buckets"]),5)

    def test_duplicate_retransmission_not_counted_twice(self):
        f, ir = simulate()
        f.append(f[2])
        write_pcap(self.foreign, f)
        foreign=compare.read_pcap(str(self.foreign),F,I)
        self.assertEqual(foreign.repeated,1)
        r=compare.analyze(foreign,compare.read_pcap(str(self.iran),F,I),3)
        self.assertEqual(r["results"][0]["sent"],50)

    def test_pcap_truncation_is_flagged_and_excluded(self):
        with open(self.foreign,"ab") as output:
            b=packet(F,I,8,900,b"PTD4"+b"a"*200)
            output.write(struct.pack("<IIII",1700000070,0,32,len(b)))
            output.write(b[:32])
        c=compare.read_pcap(str(self.foreign),F,I)
        self.assertEqual(c.truncated,1)

    def test_rejects_pcapng_and_unknown_linktypes(self):
        bad=Path(self.temp.name)/"bad.pcap"
        bad.write_bytes(b"\x0a\x0d\x0d\x0a"+b"\0"*20)
        with self.assertRaisesRegex(ValueError,"classic tcpdump PCAP"):
            compare.read_pcap(str(bad),F,I)
        bad.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4,2,4,0,0,262144,999))
        with self.assertRaisesRegex(ValueError,"link-layer"):
            compare.read_pcap(str(bad),F,I)

    def test_ipv4_fragment_not_treated_as_complete_echo(self):
        b=bytearray(packet(F,I,8,999,b"PTD4"+b"test"))
        # Mark MF=1 on IPv4; fragmented encrypted packet is not comparable
        struct.pack_into("!H",b,14+6,0x2000)
        p, reason=compare.parse_icmp(bytes(b),1,F,I)
        self.assertIsNone(p)
        self.assertEqual(reason,"fragment")

if __name__=="__main__":
    unittest.main()
