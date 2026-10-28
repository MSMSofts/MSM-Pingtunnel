# Reverse ICMP PCAP comparison / سنجش افت واقعی تونل Reverse

Diagnostic only: it does not modify Pingtunnel, encryption, Poll rate, BBR, routing, or firewalls.
The tool Source/reverse_pcap_compare.py uses the Python 3 standard library and never decrypts payloads.
It correlates full-payload SHA-256, ICMP Echo ID/sequence and type across two *simultaneous* captures.

## 1. Start captures on both VPSs

Use two SSH terminals. Start captures within a few seconds of one another. After both print
'listening on eth0', play Shorts/Reels for 40–50 seconds while noting any pauses.
Each capture runs 75 seconds; a timeout exit code 124 is normal.

On the **Foreign VPS** (replace IRAN_IP):

```bash
sudo rm -f /tmp/pt-reverse-foreign.pcap
sudo timeout -s INT 75 tcpdump -nni eth0 -s 0 -U \
  -w /tmp/pt-reverse-foreign.pcap \
  'icmp and host IRAN_IP'
```

On the **Iran VPS** (replace FOREIGN_IP):

```bash
sudo rm -f /tmp/pt-reverse-iran.pcap
sudo timeout -s INT 75 tcpdump -nni eth0 -s 0 -U \
  -w /tmp/pt-reverse-iran.pcap \
  'icmp and host FOREIGN_IP'
```

Keep the final tcpdump statistics from *both* terminals, especially 'packets dropped by kernel'.
Using -s 0 avoids ciphertext truncation. Use the physical interface (eth0 here).
Delete the previous capture file before restarting: tcpdump may drop to the tcpdump system user and
return Permission denied for a file that already exists. A 24-byte PCAP contains only its header.

## 2. Copy the Iran capture to Foreign

After both captures finish, on the **Foreign VPS**:

```bash
scp root@IRAN_IP:/tmp/pt-reverse-iran.pcap /tmp/pt-reverse-iran.pcap
ls -lh /tmp/pt-reverse-foreign.pcap /tmp/pt-reverse-iran.pcap
```

If the foreign server cannot SSH to Iran, securely copy both captures to a local workstation instead.

## 3. Run the comparator on Foreign

```bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/main/Source/reverse_pcap_compare.py \
  -o /tmp/reverse_pcap_compare.py
python3 /tmp/reverse_pcap_compare.py \
  --foreign /tmp/pt-reverse-foreign.pcap \
  --iran /tmp/pt-reverse-iran.pcap \
  --foreign-ip FOREIGN_IP \
  --iran-ip IRAN_IP
```

Share the *text output*, not the full private PCAPs.

## How to interpret the results

| Report | What it means |
| --- | --- |
| Foreign -> Iran encrypted PTD4 | Foreign encrypted Echo Requests matched at Iran ingress |
| Foreign -> Iran signed PTR4 polls | Reverse polls matched at Iran ingress |
| Iran -> Foreign genuine PTD4 | Iran encrypted DATA/ACK Echo Replies, excluding exact copies of Foreign PTD4 |
| Iran -> Foreign reflected PTD4 | Linux Echo Replies copying Foreign encrypted payload; not new peer DATA |
| Iran -> Foreign PTR4 kernel echoes | Ordinary Echo Replies to signed Reverse probes |

Sent = fingerprint recorded leaving sender interface. Matched = same Echo type,
ID/sequence and *entire* ciphertext recorded arriving at the other interface.
Missing = unmatched between the two capture files; this does **not** prove network loss
unless both captures were complete and tcpdump kernel-drop counts were zero.
The tool tries to align clock offsets from matching packets in both directions, trims
the first/last three seconds of the overlap, and reports 5-second windows to correlate stalls.

Captures may contain sensitive traffic metadata and encrypted bytes; keep them private.
IPv4 fragments and truncated packets are excluded and flagged; check warnings.
Never increase Poll rate or modify firewalls based solely on ordinary ping loss.
