#!/usr/bin/env python3
"""Real Linux network-namespace smoke test for manual and AUTO Direct.

Uses two isolated IPv4 network stacks connected by a virtual Ethernet pair,
the production Go ICMP raw sockets, the mandatory four-step Wire-v4 X25519
handshake, a real UDP client and a foreign loopback UDP echo target. Root
(CAP_NET_ADMIN and CAP_NET_RAW) is required; no application secrets or
outside network are used.

Run by GitHub Actions on an ephemeral AMD64 Linux runner, not on user VPSs.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def namespace_cmd(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


def peer_config(region: str, direction: str, key: str) -> dict:
    base = {
        "type": "client" if region == "iran" else "server",
        "region": region,
        "encrypt": "auto",
        "encrypt_key": key,
        "key": 74135,
        "icmp_direction": direction,
        "icmp_listen": "0.0.0.0",
        "nolog": 1,
        "noprint": 0,
        "loglevel": "error",
        "tcp": 0,
    }
    if region == "iran":
        base.update(server="198.18.90.2", listen="127.0.0.1:50631",
                    target="127.0.0.1:1", timeout=60)
    else:
        base.update(peer_ip="198.18.90.1", fixed_target="127.0.0.1:50632",
                    forward_protocol=0)
    return base


ECHO_SCRIPT = r"""
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("127.0.0.1",50632))
while True:
    data,who=s.recvfrom(65535)
    s.sendto(b"echo:"+data,who)
"""

CLIENT_SCRIPT = r"""
import socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(0.9)
end=time.monotonic()+25
sent=set()
n=0
while time.monotonic()<end:
    message=f"direct-mode-test-{n}".encode()
    sent.add(message)
    s.sendto(message,("127.0.0.1",50631))
    try:
        data,_=s.recvfrom(65535)
        # UDP is unordered: a perfectly valid delayed reply to any earlier
        # datagram from this socket must count as success.
        if data.startswith(b"echo:") and data[5:] in sent:
            print("REAL_DIRECT_UDP_ICMP_ROUNDTRIP_PASS",flush=True)
            sys.exit(0)
        print("Unexpected echo payload",data[:120],flush=True)
    except socket.timeout:
        pass
    n+=1
    time.sleep(0.03)
print("No authenticated Direct UDP reply in 25 seconds",flush=True)
sys.exit(1)
"""


def perform(mode: str, binary: str, i: str, f: str, temp: Path) -> None:
    # These bytes are ONLY the self-contained CI test secret; never use on VPSs.
    import base64
    key = base64.b64encode(bytes(range(1, 33))).decode("ascii")
    iran_conf = temp / "iran.json"
    foreign_conf = temp / "foreign.json"
    iran_conf.write_text(json.dumps(peer_config("iran", mode, key)))
    foreign_conf.write_text(json.dumps(peer_config("foreign", mode, key)))

    server_log = (temp / "foreign.log").open("w+")
    client_log = (temp / "iran.log").open("w+")
    server = subprocess.Popen(
        namespace_cmd(f, binary, "-c", str(foreign_conf)),
        stdout=server_log, stderr=subprocess.STDOUT,
    )
    client = subprocess.Popen(
        namespace_cmd(i, binary, "-c", str(iran_conf)),
        stdout=client_log, stderr=subprocess.STDOUT,
    )
    try:
        time.sleep(1)
        outcome = run(*namespace_cmd(i, sys.executable, "-c", CLIENT_SCRIPT),
                      check=False, capture=True)
        if outcome.returncode:
            print("Direct test failed for policy:", mode, flush=True)
            print(outcome.stdout[-2500:], flush=True)
            for name, log in (("foreign", server_log), ("iran", client_log)):
                log.flush()
                log.seek(0)
                print(name, "core logs (last 1500):", log.read()[-1500:], flush=True)
            raise RuntimeError(f"{mode}: no bidirectional encrypted Direct UDP traffic")
        if server.poll() is not None or client.poll() is not None:
            raise RuntimeError(f"{mode}: Go worker exited during smoke test")
        print(mode, "RAW_ICMP_AUTHENTICATED_UDP_PASS", flush=True)
    finally:
        for p in (client, server):
            if p.poll() is None:
                p.terminate()
        for p in (client, server):
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        server_log.close()
        client_log.close()


def main() -> None:
    arg = argparse.ArgumentParser()
    arg.add_argument("--binary", required=True)
    opt = arg.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Please run as root on an isolated test runner")
    if not shutil.which("ip"):
        raise SystemExit("Missing iproute2: cannot run network namespace smoke test")
    binary = str(Path(opt.binary).resolve())
    if not os.path.exists(binary):
        raise SystemExit(f"Core binary missing: {binary}")

    suffix = str(os.getpid() % 100000)
    iran = "ptiran" + suffix
    foreign = "ptforeign" + suffix
    veth_i = "pti" + suffix
    veth_f = "ptf" + suffix
    echo = None
    try:
        run("ip", "netns", "add", iran)
        run("ip", "netns", "add", foreign)
        run("ip", "link", "add", veth_i, "type", "veth", "peer", "name", veth_f)
        run("ip", "link", "set", veth_i, "netns", iran)
        run("ip", "link", "set", veth_f, "netns", foreign)
        for ns, iface, addr in [(iran, veth_i, "198.18.90.1/30"),
                                 (foreign, veth_f, "198.18.90.2/30")]:
            run(*namespace_cmd(ns, "ip", "link", "set", "lo", "up"))
            run(*namespace_cmd(ns, "ip", "addr", "add", addr, "dev", iface))
            run(*namespace_cmd(ns, "ip", "link", "set", iface, "up"))

        with tempfile.TemporaryDirectory(prefix="pt-direct-") as d:
            temp = Path(d)
            echo = subprocess.Popen(
                namespace_cmd(foreign, sys.executable, "-u", "-c", ECHO_SCRIPT),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            if echo.poll() is not None:
                raise RuntimeError("Foreign UDP echo service failed")
            for mode in ("direct", "auto_direct"):
                perform(mode, binary, iran, foreign, temp)
    finally:
        if echo is not None and echo.poll() is None:
            echo.terminate()
            try:
                echo.wait(timeout=2)
            except subprocess.TimeoutExpired:
                echo.kill()
                echo.wait()
        for ns in (iran, foreign):
            subprocess.run(["ip", "netns", "del", ns], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
