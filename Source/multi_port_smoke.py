#!/usr/bin/env python3
"""End-to-end mixed Multi-Port smoke over real authenticated ICMP and netns.

Launches two production Go-core processes in isolated Linux network namespaces,
six loopback TCP echo services and six UDP echo services on Foreign, and checks
twelve concurrent Iran ingress routes (including TCP+UDP sharing a numeric port).
No production credentials or external network are used. Requires root and iproute2.

Queue sizes, dispatch policy, FEC, segmentation and recovery remain the Go-core
defaults: this script tests routing only; it does not tune the transport.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import threading
import statistics
from pathlib import Path


# S01 (TCP) and S02 (UDP) deliberately share the same numeric ingress and
# target port, as do the remaining pairs. Transport *and* service ID matter.
SERVICES = [
    dict(id=f"S{i+1:02}", protocol="tcp" if i % 2 == 0 else "udp",
         iran_port=53041+i//2, foreign_port=54041+i//2, enabled=True)
    for i in range(12)
]
IRAN = "198.18.91.1"
FOREIGN = "198.18.91.2"

ECHO_SCRIPT = r"""
import socket,struct,threading,time
ports=list(range(54041,54047))
def recv_exact(s,n):
    data=bytearray()
    while len(data)<n:
        chunk=s.recv(n-len(data))
        if not chunk: raise EOFError('stream closed')
        data.extend(chunk)
    return bytes(data)
def tcp_conn(conn,port):
    try:
        conn.settimeout(20)
        with conn:
            while True:
                try: header=recv_exact(conn,4)
                except (EOFError,OSError): return
                length=struct.unpack('!I',header)[0]
                if length>32768: return
                body=recv_exact(conn,length)
                reply=f'tcp-{port}:'.encode()+body
                conn.sendall(struct.pack('!I',len(reply))+reply)
    except OSError: pass
def tcp_serve(sock,port):
    while True:
        conn,_=sock.accept()
        threading.Thread(target=tcp_conn,args=(conn,port),daemon=True).start()
def udp_serve(sock,port):
    while True:
        body,addr=sock.recvfrom(65535)
        sock.sendto(f'udp-{port}:'.encode()+body,addr)
for port in ports:
    tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    tcp.bind(('127.0.0.1',port));tcp.listen(128)
    threading.Thread(target=tcp_serve,args=(tcp,port),daemon=True).start()
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1',port))
    threading.Thread(target=udp_serve,args=(udp,port),daemon=True).start()
print('FOREIGN_TWELVE_ECHO_ENDPOINTS_READY',flush=True)
while True: time.sleep(3600)
"""

def command(*args, check=True, capture=False):
    return subprocess.run(list(args),check=check,text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)

def in_ns(ns,*args):
    return ["ip","netns","exec",ns,*args]

def recv_exact(s,n):
    result=bytearray()
    while len(result)<n:
        chunk=s.recv(n-len(result))
        if not chunk: raise EOFError("unexpected TCP EOF")
        result.extend(chunk)
    return bytes(result)

def config(region,mode,key,queue_profile):
    payload=dict(
        type="client" if region=="iran" else "server",
        region=region,encrypt="auto",encrypt_key=key,key=88124,
        icmp_direction=mode,icmp_listen="0.0.0.0",nolog=1,noprint=0,
        loglevel="error",tcp=1 if queue_profile=="tcp" else 0,services=SERVICES)
    if region=="iran":
        payload.update(server=FOREIGN,listen=":53041",
                       target="msm-service:S01",timeout=60,
                       tcp_bs=1048576,tcp_mw=20000,tcp_rst=400)
    else:
        payload.update(peer_ip=IRAN,fixed_target="127.0.0.1:54041",
                       forward_protocol=1 if queue_profile=="tcp" else 0)
    return payload

def try_udp(port,payload,foreign_port,timeout=1.2):
    expected=f"udp-{foreign_port}:".encode()+payload
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload,("127.0.0.1",port))
        data,source=sock.recvfrom(65535)
        if data!=expected: raise ValueError(f"UDP foreign target mismatch: {data!r}")
        if source[1]!=port: raise ValueError(f"UDP ingress source mismatch: {source}")

def try_tcp(port,payload,foreign_port,timeout=3.0):
    expected=f"tcp-{foreign_port}:".encode()+payload
    with socket.create_connection(("127.0.0.1",port),timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!I",len(payload))+payload)
        header=recv_exact(sock,4)
        size=struct.unpack("!I",header)[0]
        if size!=len(expected): raise ValueError(f"TCP length mismatch: {size} != {len(expected)}")
        data=recv_exact(sock,size)
        if data!=expected: raise ValueError(f"TCP foreign target mismatch: {data!r}")

def run_trial(service,mode,attempts=30):
    # Python runs under the Iran netns; namespacing is isolated from the host.
    is_tcp=service["protocol"]=="tcp"
    started=time.monotonic()
    last=None
    for round_no in range(attempts):
        payload=f"{mode}/{service['id']}/{round_no}:".encode()+os.urandom(96+round_no%3*39)
        try:
            if is_tcp:
                try_tcp(service["iran_port"],payload,service["foreign_port"])
            else:
                try_udp(service["iran_port"],payload,service["foreign_port"])
            # Second round on the same port confirms connection reuse and
            # helps distinguish stray responses during concurrent traffic.
            payload2=f"{mode}/{service['id']}/second:".encode()+os.urandom(256)
            if is_tcp:
                try_tcp(service["iran_port"],payload2,service["foreign_port"])
            else:
                try_udp(service["iran_port"],payload2,service["foreign_port"])
            return dict(id=service["id"],protocol=service["protocol"],
                        ingress=service["iran_port"],target=service["foreign_port"],
                        elapsed_ms=round((time.monotonic()-started)*1000))
        except (OSError,EOFError,ValueError) as exc:
            last=exc
            time.sleep(0.3)
    raise RuntimeError(f"{service['id']} {service['protocol']} did not complete: {last}")

def shared_udp_source_test():
    # Same client socket/source-port talks to two different UDP listeners,
    # proving that the two flow maps are keyed by service ID, not source alone.
    one,two=SERVICES[1],SERVICES[3]
    tokens=[(one,b"share-source-S02"),(two,b"share-source-S04")]
    expected={(f"udp-{s['foreign_port']}:".encode()+msg,s["iran_port"])
              for s,msg in tokens}
    deadline=time.monotonic()+15
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.8)
        while expected and time.monotonic()<deadline:
            for svc,message in tokens:
                sock.sendto(message,("127.0.0.1",svc["iran_port"]))
            for _ in range(4):
                try:
                    payload,source=sock.recvfrom(65535)
                except socket.timeout: break
                expected.discard((payload,source[1]))
            if expected: time.sleep(0.2)
    if expected: raise RuntimeError(f"UDP shared-source service isolation failed: {expected}")
    print("MULTI_PORT_SAME_UDP_SOURCE_ISOLATION_PASS",flush=True)


def continuous_direct_udp_test(mode="direct"):
    """Sustained video-like UDP + concurrent TCP in manual Direct mode.

    Loopback namespace checks latency/loss under local CPU contention; not an
    estimate for a real Iran/Foreign Internet path. Keep production defaults.
    """
    udp_rows=[SERVICES[1],SERVICES[3]]
    sent_count=90
    packet_bytes=850
    reports=[]
    def flow(service):
        sent={}
        received={}
        stop=threading.Event()
        port=service["iran_port"]
        foreign_port=service["foreign_port"]
        prefix=f"udp-{foreign_port}:".encode()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.15)
            def receiver():
                while not stop.is_set():
                    try:
                        payload,source=sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if source[1]!=port or not payload.startswith(prefix):
                        continue
                    raw=payload[len(prefix):]
                    if len(raw)<4:continue
                    seq=struct.unpack("!I",raw[:4])[0]
                    if seq in sent:
                        received[seq]=time.monotonic()-sent[seq]
            reader=threading.Thread(target=receiver,daemon=True)
            reader.start()
            try:
                for seq in range(sent_count):
                    payload=struct.pack("!I",seq)+os.urandom(packet_bytes)
                    sent[seq]=time.monotonic()
                    sock.sendto(payload,("127.0.0.1",port))
                    time.sleep(0.015)
                time.sleep(1.8)
            finally:
                stop.set()
                reader.join(timeout=1)
        if len(received)<round(sent_count*0.75):
            raise RuntimeError(f"UDP continuous delivery low on {service['id']}: {len(received)}/{sent_count}")
        rtts=sorted(n*1000 for n in received.values())
        p95=rtts[min(len(rtts)-1,int(len(rtts)*0.95))]
        if p95>800:
            raise RuntimeError(f"UDP continuous p95 latency excessive on {service['id']}: {p95:.1f} ms")
        return {"service":service["id"],"sent":sent_count,"received":len(received),
                "rtt_p50_ms":round(statistics.median(rtts),1),"rtt_p95_ms":round(p95,1)}
    def tcp_load():
        for n in range(18):
            svc=SERVICES[(n%6)*2]
            try_tcp(svc["iran_port"],os.urandom(6000),svc["foreign_port"],timeout=6)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures=[pool.submit(flow,svc) for svc in udp_rows]
        load=pool.submit(tcp_load)
        for f in futures: reports.append(f.result())
        load.result()
    for report in reports:
        print(f"MIXED_UDP_CONTINUOUS mode={mode} "+json.dumps(report,sort_keys=True),flush=True)
    print(f"MIXED_TCP_UDP_CONCURRENT_STREAM_PASS mode={mode}",flush=True)
    if mode=="direct": print("MANUAL_DIRECT_TCP_UDP_CONCURRENT_STREAM_PASS",flush=True)

def probe_all(mode):
    # Run a UDP warmup so the authenticated handshake is exercised before
    # the heavier TCP fan-out. Worker configuration remains unmodified.
    warm=SERVICES[1]
    deadline=time.monotonic()+30
    while True:
        try:
            try_udp(warm["iran_port"],f"warm-{mode}".encode(),warm["foreign_port"])
            break
        except (OSError,ValueError) as exc:
            if time.monotonic()>deadline: raise RuntimeError(f"secure warmup failed for {mode}: {exc}")
            time.sleep(0.25)
    print(f"{mode}: AUTHENTICATED_WARMUP_PASS",flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures=[executor.submit(run_trial,s,mode) for s in SERVICES]
        for future in concurrent.futures.as_completed(futures):
            print(json.dumps(future.result(),sort_keys=True),flush=True)
    shared_udp_source_test()
    # Exercise continuous UDP video-style traffic against TCP traffic on
    # all 6 TCP service aliases in each of the four route policies.
    continuous_direct_udp_test(mode)
    print(f"{mode}: TWELVE_MIXED_TCP_UDP_SERVICES_PASS",flush=True)

def soak_mixed(mode, seconds):
    """Sustained encrypted mixed TCP/UDP in isolated Linux namespaces.

    Captures each cycle's service RTT and failure count. These are local
    regression measurements, not field latency/throughput guarantees.
    """
    if seconds <= 0:
        return
    rows = [SERVICES[0], SERVICES[1], SERVICES[2], SERVICES[3]]
    began = time.monotonic()
    deadline = began + seconds
    cycles, errors = 0, 0
    samples = []
    last_report = began
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        while time.monotonic() < deadline:
            def probe(svc):
                start = time.monotonic()
                payload = os.urandom(512 if svc["protocol"] == "udp" else 12000)
                if svc["protocol"] == "udp":
                    try_udp(svc["iran_port"], payload, svc["foreign_port"], timeout=1.5)
                else:
                    try_tcp(svc["iran_port"], payload, svc["foreign_port"], timeout=6.0)
                return (time.monotonic() - start) * 1000
            results = [pool.submit(probe, svc) for svc in rows]
            for future in results:
                try:
                    samples.append(future.result())
                except (OSError, EOFError, ValueError) as exc:
                    errors += 1
                    print(f"SOAK_PROBE_ERROR {mode}: {exc}", flush=True)
            cycles += 1
            now = time.monotonic()
            if now - last_report >= 60:
                ordered = sorted(samples)
                p95 = ordered[min(len(ordered)-1, int(len(ordered)*0.95))] if ordered else -1
                print("SOAK_PROGRESS " + json.dumps(dict(mode=mode,
                    elapsed_s=round(now-began), cycles=cycles,
                    probe_errors=errors, rtt_p95_ms=round(p95,1))),flush=True)
                last_report = now
            time.sleep(0.2)
    if cycles < max(1, seconds // 20):
        raise RuntimeError(f"Soak did not exercise enough concurrent cycles: {cycles}")
    if errors:
        raise RuntimeError(f"Soak failed with {errors} application errors across {cycles} cycles")
    print("SOAK_MIXED_TCP_UDP_PASS " + json.dumps(dict(mode=mode,
        elapsed_s=round(time.monotonic()-began), cycles=cycles, samples=len(samples))),flush=True)

def perform(mode,binary,iran,foreign,tmp,echo,queue_profile,soak_seconds=0):
    key=base64.b64encode(bytes(range(1,33))).decode()
    iran_conf=tmp/f"iran-{queue_profile}-{mode}.json";foreign_conf=tmp/f"foreign-{queue_profile}-{mode}.json"
    iran_conf.write_text(json.dumps(config("iran",mode,key,queue_profile)))
    foreign_conf.write_text(json.dumps(config("foreign",mode,key,queue_profile)))
    log_i=(tmp/f"iran-{queue_profile}-{mode}.log").open("w+")
    log_f=(tmp/f"foreign-{queue_profile}-{mode}.log").open("w+")
    foreign_core=subprocess.Popen(in_ns(foreign,binary,"-c",str(foreign_conf)),
                                  stdout=log_f,stderr=subprocess.STDOUT)
    iran_core=subprocess.Popen(in_ns(iran,binary,"-c",str(iran_conf)),
                               stdout=log_i,stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        result=command(*in_ns(iran,sys.executable,"-u","-c",
                       "import sys;sys.path.insert(0,sys.argv[1]);import multi_port_smoke as m;m.probe_all(sys.argv[2]);m.soak_mixed(sys.argv[2],int(sys.argv[3]))",
                       str(Path(__file__).resolve().parent),mode,str(soak_seconds)),
                       check=False,capture=True)
        print(result.stdout[-9000:],flush=True)
        if result.returncode:
            raise RuntimeError(f"{mode}: 12-service TCP+UDP routing failed")
        if iran_core.poll() is not None or foreign_core.poll() is not None:
            raise RuntimeError(f"{mode}: Go core worker exited unexpectedly")
    except Exception:
        for name,handle in (("iran",log_i),("foreign",log_f)):
            handle.flush();handle.seek(0)
            print(f"{mode}/{name} Go log:\n"+handle.read()[-4000:],flush=True)
        raise
    finally:
        for proc in (iran_core,foreign_core):
            if proc.poll() is None: proc.terminate()
        for proc in (iran_core,foreign_core):
            try: proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        log_i.close();log_f.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",required=True)
    parser.add_argument("--modes",nargs="+",choices=["direct","auto_direct","reverse","auto"],
                        default=["direct","auto"])
    parser.add_argument("--queue-profile",choices=["tcp","udp"],default="tcp",
                        help="select the existing global queue/dispatcher profile without tuning it")
    parser.add_argument("--soak-seconds",type=int,default=0,
                        help="extra sustained clean-namespace mixed TCP/UDP probing (0..7200s)")
    args=parser.parse_args()
    if not 0 <= args.soak_seconds <= 7200:
        parser.error("--soak-seconds must be between 0 and 7200")
    if os.geteuid()!=0: raise SystemExit("Requires root, CAP_NET_RAW and CAP_NET_ADMIN")
    binary=str(Path(args.binary).resolve())
    if not Path(binary).is_file():raise SystemExit("Missing Go binary")
    suffix=str(os.getpid()%100000)
    iran="mpi"+suffix;foreign="mpf"+suffix
    iface_i="mi"+suffix;iface_f="mf"+suffix
    echo=None
    try:
        command("ip","netns","add",iran)
        command("ip","netns","add",foreign)
        command("ip","link","add",iface_i,"type","veth","peer","name",iface_f)
        command("ip","link","set",iface_i,"netns",iran)
        command("ip","link","set",iface_f,"netns",foreign)
        for ns,iface,addr in [(iran,iface_i,IRAN+"/30"),(foreign,iface_f,FOREIGN+"/30")]:
            command(*in_ns(ns,"ip","link","set","lo","up"))
            command(*in_ns(ns,"ip","addr","add",addr,"dev",iface))
            command(*in_ns(ns,"ip","link","set",iface,"up"))
        with tempfile.TemporaryDirectory(prefix="msm-multi-port-") as dirname:
            temp=Path(dirname)
            echo_log=(temp/"foreign-echo.log").open("w+")
            echo=subprocess.Popen(in_ns(foreign,sys.executable,"-u","-c",ECHO_SCRIPT),
                                  stdout=echo_log,stderr=subprocess.STDOUT)
            try:
                time.sleep(0.8)
                if echo.poll() is not None:
                    echo_log.seek(0)
                    raise RuntimeError("Foreign echo services exited: "+echo_log.read())
                for mode in args.modes:
                    perform(mode,binary,iran,foreign,temp,echo,args.queue_profile,args.soak_seconds)
            finally:
                if echo.poll() is None:
                    echo.terminate()
                    try:echo.wait(timeout=2)
                    except subprocess.TimeoutExpired:echo.kill();echo.wait()
                echo_log.close()
    finally:
        for ns in (iran,foreign):
            subprocess.run(["ip","netns","del",ns],stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,check=False)
    print(f"MULTI_PORT_ALL_SELECTED_ROUTE_POLICIES_PASS queue_profile={args.queue_profile}",flush=True)

if __name__=="__main__":
    main()
