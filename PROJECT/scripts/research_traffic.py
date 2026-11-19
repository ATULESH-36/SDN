#!/usr/bin/env python3
"""Loopback/private-lab traffic worker; invoked only by network_campaign.py."""
import argparse
import csv
import ipaddress
import json
from pathlib import Path
import random
import selectors
import socket
import time


def private(text):
    ip = ipaddress.ip_address(text)
    if not ip.is_private or ip.is_multicast or ip.is_unspecified:
        raise ValueError("experiment traffic requires a private unicast address")
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["sink", "udp", "tcp", "serve"])
    p.add_argument("--config", required=True)
    a = p.parse_args()
    c = json.loads(Path(a.config).read_text())
    if "start_file" in c:
        Path(c["log"] + ".ready").touch()
        deadline = time.time() + 120
        while not Path(c["start_file"]).exists():
            if time.time() > deadline:
                raise TimeoutError("no synchronized experiment start signal")
            time.sleep(0.02)
        c["start"] = float(Path(c["start_file"]).read_text())
    start, end = c["start"], c["start"] + c["duration"]
    rng = random.Random(c["seed"])
    if a.mode in ("sink", "serve"):
        sockets = selectors.DefaultSelector()
        for port in c.get("ports", [9000]):
            s = socket.socket(type=socket.SOCK_DGRAM if a.mode == "sink" else socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            if a.mode == "serve":
                s.listen(4096)
            s.setblocking(False)
            sockets.register(s, selectors.EVENT_READ)
        with open(c["log"], "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["time", "source", "payload"])
            while time.time() < end + 0.5:
                for key, _ in sockets.select(0.05):
                    if a.mode == "sink":
                        data, peer = key.fileobj.recvfrom(1024)
                        w.writerow(["%.9f" % time.time(), peer[0], data.decode("ascii")])
                    else:
                        conn, _ = key.fileobj.accept()
                        conn.close()
        return
    with open(c["log"], "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "source", "destination", "sequence", "success"])
        seq, attack_probes, next_t = 0, 0, start
        while time.time() < end:
            if time.time() < next_t:
                time.sleep(max(0.0, min(0.02, next_t - time.time())))
                continue
            now = time.time()
            if a.mode == "udp":
                dst = private(c["targets"][seq % len(c["targets"])])
                with socket.socket(type=socket.SOCK_DGRAM) as sock:
                    payload = "%s|%d|%.9f" % (c["role"], seq, now)
                    sock.sendto(payload.encode("ascii"), (dst, 9000))
                success = True
            else:
                dst = private(c["targets"][seq % len(c["targets"])])
                since = now - start
                attack = c["role"] != "benign" and since >= c["attack_at"]
                port = 8000 + seq % 4
                if attack and c["role"] != "ddos":
                    port = 10000 + seq % 50000
                    if c["role"] == "success_padding" and seq % 4:
                        port = 8000 + seq % 4
                    if c["role"] == "popular_targets":
                        port = 9001
                    if c["role"] == "burst_pause" and int(since) % 4:
                        next_t = now + 0.1
                        continue
                    if c["role"] == "source_churn" and attack_probes >= c["max_probes"]:
                        break
                elif not attack and rng.random() < c.get("failure_probability", 0.05):
                    port = 9001
                with socket.socket() as sock:
                    sock.settimeout(0.15)
                    success = sock.connect_ex((dst, port)) == 0
                if attack:
                    attack_probes += 1
                rate = c["attack_rate"] if attack else c["rate"]
                c["current_rate"] = rate
            w.writerow(["%.9f" % now, c["role"], dst, seq, int(success)])
            seq += 1
            next_t += rng.expovariate(c.get("current_rate", c["rate"]))
            if next_t < time.time() - 0.1:
                next_t = time.time()


if __name__ == "__main__":
    main()
