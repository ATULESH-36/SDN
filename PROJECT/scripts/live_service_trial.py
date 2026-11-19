"""Matched first-action experiment using only harmless HTTP requests in Mininet."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import random
import socket
import subprocess
import sys
import time


ARMS = ("graded", "fixed", "monitor")
ROLES = ("target", "unrelated", "control")


def serve(address, log_path):
    with open(log_path, "w", buffering=1) as log:
        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                log.write(json.dumps({"path": self.path, "time": time.time()}) + "\n")
                self.send_response(204)
                self.end_headers()

            def log_message(self, fmt, *args):
                pass

        with HTTPServer((address, 8080), HealthHandler) as server:
            Path(log_path + ".ready").touch()
            server.serve_forever()


def request_series(role, start, log_path):
    address = "10.0.0.11" if role == "target" else "10.0.0.12"
    rows = []
    for i in range(16):
        delay = (i + 1) * 0.25
        time.sleep(max(0, start + delay - time.time()))
        sent = time.time()
        conn = http.client.HTTPConnection(address, 8080, timeout=0.15)
        try:
            conn.request("GET", f"/{role}/{i}")
            ok = conn.getresponse().status == 204
        except (OSError, http.client.RemoteDisconnected):
            ok = False
        finally:
            conn.close()
        rows.append({"i": i, "sent": sent, "elapsed": time.time() - sent, "ok": ok})
    Path(log_path).write_text(json.dumps(rows, indent=2))


def retire_checks(start):
    time.sleep(max(0, start - time.time()))
    for port in (8000, 8001):
        with socket.socket() as sock:
            sock.settimeout(0.15)
            sock.connect_ex(("10.0.0.11", port))


def fixture(net, trial, blocklist, trace, seed, policy, procs):
    from network_campaign import PROJECT, trace_rows, wait

    def worker(host, *args):
        proc = net.get(host).popen([sys.executable, __file__, *map(str, args)])
        procs.append(proc)
        return proc

    for i in range(2):
        path = trial / f"server{i}.jsonl"
        worker(f"v{i}", "serve", f"10.0.0.{11 + i}", path)
        wait(lambda: Path(str(path) + ".ready").is_file())
    for host, address in (("h1", "10.0.0.11"), ("h1", "10.0.0.12"), ("h2", "10.0.0.12")):
        probe = worker(host, "probe", address)
        if probe.wait(timeout=5) != 0:
            raise RuntimeError(f"Application preflight failed for {host}: {trial}")
    detector_log = trial / "detector.log"
    detector = subprocess.Popen([sys.executable, str(PROJECT / "detector" / "live.py"),
                                 "--blocklist", str(blocklist), "--log", str(detector_log)],
                                stdout=subprocess.DEVNULL)
    procs.append(detector)
    wait(lambda: detector_log.exists() and "AIS-SPRT live" in detector_log.read_text())
    start = time.time() + 1.8
    tasks = [worker("h1" if role != "control" else "h2", "request", role, start,
                    trial / f"{role}.json") for role in ROLES]
    tasks.append(worker("h1", "checks", start))
    for proc in tasks:
        if proc.wait(timeout=10) != 0:
            raise RuntimeError(f"HTTP fixture worker failed: {trial}")
    if detector.poll() is not None:
        raise RuntimeError(f"Detector exited: {trial}")
    requests = [line.split("\t") for line in blocklist.read_text().splitlines()]
    traces = trace_rows(trace) if trace.exists() else []
    accepted = [r for r in traces if r["event"] == "REQUEST_ACCEPTED"]
    acks = {r["dpid"] for r in traces if r["event"] == "INSTALL_ACK" and r["ip"] == "10.1.0.2"}
    row = {"seed": seed, "policy": policy, "trigger_time": start, "detector_requests": requests,
           "accepted": accepted, "ack_switches": len(acks), "switches": len(net.switches)}
    for role in ROLES:
        sent = json.loads((trial / f"{role}.json").read_text())
        if len(sent) != 16:
            raise RuntimeError(f"Incomplete application stream for {role}: {trial}")
        row[role + "_success"] = sum(r["ok"] for r in sent)
    arrivals = [json.loads(line) for line in (trial / "server0.jsonl").read_text().splitlines()]
    targets = [a for a in arrivals if a["path"].startswith("/target/")]
    row["target_received"] = len(targets)
    row["contained_by_2s"] = not any(a["time"] >= start + 2 for a in targets)
    (trial / "summary.json").write_text(json.dumps(row, indent=2))
    return row


def run(first_seed, seeds, out):
    from network_campaign import checked, mitigation_trial, setLogLevel
    if checked(["ovs-vsctl", "list-br"]).strip():
        raise RuntimeError("Run only in a dedicated lab without existing OVS bridges")
    setLogLevel("warning")
    out = out.resolve()
    out.mkdir(parents=True)
    campaign = {seed: random.Random(seed).sample(ARMS, 3) for seed in range(first_seed, first_seed + seeds)}
    (out / "design.json").write_text(json.dumps({
        "arm_order": campaign, "ttl_s": 5, "receipt_deadline_s": 2, "horizon_s": 4,
        "requests_per_stream": 16, "control": "detector logs requests; controller reads an empty file",
    }, indent=2))
    completed = []
    for seed, order in campaign.items():
        for policy in order:
            row = mitigation_trial(seed, policy, 1, out, Path("/opt/sdn-pox"), application_fixture=fixture)
            completed.append(row)
            (out / "completed.json").write_text(json.dumps(completed, indent=2))
            print(seed, policy, row["unrelated_success"], row["target_received"], row["contained_by_2s"],
                  len(row["detector_requests"]), row["ack_switches"], flush=True)


if __name__ == "__main__":
    mode, *args = sys.argv[1:]
    if mode == "serve":
        serve(*args)
    elif mode == "request":
        request_series(args[0], float(args[1]), args[2])
    elif mode == "checks":
        retire_checks(float(args[0]))
    elif mode == "probe":
        conn = http.client.HTTPConnection(args[0], 8080, timeout=1)
        try:
            conn.request("GET", "/preflight")
            if conn.getresponse().status != 204:
                raise SystemExit("Unexpected preflight response")
        finally:
            conn.close()
    elif mode == "run":
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--first-seed", type=int, default=4101)
        parser.add_argument("--seeds", type=int, default=20)
        options = parser.parse_args(args)
        if options.seeds < 1:
            parser.error("--seeds must be positive")
        run(options.first_seed, options.seeds, options.out)
    else:
        raise SystemExit(f"Unknown mode: {mode}")
