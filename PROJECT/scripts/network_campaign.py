#!/usr/bin/env python3
"""Measured Mininet experiments. Run only inside the dedicated sdn-research WSL.

mitigation: paired 2x2 policy/packet-in-guard trials with timestamped UDP receipts.
scale: randomized packet captures with hundreds of real host namespaces.
"""
import argparse
import csv
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT / "topology"))
from campus_topo import add_mirror
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

WORKER = HERE / "research_traffic.py"


def checked(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def wait(predicate, seconds=15):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise TimeoutError("network experiment readiness/installation deadline exceeded")


def launch(host, mode, config, directory, name):
    path = directory / (name + ".json")
    path.write_text(json.dumps(config))
    stream = open(directory / (name + ".stderr"), "w")
    try:
        proc = host.popen([sys.executable, str(WORKER), mode, "--config", str(path)],
                          stdout=stream, stderr=stream)
    finally:
        stream.close()
    return proc


def stop(procs):
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class ResearchTopo(Topo):
    def build(self, seed, clients=3):
        rng = random.Random(seed)
        core = self.addSwitch("s1", protocols="OpenFlow10")
        edges = [self.addSwitch("s%d" % (i + 2), protocols="OpenFlow10") for i in range(rng.randint(3, 5))]
        for edge in edges:
            self.addLink(core, edge)
        for i in range(2):
            name = self.addHost("v%d" % i, ip="10.0.0.%d/8" % (11 + i))
            self.addLink(name, edges[0])
        for i in range(clients):
            ip = "10.1.%d.%d/8" % (i // 254, i % 254 + 1)
            name = self.addHost("h%d" % i, ip=ip)
            self.addLink(name, rng.choice(edges[1:]))


def start_net(seed, clients, controlled):
    from functools import partial
    switch = OVSSwitch if controlled else partial(OVSSwitch, failMode="standalone", batch=True)
    net = Mininet(topo=ResearchTopo(seed=seed, clients=clients), controller=None, switch=switch,
                  autoSetMacs=True, autoStaticArp=controlled, waitConnected=False)
    if controlled:
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=16633)
    ready = False
    try:
        net.start()
        if not controlled:
            expected = {i.name for sw in net.switches for i in sw.intfList() if sw.ports[i]}

            def ports_ready():
                data = json.loads(checked(["ovs-vsctl", "--format=json", "--columns=name,ofport,error", "list", "Interface"]))
                actual = {r[0]: r[1] for r in data["data"] if isinstance(r[1], int) and r[1] > 0}
                return expected <= actual.keys()

            wait(ports_ready)
            servers = [net.get("v0"), net.get("v1")]
            for host in net.hosts:
                peers = net.hosts if host in servers else servers
                commands = ["arp -s %s %s" % (peer.IP(), peer.MAC()) for peer in peers if peer != host]
                # Node.cmd uses a canonical PTY; long lines truncate before all neighbours are configured.
                for offset in range(0, len(commands), 32):
                    host.cmd("; ".join(commands[offset:offset + 32]))
        for h in net.hosts:
            h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1")
        # Populate every destination MAC at the learning switch before timed traffic.
        for h in net.hosts:
            result = h.cmd("ping -c 1 -W 1 10.0.0.11")
            if not controlled and "1 received" not in result:
                raise RuntimeError("preflight connectivity failed for %s: %s" % (h.name, result))
        ready = True
        return net
    finally:
        if not ready:
            net.stop()


def trace_rows(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def mitigation_trial(seed, policy, guard, out, pox, live_fixture=False, application_fixture=None):
    trial = out / ("%d_%s_guard%d" % (seed, policy, guard))
    trial.mkdir()
    blocklist, events, trace = [trial / name for name in ("blocklist.txt", "events.csv", "trace.csv")]
    blocklist.touch()
    monitor_only = application_fixture is not None and policy == "monitor"
    controller_requests = trial / "monitor_empty.txt" if monitor_only else blocklist
    controller_requests.touch()
    ttl = "5" if application_fixture is not None else ("3" if live_fixture else "1")
    env = {**os.environ, "PYTHONPATH": str(PROJECT / "controller"), "PYTHONDONTWRITEBYTECODE": "1"}
    log = open(trial / "controller.log", "w")
    controller = subprocess.Popen([sys.executable, str(pox / "pox.py"), "log.level", "--WARNING",
        "openflow.of_01", "--port=16633", "forwarding.l2_learning",
        "pacman_ips", "--interval=60", "--block_seconds=" + ttl, "--protect=",
        "--policy=" + ("fixed" if monitor_only else policy), "--packet_in_guard=" + str(bool(guard)).lower(),
        "--stats_file=" + str(trial / "flow_stats.csv"), "--blocklist=" + str(controller_requests),
        "--events_file=" + str(events), "--trace_file=" + str(trace)], env=env, stdout=log, stderr=log)
    procs, net = [], None
    try:
        time.sleep(0.7)
        if controller.poll() is not None:
            raise RuntimeError("POX failed; inspect %s" % (trial / "controller.log"))
        net = start_net(seed, 3, True)
        wait(lambda: all(s.connected() for s in net.switches))
        if application_fixture is not None:
            add_mirror()
            return application_fixture(net, trial, blocklist, trace, seed, policy, procs)
        if live_fixture:
            add_mirror()
            return live_collateral_trial(net, trial, blocklist, trace, seed, policy, procs)
        rng = random.Random(seed)
        start, duration = time.time() + 1, 11.5
        for name in ("v0", "v1"):
            procs.append(launch(net.get(name), "sink", dict(start=start, duration=duration, seed=seed,
                log=str(trial / (name + "_received.csv"))), trial, name))
        roles = [("h0", "attacker", rng.randint(200, 500), ["10.0.0.11"]),
                 ("h1", "mixed", rng.randint(30, 60), ["10.0.0.11", "10.0.0.12"]),
                 ("h2", "benign", rng.randint(30, 60), ["10.0.0.12"])]
        for host, role, rate, targets in roles:
            procs.append(launch(net.get(host), "udp", dict(start=start, duration=duration, seed=seed,
                role=role, rate=rate, targets=targets, log=str(trial / (role + "_sent.csv"))), trial, role))
        requests = [(1.0, "10.1.0.2", "10.0.0.11", "injected_false_positive"),
                    (1.25, "10.1.0.1", "10.0.0.11", "suspicion"),
                    (1.75, "10.1.0.1", "host", "decision"),
                    (3.5, "10.1.0.1", "host", "persistent_2"),
                    (7.0, "10.1.0.1", "host", "persistent_3")]
        decisions = []
        for offset, ip, scope, reason in requests:
            time.sleep(max(0, start + offset - time.time()))
            now = time.time()
            with open(blocklist, "a") as f:
                f.write("%s\t%.9f\t%s\t%s\n" % (ip, now, reason, scope))
            decisions.append(dict(time=now, ip=ip, scope=scope, reason=reason))
        for proc in procs:
            if proc.wait(timeout=duration + 5) != 0:
                raise RuntimeError("traffic worker failed in %s" % trial)
        (trial / "decisions.json").write_text(json.dumps(decisions, indent=2))
        rows = trace_rows(trace)
        attacker_begin = [float(r["time"]) for r in rows if r["event"] == "INSTALL_BEGIN" and r["ip"] == "10.1.0.1"]
        attacker_ack = [r for r in rows if r["event"] == "INSTALL_ACK" and r["ip"] == "10.1.0.1"]
        if not attacker_begin or not attacker_ack:
            raise RuntimeError("no measured installation/barrier evidence in %s" % trial)
        first_begin = min(attacker_begin)
        initial_acks = {r["dpid"]: min(float(x["time"]) for x in attacker_ack if x["dpid"] == r["dpid"])
                        for r in attacker_ack}
        if len(initial_acks) != len(net.switches):
            raise RuntimeError("not every switch acknowledged initial installation")
        first_ack = max(initial_acks.values())
        host_acks = [r for r in attacker_ack if not r["dst"]]
        if len(host_acks) < len(net.switches):
            raise RuntimeError("no complete host-block barrier acknowledgement")
        host_group = {r["dpid"]: min(float(x["time"]) for x in host_acks if x["dpid"] == r["dpid"])
                      for r in host_acks}
        if len(host_group) != len(net.switches):
            raise RuntimeError("not every switch acknowledged the host block")
        host_ack = max(host_group.values())
        received = trace_rows(trial / "v0_received.csv") + trace_rows(trial / "v1_received.csv")
        leaked = sum(r["payload"].startswith("attacker|") and first_begin <= float(r["time"]) <= first_ack
                     for r in received)
        arrival = {r["payload"].split("|")[0] + "|" + r["payload"].split("|")[1] for r in received}
        collateral = {}
        for role in ("mixed", "benign"):
            # Other-victim traffic is legitimate even after the injected false positive.
            sent = [r for r in trace_rows(trial / (role + "_sent.csv"))
                    if r["destination"] == "10.0.0.12" and start + 1 <= float(r["time"]) < start + 3.25]
            lost = sum("%s|%s" % (role, r["sequence"]) not in arrival for r in sent)
            collateral[role] = (lost, len(sent))
        blocks = [r for r in rows if r["event"] == "REQUEST_ACCEPTED" and r["ip"] == "10.1.0.1" and not r["dst"]]
        result = dict(seed=seed, policy=policy, guard=guard, leaked_installation_packets=leaked,
                      initial_installation_s=first_ack - first_begin,
                      decision_to_initial_ack_s=first_ack - decisions[1]["time"],
                      host_block_from_attack_start_s=host_ack - start,
                      collateral_lost=collateral["mixed"][0], collateral_sent=collateral["mixed"][1],
                      unaffected_lost=collateral["benign"][0], unaffected_sent=collateral["benign"][1],
                      persistent_block_seconds=";".join(r["seconds"] for r in blocks),
                      switch_count=len(net.switches), evidence="measured_UDP_receipts_OpenFlow_barriers")
        (trial / "summary.json").write_text(json.dumps(result, indent=2))
        return result
    finally:
        stop(procs)
        if net:
            net.stop()
        stop([controller])
        log.close()


def live_collateral_trial(net, trial, blocklist, trace, seed, policy, procs):
    """A benign stale health-check configuration drives real detector decisions."""
    detector_log = trial / "detector.log"
    detector = subprocess.Popen([sys.executable, str(PROJECT / "detector" / "live.py"),
                                 "--blocklist", str(blocklist), "--log", str(detector_log)],
                                stdout=subprocess.DEVNULL)
    procs.append(detector)
    wait(lambda: detector_log.exists() and "AIS-SPRT live" in detector_log.read_text())
    start, duration = time.time() + 1.5, 9.0
    for name in ("v0", "v1"):
        procs.append(launch(net.get(name), "sink", dict(start=start, duration=duration, seed=seed,
            log=str(trial / (name + "_received.csv"))), trial, name))
    for host, role in (("h1", "mixed"), ("h2", "benign")):
        procs.append(launch(net.get(host), "udp", dict(start=start, duration=duration, seed=seed,
            role=role, rate=8, targets=["10.0.0.12"], log=str(trial / (role + "_sent.csv"))), trial, role))
    time.sleep(max(0, start + 2 - time.time()))
    # Two configured health checks refer to retired services; no attack traffic is generated.
    health = net.get("h1").popen([sys.executable, "-c",
        "import socket; "
        "[(s.connect_ex(('10.0.0.11', port)), s.close()) "
        "for port in (8000, 8001) for s in [socket.socket()]]"])
    procs.append(health)
    for proc in procs[1:]:
        if proc.wait(timeout=duration + 5) != 0:
            raise RuntimeError("live fixture worker failed: %s" % trial)
    if detector.poll() is not None:
        raise RuntimeError("live detector exited: %s" % trial)
    requests = [line.split("\t") for line in blocklist.read_text().splitlines()]
    source = "10.1.0.2"
    matched = [r for r in requests if r[0] == source and r[3] == "10.0.0.11"]
    acks = {r["dpid"] for r in trace_rows(trace) if r["event"] == "INSTALL_ACK" and r["ip"] == source}
    if not matched or len(acks) != len(net.switches):
        raise RuntimeError("expected false suspicion and all-switch acknowledgement: %s" % trial)
    arrivals = {r["payload"].rsplit("|", 1)[0] for r in trace_rows(trial / "v1_received.csv")}
    row = dict(seed=seed, policy=policy, policy_ack_switches=len(acks),
               false_suspicion_requests=len(matched), total_requests=len(requests))
    for role in ("mixed", "benign"):
        sent = [r for r in trace_rows(trial / (role + "_sent.csv")) if start + 2 <= float(r["time"]) < start + 7]
        if not sent:
            raise RuntimeError("no offered fixture traffic: %s" % trial)
        row[role + "_sent"] = len(sent)
        row[role + "_lost"] = sum(f"{role}|{r['sequence']}" not in arrivals for r in sent)
    (trial / "summary.json").write_text(json.dumps(row, indent=2))
    return row


def scale_trial(seed, scenario, sources, out, duration):
    trial = out / ("%s_s%d" % (scenario, seed))
    trial.mkdir()
    net, procs, cap = None, [], None
    spool = tempfile.TemporaryDirectory(prefix="sdn-capture-")
    native_pcap = Path(spool.name) / "traffic.pcap"
    pcap = trial / "traffic.pcap"
    try:
        net = start_net(seed, sources + 12, False)
        add_mirror()
        capture_log = open(trial / "capture.log", "w")
        cap = subprocess.Popen(["tcpdump", "-B", "16384", "-n", "-i", "mon0", "-s", "96", "-w", str(native_pcap), "ip"],
                               stdout=capture_log, stderr=capture_log)
        time.sleep(0.5)
        if cap.poll() is not None:
            raise RuntimeError("tcpdump failed")
        rng = random.Random(seed)
        start, attack_at = 0, rng.uniform(3, 5)
        start_file = trial / "start.txt"
        for i in range(2):
            procs.append(launch(net.get("v%d" % i), "serve", dict(start=start, duration=duration + 2,
                ports=list(range(8000, 8004)), seed=seed, start_file=str(start_file),
                log=str(trial / ("server%d.csv" % i))), trial, "server%d" % i))
        attackers = []
        params = []
        for i in range(sources + 12):
            host = net.get("h%d" % i)
            role = scenario if i < sources else "benign"
            if role != "benign":
                attackers.append(host.IP())
            config = dict(start=start, duration=duration, seed=seed * 1000 + i, role=role,
                          rate=rng.uniform(0.2, 2), attack_rate=rng.uniform(0.3, 2) if scenario != "ddos" else rng.uniform(2, 8),
                          attack_at=attack_at + rng.uniform(0, 0.3), failure_probability=rng.uniform(0.01, 0.1),
                          max_probes=2, start_file=str(start_file), targets=["10.0.0.11", "10.0.0.12"],
                          log=str(trial / ("host%d.csv" % i)))
            params.append(config)
            procs.append(launch(host, "tcp", config, trial, "host%d" % i))
        wait(lambda: len(list(trial.glob("*.ready"))) == sources + 14, seconds=90)
        if any(proc.poll() is not None for proc in procs):
            raise RuntimeError("traffic worker exited before synchronized start")
        start = time.time() + 2
        pending_start = start_file.with_suffix(".tmp")
        pending_start.write_text("%.9f" % start)
        pending_start.replace(start_file)
        for config in params:
            config["start"] = start
        for proc in procs:
            if proc.wait(timeout=duration + 15) != 0:
                raise RuntimeError("scale traffic worker failed")
        time.sleep(1)
        cap.send_signal(signal.SIGINT)
        cap.wait(timeout=10)
        cap = None
        capture_log.close()
        shutil.copyfile(native_pcap, pcap)
        dropped = re.search(r"(\d+) packets dropped by kernel", (trial / "capture.log").read_text())
        if dropped is None or int(dropped.group(1)):
            raise RuntimeError("capture integrity failed: absent statistics or kernel packet loss")
        sys.path.insert(0, str(PROJECT / "detector"))
        import pcapio
        attempts, _, packets, _, _ = pcapio.extract(pcap)
        onsets = {ip: start + params[i]["attack_at"] for i, ip in enumerate(attackers)}
        observed_attackers = {a.src for a in attempts if a.src in onsets and a.t >= onsets[a.src]}
        if len(observed_attackers) != sources:
            raise RuntimeError("only %d/%d attacker sources appear after attack start in capture" %
                               (len(observed_attackers), sources))
        return dict(seed=seed, scenario=scenario, attackers=attackers, attack_t=start + attack_at,
                    capture=str(pcap), parameters=params, duration=duration,
                    attack_onsets=onsets,
                    observed_attack_sources=len(observed_attackers), captured_packets=packets,
                    captured_attempts=len(attempts), capture_sha256=hashlib.sha256(pcap.read_bytes()).hexdigest(),
                    kernel_capture_drops=int(dropped.group(1)),
                    links=[(link.intf1.name, link.intf2.name) for link in net.links],
                    evidence="measured_Mininet_%d_source_namespaces" % sources)
    finally:
        stop(procs + ([cap] if cap else []))
        if cap:
            capture_log.close()
        if net:
            net.stop()
        if native_pcap.exists() and not pcap.exists():
            shutil.copyfile(native_pcap, pcap)
        spool.cleanup()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["mitigation", "scale", "live-collateral"])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--sources", type=int, default=200)
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--split", choices=["train", "validation", "test"], default="test")
    p.add_argument("--pox", type=Path, default=Path("/opt/sdn-pox"))
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error("requires root in the dedicated WSL lab")
    if a.seeds < 1 or (a.mode != "live-collateral" and a.split == "test" and a.seeds < 20):
        p.error("at least 20 held-out seeds required")
    if a.sources < 100 or a.duration < 10:
        p.error("scale campaign requires >=100 namespaces and >=10 seconds")
    a.out = a.out.resolve()
    if a.out.exists():
        p.error("choose a fresh output directory")
    a.out.mkdir(parents=True)
    setLogLevel("error")
    rows = []
    first_seed = {"train": 1, "validation": 1001, "test": 2001}[a.split]
    if a.mode == "live-collateral":
        first_seed = 3101
    source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
                     (Path(__file__), WORKER, PROJECT / "controller" / "pacman_ips.py")}
    complete = False
    try:
        for seed in range(first_seed, first_seed + a.seeds):
            if a.mode in ("mitigation", "live-collateral"):
                fixture = a.mode == "live-collateral"
                arms = [(policy, 1) for policy in ("fixed", "graded")] if fixture else list(
                    itertools.product(["graded", "fixed"], [0, 1]))
                random.Random(seed).shuffle(arms)
                for policy, guard in arms:
                    result = mitigation_trial(seed, policy, guard, a.out, a.pox, live_fixture=fixture)
                    rows.append(result)
                    print(json.dumps(result), flush=True)
            else:
                for scenario in ("distributed", "ddos", "burst_pause", "success_padding", "popular_targets", "source_churn"):
                    result = scale_trial(seed, scenario, a.sources, a.out, a.duration)
                    rows.append(result)
                    print("Recorded %s seed %d" % (scenario, seed), flush=True)
            (a.out / "completed.json").write_text(json.dumps(rows, indent=2))
        complete = True
    finally:
        manifest = dict(mode=a.mode, completed_trials=len(rows), requested_seeds=a.seeds,
                        complete=complete, source_sha256=source_hashes,
                        split=a.split, seeds=list(range(first_seed, first_seed + a.seeds)),
                        evidence="real_Mininet_OpenFlow_not_simulated")
        (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
