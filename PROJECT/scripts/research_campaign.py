#!/usr/bin/env python3
"""Reproducible attempt-level simulation, NOT packet/network emulation.

Outputs are deliberately separate from the original packet-capture results. No
simulated delay, topology or mitigation result is labelled a network measurement.
"""
import argparse
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import sys
import time
import tracemalloc

import numpy as np
from scipy.stats import beta as beta_dist
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_curve

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detector"))
from detectors import AISPRT, TRW, IAWindow, Entropy
from pcapio import Attempt
from eval_cicids import bucket_features

SCENARIOS = ("benign", "outage", "fast", "slow", "horizontal", "distributed",
             "ddos", "burst_pause", "success_padding", "popular_targets", "source_churn", "flash_crowd")
SPLITS = {"train": list(range(1, 13)), "validation": list(range(1001, 1009)),
          "test": list(range(2001, 2021))}


def write_csv(path, rows):
    rows = list(rows)
    if not rows:
        raise ValueError("refusing to write an empty results table: %s" % path)
    with open(path, "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def exact_ci(k, n, level=0.95):
    if not n:
        return (float("nan"), float("nan"))
    a = (1 - level) / 2
    return (0.0 if k == 0 else beta_dist.ppf(a, k, n - k + 1),
            1.0 if k == n else beta_dist.ppf(1 - a, k + 1, n - k))


def cluster_ci(values, seed=917, repetitions=2000):
    """Resample independent seed-level summaries, not correlated hosts/windows."""
    xs = np.asarray(values, dtype=float)
    xs = xs[np.isfinite(xs)]
    if not len(xs):
        return (float("nan"),) * 3
    rng = np.random.default_rng(seed)
    means = xs[rng.integers(0, len(xs), size=(repetitions, len(xs)))].mean(axis=1)
    return (float(xs.mean()), *np.quantile(means, [0.025, 0.975]).tolist())


def generate(seed, scenario, sources=None, padding=None, fail_prob=None):
    """A stochastic event model. Topology changes delay only, not queueing/loss."""
    rng = np.random.default_rng(np.random.SeedSequence([seed, SCENARIOS.index(scenario)]))
    edges = int(rng.integers(3, 9))
    latency = float(rng.uniform(0.001, 0.03))
    nbenign = int(rng.integers(20, 45))
    nattack = (sources or int(rng.choice([100, 200, 400]))) if scenario in (
        "distributed", "ddos", "source_churn") else 1
    attack_at = float(rng.uniform(15, 25))
    duration = 100.0
    attackers = set() if scenario in ("benign", "outage", "flash_crowd") else {
        "10.%d.%d.%d" % (2, i // 254, i % 254 + 1) for i in range(nattack)}
    events = []
    routes = rng.integers(0, edges, size=nbenign)
    profile = float(rng.uniform(0.2, 1.5))
    failure = float(rng.uniform(0.01, 0.12)) if fail_prob is None else fail_prob
    ports = [22, 80, 443, 8080, 3306]

    def add(t, src, dst, port, success):
        hop_delay = latency * int(rng.integers(2, 5))
        events.append(Attempt(float(t), src, dst, 6, int(port), int(rng.integers(1024, 65535)),
                              "success" if success else "failure", float(t + hop_delay)))

    for i in range(nbenign):
        src, t = "10.1.0.%d" % (i + 1), 0.0
        rate = profile * float(rng.uniform(0.5, 3))
        while t < duration:
            t += float(rng.exponential(1 / rate))
            if t >= duration:
                break
            server = int(rng.choice(4, p=[0.5, 0.25, 0.15, 0.1]))
            port = int(rng.choice(ports))
            ok = rng.random() >= failure
            if scenario == "outage" and attack_at < t < attack_at + 30 and server == 0:
                ok = False
            if scenario == "flash_crowd" and attack_at < t < attack_at + 2:
                for j in range(50):
                    add(t + j * 0.001, src, "10.0.0.11", 80, True)
            add(t, src, "10.0.0.%d" % (11 + server), port if ok else 9000 + server, ok)

    for j, src in enumerate(sorted(attackers)):
        rate = float(rng.uniform(8, 30))
        if scenario == "slow":
            rate = float(rng.uniform(0.1, 0.5))
        elif scenario in ("distributed", "source_churn"):
            rate = float(rng.uniform(0.1, 1.5))
        elif scenario == "ddos":
            rate = float(rng.uniform(2, 8))
        elif scenario == "success_padding":
            rate = float(rng.uniform(1, 4))
        times = np.arange(attack_at + float(rng.uniform(0, 1)), min(duration, attack_at + 35), 1 / rate)
        if scenario == "source_churn":
            times = times[:2]
        for k, t in enumerate(times):
            if scenario == "burst_pause" and int((t - attack_at) // 3) % 3 != 0:
                continue
            dst = "10.0.0.%d" % (11 + (k % 4 if scenario == "horizontal" else 0))
            port, ok = 10000 + k % 50000, False
            if scenario == "ddos":
                port, ok = 80, True
            if scenario == "popular_targets":
                port = ports[k % len(ports)]
            add(t, src, dst, port, ok)
            if scenario == "success_padding":
                for p in range(padding if padding is not None else int(rng.integers(1, 5))):
                    add(t + 0.0001 * (p + 1), src, "10.0.0.12", 2000 + k * 5 + p, True)
    events.sort(key=lambda a: a.t_outcome)
    return dict(seed=seed, scenario=scenario, attempts=events, attackers=attackers, attack_at=attack_at,
                parameters=dict(edges=edges, host_edges=routes.tolist(), link_delay_s=latency,
                                benign_sources=nbenign, attack_sources=len(attackers), benign_profile=profile,
                                benign_failure_probability=failure, attack_at=attack_at))


def feature_rows(run, training=False):
    feats = bucket_features(run["attempts"])
    keys, values, labels = [], [], []
    for (src, end), value in feats.items():
        keys.append((src, end))
        values.append(value)
        onset = run.get("attack_onsets", {}).get(src, run["attack_at"])
        if training and src in run["attackers"] and end - 10.0 < onset < end:
            keys.pop()
            values.pop()
            continue
        labels.append(int(src in run["attackers"] and end > onset))
    return keys, values, labels


def evaluate(run, events):
    hosts = {a.src for a in run["attempts"]}
    first = {}
    pre = set()
    suspects = set()
    onsets = run.get("attack_onsets", {})
    for t, src, kind, _ in events:
        if kind == "SUSPECT":
            suspects.add(src)
            continue
        if src in run["attackers"] and t < onsets.get(src, run["attack_at"]):
            pre.add(src)
        elif src not in first:
            first[src] = t
    pos = run["attackers"] & hosts
    neg = hosts - pos
    tp, fp = len(pos & first.keys()), len(neg & first.keys())
    p, n = len(pos), len(neg)
    delays = [first[s] - onsets.get(s, run["attack_at"]) for s in pos & first.keys()]
    return dict(seed=run["seed"], scenario=run["scenario"], P=p, N=n, TP=tp, FP=fp, TN=n-fp, FN=p-tp,
                TPR=tp / p if p else float("nan"), FPR=fp / n if n else float("nan"),
                precision=tp / (tp + fp) if tp + fp else float("nan"),
                recall_10s=sum(d <= 10 for d in delays) / p if p else float("nan"),
                suspicion_FPR=len(suspects & neg) / n if n else float("nan"),
                F1=2 * tp / (p + tp + fp) if p else float("nan"),
                pre_attack_alarm_hosts=len(pre), suspect_benign_hosts=len(suspects & neg),
                delay_s=float(np.median(delays)) if delays else float("nan"))


def rf_result(run, clf, threshold):
    keys, xs, _ = feature_rows(run)
    probabilities = clf.predict_proba(xs)[:, list(clf.classes_).index(1)]
    events = [(t, s, "PORT_SCAN", "host") for (s, t), p in zip(keys, probabilities) if p >= threshold]
    return evaluate(run, events)


def fit_models(train, validation):
    X, y = [], []
    for run in train:
        _, xs, ys = feature_rows(run, training=True)
        X.extend(xs)
        y.extend(ys)
    tuning, candidates = [], []
    for depth, leaf, weight in itertools.product([8, None], [1, 5], ["balanced"]):
        clf = RandomForestClassifier(n_estimators=200, max_depth=depth, min_samples_leaf=leaf,
                                     class_weight=weight, random_state=701, n_jobs=2).fit(X, y)
        for threshold in [0.25, 0.5, 0.75, 0.9]:
            rows = [rf_result(run, clf, threshold) for run in validation]
            f1 = float(np.nanmean([r["F1"] for r in rows]))
            fpr = sum(r["FP"] for r in rows) / sum(r["N"] for r in rows)
            row = dict(model="RF", max_depth=depth, min_samples_leaf=leaf, threshold=threshold, F1=f1, FPR=fpr)
            tuning.append(row)
            candidates.append(((fpr <= 0.01, f1, -fpr), clf, threshold, row))
    _, rf, threshold, rf_meta = max(candidates, key=lambda x: x[0])
    ais_candidates = []
    for alpha, tau, h in itertools.product([0.01, 0.001, 0.0003], [300.0, 600.0], [150.0, 620.0]):
        params = dict(alpha=alpha, tau=tau, cusum_h=h)
        rows = [evaluate(run, AISPRT(**params).run(run["attempts"]).events) for run in validation]
        f1 = float(np.nanmean([r["F1"] for r in rows]))
        fpr = sum(r["FP"] for r in rows) / sum(r["N"] for r in rows)
        ais_candidates.append(((fpr <= 0.01, f1, -fpr), params))
        tuning.append(dict(model="AIS", parameters=params, F1=f1, FPR=fpr))
    params = max(ais_candidates, key=lambda x: x[0])[1]
    return rf, threshold, params, dict(RF=rf_meta, AIS=params, tuning=tuning, train_windows=len(y),
                                     train_attack_windows=int(sum(y)))


def bound_experiment(trials, seed=808):
    """One stopped Wald trial versus finite-horizon restarts/decay (not same bound)."""
    rng = np.random.default_rng(seed)
    rows = []
    for alpha in [0.03, 0.01, 0.003, 0.001]:
        upper, lower = math.log(0.99 / alpha), math.log(0.01 / (1 - alpha))
        for hypothesis, success_prob in [("H0", 0.8), ("H1", 0.2)]:
            outcomes = rng.random((trials, 400)) < success_prob
            for mode in ["one_stopped_test", "restarting", "decay_and_weights"]:
                L = np.zeros(trials)
                active = np.ones(trials, dtype=bool)
                alarm = np.zeros(trials, dtype=bool)
                for i in range(outcomes.shape[1]):
                    delta = np.where(outcomes[:, i], -math.log(4), math.log(4))
                    if mode == "decay_and_weights":
                        L *= math.exp(-30 / 600)
                        delta = np.where(delta > 0, 0.5 * delta, delta)
                    L[active] += delta[active]
                    hit = active & (L >= upper)
                    alarm |= hit
                    if mode == "one_stopped_test":
                        active &= (L < upper) & (L > lower)
                    else:
                        L[(L >= upper) | (L <= lower)] = 0
                k = int(alarm.sum())
                lo, hi = exact_ci(k, trials)
                rows.append(dict(alpha=alpha, hypothesis=hypothesis, mode=mode, trials=trials, alarms=k,
                                 rate=k / trials, ci_low=lo, ci_high=hi, horizon=400,
                                 classical_fp_bound=alpha / 0.99))
    return rows


def state_experiment():
    rows = []
    for count in [1000, 5000, 10000, 30000]:
        det = AISPRT(max_hosts=256, max_contacts=2048, max_services=512)
        tracemalloc.start()
        begin = time.perf_counter()
        for i in range(count):
            a = Attempt(i * 0.01, "s%d" % (i % 1000), "d%d" % i, 6, 80, 2000, "failure", i * 0.01)
            det.step(a)
        elapsed = time.perf_counter() - begin
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(dict(attempts=count, peak_traced_bytes=peak, attempts_per_s=count / elapsed, **det.state_stats()))
    return rows


def plot_results(out, rows, bounds, state, robustness, rf, threshold, test):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figures = out / "figures"
    figures.mkdir()
    inventory = []

    def save(name, title, xlabel, ylabel):
        plt.title(title)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.tight_layout()
        plt.savefig(figures / (name + ".pdf"))
        plt.savefig(figures / (name + ".png"), dpi=140)
        plt.close()
        inventory.append(name)

    methods = sorted({r["method"] for r in rows})
    for number, metric, ylabel in [(1, "F1", "Seed-macro F1"), (2, "FPR", "Benign-host alarm fraction")]:
        plt.figure(figsize=(8, 4))
        for x, method in enumerate(methods):
            grouped = {}
            for row in rows:
                if row["method"] == method:
                    grouped.setdefault(row["seed"], []).append(row[metric])
            vals = [np.nanmean(v) for v in grouped.values()]
            mean, low, high = cluster_ci(vals)
            plt.errorbar(x, mean, yerr=[[max(0, mean - low)], [max(0, high - mean)]], fmt="o", capsize=4)
        plt.xticks(range(len(methods)), methods, rotation=20)
        save("%02d_%s_ci" % (number, metric), "Attempt simulation: 95% seed-bootstrap CI", "Method", ylabel)
    for number, metric, ylabel in [(3, "TPR", "Recall"), (4, "FPR", "False-positive fraction")]:
        plt.figure(figsize=(11, 4))
        for method in methods:
            ys = [np.nanmean([r[metric] for r in rows if r["method"] == method and r["scenario"] == sc])
                  if sc not in ("benign", "outage", "flash_crowd") or metric == "FPR" else np.nan for sc in SCENARIOS]
            plt.plot(SCENARIOS, ys, ".-", label=method)
        plt.xticks(rotation=35)
        plt.legend(fontsize=7)
        save("%02d_scenario_%s" % (number, metric), "Attempt simulation: per-scenario behaviour", "Scenario", ylabel)
    plt.figure(figsize=(8, 4))
    for method in methods:
        xs = sorted(r["delay_s"] for r in rows if r["method"] == method and np.isfinite(r["delay_s"]))
        if xs:
            plt.step(xs, np.arange(1, len(xs) + 1) / len(xs), label=method)
    plt.legend(fontsize=7)
    save("05_delay", "Conditional delay ECDF (detected seed-scenarios only; misses in recall)", "Modelled delay (s)", "ECDF")
    plt.figure()
    X, y = [], []
    for run in test:
        _, xs, ys = feature_rows(run)
        X.extend(xs)
        y.extend(ys)
    probs = rf.predict_proba(X)[:, list(rf.classes_).index(1)]
    prec, recall, _ = precision_recall_curve(y, probs)
    plt.plot(recall, prec)
    plt.axhline(np.mean(y), ls="--", label="prevalence")
    plt.legend()
    save("06_RF_pr", "Held-out attempt simulation: RF windows (descriptive curve)", "Recall", "Precision")
    for number, group, xlabel in [(7, "padding", "Successful first contacts per failed probe"),
                                  (8, "sources", "Distributed source count"),
                                  (9, "failure", "Benign stale-service probability"),
                                  (10, "tau", "Evidence-decay time constant (s)")]:
        plt.figure()
        rs = [r for r in robustness if r["group"] == group]
        for method in sorted({r["method"] for r in rs}):
            xs = sorted({r["x"] for r in rs})
            means, lows, highs = [], [], []
            for x in xs:
                vals = [r["value"] for r in rs if r["method"] == method and r["x"] == x]
                mean, low, high = cluster_ci(vals)
                means.append(mean)
                lows.append(low)
                highs.append(high)
            plt.plot(xs, means, ".-", label=method)
            plt.fill_between(xs, lows, highs, alpha=0.15)
        plt.legend()
        save("%02d_%s" % (number, group), "Attempt simulation: robustness (95% seed-bootstrap CI)",
             xlabel, "Benign-host FPR" if group == "failure" else "Attacker recall")
    for number, hypothesis in [(11, "H0"), (12, "H1")]:
        plt.figure()
        for mode in sorted({r["mode"] for r in bounds}):
            rs = sorted((r for r in bounds if r["mode"] == mode and r["hypothesis"] == hypothesis),
                        key=lambda r: r["alpha"])
            plt.errorbar([r["alpha"] for r in rs], [r["rate"] for r in rs],
                         yerr=[[r["rate"] - r["ci_low"] for r in rs], [r["ci_high"] - r["rate"] for r in rs]],
                         fmt=".-", label=mode)
        if hypothesis == "H0":
            xs = sorted({r["alpha"] for r in bounds})
            plt.plot(xs, np.asarray(xs) / 0.99, "--", label="one-test classical bound")
            plt.yscale("log")
        plt.xscale("log")
        plt.legend(fontsize=7)
        save("%02d_bound_%s" % (number, hypothesis), "IID Bernoulli Monte Carlo; exact binomial 95% CI",
             "Nominal alpha", "False-alarm probability" if hypothesis == "H0" else "Detection probability")
    plt.figure()
    plt.plot([r["attempts"] for r in state], [r["peak_traced_bytes"] / 2 ** 20 for r in state], ".-")
    save("13_memory", "Measured Python state allocation under source/service churn", "Processed attempts", "Peak traced MiB")
    plt.figure()
    plt.plot([r["attempts"] for r in state], [r["attempts_per_s"] for r in state], ".-")
    save("14_throughput", "Measured detector throughput (tracemalloc enabled; not line rate)",
         "Processed attempts", "Resolved attempts / s")
    return inventory


def summarize_rows(rows, seeds):
    metrics = ("F1", "TPR", "FPR", "precision", "recall_10s", "suspicion_FPR", "delay_s")
    groups = {}
    for row in rows:
        groups.setdefault((row["method"], int(row["seed"])), []).append(row)
    summary = []
    for method in sorted({r["method"] for r in rows}):
        for metric in metrics:
            samples = []
            for seed in seeds:
                values = [float(r[metric]) for r in groups.get((method, seed), ())]
                finite = [v for v in values if np.isfinite(v)]
                if finite:
                    samples.append(float(np.mean(finite)))
            mean, low, high = cluster_ci(samples)
            summary.append(dict(method=method, metric=metric, mean=mean, ci_low=low, ci_high=high,
                                independent_test_seeds=len(samples)))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--test-seeds", type=int, default=20)
    parser.add_argument("--bound-trials", type=int, default=20000)
    args = parser.parse_args()
    if args.test_seeds < 20 or args.bound_trials < 1000:
        parser.error("publication campaign requires >=20 held-out seeds and >=1000 bound trials")
    if args.out.exists():
        parser.error("output already exists; choose a fresh directory to preserve provenance")
    args.out.mkdir(parents=True)
    splits = {**SPLITS, "test": list(range(2001, 2001 + args.test_seeds))}
    runs = {split: [generate(seed, sc) for seed in seeds for sc in SCENARIOS] for split, seeds in splits.items()}
    print("Generated attempt-level simulation; fitting on train, selecting on validation only", flush=True)
    rf, threshold, ais, selection = fit_models(runs["train"], runs["validation"])
    rows = []
    for run in runs["test"]:
        methods = {"AIS-default": AISPRT(), "AIS-tuned": AISPRT(**ais), "TRW": TRW(),
                   "IA-Window": IAWindow(), "Entropy": Entropy()}
        for name, det in methods.items():
            rows.append(dict(method=name, **evaluate(run, det.run(run["attempts"]).events)))
        rows.append(dict(method="RF-tuned", **rf_result(run, rf, threshold)))
    write_csv(args.out / "metrics.csv", rows)
    print("Held-out evaluation complete; running robustness and bound experiments", flush=True)
    robustness = []
    for seed in splits["test"]:
        for group, xs in [("padding", [0, 1, 2, 4, 8]), ("sources", [1, 10, 100, 200, 400]),
                          ("failure", [0.01, 0.08, 0.2, 0.4]), ("tau", [60, 300, 600, 1800])]:
            for x in xs:
                sc = {"padding": "success_padding", "sources": "distributed", "failure": "benign", "tau": "slow"}[group]
                kwargs = {"padding": {"padding": x}, "sources": {"sources": x}, "failure": {"fail_prob": x}, "tau": {}}[group]
                run = generate(seed, sc, **kwargs)
                params = {**ais, **({"tau": x} if group == "tau" else {})}
                for name, det in [("AIS-tuned", AISPRT(**params)), ("TRW", TRW())]:
                    result = evaluate(run, det.run(run["attempts"]).events)
                    robustness.append(dict(group=group, x=x, seed=seed, method=name,
                                           value=result["FPR" if group == "failure" else "TPR"]))
    bounds = bound_experiment(args.bound_trials)
    state = state_experiment()
    write_csv(args.out / "robustness.csv", robustness)
    write_csv(args.out / "bound.csv", bounds)
    write_csv(args.out / "state.csv", state)
    inventory = plot_results(args.out, rows, bounds, state, robustness, rf, threshold, runs["test"])
    write_csv(args.out / "summary_ci.csv", summarize_rows(rows, splits["test"]))
    seed_alarm_ci = []
    for method in sorted({r["method"] for r in rows}):
        hits = sum(any(r["FP"] for r in rows if r["method"] == method and r["seed"] == seed)
                   for seed in splits["test"])
        low, high = exact_ci(hits, len(splits["test"]))
        seed_alarm_ci.append(dict(method=method, seeds_with_any_FP=hits, seeds=len(splits["test"]),
                                  seed_false_alarm_probability=hits / len(splits["test"]), ci_low=low, ci_high=high))
    write_csv(args.out / "seed_alarm_ci.csv", seed_alarm_ci)
    files = [Path(__file__), HERE / "eval_cicids.py", HERE.parent / "detector" / "detectors.py",
             HERE.parent / "detector" / "state.py"]
    manifest = dict(evidence="attempt_level_simulation_NOT_network_emulation", seed_splits=splits,
                    selection=selection, RF_threshold=threshold, figures=inventory,
                    assumptions=["synthetic outcomes", "random propagation delay; edge assignments are metadata only",
                                 "no packet queue, loss, OpenFlow installation or controller simulation",
                                 "adaptive patterns are scripted; not a learning attacker",
                                 "source count represents logical IPs, not OS namespaces"],
                    scenario_parameters=[dict(split=split, seed=r["seed"], scenario=r["scenario"], **r["parameters"])
                                         for split, group in runs.items() for r in group],
                    versions=dict(python=sys.version, numpy=np.__version__, sklearn=sklearn.__version__,
                                  platform=platform.platform()),
                    source_sha256={str(p.relative_to(HERE.parent)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("Saved %d figures and raw tables to %s" % (len(inventory), args.out), flush=True)


if __name__ == "__main__":
    main()
