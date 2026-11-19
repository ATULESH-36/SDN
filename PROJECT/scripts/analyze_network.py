#!/usr/bin/env python3
"""Analyze recorded network campaigns; never substitute simulation for missing data."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from research_campaign import cluster_ci, write_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads((args.input / "completed.json").read_text())
    seeds = sorted({r["seed"] for r in rows})
    expected = {(seed, policy, guard) for seed in seeds for policy in ("fixed", "graded") for guard in (0, 1)}
    actual = [(r["seed"], r["policy"], r["guard"]) for r in rows]
    if len(seeds) < 20 or len(actual) != len(expected) or set(actual) != expected:
        parser.error("requires complete paired 2x2 measurements on at least 20 seeds, without duplicates")
    if args.out.exists():
        parser.error("output already exists")
    args.out.mkdir(parents=True)
    input_hashes = {}
    for r in rows:
        r["collateral_fraction"] = r["collateral_lost"] / r["collateral_sent"]
        r["unaffected_fraction"] = r["unaffected_lost"] / r["unaffected_sent"]
        r["last_block_duration_s"] = float(r["persistent_block_seconds"].split(";")[-1])
        trial = args.input / ("%d_%s_guard%d" % (r["seed"], r["policy"], r["guard"]))
        decisions = json.loads((trial / "decisions.json").read_text())
        repeat_at = next(d["time"] for d in decisions if d["reason"] == "persistent_2")
        with open(trial / "attacker_sent.csv") as f:
            sent = [x for x in csv.DictReader(f) if float(x["time"]) >= repeat_at]
        received = set()
        for name in ("v0_received.csv", "v1_received.csv"):
            with open(trial / name) as f:
                received.update(x["payload"].split("|")[1] for x in csv.DictReader(f)
                                if x["payload"].startswith("attacker|"))
        if not sent:
            parser.error("no actual persistent attacker traffic in %s" % trial)
        r["persistent_attacker_sent"] = len(sent)
        r["persistent_attacker_delivered"] = sum(x["sequence"] in received for x in sent)
        r["persistent_delivery_fraction"] = r["persistent_attacker_delivered"] / len(sent)
        for name in ("decisions.json", "attacker_sent.csv", "v0_received.csv", "v1_received.csv"):
            path = trial / name
            input_hashes[str(path.relative_to(args.input))] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_csv(args.out / "trials.csv", rows)
    metrics = ["leaked_installation_packets", "collateral_fraction", "decision_to_initial_ack_s",
               "host_block_from_attack_start_s", "last_block_duration_s", "persistent_delivery_fraction",
               "unaffected_fraction"]
    summary, paired = [], []
    for metric in metrics:
        for policy in ("fixed", "graded"):
            for guard in (0, 1):
                vals = [r[metric] for r in rows if r["policy"] == policy and r["guard"] == guard]
                mean, low, high = cluster_ci(vals)
                summary.append(dict(policy=policy, guard=guard, metric=metric, mean=mean,
                                    ci_low=low, ci_high=high, seeds=len(seeds)))
        for comparison in ("guard_on_minus_off", "graded_minus_fixed"):
            vals = []
            for seed in seeds:
                rs = [r for r in rows if r["seed"] == seed]
                if comparison == "guard_on_minus_off":
                    val = np.mean([r[metric] for r in rs if r["guard"] == 1]) - np.mean(
                        [r[metric] for r in rs if r["guard"] == 0])
                else:
                    val = np.mean([r[metric] for r in rs if r["policy"] == "graded"]) - np.mean(
                        [r[metric] for r in rs if r["policy"] == "fixed"])
                vals.append(val)
            mean, low, high = cluster_ci(vals)
            paired.append(dict(metric=metric, comparison=comparison, mean_difference=mean, ci_low=low, ci_high=high))
    write_csv(args.out / "summary_ci.csv", summary)
    write_csv(args.out / "paired_effects.csv", paired)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = ["fixed/off", "fixed/on", "graded/off", "graded/on"]
    for index, metric in enumerate(metrics[:6], start=15):
        fig, ax = plt.subplots(figsize=(7, 4))
        for x, label in enumerate(labels):
            policy, guard = label.split("/")
            r = next(r for r in summary if r["metric"] == metric and r["policy"] == policy
                     and r["guard"] == int(guard == "on"))
            ax.errorbar(x, r["mean"], yerr=[[max(0, r["mean"] - r["ci_low"])],
                                          [max(0, r["ci_high"] - r["mean"])]], fmt="o", capsize=5)
        ax.set_xticks(range(4), labels)
        ax.set_ylabel(metric.replace("_", " "))
        ax.set_title("Measured OpenFlow: %d paired seeds, 95%% seed-bootstrap CI" % len(seeds))
        fig.tight_layout()
        fig.savefig(args.out / ("%02d_%s.pdf" % (index, metric)))
        fig.savefig(args.out / ("%02d_%s.png" % (index, metric)), dpi=140)
        plt.close(fig)
    (args.out / "definitions.json").write_text(json.dumps(dict(
        leakage="Victim receipt timestamps between first switch install-send and last initial barrier reply; includes in-flight packets.",
        collateral="Other-destination legitimate packets lost from the falsely suspected source, relative seconds [1,3.25).",
        timing="Injected suspicion to all-switch barrier ACK; not detector latency.",
        persistence="Accepted controller TTL for final repeated offence, not inferred packet delivery.",
        persistent_delivery="Fraction of actual attacker sequence IDs delivered after the second repeated decision.",
        ci="Percentile bootstrap of paired independent seeds (2000 resamples); degenerate intervals are not guarantees.",
        scope="Private UDP lab with randomized switch count, rates and paired arm order; not Internet DDoS.",
        seeds=seeds), indent=2))
    (args.out / "manifest.json").write_text(json.dumps(dict(
        input_campaign=json.loads((args.input / "manifest.json").read_text()),
        analysis_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        raw_file_sha256=input_hashes), indent=2))
    print("Analyzed %d complete measured trials; six additional figures saved to %s" % (len(rows), args.out))


if __name__ == "__main__":
    main()
