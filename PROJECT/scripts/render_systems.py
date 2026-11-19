"""Build tables and the deterministic slow-boundary check for the systems draft."""
import argparse
import csv
import json
import math
from pathlib import Path

from research_campaign import AISPRT, Attempt, cluster_ci, summarize_rows, write_csv


def build(root):
    results = root / "results"
    output = root / "report_ieee" / "generated"
    simulation = results / "research_simulation_v3"
    with (simulation / "metrics.csv").open() as f:
        rows = list(csv.DictReader(f))
    manifest = json.loads((simulation / "manifest.json").read_text())
    seeds = manifest["seed_splits"]["test"]
    stats = summarize_rows(rows, seeds)
    if any(r["independent_test_seeds"] != len(seeds) for r in stats if r["metric"] in ("F1", "TPR", "FPR")):
        raise ValueError("core detector metrics must cover every held-out seed")
    write_csv(simulation / "summary_ci.csv", stats)
    summary = {(r["method"], r["metric"]): r for r in stats}
    with (results / "mitigation_analysis_v3" / "paired_effects.csv").open() as f:
        effects = {(r["metric"], r["comparison"]): r for r in csv.DictReader(f)}
    live = json.loads((results / "live_collateral_pilot" / "completed.json").read_text())
    paired = {r["seed"]: {} for r in live}
    for r in live:
        paired[r["seed"]][r["policy"]] = r
    if len(live) != 12 or len(paired) != 6 or any(set(p) != {"fixed", "graded"} for p in paired.values()):
        raise ValueError("the draft requires all six live pilot pairs")
    delta = [p["graded"]["mixed_lost"] / p["graded"]["mixed_sent"]
             - p["fixed"]["mixed_lost"] / p["fixed"]["mixed_sent"] for p in paired.values()]
    values = [round(100*x, 1) for x in cluster_ci(delta)]
    tables = [r"\newcommand{\LiveDelta}{%.1f [%.1f, %.1f]}" % tuple(values)]
    for arm in ("fixed", "graded"):
        sample = [r for r in live if r["policy"] == arm]
        counts = tuple(sum(r[m] for r in sample) for m in ("mixed_lost", "mixed_sent", "benign_lost", "benign_sent"))
        tables.append(r"\newcommand{\Live%s}{%d/%d & %d/%d}" % (arm.title(), *counts))
    tables.append(r"\newcommand{\PolicyEffects}{%")
    for metric, comparison, label, factor in [
        ("collateral_fraction", "graded_minus_fixed", "Collateral (pp)", 100),
        ("persistent_delivery_fraction", "graded_minus_fixed", "Persistent delivery (pp)", 100),
        ("host_block_from_attack_start_s", "graded_minus_fixed", "Full-host ACK (s)", 1),
        ("decision_to_initial_ack_s", "graded_minus_fixed", "Initial ACK (s)", 1),
        ("leaked_installation_packets", "guard_on_minus_off", "Install-window receipts (packets)", 1),
    ]:
        result = effects[metric, comparison]
        vals = tuple(factor * float(result[k]) for k in ("mean_difference", "ci_low", "ci_high"))
        arm = "Graded--fixed" if comparison == "graded_minus_fixed" else "Guard on--off"
        tables.append(r"%s & %s & %.3f [%.3f, %.3f] \\" % (label, arm, *vals))
    tables.append("}")
    tables.append(r"\newcommand{\DetectorRows}{%")
    for method in ["AIS-default", "AIS-tuned", "TRW", "RF-tuned", "Entropy", "IA-Window"]:
        values = [sum(int(r[m]) for r in rows if r["method"] == method) for m in ("TP", "FN", "FP", "TN")]
        vals = [float(summary[method, metric]["mean"]) for metric in
                ("F1", "precision", "recall_10s", "suspicion_FPR")]
        tables.append(r"%s & %d & %d & %d & %d & %.3f & %.3f & %.3f & %.3f \\" % (method, *values, *vals))
    tables.append("}")
    tables.append(r"\newcommand{\DetectorIntervals}{%")
    for method in ["AIS-tuned", "TRW", "RF-tuned"]:
        cells = [tuple(float(summary[method, metric][k]) for k in ("mean", "ci_low", "ci_high"))
                 for metric in ("F1", "TPR", "FPR")]
        tables.append(method + " & " + " & ".join("%.3f [%.3f, %.3f]" % c for c in cells) + r" \\")
    tables.append("}")
    (output / "systems_results.tex").write_text("\n".join(tables) + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    boundary = -600 * math.log1p(-math.log(4) / math.log(99))
    horizon = 18000
    checks = []
    for ratio in (.7, .85, .95, .98, 1, 1.02, 1.05, 1.15, 1.3):
        gap = boundary * ratio
        det = AISPRT(use_cusum=False)
        detected = None
        peak = 0
        for i in range(math.floor(horizon / gap) + 1):
            events = det.step(Attempt(i*gap, "s", "d", 6, 1000+i, 32000+i, "failure", i*gap))
            peak = max(peak, det.score.get("s", 0))
            if any(e[2] == "PORT_SCAN" for e in events):
                detected = i*gap
                break
        checks.append(dict(gap_s=gap, theoretical_asymptote_ratio=(math.log(4) / math.log(99)) /
                           -math.expm1(-gap/600), detected=detected is not None, detection_s=detected,
                           observed_peak_ratio=peak, horizon_s=horizon))
    write_csv(simulation / "slow_boundary.csv", checks)
    if any(r["detected"] != (r["gap_s"] < boundary) for r in checks):
        raise RuntimeError("detector disagrees with the analytic boundary at the tested horizon")
    plt.plot([r["gap_s"] for r in checks], [r["theoretical_asymptote_ratio"] for r in checks], label="Analytic limit")
    for observed, marker, label in ((True, "o", "Detected"), (False, "x", "No alarm by 5 h")):
        selected = [r for r in checks if r["detected"] == observed]
        plt.scatter([r["gap_s"] for r in selected], [r["observed_peak_ratio"] for r in selected], marker=marker, label=label)
    plt.axhline(1, color="grey", linestyle=":")
    plt.axvline(boundary, color="grey", linestyle="--")
    plt.xlabel("Inter-attempt gap (s)")
    plt.ylabel("Score / decision threshold")
    plt.legend()
    plt.tight_layout()
    plt.savefig(simulation / "figures" / "15_slow_boundary.pdf")
    plt.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    build(parser.parse_args().project)
