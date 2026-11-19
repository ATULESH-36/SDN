"""Seed-level inferential statistics for the unified paper, derived only from recorded results."""
import argparse
import csv
import json
import math
import warnings
from pathlib import Path

import numpy as np
from scipy import stats

from research_campaign import cluster_ci

METRICS = [
    ("leaked_installation_packets", "Install-window receipts (pkts)", 1, "lower"),
    ("collateral_fraction", "Collateral loss (pp)", 100, "lower"),
    ("decision_to_initial_ack_s", "Decision to initial ACK (s)", 1, "lower"),
    ("host_block_from_attack_start_s", "Full-host ACK (s)", 1, "lower"),
    ("persistent_delivery_fraction", "Persistent delivery (pp)", 100, "lower"),
]
ARMS = [("fixed", "0"), ("fixed", "1"), ("graded", "0"), ("graded", "1")]


def wilson(k, n, z=1.959964):
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def paired_test(diff):
    diff = np.asarray(diff, dtype=float)
    sd = float(diff.std(ddof=1))
    dz = float(diff.mean() / sd) if sd > 0 else float("nan")
    if np.allclose(diff, 0):
        p = float("nan")
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            p = float(stats.wilcoxon(diff, zero_method="wilcox", alternative="two-sided").pvalue)
    return sd, dz, p


def holm(pvalues):
    order = sorted((p, i) for i, p in enumerate(pvalues) if not math.isnan(p))
    adjusted = [float("nan")] * len(pvalues)
    running = 0.0
    for rank, (p, i) in enumerate(order):
        running = max(running, min(1.0, (len(order) - rank) * p))
        adjusted[i] = running
    return adjusted


def fmt_p(p):
    if math.isnan(p):
        return "--"
    return r"$<$0.001" if p < 0.001 else "%.3f" % p


def fmt_dz(d):
    if math.isnan(d):
        return "--"
    return (r"$>$20" if d > 0 else r"$<-$20") if abs(d) > 20 else "%.2f" % d


def build(root):
    results = root / "results"
    out_dir = root / "report_ieee" / "generated"
    with (results / "mitigation_analysis_v3" / "trials.csv").open() as f:
        trials = list(csv.DictReader(f))
    table = {(r["seed"], r["policy"], r["guard"]): r for r in trials}
    seeds = sorted({r["seed"] for r in trials})
    if len(trials) != 80 or len(seeds) != 20 or len(table) != 80:
        raise ValueError("expected 20 seeds x 4 arms of controlled trials")

    tests = []
    for metric, label, factor, better in METRICS:
        value = lambda s, p, g: factor * float(table[s, p, g][metric])
        for name, diff in [
            ("Graded$-$fixed", [(value(s, "graded", "0") + value(s, "graded", "1")
                                 - value(s, "fixed", "0") - value(s, "fixed", "1")) / 2 for s in seeds]),
            ("Guard on$-$off", [(value(s, "fixed", "1") + value(s, "graded", "1")
                                 - value(s, "fixed", "0") - value(s, "graded", "0")) / 2 for s in seeds]),
        ]:
            sd, dz, p = paired_test(diff)
            mean, low, high = cluster_ci(diff)
            favours = sum(1 for d in diff if d < 0)
            ties = sum(1 for d in diff if d == 0)
            tests.append(dict(label=label, contrast=name, mean=mean, low=low, high=high, sd=sd,
                              dz=dz, p=p, favours=favours, ties=ties))
    for row, adj in zip(tests, holm([t["p"] for t in tests])):
        row["p_holm"] = adj

    lines = [r"\newcommand{\InferenceRows}{%"]
    for t in tests:
        lines.append(r"%s & %s & %.3f [%.3f, %.3f] & %.3f & %s & %d/%d/%d & %s & %s \\" % (
            t["label"], t["contrast"], t["mean"], t["low"], t["high"], t["sd"], fmt_dz(t["dz"]),
            t["favours"], t["ties"], len(seeds) - t["favours"] - t["ties"], fmt_p(t["p"]), fmt_p(t["p_holm"])))
    lines.append("}")

    lines.append(r"\newcommand{\ArmDescriptiveRows}{%")
    for metric, label, factor, _ in METRICS:
        cells = []
        for policy, guard in ARMS:
            xs = np.array([factor * float(table[s, policy, guard][metric]) for s in seeds])
            q1, med, q3 = np.percentile(xs, [25, 50, 75])
            cells.append("%.2f (%.2f--%.2f)" % (med, q1, q3))
        lines.append(label + " & " + " & ".join(cells) + r" \\")
    lines.append("}")

    live = json.loads((results / "live_collateral_pilot" / "completed.json").read_text())
    pairs = {}
    for r in live:
        pairs.setdefault(r["seed"], {})[r["policy"]] = r
    if len(pairs) != 6 or any(set(p) != {"fixed", "graded"} for p in pairs.values()):
        raise ValueError("expected six complete live pairs")
    lines.append(r"\newcommand{\LivePairRows}{%")
    live_diff = []
    for seed in sorted(pairs):
        f, g = pairs[seed]["fixed"], pairs[seed]["graded"]
        lf, lg = f["mixed_lost"] / f["mixed_sent"], g["mixed_lost"] / g["mixed_sent"]
        live_diff.append(100 * (lg - lf))
        lines.append(r"%d & %d/%d (%.1f) & %d/%d (%.1f) & %d/%d & %.1f \\" % (
            seed, f["mixed_lost"], f["mixed_sent"], 100 * lf, g["mixed_lost"], g["mixed_sent"], 100 * lg,
            f["benign_lost"] + g["benign_lost"], f["benign_sent"] + g["benign_sent"], 100 * (lg - lf)))
    lines.append("}")
    sd, dz, p = paired_test(live_diff)
    sign_p = float(stats.binomtest(sum(d < 0 for d in live_diff), len(live_diff), 0.5).pvalue)
    fixed_k = sum(pairs[s]["fixed"]["mixed_lost"] for s in pairs)
    fixed_n = sum(pairs[s]["fixed"]["mixed_sent"] for s in pairs)
    graded_k = sum(pairs[s]["graded"]["mixed_lost"] for s in pairs)
    graded_n = sum(pairs[s]["graded"]["mixed_sent"] for s in pairs)
    fl, fh = wilson(fixed_k, fixed_n)
    gl, gh = wilson(graded_k, graded_n)
    lines += [
        r"\newcommand{\LiveSD}{%.1f}" % sd,
        r"\newcommand{\LiveDz}{%s}" % fmt_dz(dz),
        r"\newcommand{\LiveWilcoxonP}{%s}" % fmt_p(p),
        r"\newcommand{\LiveSignP}{%s}" % fmt_p(sign_p),
        r"\newcommand{\LiveFixedWilson}{%.1f\%% [%.1f, %.1f]}" % (100 * fixed_k / fixed_n, 100 * fl, 100 * fh),
        r"\newcommand{\LiveGradedWilson}{%.1f\%% [%.1f, %.1f]}" % (100 * graded_k / graded_n, 100 * gl, 100 * gh),
    ]

    with (results / "research_simulation_v3" / "metrics.csv").open() as f:
        rows = list(csv.DictReader(f))
    manifest = json.loads((results / "research_simulation_v3" / "manifest.json").read_text())
    test_seeds = [str(s) for s in manifest["seed_splits"]["test"]]

    def seed_metric(method, metric):
        out = []
        for s in test_seeds:
            xs = [float(r[metric]) for r in rows if r["method"] == method and r["seed"] == s]
            xs = [x for x in xs if np.isfinite(x)]
            out.append(float(np.mean(xs)) if xs else float("nan"))
        return np.array(out)

    lines.append(r"\newcommand{\DetectorPairRows}{%")
    for metric, label in (("F1", "F1"), ("TPR", "TPR"), ("FPR", "Confirmed FPR")):
        base = seed_metric("RF-tuned", metric)
        for other in ("AIS-tuned", "TRW"):
            diff = base - seed_metric(other, metric)
            diff = diff[np.isfinite(diff)]
            mean, low, high = cluster_ci(diff)
            sd, dz, p = paired_test(diff)
            wins = int(np.sum(diff > 0))
            lines.append(r"%s & RF$-$%s & %.3f [%.3f, %.3f] & %s & %d/%d & %s \\" % (
                label, other, mean, low, high, fmt_dz(dz), wins, len(diff), fmt_p(p)))
    lines.append("}")

    lines.append(r"\newcommand{\DetectorWilsonRows}{%")
    for method in ("AIS-tuned", "TRW", "RF-tuned"):
        tp, fn, fp, tn = (sum(int(r[m]) for r in rows if r["method"] == method) for m in ("TP", "FN", "FP", "TN"))
        rl, rh = wilson(tp, tp + fn)
        ol, oh = wilson(fp, fp + tn)
        precision = tp / (tp + fp) if tp + fp else float("nan")
        lines.append(r"%s & %.3f [%.3f, %.3f] & %.4f [%.4f, %.4f] & %.3f \\" % (
            method, tp / (tp + fn), rl, rh, fp / (fp + tn), ol, oh, precision))
    lines.append("}")
    (out_dir / "extended_stats.tex").write_text("\n".join(lines) + "\n")
    return tests


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    for t in build(parser.parse_args().project):
        print(t)
