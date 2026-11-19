#!/usr/bin/env python3
"""Train/tune once on recorded train/validation campaigns, then evaluate held-out PCAPs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import numpy as np

from research_campaign import AISPRT, TRW, IAWindow, Entropy, fit_models, evaluate, rf_result, cluster_ci, write_csv
import pcapio


def load(directory):
    rows = json.loads((directory / "completed.json").read_text())
    runs = []
    for r in rows:
        path = Path(r["capture"])
        attempts, _, _, _, _ = pcapio.extract(path)
        runs.append(dict(seed=r["seed"], scenario=r["scenario"], attempts=attempts, attackers=set(r["attackers"]),
                         attack_at=r["attack_t"], attack_onsets=r.get("attack_onsets", {})))
    return runs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for split in ("train", "validation", "test"):
        p.add_argument("--" + split, type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    groups = {split: load(getattr(a, split)) for split in ("train", "validation", "test")}
    seeds = {split: {r["seed"] for r in runs} for split, runs in groups.items()}
    if any(seeds[x] & seeds[y] for x, y in (("train", "validation"), ("train", "test"), ("validation", "test"))):
        p.error("seed splits overlap")
    if len(seeds["test"]) < 20:
        p.error("requires at least 20 held-out network seeds")
    if a.out.exists():
        p.error("output already exists")
    a.out.mkdir(parents=True)
    rf, threshold, ais, selection = fit_models(groups["train"], groups["validation"])
    rows = []
    for r in groups["test"]:
        for method, detector in [("AIS-tuned", AISPRT(**ais)), ("TRW", TRW()),
                                 ("IA-Window", IAWindow()), ("Entropy", Entropy())]:
            rows.append(dict(method=method, **evaluate(r, detector.run(r["attempts"]).events)))
        rows.append(dict(method="RF-tuned", **rf_result(r, rf, threshold)))
    write_csv(a.out / "metrics.csv", rows)
    summary = []
    for method in sorted({r["method"] for r in rows}):
        for metric in ("F1", "TPR", "FPR", "delay_s"):
            values = [np.nanmean([r[metric] for r in rows if r["method"] == method and r["seed"] == seed])
                      for seed in sorted(seeds["test"])]
            mean, low, high = cluster_ci(values)
            summary.append(dict(method=method, metric=metric, mean=mean, ci_low=low, ci_high=high))
    write_csv(a.out / "summary_ci.csv", summary)
    manifest = dict(evidence="recorded_Mininet_PCAPHeldOut", selection=selection, RF_threshold=threshold,
                    seed_splits={k: sorted(v) for k, v in seeds.items()}, python=sys.version,
                    inputs={split: hashlib.sha256((getattr(a, split) / "completed.json").read_bytes()).hexdigest()
                            for split in groups})
    (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
