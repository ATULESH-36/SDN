#!/usr/bin/env python3
"""Generate paper tables from recorded CSVs; no hand-entered performance numbers."""
import argparse
import csv
import json
from pathlib import Path


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--simulation", type=Path, required=True)
    p.add_argument("--mitigation", type=Path)
    p.add_argument("--scale-smoke", type=Path)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    rows = read(a.simulation / "summary_ci.csv")
    meta = json.loads((a.simulation / "manifest.json").read_text())
    lines = ["% Generated from research CSVs; not manually entered.",
             "\\newcommand{\\ResearchTrainWindows}{%d}" % meta["selection"]["train_windows"],
             "\\newcommand{\\ResearchRFFone}{%.3f}" % float(next(
                 r["mean"] for r in rows if r["method"] == "RF-tuned" and r["metric"] == "F1")),
             "\\newcommand{\\ResearchAISFone}{%.3f}" % float(next(
                 r["mean"] for r in rows if r["method"] == "AIS-tuned" and r["metric"] == "F1")),
             "\\newcommand{\\ResearchRows}{"]
    for method in sorted({r["method"] for r in rows}):
        values = []
        for metric in ("F1", "TPR", "FPR"):
            r = next(r for r in rows if r["method"] == method and r["metric"] == metric)
            values.append("%.3f [%.3f, %.3f]" % tuple(float(r[k]) for k in ("mean", "ci_low", "ci_high")))
        lines.append(method + " & " + " & ".join(values) + " \\\\")
    lines.append("}")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "research_summary.tex").write_text("\n".join(lines) + "\n")
    if a.mitigation:
        rows = read(a.mitigation / "summary_ci.csv")
        lines = ["% Generated from complete measured mitigation campaign.", "\\newcommand{\\MitigationRows}{"]
        for policy in ("fixed", "graded"):
            for guard in (0, 1):
                values = []
                for metric in ("leaked_installation_packets", "collateral_fraction", "decision_to_initial_ack_s"):
                    r = next(r for r in rows if r["policy"] == policy and int(r["guard"]) == guard and r["metric"] == metric)
                    values.append("%.3f [%.3f, %.3f]" % tuple(float(r[k]) for k in ("mean", "ci_low", "ci_high")))
                lines.append("%s/%s & %s \\\\" % (policy, "on" if guard else "off", " & ".join(values)))
        lines.append("}")
        (a.out / "mitigation_summary.tex").write_text("\n".join(lines) + "\n")
    if a.scale_smoke:
        smoke = json.loads(a.scale_smoke.read_text())
        if smoke["observed_attack_sources"] != 200 or smoke["kernel_capture_drops"] != 0:
            p.error("scale smoke evidence does not establish 200 observed sources with zero kernel drops")
        lines = ["% Generated from successful real-source smoke-trial metadata.",
                 "\\newcommand{\\ScaleSources}{%d}" % smoke["observed_attack_sources"],
                 "\\newcommand{\\ScalePackets}{%d}" % smoke["captured_packets"],
                 "\\newcommand{\\ScaleAttempts}{%d}" % smoke["captured_attempts"]]
        (a.out / "scale_smoke.tex").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
