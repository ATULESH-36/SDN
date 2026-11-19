"""Verify and render the completed, prespecified three-arm service campaign."""
import json
from pathlib import Path

from research_campaign import cluster_ci


def render(root):
    results = root / "results" / "live_service_v1"
    design = json.loads((results / "design.json").read_text())
    rows = json.loads((results / "completed.json").read_text())
    arms = ("monitor", "fixed", "graded")
    seeds = range(4101, 4121)
    expected = {(seed, arm) for seed in seeds for arm in arms}
    data = {(r["seed"], r["policy"]): r for r in rows}
    if set(data) != expected or len(rows) != len(expected):
        raise ValueError(f"Expected 60 distinct trials, found {len(data)}")
    if any(design[key] != value for key, value in {
        "ttl_s": 5, "receipt_deadline_s": 2, "horizon_s": 4, "requests_per_stream": 16,
    }.items()):
        raise ValueError("Campaign settings differ from the paper protocol")
    lines = []
    for arm in arms:
        selected = [data[seed, arm] for seed in seeds]
        alerts = sum(any(len(req) == 4 and req[0] == "10.1.0.2" and req[3] == "10.0.0.11"
                         for req in r["detector_requests"]) for r in selected)
        installed = 0
        for r in selected:
            accepted = r["accepted"]
            if not accepted:
                continue
            dst = "10.0.0.11" if arm == "graded" else ""
            if (arm == "monitor" or len(accepted) != 1
                    or accepted[0]["ip"] != "10.1.0.2" or accepted[0]["dst"] != dst
                    or float(accepted[0]["seconds"]) != 5):
                raise ValueError(f"Unmatched enforcement in seed {r['seed']}, arm {arm}")
            installed += r["ack_switches"] == r["switches"]
        counts = [sum(r[key] for r in selected) for key in
                  ("target_received", "unrelated_success", "control_success", "contained_by_2s")]
        lines.append(r"%s & %d & %d & %d/320 & %d/320 & %d/320 & %d/20 \\" %
                     (arm.capitalize(), alerts, installed, *counts))

    diffs = []
    for first, second in (("graded", "fixed"), ("graded", "monitor"), ("fixed", "monitor")):
        for key, metric, denominator in (
            ("unrelated_success", "Unrelated HTTP success", 16),
            ("target_received", "Target HTTP receipt", 16),
        ):
            vals = [(data[s, first][key] - data[s, second][key]) * 100 / denominator for s in seeds]
            diffs.append(r"%s--%s & %s & %.1f [%.1f, %.1f] \\" %
                         (first.capitalize(), second, metric, *cluster_ci(vals)))
    output = root / "report_ieee" / "generated" / "live_service.tex"
    output.write_text("\\newcommand{\\ServiceRows}{%\n" + "\n".join(lines)
                      + "\n}\n\\newcommand{\\ServiceDiffs}{%\n" + "\n".join(diffs) + "\n}\n")


if __name__ == "__main__":
    render(Path(__file__).resolve().parents[1])
