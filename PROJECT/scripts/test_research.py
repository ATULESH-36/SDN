"""Focused tests for state pressure, expiry and research evaluation contracts."""
import math
import csv
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
from detectors import AISPRT
from live import Tracker
from pcapio import Attempt
from state import TTLMap


def attempt(t, src="s", dst="d", outcome="failure", port=80):
    return Attempt(t, src, dst, 6, port, 50000, outcome, t)


class StateTests(unittest.TestCase):
    def test_idle_ttl_and_lru_pressure_are_distinct(self):
        state = TTLMap(2, 10)
        state.put("a", 1, 0)
        state.put("b", 2, 1)
        self.assertEqual(state.get("a", 2), 1)
        state.put("c", 3, 3)
        self.assertIsNone(state.get("b", 3))
        self.assertEqual(state.evicted, 1)
        state.expire(12)
        self.assertEqual(state.expired, 1)
        self.assertEqual(len(state), 1)

    def test_all_detector_maps_remain_bounded(self):
        det = AISPRT(max_hosts=3, max_contacts=5, max_services=4, max_service_users=2, max_victims=2)
        for i in range(50):
            det.step(attempt(i, src=str(i % 7), dst=str(i), port=i))
        stats = det.state_stats()
        self.assertLessEqual(stats["hosts"], 3)
        self.assertLessEqual(stats["contacts"], 5)
        self.assertLessEqual(stats["services"], 4)
        self.assertLessEqual(len(det.L), 3)
        self.assertLessEqual(len(det.fails_to), 3)
        self.assertTrue(all(len(x) <= 2 for x in det.fails_to.values()))
        self.assertGreater(stats["evicted"], 0)
        det.age(5000)
        self.assertEqual(len(det.L), 0)
        self.assertEqual(len(det.contact_state), 0)

    def test_contact_expiry_enables_rescoring(self):
        det = AISPRT(contact_ttl=10, use_cusum=False)
        det.step(attempt(0))
        initial = det.L["s"]
        det.step(attempt(1))
        self.assertEqual(det.L["s"], initial)
        det.step(attempt(11))
        self.assertGreater(det.L["s"], initial)

    def test_tracker_overflow_is_counted_not_forced_failure(self):
        tracker = Tracker(max_pending=1)
        tracker._start(("a", "b", 6, 1, 80), 0)
        tracker._start(("c", "d", 6, 2, 80), 0)
        self.assertEqual(tracker.overflow, 1)
        self.assertEqual(len(tracker.pending), 1)
        self.assertEqual(len(tracker.expire(4)), 1)

    def test_slow_rate_recurrence(self):
        det = AISPRT(use_cusum=False)
        delta = 100
        for i in range(4):
            det.step(attempt(i * delta, port=i))
        q = math.exp(-delta / det.tau)
        self.assertAlmostEqual(det.L["s"], det.s_fail * (1 - q ** 4) / (1 - q))


class EvaluationTests(unittest.TestCase):
    def test_summary_uses_all_seeds_with_equal_weight(self):
        from research_campaign import summarize_rows
        metric_names = ("F1", "TPR", "FPR", "precision", "recall_10s", "suspicion_FPR", "delay_s")
        rows = [dict(method="fixture", seed=seed, **dict.fromkeys(metric_names, value))
                for seed, value in [(1, 0), (1, 0), (2, 1)]]
        summary = summarize_rows(rows, [1, 2])
        self.assertEqual(summary[0]["mean"], 0.5)
        self.assertEqual(summary[0]["independent_test_seeds"], 2)

    def test_rf_window_excludes_outcome_until_available(self):
        from eval_cicids import bucket_features
        late = attempt(9.9)._replace(t_outcome=12.9)
        on_time = attempt(8, outcome="success")
        observed = bucket_features([late, on_time])
        self.assertEqual(observed[("s", 10)][3], 0)
        self.assertEqual(observed[("s", 20)][3], 1)

    def test_false_positive_suspicion_is_not_hidden_by_host_alarm_metric(self):
        from research_campaign import evaluate
        run = dict(seed=1, scenario="benign", attempts=[attempt(1)], attackers=set(), attack_at=5)
        row = evaluate(run, [(2, "s", "SUSPECT", "d")])
        self.assertEqual(row["FP"], 0)
        self.assertEqual(row["suspect_benign_hosts"], 1)

    def test_preattack_alarm_does_not_count_as_detection(self):
        from research_campaign import evaluate
        run = dict(seed=1, scenario="fast", attempts=[attempt(1)], attackers={"s"}, attack_at=5)
        row = evaluate(run, [(2, "s", "PORT_SCAN", "host")])
        self.assertEqual(row["TP"], 0)
        self.assertEqual(row["pre_attack_alarm_hosts"], 1)

    def test_zero_observations_do_not_imply_zero_uncertainty(self):
        from research_campaign import exact_ci
        low, high = exact_ci(0, 20)
        self.assertEqual(low, 0)
        self.assertGreater(high, 0.16)

    def test_jittered_host_onset_controls_label_and_delay(self):
        from research_campaign import evaluate
        run = dict(seed=1, scenario="distributed", attempts=[attempt(1)], attackers={"s"}, attack_at=5,
                   attack_onsets={"s": 7})
        row = evaluate(run, [(6, "s", "PORT_SCAN", "host"), (8, "s", "PORT_SCAN", "host")])
        self.assertEqual(row["pre_attack_alarm_hosts"], 1)
        self.assertEqual(row["TP"], 1)
        self.assertEqual(row["delay_s"], 1)


class TrafficTests(unittest.TestCase):
    def test_churn_budget_excludes_benign_warmup(self):
        import research_traffic
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            log = Path(directory) / "sent.csv"
            config.write_text(json.dumps(dict(start=0, duration=10, seed=1, role="source_churn",
                attack_at=1, max_probes=2, rate=1000, attack_rate=1000, failure_probability=0,
                targets=["10.0.0.11"], log=str(log))))
            ticks = itertools.count()
            with patch.object(sys, "argv", ["research_traffic.py", "tcp", "--config", str(config)]), \
                    patch.object(research_traffic.time, "time", side_effect=lambda: next(ticks) / 100), \
                    patch.object(research_traffic.time, "sleep"), \
                    patch.object(research_traffic.socket, "socket") as sock:
                sock.return_value.__enter__.return_value.connect_ex.return_value = 1
                research_traffic.main()
            with open(log) as stream:
                rows = list(csv.DictReader(stream))
            self.assertGreater(sum(float(r["time"]) < 1 for r in rows), 2)
            self.assertEqual(sum(float(r["time"]) >= 1 for r in rows), 2)


if __name__ == "__main__":
    unittest.main()
