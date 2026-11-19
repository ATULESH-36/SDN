# Research revision protocol

## Systems paper update

The [unified IEEE-style paper](IEEE_PAPER.pdf) leads with measured enforcement.
Its [LaTeX source](PROJECT/report_ieee/systems.tex) includes the secondary plots,
the slow-rate boundary check, and historical negative results in appendices in
the same PDF. The separate systems draft and supplement PDFs are earlier versions.
The unified paper also includes related work, seed-level interval methods,
detector selection details, and a reproducibility section. The expanded text
interprets the recorded trials. The live HTTP revision adds an application-level
comparison described below.
`scripts/extended_stats.py` regenerates `generated/extended_stats.tex` (paired
Wilcoxon tests with Holm correction, d_z effect sizes, per-seed sign counts,
per-arm medians/IQRs, live per-pair losses, Wilson intervals, and paired
detector contrasts) from the recorded trial CSVs and JSON only.

- `research_simulation_v3` supersedes v2 **for detector comparison**. ML windows
  now group by when outcomes become available, not when connections start; onset-
  straddling windows are excluded from RF fitting only. Predictions never consult
  labels. The historical CIC CSVs and v2 outputs were not regenerated.
- `live_collateral_pilot` is a six-pair experiment on seeds 3101--3106, both
  policies with guard enabled and the same three-second base timeout. Actual
  detector requests were caused by benign stale health checks, not injected.
  The workload tests collateral, not large-scale live attack containment.
- The new tables report pooled host-run confusion counts alongside seed-macro
  precision, F1, 10-second recall, and confirmed and suspicion false-positive
  rates. Policy effects are paired by seed, not by packet.

Run from `PROJECT` in the dedicated lab, using fresh output directories for new
campaigns:

```
python3 scripts/research_campaign.py --out results/research_simulation_v3
python3 scripts/network_campaign.py live-collateral --seeds 6 --out results/live_collateral_pilot
python3 scripts/render_systems.py
python3 scripts/render_live_service.py
cd report_ieee
python3 ../scripts/extended_stats.py
pdflatex -halt-on-error systems.tex
bibtex systems
pdflatex -halt-on-error systems.tex
pdflatex -halt-on-error systems.tex
cp systems.pdf ../../IEEE_PAPER.pdf
```

### Matched first-action HTTP fixture

Run only in the dedicated Mininet lab with no existing OVS bridges. From
`PROJECT` in that lab:

```
python3 scripts/live_service_trial.py run --out results/live_service_v1
python3 scripts/render_live_service.py
```

The campaign has 20 matched topology seeds (4101--4120) and randomized arm
order. The graded and fixed arms use a five-second first-action timeout and
the packet-in guard. The monitor arm runs the same detector without feeding
its requests to enforcement. The primary outcomes are unrelated HTTP response
success and selected-stream server receipt, with a two-second containment
criterion. Requests are harmless and scoped to the isolated lab. The renderer
requires all 60 arm runs and checks the accepted scope and configured TTL.
Rebuild the unified PDF after rendering. The paper requires the generated
campaign table; neither development run contributes to it.

The first development attempt did not elicit a detector request in any arm;
HTTP connectivity checks happened while detection was running. The revised
fixture performs those checks before starting the detector. Both development
runs are separate from seeds 4101--4120.

This fixture does not establish containment of a malicious workload, victim
availability under load, or what happens after expiration. Those require
independently held-out workloads and explicit service objectives.

## Evidence classes and publication status

The original paper and recorded results remain available. They are **not** evidence
for the new bounded-state algorithm on a large deployment. The revision separates:

1. `PROJECT/results/research_simulation_v2/`: attempt-level stochastic simulation.
   Logical source IPs and randomized topology-dependent propagation delays are
   **not** Mininet hosts, queueing simulation, packet-rate benchmarks, or Internet traffic.
2. `PROJECT/results/mitigation_20seed_v2/`: real Mininet/OVS/POX UDP A/B receipts,
   controller traces and per-worker send logs. A campaign is complete only when
   its manifest says `complete: true`.
3. `PROJECT/results/mitigation_analysis_v3/`: paired seed confidence intervals and
   six measured mitigation plots, generated only from a complete campaign.
4. Large-source packet captures: a separate `network_campaign.py scale` campaign.
   Do not present these as completed unless their manifests and captures exist.

**Execution status:** the 20-test-seed simulation and all 80 paired mitigation
trials completed. One independent 200-source DDoS smoke trial (seed 3001) also
completed: 159,033 captured packets, 26,485 resolved attempts, all 200 attack
source addresses observed after their individual onset times, and zero reported
kernel capture drops. It used 200 attacking namespaces plus twelve benign hosts
and two servers. Evidence is in `PROJECT/results/scale_200source_smoke_v4/`.
The full train/validation/20-seed large-source PCAP campaign remains **pending,
explicitly deferred by the user**. A single scale trial is not a confidence interval.

Early scale attempts were rejected rather than included: direct capture to the
Windows/OneDrive mount lost packets, and long Mininet PTY commands truncated
port/neighbour setup. The corrected runner spools PCAP to native Linux storage,
checks tcpdump drop statistics, batches OVS setup, chunks neighbour commands,
verifies every port and host's connectivity, synchronizes worker start, and
verifies all requested source addresses in the resulting capture.
Failed/superseded directories are not publication evidence.

### Main findings, not claims of universal superiority

- On the expanded **simulation**, trained RF macro attack-scenario F1 is
  0.932 [0.911,0.952], versus 0.543 [0.542,0.544] for low-FPR-tuned AIS.
  The original perfect small-testbed result does not generalize to these cases.
- In the measured 80-trial lab, guard-on reduced installation-window attacker
  receipts by 0.975 packets per trial on average (paired CI [-1.425,-0.575]),
  but did not make observed leakage universally zero.
- Graded policy reduced other-destination collateral after the injected
  false suspicion by about 50 percentage points. It also delayed full-host ACK
  by about 0.675 s [0.583,0.758], an intentional containment/response-strength trade-off.
- Actual persistent-attacker delivery fell by about 47.6 percentage points
  (graded minus fixed CI [-0.496,-0.452]) in this short repeated-decision workload.
- Ten focused regression tests pass. Original stored-capture classifications
  remain unchanged for the five deterministic baseline/proposed detector cases.

The expanded PDF is a research revision, not an acceptance-ready venue-length
submission. Check the target venue's page limit and independently verify prior
work, dataset provenance, calibration and external validity before submitting.

The request is to improve the evidence, not force the proposed method to win.
Success padding, reused popular targets, source churn and low-rate distributed
flooding intentionally expose limitations of source-local evidence.

## Reproducible runtime

A dedicated Ubuntu 24.04 WSL distribution, `sdn-research`, was installed with
permission. Docker Desktop's internal distribution was not modified. Packages:

```
apt-get install python3-numpy python3-scipy python3-sklearn python3-matplotlib \
  mininet openvswitch-switch tcpdump git iproute2 iputils-ping
service openvswitch-switch start
git clone https://github.com/noxrepo/pox.git /opt/sdn-pox
git -C /opt/sdn-pox checkout 5f82461e01f8822bd7336603b361bff4ffbd2380
```

Executed runtime: Python 3.12.3, NumPy 1.26.4, SciPy 1.11.4,
scikit-learn 1.4.1.post1, matplotlib 3.6.3, OVS 3.3.9;
POX commit `5f82461e01f8822bd7336603b361bff4ffbd2380`.
POX warns that Python 3.12 is outside its advertised 3.6--3.9 range.
Real smoke testing is therefore essential; the warning is not suppressed.
All network tests must run only in this dedicated lab, not against external hosts.

Commands below run from `PROJECT` inside that distribution. Always choose fresh
output directories; campaigns refuse to overwrite prior evidence.

```
python3 -m unittest discover -s scripts -p test_research.py -v
python3 scripts/research_campaign.py --out results/research_simulation_v2
python3 scripts/network_campaign.py mitigation --out results/mitigation_20seed_v2
python3 scripts/analyze_network.py --input results/mitigation_20seed_v2 \
  --out results/mitigation_analysis_v3
bash scripts/build_research.sh
```

Do not run two network campaigns concurrently: Mininet bridge names and the POX
port are shared **inside this dedicated distribution**. No global process-killing
or host-wide Mininet cleanup is used by the new runner.

## Seed isolation, parameter selection and uncertainty

| Purpose | Seeds | Allowed use |
|---|---|---|
| Training | 1--12 | Fit RF trees |
| Validation | 1001--1008 | Select RF settings/threshold and AIS settings |
| Held-out test | 2001--2020 | Final evaluation only |
| Bound Monte Carlo | RNG 808 | Separate IID null/alternative trial experiment |
| Bootstrap | RNG 917 | Resampling independent seed summaries |

RF: 200 trees, two CPU workers, balanced class weights; validation grid:
depth 8/unlimited, minimum leaf 1/5, probability threshold .25/.5/.75/.9.
AIS validation grid: alpha .01/.001/.0003, tau 300/600 s, CUSUM h 150/620.
Selection first prefers validation FPR <= 1%, then macro attack-scenario F1,
then lower FPR; if no candidate meets the constraint, the best remaining
candidate is still reported, not represented as satisfying the constraint.
No test label selects a parameter. Full candidate scores and exact randomized
run parameters are stored in the manifest.

F1 is macro-averaged over attack scenarios within each seed; pure benign
scenarios contribute to FPR, not F1. Delays condition on detection and are
medians within a scenario; missed cases remain visible in recall. Metrics also
record benign **suspicion** events and attacker pre-attack alarms separately.
These must not be hidden just because the host-block FPR is low.

95% percentile bootstrap intervals use 2,000 resamples of **seeds**, not hosts or
windows. A degenerate all-zero bootstrap CI is not evidence that the underlying
error probability is zero. `seed_alarm_ci.csv` also reports an exact binomial
interval for the event "any benign alarm in this independent seed"; 0/20 still
has an upper two-sided 95% limit of about 16.8%.

## Proposition 1: what can actually be claimed

The classical bound applies to one **unmodified, stopped** likelihood-ratio
test under the stated independent Bernoulli hypotheses. It is not a lifetime
guarantee for a detector that resets repeatedly, decays evidence, changes weights,
or adds CUSUM alarms. Alpha is a tuning parameter, not a certified deployment FPR.

Plots 11 and 12 use 20,000 trials per point and exact binomial intervals to compare:
one stopped classical test, repeated restarts over 400 observations, and a
finite-horizon toy weighted/decayed recurrence. The latter uses constant failure
weight .5 and 30 s gaps; it is **not** a proof or full simulation of learned
service popularity. At alpha .01, the recorded first campaign found classical
one-test FPR .00335, but restarting FPR .2084 over the finite horizon.

The slow-rate proposition also assumes all probes fail, previously unused services,
no success padding and no pressure eviction. Test around its predicted boundary,
not only at .2/.5 probes/s.

## Explicit aging and memory contract

Live AIS state:

| State | Capacity | Aging/pressure policy |
|---|---:|---|
| Source scores, rate state, victim counters | 4,096 sources | 3,600 s idle TTL; LRU source eviction removes all source-local maps |
| Scored `(source,destination,port)` contacts | 65,536 | 3,600 s **since scoring**; duplicates do not extend it; LRU pressure |
| Service popularity | 16,384 services | 3,600 s service-idle TTL; LRU pressure |
| Sources remembered per service | 64 | Saturated membership; the novelty weight already saturates at four peers |
| Victims counted per source | 256 | Oldest inserted victim removed on pressure |
| Pending packet resolutions | 65,536 | Three-second resolution timeout; overflow rejected and **counted** |
| Recently seen wire tuples | 131,072 | 120 s idle TTL/LRU; no whole-set reset |
| Emitted-request cooldown keys | 8,192 | At least 600 s idle TTL/LRU |

Approximate entry bound: `O(H*V + C + S*U + P + T + Q)`, not a fixed byte/RSS
guarantee. Python object sizes and allocator retention vary. Capacity pressure
can forget attack evidence or suppress repeat alarms; this is a measured
accuracy/resource trade-off, **not** fail-closed protection. Periodic live logs
report state sizes, expiry, pressure eviction and tracker overflow.
`state.csv` measures traced Python allocations and throughput under churn with
smaller published caps (H=256,C=2048,S=512). Tracemalloc slows execution;
the plotted rate is not uninstrumented pcap ingestion capacity.
Offline capture extraction and `run()` result/event materialization are **not**
claimed bounded-memory streaming APIs.

## Actual mitigation A/B design

Twenty paired seeds x two policies x guard on/off = 80 trials. Each seed fixes
topology, traffic rates and sender RNG; arm execution order is randomized.
The tree has 4--6 switches. Repeated trials use fresh topology/controller state.

Policies:

- Fixed: the same suspicion request immediately blocks the whole host; fixed TTL.
- Graded: suspicion blocks one destination, later decision blocks the host;
  repeated decisions request TTLs 1, 2, 4 s in this short experiment.
- Guard: either registers the existing high-priority PacketIn handler or omits it.
- False positive: an explicitly injected suspicion for a legitimate mixed-use
  source. Collateral counts its legitimate packets to the **other** server.

The test bypasses detection to isolate enforcement policy. It does not measure
AIS detection accuracy or detection latency. Raw send/receive records retain
payload IDs and timestamps. Metrics:

- Installation leakage: victim receipts between the first INSTALL_BEGIN and
  the last initial per-switch barrier ACK. Includes in-flight packets and cannot,
  by itself, attribute every packet to the PacketIn race.
- Decision-to-ACK delay: injected suspicion to all-switch barrier ACK.
- Host-block time: first host-block ACK across every switch, relative to traffic
  start (fixed policy intentionally acts on suspicion earlier).
- Collateral loss: sent but unreceived other-server packets of the falsely
  suspected source during relative seconds [1,3.25).
- Unaffected-host loss: same measurement for an unrelated legitimate source.
- Persistence: accepted requested TTL for repeated decisions, plus actual delivered
  attacker sequence IDs after the second repeated decision. This is not a claim
  that back-off eliminates an adaptive attack.

The one-second file polling interval, filesystem instrumentation, WSL scheduling,
short block durations and low lab traffic rates limit generalization. In-flight
traffic may arrive after an ACK. A guard must not be described as "zero leakage"
or "race-free end-to-end" just because it stops controller learning.
Paired effect intervals that contain zero are inconclusive, not positive results.
The actual 80-trial executable sources were hash-verified and preserved in
`mitigation_20seed_v2/executed_sources/` before scale-only setup refinements.
Use those snapshots in a fresh checkout to reproduce the exact measured revision.
The simulation and successful scale smoke trial also retain their executed
source snapshots. Subsequent host-specific onset-label support and resource-handle
cleanup do not rewrite old evidence or its source hashes.

Measured paired effects (95% seed-bootstrap intervals): guard-on minus guard-off
installation-window receipts = -0.975 packets [-1.425,-0.575]; graded minus fixed
other-destination collateral = -0.4995 [-0.5200,-0.4784]. This controlled injected-
false-suspicion workload favours the intended narrower policy by design; it is
not evidence of universally zero collateral or zero leakage.

## Large-source packet capture campaign

Use independent real namespaces, not aliases or relabelled single-source traffic:

```
python3 scripts/network_campaign.py scale --split train --seeds 12 --sources 200 \
  --out results/scale_train
python3 scripts/network_campaign.py scale --split validation --seeds 8 --sources 200 \
  --out results/scale_validation
python3 scripts/network_campaign.py scale --split test --seeds 20 --sources 200 \
  --out results/scale_test
python3 scripts/evaluate_captures.py --train results/scale_train \
  --validation results/scale_validation --test results/scale_test --out results/scale_eval
```

This is a much longer campaign. It records distributed scan, DDoS, burst/pause,
success-padding, popular-target and source-churn scenarios with twelve additional
benign hosts, randomized attachment and rates, attack timing, full per-host
parameters and PCAPs. Test seed overlap is rejected by the evaluator. Completing
only the simulator or one scale smoke trial does not satisfy this campaign.
Capture and sender integrity must be inspected before any publication claim.

## Fourteen core plots

1. Held-out macro attack-scenario F1 with seed CI.
2. Benign-host FPR with seed CI.
3. Per-scenario recall.
4. Per-scenario false-alarm fraction.
5. Conditional detection-delay ECDF, with recall beside it to expose censoring.
6. RF precision--recall curve; descriptive only, operating threshold already frozen.
7. Success-padding strength versus recall.
8. Distributed source count versus recall (1,10,100,200,400 logical sources).
9. Benign failure probability versus false alarms.
10. Evidence-decay sensitivity versus slow-scan recall.
11. Null false-alarm rate versus alpha, one-shot/restart/weighted-decayed comparison.
12. Alternative detection probability versus alpha for the same experiments.
13. Measured memory allocation under source/service churn.
14. Instrumented detector throughput under the same churn.

Six additional measured A/B plots cover leakage, collateral, installation
delay, host-block time, persistent-offender TTL and actual persistent-attacker
delivery. Plot quantity alone is not a
publication contribution; do not pad figures or omit negative results.

## Recommended next stress tests and potentially novel contributions

| Priority | Test / research question | Required outcome |
|---|---|---|
| P0 | Correlated benign failures, outages and flash crowds over 24--72 h | Host-hours, benign suspicion/block rates, recovery and CIs |
| P0 | 100/200/500 real sources, low individual rates but large aggregate load | Delivered attack load, victim availability, per-source and episode recall |
| P0 | Delayed switch ACK, controller overload/reconnect, queued PacketIns | Sequence-ID leakage before/during/after install, control overhead, no claim of zero leakage |
| P0 | Source/service churn above every state cap; repeated tuple reuse | Peak RSS, eviction/overflow counts, detection degradation and recovery |
| P1 | Threshold-aware success padding, pause lengths around tau and TTL, IP churn | Attacker utility versus detection probability; include unsuccessful defence cases |
| P1 | Mirror loss/reordering/duplication; asymmetric capture | Outcome-label disagreement, robustness and false-block impact |
| P1 | NAT/shared addresses and mixed benign/malicious applications | User-level collateral and protected-service reachability |
| P1 | Train on one day/site, validate on a second, freeze and test on a third | Domain-shift performance and calibrated operating points |
| Novelty A | **Success-conditioned, trust-weighted popularity** instead of counting every probing source | Resist attackers poisoning novelty by making unused ports appear popular; compare to the current simple discount |
| Novelty B | **Hierarchical destination/subnet evidence** with source attribution | Detect many individually subthreshold scanners/flooders without blocking a benign flash crowd |
| Novelty C | **Anytime-valid e-process / alpha-spending** with explicit reset policy | A provable false-alarm budget for the actual deployed algorithm, not borrowed Wald thresholds |
| Novelty D | **Budget-aware state admission/aging** with quantified evidence-loss bounds | Formal resource limits plus an empirical accuracy/memory frontier |
| Novelty E | **Cost-aware reversible enforcement** using victim utility and benign harm | Statistically supported reduction in collateral at equivalent attack containment |

These are research proposals, not established novel claims. Verify prior work and
patent/publication overlap before claiming novelty. The strongest direction is a
small defensible contribution plus rigorous measurements, not merely adding ML.
