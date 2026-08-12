# TemporalCTI

**Temporal analysis of APT (Advanced Persistent Threat) behavioral evolution using MITRE ATT&CK data.**

TemporalCTI is a 12-module Python framework that analyses how APT groups' tradecraft (TTPs — Tactics, Techniques, and Procedures) evolves over time. It ingests MITRE ATT&CK STIX data, scores group- and technique-level behavior along multiple dimensions, predicts likely future technique adoption, and surfaces actionable defence gaps — all served through an interactive dashboard.

Built as part of a summer research internship at the Centre for Computer Networks and Cyber Security (CCNCS), PES University.

---

## Live Dashboard

**[Launch the dashboard](https://temporalcti-eq7o4xmbfyv6meqrgwlaab.streamlit.app/)** — deployed via Streamlit Community Cloud.

> Note: free-tier Streamlit apps sleep after inactivity. If it shows a "waking up" screen, give it ~30–60 seconds.

---

## What it does

| Module | Question it answers |
|---|---|
| **Temporal Profiling** | What's the year-by-year technique timeline for each APT group? |
| **Evolution Score** | How much has a group's tradecraft changed over time, adjusted for data maturity? |
| **Emerging TTP Detection** | Which techniques are rapidly gaining adopters right now? |
| **Cross-Actor Convergence** | Which techniques are multiple unrelated groups adopting simultaneously? |
| **TTP Retirement Detection** | Which group→technique pairs have gone dormant? |
| **Markov Chain Prediction** | What technique is a group likely to adopt next, based on its own history, global patterns, and recent adoption velocity? |
| **Nation-State Behavioural Analysis** | How do attributed nation-state actors differ in adaptability and shared tradecraft? |
| **Adaptability Index** | Which groups show the most sustained, well-rounded evolution over time? |
| **Technique Lifespan** | How long has each technique persisted, and is it still active or globally retired? |
| **TTP Velocity Tracking** | How fast is a technique's adoption growing or shrinking, year over year? |
| **Defence Gap Analysis** | Which techniques are both high-threat and poorly covered by existing MITRE mitigations? |
| **Mitigation Engine** | What real, MITRE-sourced mitigations apply to the highest-priority emerging/predicted techniques? |

Every module operates on a shared SQLite database (`data/temporal_db/apt.db`) built from MITRE ATT&CK STIX data, and writes its results to `data/processed/*.csv`.

---

## Dataset

- **170** APT groups
- **465** unique MITRE ATT&CK techniques (after filtering out generic STIX object-types: `Tool`, `Malware`, `Vulnerability`, `Exploits`, `Audio-Visual Content`, `Written Content`)
- **4,390** deduplicated group–technique–year observations
- **2017–2026** coverage window
- Source: MITRE ATT&CK STIX corpus

---

## Key results

- **Kimsuky** — most adaptive group by Evolution Score (0.689)
- **APT28** — most adaptive group by Adaptability Index (0.731), highest combined span/volume/consistency
- **Impersonation** — fastest-growing technique (7.0x growth), highest velocity (2.333/yr), top Defence Gap priority
- **1,061** cross-actor convergence alerts detected; max 50 groups converging on a single technique
- **373 Active / 92 Retired** techniques (technique-level, global; distinct from the 3,721 per-group retirement *events*)
- **Markov + Velocity Prediction**: Precision@1 = 0.231 — correctly predicted 9 of 39 held-out groups' next technique at rank 1, a **+10.3 percentage point** improvement over the strongest baseline (the original, un-augmented Markov model, P@1 = 0.128) — held-out validated (train <2024, test ≥2024). The final model was built via single-signal additive ablation on top of a frozen Markov baseline: velocity (technique adoption growth, computed train-only) improved P@1 at weight γ=0.15 and was kept; recency (how recently a technique was last observed) was tested the same way across the same weight range and did not improve P@1 at any setting, so it was discarded. The reported model is "Markov + Velocity Backoff," not a larger multi-signal system. Note: the Frequency baseline still ties at P@3 (0.333) and outperforms at P@5 (0.436 vs 0.410, −2.6pp); TemporalCTI's advantage is specifically at P@1, and this is reported transparently rather than as an overall win.
- **80/465 (17.2%)** techniques have no MITRE-published mitigation mapped at all

Full breakdown: [`data/processed/evaluation_summary.csv`](data/processed/evaluation_summary.csv)

---

## Project structure

```
temporal_cti_framework/
├── data/
│   ├── temporal_db/
│   │   └── apt.db                  # Main SQLite database (apt_timeline table)
│   └── processed/                  # All module outputs (CSV)
├── src/
│   ├── extraction/                 # MITRE STIX → SQLite ingestion
│   │   ├── mitre_extractor.py
│   │   ├── mitre_mitigations_extractor.py
│   │   ├── download_reports.py
│   │   └── pdf_parser.py
│   ├── analysis/                   # The 12 core modules
│   │   ├── temporal_profile.py
│   │   ├── evolution_score.py
│   │   ├── emerging_ttp.py
│   │   ├── convergence.py
│   │   ├── retirement_detector.py
│   │   ├── adaptability_index.py
│   │   ├── technique_lifespan.py
│   │   ├── ttp_velocity.py
│   │   ├── nation_state_clustering.py
│   │   ├── markov_prediction.py
│   │   ├── mitigation.py
│   │   └── defence_gap.py
│   ├── evaluation/
│   │   ├── evaluator.py            # Aggregates all module outputs into evaluation_summary.csv
│   │   └── baseline_comparison.py  # Random / Frequency / original Markov baselines vs. the final (Markov + Velocity) model
│   └── dashboard/
│       ├── app.py                  # Streamlit dashboard (the live deployment above)
│       └── generate_data.py
└── requirements.txt
```

---

## Running it locally

```bash
git clone https://github.com/CodeWithSharon/TemporalCTI.git
cd TemporalCTI
pip install -r requirements.txt
```

**Run the full analysis pipeline** (from the project root — every module reads/writes relative paths from here). Order matters: `mitre_mitigations_extractor.py` must run before `mitigation.py` and `defence_gap.py`, both of which read its output; `baseline_comparison.py` must run before `evaluator.py`, which reads its output for the Held-Out Validation comparison.

```bash
python3 src/extraction/mitre_mitigations_extractor.py
python3 src/analysis/temporal_profile.py
python3 src/analysis/evolution_score.py
python3 src/analysis/emerging_ttp.py
python3 src/analysis/convergence.py
python3 src/analysis/retirement_detector.py
python3 src/analysis/markov_prediction.py
python3 src/analysis/mitigation.py
python3 src/analysis/defence_gap.py
python3 src/analysis/nation_state_clustering.py
python3 src/analysis/adaptability_index.py
python3 src/analysis/technique_lifespan.py
python3 src/analysis/ttp_velocity.py
python3 src/evaluation/baseline_comparison.py
python3 src/evaluation/evaluator.py
```

> **Note:** `src/extraction/mitre_extractor.py` is not part of this list and should not be re-run against the shipped `apt.db` — it inserts rows without clearing the table first, so re-running it against an already-populated database will duplicate every row rather than refresh it. It's included for provenance (showing how `apt.db` was originally built from the raw MITRE STIX corpus), not for repeated use.
>
> `src/extraction/mitre_mitigations_extractor.py` does not have this issue — it only reads from `apt.db` and overwrites its own output CSV (`technique_mitigations.csv`) completely on each run, so it's safe to re-run at any time. Unlike `mitre_extractor.py`, it **is** a required step in the pipeline above, since `mitigation.py` and `defence_gap.py` both depend on its output.

**Launch the dashboard:**

```bash
streamlit run src/dashboard/app.py
```

---

## Methodology notes

- **Determinism:** every module that produces score ties uses an explicit secondary sort key (technique/group name, ascending) so results are reproducible across environments and reruns, not dependent on pandas/Python iteration order.
- **Normalization:** composite scores use `min(x/N, 1.0)`-style caps anchored to real observed maxima in the dataset (e.g. 9-year span, 465 techniques), not arbitrary constants.
- **Weight selection:** composite score weights (Adaptability Index, Evolution Score, Defence Gap Analysis) are heuristically assigned based on domain-reasoned signal priority, not fitted to a labeled ground-truth dataset — consistent with established practice in security scoring systems such as CVSS. A ±20% weight-perturbation sensitivity analysis on Adaptability Index (n=94 groups) and Defence Gap Analysis (n=465 techniques) confirmed resulting rankings are robust to reasonable variation in these weights (Spearman correlation ≥0.97, top-10 overlap ≥9/10 across all perturbations tested).
- **Held-out validation:** predictions are evaluated by training on data before 2024 and testing on 2024+ — the same protocol is applied identically across all baselines (Random, Frequency, the original Markov model, and the final model) for a fair comparison. Improvements are reported in percentage points rather than relative percentages, since relative framing over a small baseline value can overstate practical significance.
- **Additive signal ablation:** the final prediction model was built by freezing the original Markov model as a baseline (P@1 = 0.128, P@3 = 0.308, P@5 = 0.410) and testing candidate signals one at a time as small additive terms on top of it — never combined speculatively. Each candidate signal was computed strictly from training-period data to avoid leakage into the held-out test set. Velocity (adoption growth across the training window) improved P@1 to 0.231 at weight γ=0.15 and plateaued beyond that value; it was kept. Recency (how recently a technique was last observed) was swept across the same weight range and produced no improvement in P@1 at any setting; it was discarded. Because only one signal survived independent testing, no combination step was needed — the final model is "Markov + Velocity Backoff," a single additive term on a frozen base, not a larger multi-signal system.
- **Mitigations are MITRE-native:** all mitigation mappings are extracted directly from MITRE's own `course-of-action` STIX objects and `mitigates` relationships, not a third-party framework.

---

## Contributors

- **Sharon**
- **Vedanti Sinha**
Supervised by **Dr. Vinodha K**, Centre for Computer Networks and Cyber Security (CCNCS), PES University EC Campus.
