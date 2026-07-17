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
| **Markov Chain Prediction** | What technique is a group likely to adopt next, based on its own history + global patterns? |
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
- **Markov Chain Prediction**: Precision@1 = 0.128 — correctly predicted 5 of 39 held-out groups' next technique at rank 1, versus 2 of 39 for the strongest baseline (Frequency/popularity), a **+7.7 percentage point** improvement — held-out validated (train <2024, test ≥2024). Note: the Frequency baseline outperforms at P@3/P@5 (0.333/0.436 vs 0.308/0.410, a −2.6pp difference at each); TemporalCTI's advantage is specifically at P@1, and this is reported transparently rather than as an overall win.
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
│   │   └── baseline_comparison.py  # Random / Frequency baselines vs. Markov prediction
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

**Run the full analysis pipeline** (from the project root — every module reads/writes relative paths from here):

```bash
python3 src/analysis/temporal_profile.py
python3 src/analysis/evolution_score.py
python3 src/analysis/emerging_ttp.py
python3 src/analysis/convergence.py
python3 src/analysis/retirement_detector.py
python3 src/analysis/adaptability_index.py
python3 src/analysis/technique_lifespan.py
python3 src/analysis/ttp_velocity.py
python3 src/analysis/nation_state_clustering.py
python3 src/analysis/markov_prediction.py
python3 src/analysis/mitigation.py
python3 src/analysis/defence_gap.py
python3 src/evaluation/evaluator.py
python3 src/evaluation/baseline_comparison.py
```

> **Note:** `src/extraction/mitre_extractor.py` is not part of this list and should not be re-run against the shipped `apt.db` — it inserts rows without clearing the table first, so re-running it against an already-populated database will duplicate every row rather than refresh it. It's included for provenance (showing how `apt.db` was originally built from the raw MITRE STIX corpus), not for repeated use.
>
> `src/extraction/mitre_mitigations_extractor.py` does not have this issue — it only reads from `apt.db` and overwrites its own output CSV (`technique_mitigations.csv`) completely on each run, so it's safe to re-run at any time.

**Launch the dashboard:**

```bash
streamlit run src/dashboard/app.py
```

---

## Methodology notes

- **Determinism:** every module that produces score ties uses an explicit secondary sort key (technique/group name, ascending) so results are reproducible across environments and reruns, not dependent on pandas/Python iteration order.
- **Normalization:** composite scores use `min(x/N, 1.0)`-style caps anchored to real observed maxima in the dataset (e.g. 9-year span, 465 techniques), not arbitrary constants.
- **Weight selection:** composite score weights (Adaptability Index, Evolution Score, Defence Gap Analysis) are heuristically assigned based on domain-reasoned signal priority, not fitted to a labeled ground-truth dataset — consistent with established practice in security scoring systems such as CVSS. A ±20% weight-perturbation sensitivity analysis on Adaptability Index (n=94 groups) and Defence Gap Analysis (n=465 techniques) confirmed resulting rankings are robust to reasonable variation in these weights (Spearman correlation ≥0.97, top-10 overlap ≥9/10 across all perturbations tested).
- **Held-out validation:** Markov prediction is evaluated by training on data before 2024 and testing on 2024+ — the same protocol is applied identically to both baselines for a fair comparison. Improvements are reported in percentage points rather than relative percentages, since relative framing over a small baseline value can overstate practical significance.
- **Mitigations are MITRE-native:** all mitigation mappings are extracted directly from MITRE's own `course-of-action` STIX objects and `mitigates` relationships, not a third-party framework.

---

## Contributors

- **Sharon** — Introduction, Related Work, Methodology
- **Vedanti Sinha** — Results, Evaluation, Conclusion, React dashboard deployment

Supervised by **Dr. Vinodha K**, Centre for Computer Networks and Cyber Security (CCNCS), PES University EC Campus.
