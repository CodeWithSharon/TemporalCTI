TemporalCTI
Temporal analysis and prediction of APT behavioral evolution using MITRE ATT&CK.

TemporalCTI is a Python-based Cyber Threat Intelligence (CTI) framework that analyzes how Advanced Persistent Threat (APT) groups use and change their Tactics, Techniques, and Procedures (TTPs) over time. It combines temporal profiling, behavioral evolution analysis, emerging and retired TTP detection, cross-actor convergence, future TTP prediction, nation-state behavioral analysis, and defense-gap analysis using MITRE ATT&CK data.

Developed as part of a summer research internship at the Centre for Computer Networks and Cyber Security (CCNCS), PES University.
🚀 Live Dashboard
Launch the TemporalCTI Dashboard

The Streamlit app may take a few seconds to wake up after a period of inactivity.
🔍 Features
- Temporal profiling: Explore APT group–technique activity across years.
- APT Evolution Score: Summarize temporal changes in observed group behavior.
- Emerging TTP detection: Identify techniques with increasing observed adoption.
- Cross-actor convergence: Examine techniques shared across multiple APT groups.
- TTP retirement and inactivity analysis: Identify group–technique activity that is no longer observed in a selected period.
- Technique lifespan analysis: Examine how long techniques remain observed in the dataset.
- TTP velocity tracking: Measure changes in the number of APT groups observed using a technique over time.
- APT Adaptability Index: Summarize changes in an APT group's technique usage.
- Nation-state behavioral analysis: Explore technique-sharing patterns using available attribution information.
- Future TTP prediction: Rank candidate techniques using a first-order Markov approach augmented with temporal signals such as velocity and recency, where enabled in the current model.
- Defense-gap analysis: Identify techniques with missing or limited MITRE ATT&CK mitigation mappings.
- Mitigation mapping: Connect techniques to relevant defensive mitigations available in MITRE ATT&CK.
📊 Dataset
TemporalCTI uses data derived from MITRE ATT&CK STIX.
Dataset measure	Reported value
APT groups	170
Techniques	465
Group–technique–year observations	4,390
Temporal coverage	2017–2026


Each observation represents an APT group–technique relationship associated with a year in the prepared dataset. The interpretation of the year depends on the project's data-preparation logic.
📈 Reported Results
The following values are reported in the current project summary. Prediction metrics from different evaluation procedures are listed separately because they are not directly interchangeable.
Temporal and behavioral analysis
Metric	Reported result
Emerging TTPs	22
Cross-actor convergence alerts	1,061
Active techniques	373
Retired techniques	92
Techniques without mapped mitigations	80 of 465 (17.2%)
Highest Evolution Score	Kimsuky — 0.689
Highest Adaptability Index	APT28 — 0.731
Reported fastest-growing technique	Impersonation — 7.0× growth


Prediction evaluation
Rolling chronological Hit@K evaluation (2022–2025):
Model	Hit@1	Hit@3	Hit@5
Random	0.011	0.045	0.068
Frequency	0.091	0.239	0.318
Recency	0.136	0.307	0.341
First-order Markov	0.068	0.193	0.295
TemporalCTI	0.148	0.273	0.352


This evaluation reports 88 eligible group–year cases. TemporalCTI has the highest reported Hit@1 and Hit@5, while the Recency baseline has the highest Hit@3.

Separate held-out Precision@K evaluation reported in the project summary:
Model	Precision@1
Markov baseline	0.128
TemporalCTI hybrid Markov model	0.231


The project summary reports a 10.3 percentage-point Precision@1 difference between these two results. This is a separate evaluation from the rolling-year Hit@K results above; the metrics and evaluation setups should not be treated as the same experiment.
🛠️ Tech Stack
- Python
- Pandas and NumPy
- SQLite
- Streamlit
- Plotly
- MITRE ATT&CK STIX data
- First-order Markov modelling
Additional packages may be required by individual analysis or visualization modules; see requirements.txt.
📁 Project Structure
TemporalCTI/
├── data/
│   ├── temporal_db/
│   └── processed/
├── src/
│   ├── extraction/
│   ├── analysis/
│   ├── evaluation/
│   └── dashboard/
│       └── app.py
├── requirements.txt
└── README.md
The structure above shows the main project directories; local data files and additional modules may vary by checkout.
👥 Contributors
- Sharon A
- Vedanti Sinha
Supervisor: Dr. Vinodha K
Centre for Computer Networks and Cyber Security (CCNCS), PES University
📜 Research Context
TemporalCTI was developed as part of a research internship focused on temporal Cyber Threat Intelligence and APT behavioral evolution using the MITRE ATT&CK framework. The framework is intended to support exploration of historical adversarial behavior, ranking of potential future techniques, and investigation of defensive coverage.

Note: Results describe patterns in the available MITRE ATT&CK STIX-derived dataset. They do not by themselves establish that a particular organization lacks a security control or that a predicted technique will necessarily be adopted.
