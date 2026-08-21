# TemporalCTI

**Temporal analysis and prediction of APT behavioral evolution using MITRE ATT&CK.**

TemporalCTI is a Python-based Cyber Threat Intelligence framework that analyzes how Advanced Persistent Threat (APT) groups evolve their TTPs over time. It combines temporal profiling, emerging TTP detection, behavioral evolution analysis, cross-actor convergence, prediction, defense-gap analysis, and MITRE ATT&CK mitigation mapping.

Built as part of a summer research internship at the **Centre for Computer Networks and Cyber Security (CCNCS), PES University**.

---

## 🚀 Live Dashboard

[**Launch TemporalCTI Dashboard**](https://temporalcti-eq7o4xmbfyv6meqrgwlaab.streamlit.app/)

> The Streamlit application may take a few seconds to wake up after inactivity.

---

## 🔍 Features

- Temporal profiling of APT groups
- APT Evolution Score
- Emerging TTP detection
- Cross-actor convergence analysis
- TTP retirement detection
- Markov-based future TTP prediction
- TTP velocity tracking
- Nation-state behavioral analysis
- APT Adaptability Index
- Technique lifespan analysis
- Defense gap analysis
- MITRE ATT&CK mitigation mapping

---

## 📊 Dataset

The framework uses MITRE ATT&CK STIX data.

- **170** APT groups
- **465** techniques
- **4,390** observations
- **2017–2026** temporal coverage

---

## 📈 Key Results

| Metric | Result |
|---|---:|
| APT Groups | 170 |
| Techniques | 465 |
| Emerging TTPs | 22 |
| Convergence Alerts | 1,061 |
| Active Techniques | 373 |
| Retired Techniques | 92 |
| Unmapped Techniques | 80 (17.2%) |
| Prediction Precision@1 | **0.231** |
| Markov Baseline P@1 | 0.128 |
| Improvement | **+10.3 pp** |

**Notable findings:**

- **Kimsuky** achieved the highest Evolution Score: **0.689**
- **APT28** achieved the highest Adaptability Index: **0.731**
- **Impersonation** showed the fastest growth: **7.0×**
- TemporalCTI achieved **P@1 = 0.231** using a Markov + Velocity model

---

## 🛠️ Tech Stack

- Python
- Pandas
- NumPy
- SQLite
- Streamlit
- MITRE ATT&CK STIX
- Markov Chains

---

## 📁 Project Structure

```text
TemporalCTI/
├── data/
│   ├── temporal_db/
│   └── processed/
├── src/
│   ├── extraction/
│   ├── analysis/
│   ├── evaluation/
│   └── dashboard/
├── requirements.txt
└── README.md

⚙️ Installation
git clone https://github.com/CodeWithSharon/TemporalCTI.git
cd TemporalCTI
pip install -r requirements.txt

Run the dashboard:

streamlit run src/dashboard/app.py
👥 Contributors

Sharon A
Vedanti Sinha

Supervisor:
Dr. Vinodha K
Centre for Computer Networks and Cyber Security (CCNCS), PES University

📜 Research

TemporalCTI was developed as part of a research internship focused on temporal Cyber Threat Intelligence and APT behavioral evolution using the MITRE ATT&CK framework.
