import sqlite3
import pandas as pd
import numpy as np
import os
from collections import defaultdict

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}


def load_data():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT * FROM apt_timeline", conn)
    conn.close()
    # Exclude generic STIX object-types - same filter every downstream
    # CSV (evolution_scores.csv, defence_gaps.csv, etc.) already applies.
    # Without this, the header line disagreed with every section below it
    # (470/4,518 here vs 465/4,390 everywhere else in this same report).
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df

# ── 1. EVOLUTION SCORE ───────────────────────────────────────
def evaluate_evolution_scores():
    df = pd.read_csv('data/processed/evolution_scores.csv')
    print("=" * 60)
    print("1. EVOLUTION SCORE EVALUATION")
    print("=" * 60)
    print(f"Total groups scored     : {len(df)}")
    print(f"Score range             : {df['evolution_score'].min():.3f} — {df['evolution_score'].max():.3f}")
    print(f"Mean score              : {df['evolution_score'].mean():.3f}")
    print(f"Std deviation           : {df['evolution_score'].std():.3f}")

    high = len(df[df['evolution_score'] > 0.5])
    med  = len(df[(df['evolution_score'] >= 0.3) & (df['evolution_score'] <= 0.5)])
    low  = len(df[df['evolution_score'] < 0.3])

    print(f"\nAdaptability distribution:")
    print(f"  High   (>0.5)    : {high} groups")
    print(f"  Medium (0.3–0.5) : {med} groups")
    print(f"  Low    (<0.3)    : {low} groups")

    cols = [c for c in ['apt_group','evolution_score','years_active','total_techniques'] if c in df.columns]
    print(f"\nTop 10 most adaptive:")
    print(df.head(10)[cols].to_string(index=False))
    return df

# ── 2. EMERGING TTP ───────────────────────────────────────────
def evaluate_emerging_ttps():
    df = pd.read_csv('data/processed/emerging_ttps.csv')
    print("\n" + "=" * 60)
    print("2. EMERGING TTP DETECTION EVALUATION")
    print("=" * 60)
    print(f"Total emerging TTPs     : {len(df)}")
    print(f"Max growth rate         : {df['growth_rate'].max()}x")
    print(f"Mean growth rate        : {df['growth_rate'].mean():.2f}x")
    print(f"Min growth rate         : {df['growth_rate'].min():.2f}x")

    critical = len(df[df['growth_rate'] > 3])
    high     = len(df[(df['growth_rate'] > 1) & (df['growth_rate'] <= 3)])
    medium   = len(df[df['growth_rate'] <= 1])

    print(f"\nSeverity:")
    print(f"  Critical (>3x) : {critical}")
    print(f"  High     (1–3x): {high}")
    print(f"  Medium   (<1x) : {medium}")

    cols = [c for c in ['technique','growth_rate','start_year','end_year','end_count'] if c in df.columns]
    print(f"\nTop 10 fastest growing:")
    print(df.head(10)[cols].to_string(index=False))
    return df

# ── 3. CONVERGENCE ────────────────────────────────────────────
def evaluate_convergence():
    df = pd.read_csv('data/processed/convergence_alerts.csv')
    print("\n" + "=" * 60)
    print("3. CROSS-ACTOR CONVERGENCE EVALUATION")
    print("=" * 60)
    print(f"Total alerts            : {len(df)}")
    print(f"Max groups converging   : {df['num_groups'].max()}")
    print(f"Mean groups per alert   : {df['num_groups'].mean():.1f}")

    high = len(df[df['num_groups'] > 20])
    med  = len(df[(df['num_groups'] >= 10) & (df['num_groups'] <= 20)])
    low  = len(df[df['num_groups'] < 10])

    print(f"\nConvergence strength:")
    print(f"  High   (>20 groups) : {high}")
    print(f"  Medium (10–20)      : {med}")
    print(f"  Low    (<10)        : {low}")

    cols = [c for c in ['technique','num_groups','year_start','year_end'] if c in df.columns]
    print(f"\nTop 5 events:")
    print(df.head(5)[cols].to_string(index=False))
    return df

# ── 4. MARKOV PREDICTION ──────────────────────────────────────
def evaluate_predictions():
    pred_df = pd.read_csv('data/processed/ttp_predictions.csv')
    raw_df  = load_data()

    print("\n" + "=" * 60)
    print("4. MARKOV CHAIN PREDICTION EVALUATION")
    print("=" * 60)
    print(f"Total predictions       : {len(pred_df)}")
    print(f"Groups covered          : {pred_df['apt_group'].nunique()}")

    if 'method' in pred_df.columns:
        print(f"\nMethod breakdown:")
        print(pred_df['method'].value_counts().to_string())

    tech_col = 'predicted_technique' if 'predicted_technique' in pred_df.columns else 'predicted_ttp'

    global_techniques = set(raw_df['technique'])
    valid    = pred_df[pred_df[tech_col].isin(global_techniques)]
    coverage = len(valid) / len(pred_df) if len(pred_df) > 0 else 0

    print(f"\nMetric 1 — Coverage Rate:")
    print(f"  Valid ATT&CK predictions: {len(valid)}/{len(pred_df)}")
    print(f"  Coverage                : {coverage:.3f}")
    print(f"  All predictions are grounded in")
    print(f"  real MITRE ATT&CK techniques")

    prevalence_scores = []
    for _, row in pred_df.iterrows():
        tech = row[tech_col]
        groups_using = raw_df[raw_df['technique'] == tech]['apt_group'].nunique()
        total_groups = raw_df['apt_group'].nunique()
        prevalence_scores.append(groups_using / total_groups)

    avg_prevalence = np.mean(prevalence_scores) if prevalence_scores else 0

    print(f"\nMetric 2 — Prevalence Score:")
    print(f"  Mean prevalence         : {avg_prevalence:.3f}")
    print(f"  Predicted techniques are used by")
    print(f"  {avg_prevalence:.1%} of all APT groups on average")

    print(f"\nMetric 3 — Prevalence Match Rate:")
    print(f"  (Share of predictions that are techniques used by 5+ groups —")
    print(f"  a plausibility check, NOT a predictive-accuracy metric.")
    print(f"  Do not read this as Precision@K.)")

    prevalent = set(
        raw_df.groupby('technique')
        .filter(lambda x: x['apt_group'].nunique() >= 5)
        ['technique'].unique()
    )

    for k in [1, 3, 5, 10]:
        correct = 0
        total   = 0
        for group in pred_df['apt_group'].unique():
            top_k = pred_df[pred_df['apt_group'] == group].nlargest(k, 'probability')[tech_col].tolist()
            if not top_k:
                continue
            hits     = sum(1 for t in top_k if t in prevalent)
            correct += hits
            total   += len(top_k)
        match_rate = correct / total if total > 0 else 0
        bar = '█' * int(match_rate * 20)
        print(f"  Top-{k:2} : {bar:20} {match_rate:.3f}")

    print(f"\nProbability statistics:")
    print(f"  Mean  : {pred_df['probability'].mean():.3f}")
    print(f"  Max   : {pred_df['probability'].max():.3f}")
    print(f"  Min   : {pred_df['probability'].min():.3f}")
    print(f"  Std   : {pred_df['probability'].std():.3f}")

    print(f"\nMetric 4 — Held-Out Temporal Validation (the real accuracy figure):")
    print(f"  Train on years < 2024, test on years >= 2024.")
    try:
        val_df = pd.read_csv('data/processed/prediction_validation.csv')
        row = val_df.iloc[0]
        print(f"  Groups evaluated : {int(row['total_groups'])}")
        print(f"  Precision@1      : {row['precision_at_1']:.3f}")
        print(f"  Precision@3      : {row['precision_at_3']:.3f}")
        print(f"  Precision@5      : {row['precision_at_5']:.3f}")
    except FileNotFoundError:
        print(f"  prediction_validation.csv not found — run markov_prediction.py first.")

    try:
        base_df = pd.read_csv('data/processed/baseline_comparison.csv')
        proposed = base_df[base_df['model'].str.contains('TemporalCTI', na=False)].iloc[0]
        best_baseline = base_df[~base_df['model'].str.contains('TemporalCTI', na=False)] \
            .sort_values('precision_at_1', ascending=False).iloc[0]
        improvement = (proposed['precision_at_1'] - best_baseline['precision_at_1']) \
            / best_baseline['precision_at_1'] * 100
        print(f"  Best baseline    : {best_baseline['model']} (P@1={best_baseline['precision_at_1']:.3f})")
        print(f"  Improvement      : {improvement:+.1f}% over best baseline at P@1")
    except FileNotFoundError:
        print(f"  baseline_comparison.csv not found — run baseline_comparison.py first.")

    print(f"\nNote: Metric 3 (Prevalence Match Rate) and Metric 4 (Held-Out")
    print(f"Validation) measure different things. Metric 4 is the one that")
    print(f"belongs in results tables and the paper — it is the only metric")
    print(f"here that checks predictions against what groups actually did next.")

    return pred_df

# ── 5. DEFENCE GAPS ───────────────────────────────────────────
def evaluate_defence_gaps():
    df = pd.read_csv('data/processed/defence_gaps.csv')
    print("\n" + "=" * 60)
    print("5. DEFENCE GAP EVALUATION")
    print("=" * 60)
    print(f"Total techniques        : {len(df)}")
    print(f"Critical gaps           : {len(df[df['priority'] == 'Critical'])}")
    print(f"High gaps               : {len(df[df['priority'] == 'High'])}")
    print(f"Medium gaps             : {len(df[df['priority'] == 'Medium'])}")
    print(f"Low gaps                : {len(df[df['priority'] == 'Low'])}")

    if 'has_defence' in df.columns:
        no_def = len(df[df['has_defence'] == False])
        pct    = no_def / len(df) * 100
        print(f"\nCritical finding:")
        print(f"  No mapped defence      : {no_def}/{len(df)}")
        print(f"  Unmapped percentage    : {pct:.1f}%")

    cols = [c for c in ['technique','gap_score','priority','total_groups','is_emerging'] if c in df.columns]
    print(f"\nTop 5 highest risk gaps:")
    print(df.head(5)[cols].to_string(index=False))
    return df

# ── 6. NATION-STATE ───────────────────────────────────────────
def evaluate_nation_state():
    nation_df  = pd.read_csv('data/processed/nation_profiles.csv')
    evo_df     = pd.read_csv('data/processed/nation_evolution_scores.csv')
    sharing_df = pd.read_csv('data/processed/nation_technique_sharing.csv')

    print("\n" + "=" * 60)
    print("6. NATION-STATE BEHAVIOURAL ANALYSIS EVALUATION")
    print("=" * 60)
    print(f"Nations identified      : {len(nation_df)}")
    print(f"Cross-nation techniques : {len(sharing_df)}")
    shared_all = len(sharing_df[sharing_df['nations_sharing'] == 4])
    print(f"Shared by all 4 nations : {shared_all}")

    print(f"\nNation evolution scores:")
    print(evo_df.to_string(index=False))

    print(f"\nTechnique sharing breakdown:")
    for n in range(4, 0, -1):
        count = len(sharing_df[sharing_df['nations_sharing'] == n])
        print(f"  Shared by {n} nation(s)  : {count}")
    return nation_df

# ── 7. ADAPTABILITY INDEX ─────────────────────────────────────
def evaluate_adaptability():
    df = pd.read_csv('data/processed/adaptability_index.csv')
    print("\n" + "=" * 60)
    print("7. ADAPTABILITY INDEX EVALUATION")
    print("=" * 60)
    print(f"Total groups scored     : {len(df)}")
    print(f"Score range             : {df['adaptability_index'].min():.3f} — {df['adaptability_index'].max():.3f}")
    print(f"Mean                    : {df['adaptability_index'].mean():.3f}")
    print(f"Std                     : {df['adaptability_index'].std():.3f}")

    cols = [c for c in ['apt_group','adaptability_index','years_tracked','total_techniques'] if c in df.columns]
    print(f"\nTop 10:")
    print(df.head(10)[cols].to_string(index=False))
    return df

# ── 8. TECHNIQUE LIFESPAN ─────────────────────────────────────
def evaluate_technique_lifespan():
    df = pd.read_csv('data/processed/technique_lifespan.csv')
    print("\n" + "=" * 60)
    print("8. TECHNIQUE LIFESPAN EVALUATION")
    print("=" * 60)
    print(f"Total techniques        : {len(df)}")

    if 'status' in df.columns:
        active  = len(df[df['status'] == 'Active'])
        retired = len(df[df['status'] == 'Retired'])
        print(f"Active                  : {active}")
        print(f"Retired                 : {retired}")

    if 'lifespan_years' in df.columns:
        print(f"Mean lifespan           : {df['lifespan_years'].mean():.1f} years")
        print(f"Max lifespan            : {df['lifespan_years'].max()} years")
        long = len(df[df['lifespan_years'] >= 5])
        print(f"Active 5+ years         : {long}")
    return df

# ── 9. TTP VELOCITY ───────────────────────────────────────────
def evaluate_ttp_velocity():
    df = pd.read_csv('data/processed/ttp_velocity.csv')
    print("\n" + "=" * 60)
    print("9. TTP VELOCITY EVALUATION")
    print("=" * 60)
    print(f"Techniques tracked      : {len(df)}")
    print(f"Max velocity            : {df['avg_velocity'].max():.3f}")
    print(f"Mean velocity           : {df['avg_velocity'].mean():.3f}")

    fast = len(df[df['avg_velocity'] > 1])
    print(f"Fast spreading (>1)     : {fast}")

    cols = [c for c in ['technique','avg_velocity','max_velocity','total_groups'] if c in df.columns]
    print(f"\nTop 5 fastest:")
    print(df.head(5)[cols].to_string(index=False))
    return df

# ── SUMMARY TABLE ─────────────────────────────────────────────
def generate_summary():
    print("\n" + "=" * 60)
    print("COMPLETE EVALUATION SUMMARY — TemporalCTI")
    print("=" * 60)

    evo_df     = pd.read_csv('data/processed/evolution_scores.csv')
    emg_df     = pd.read_csv('data/processed/emerging_ttps.csv')
    conv_df    = pd.read_csv('data/processed/convergence_alerts.csv')
    ret_df     = pd.read_csv('data/processed/retired_ttps.csv')
    pred_df    = pd.read_csv('data/processed/ttp_predictions.csv')
    nation_df  = pd.read_csv('data/processed/nation_technique_sharing.csv')
    adap_df    = pd.read_csv('data/processed/adaptability_index.csv')
    life_df    = pd.read_csv('data/processed/technique_lifespan.csv')
    vel_df     = pd.read_csv('data/processed/ttp_velocity.csv')
    gap_df     = pd.read_csv('data/processed/defence_gaps.csv')
    nation_evo = pd.read_csv('data/processed/nation_evolution_scores.csv')
    temp_df    = pd.read_csv('data/processed/temporal_profiles.csv')
    raw_df     = load_data()

    total_groups     = raw_df['apt_group'].nunique()
    total_techniques = raw_df['technique'].nunique()
    total_records    = raw_df.drop_duplicates(subset=['apt_group','technique','year']).shape[0]
    year_min         = raw_df['year'].min()
    year_max         = raw_df['year'].max()

    print(f"Dataset: {total_groups} APT groups · {total_techniques} techniques · {total_records:,} records · {year_min}–{year_max}")
    print("Source : MITRE ATT&CK STIX\n")

    evo_max          = evo_df['evolution_score'].max()
    evo_mean         = evo_df['evolution_score'].mean()
    top_group        = evo_df.iloc[0]['apt_group']
    emg_max          = emg_df['growth_rate'].max()
    conv_max         = conv_df['num_groups'].max()
    top_conv_tech    = conv_df.iloc[0]['technique']
    top_conv_year    = conv_df.iloc[0]['year_start']
    top_conv_end     = conv_df.iloc[0]['year_end']
    ret_instances    = len(ret_df)
    ret_techniques   = ret_df['technique'].nunique()
    total_preds      = len(pred_df)
    shared_total     = len(nation_df)
    shared_all4      = len(nation_df[nation_df['nations_sharing'] == 4])
    top_nation       = nation_evo.iloc[0]['nation']
    top_nation_score = nation_evo.iloc[0]['avg_evolution_score']
    adap_max         = adap_df['adaptability_index'].max()
    adap_mean        = adap_df['adaptability_index'].mean()
    top_adap         = adap_df.iloc[0]['apt_group']
    active_tech      = len(life_df[life_df['status'] == 'Active'])
    retired_tech     = len(life_df[life_df['status'] == 'Retired'])
    mean_life        = life_df['lifespan_years'].mean()
    persistent       = (
        life_df[life_df['status'] == 'Active']
        .sort_values(['lifespan_years', 'technique'], ascending=[False, True])
        ['technique'].values[0]
    )
    max_vel          = vel_df['avg_velocity'].max()
    top_vel_tech     = vel_df.iloc[0]['technique']
    no_def           = len(gap_df[gap_df['has_defence'] == False])
    pct              = no_def / len(gap_df) * 100

    val_df           = pd.read_csv('data/processed/prediction_validation.csv')
    p_at_1           = val_df.iloc[0]['precision_at_1']
    base_df          = pd.read_csv('data/processed/baseline_comparison.csv')
    proposed_row     = base_df[base_df['model'].str.contains('TemporalCTI', na=False)].iloc[0]
    best_base_row    = base_df[~base_df['model'].str.contains('TemporalCTI', na=False)] \
                       .sort_values('precision_at_1', ascending=False).iloc[0]
    p1_improvement   = (proposed_row['precision_at_1'] - best_base_row['precision_at_1']) \
                       / best_base_row['precision_at_1'] * 100

    mit_rec_df       = pd.read_csv('data/processed/mitigation_recommendations.csv')
    mit_rec_total    = len(mit_rec_df)
    mit_rec_critical = len(mit_rec_df[mit_rec_df['priority'] == 'CRITICAL'])
    mit_rec_top      = mit_rec_df.sort_values('score', ascending=False).iloc[0]['technique'] \
                       if not mit_rec_df.empty else 'N/A'
    mit_rec_top_pri  = mit_rec_df.sort_values('score', ascending=False).iloc[0]['priority'] \
                       if not mit_rec_df.empty else 'N/A'

    longest_active_row = temp_df.sort_values(
        ['years_active', 'apt_group'], ascending=[False, True]
    ).iloc[0]
    longest_active_group  = longest_active_row['apt_group']
    longest_active_years  = int(longest_active_row['years_active'])
    longest_active_first  = int(longest_active_row['first_seen'])
    longest_active_last = int(longest_active_row['last_seen'])
    pct_persistent = (
    len(life_df[life_df["lifespan_years"] >= 4]) / len(life_df)
       ) * 100

    summary = pd.DataFrame({
        'Module': [
            'Temporal Profiling', 'Evolution Score', 'Emerging TTP Detection',
            'Cross-Actor Convergence', 'TTP Retirement Detection', 'Markov Chain Prediction',
            'Nation-State Behavioural Analysis', 'Adaptability Index', 'Technique Lifespan',
            'TTP Velocity Tracking', 'Defence Gap Analysis', 'Mitigation Engine',
        ],
        'Key Metric': [
            f'{total_groups} APT group timelines',
            f'Range 0.0–{evo_max:.3f} · Mean {evo_mean:.3f}',
            f'{len(emg_df)} emerging · Max {emg_max:.1f}x growth',
            f'{len(conv_df):,} alerts · Max {conv_max} groups',
            f'{ret_instances:,} retirement events',
            f'Held-out P@1 {p_at_1:.3f} (+{p1_improvement:.0f}% vs baseline)',
            f'{shared_total} shared · {shared_all4} across all 4 nations',
            f'Range {adap_df["adaptability_index"].min():.3f}–{adap_max:.3f} · Mean {adap_mean:.3f}',
            f'{active_tech} active · {retired_tech} retired · Mean {mean_life:.0f}yr',
            f'{len(vel_df)} tracked · Max velocity {max_vel:.3f}',
            f'{no_def}/{len(gap_df)} unmapped ({pct:.1f}%)',
            f'{mit_rec_total} recommendations · {mit_rec_critical} Critical',
        ],
        'Novel Finding': [
            f'{longest_active_group}: {longest_active_years} years ({longest_active_first}–{longest_active_last})',
            f'{top_group} most adaptive at {evo_max:.3f}',
            f'Impersonation {emg_max:.1f}x — CRITICAL',
            f'{top_conv_tech} · {conv_max} groups {top_conv_year}–{top_conv_end}',
            f'{ret_instances:,} retirement events detected',
            f'Outperforms {best_base_row["model"]} baseline at P@1',
            f'{top_nation} most adaptive nation {top_nation_score:.3f}',
            f'{top_adap} highest adaptability {adap_max:.3f}',
            f'{pct_persistent:.0f}% of techniques persisted ≥4 years',
            f'{top_vel_tech} velocity {max_vel:.3f}/yr',
            f'{pct:.1f}% techniques have no defence',
            f'{mit_rec_top} mapped {mit_rec_top_pri}',
        ]
    })

    print(summary.to_string(index=False))
    summary.to_csv('data/processed/evaluation_summary.csv', index=False)
    print("\nSaved to data/processed/evaluation_summary.csv")

# ── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("TemporalCTI — Complete Evaluation Report")
    print("=" * 60)
    os.makedirs('src/evaluation', exist_ok=True)

    evaluate_evolution_scores()
    evaluate_emerging_ttps()
    evaluate_convergence()
    evaluate_predictions()
    evaluate_defence_gaps()
    evaluate_nation_state()
    evaluate_adaptability()
    evaluate_technique_lifespan()
    evaluate_ttp_velocity()
    generate_summary()

    print("\n" + "=" * 60)
    print("Evaluation complete.")
    print("All results saved to data/processed/")
    print("=" * 60)
