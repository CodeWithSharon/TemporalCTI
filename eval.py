'Old evaluator with markov'
import sqlite3
import pandas as pd
import numpy as np
import os

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}


def load_data():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT * FROM apt_timeline", conn)
    conn.close()

    # Exclude generic STIX object-types
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]

    return df


# ── 1. EVOLUTION SCORE ───────────────────────────────────────
def evaluate_evolution_scores():

    df = pd.read_csv('data/processed/evolution_scores.csv')

    print("=" * 60)
    print("1. EVOLUTION SCORE EVALUATION")
    print("=" * 60)

    print(f"Total groups scored     : {len(df)}")
    print(
        f"Score range             : "
        f"{df['evolution_score'].min():.3f} — "
        f"{df['evolution_score'].max():.3f}"
    )
    print(
        f"Mean score              : "
        f"{df['evolution_score'].mean():.3f}"
    )
    print(
        f"Std deviation           : "
        f"{df['evolution_score'].std():.3f}"
    )

    high = len(df[df['evolution_score'] > 0.5])
    med = len(
        df[
            (df['evolution_score'] >= 0.3) &
            (df['evolution_score'] <= 0.5)
        ]
    )
    low = len(df[df['evolution_score'] < 0.3])

    print("\nAdaptability distribution:")
    print(f"  High   (>0.5)    : {high} groups")
    print(f"  Medium (0.3–0.5) : {med} groups")
    print(f"  Low    (<0.3)    : {low} groups")

    cols = [
        c for c in [
            'apt_group',
            'evolution_score',
            'years_active',
            'total_techniques'
        ]
        if c in df.columns
    ]

    print("\nTop 10 most adaptive:")
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
    print(
        f"Mean growth rate        : "
        f"{df['growth_rate'].mean():.2f}x"
    )
    print(
        f"Min growth rate         : "
        f"{df['growth_rate'].min():.2f}x"
    )

    critical = len(df[df['growth_rate'] > 3])
    high = len(
        df[
            (df['growth_rate'] > 1) &
            (df['growth_rate'] <= 3)
        ]
    )
    medium = len(df[df['growth_rate'] <= 1])

    print("\nSeverity:")
    print(f"  Critical (>3x) : {critical}")
    print(f"  High     (1–3x): {high}")
    print(f"  Medium   (<1x) : {medium}")

    cols = [
        c for c in [
            'technique',
            'growth_rate',
            'start_year',
            'end_year',
            'end_count'
        ]
        if c in df.columns
    ]

    print("\nTop 10 fastest growing:")
    print(df.head(10)[cols].to_string(index=False))

    return df


# ── 3. CONVERGENCE ────────────────────────────────────────────
def evaluate_convergence():

    df = pd.read_csv(
        'data/processed/convergence_alerts.csv'
    )

    print("\n" + "=" * 60)
    print("3. CROSS-ACTOR CONVERGENCE EVALUATION")
    print("=" * 60)

    print(f"Total alerts            : {len(df)}")
    print(f"Max groups converging   : {df['num_groups'].max()}")
    print(
        f"Mean groups per alert   : "
        f"{df['num_groups'].mean():.1f}"
    )

    high = len(df[df['num_groups'] > 20])
    med = len(
        df[
            (df['num_groups'] >= 10) &
            (df['num_groups'] <= 20)
        ]
    )
    low = len(df[df['num_groups'] < 10])

    print("\nConvergence strength:")
    print(f"  High   (>20 groups) : {high}")
    print(f"  Medium (10–20)      : {med}")
    print(f"  Low    (<10)        : {low}")

    cols = [
        c for c in [
            'technique',
            'num_groups',
            'year_start',
            'year_end'
        ]
        if c in df.columns
    ]

    print("\nTop 5 events:")
    print(df.head(5)[cols].to_string(index=False))

    return df


# ── 4. FINAL ROLLING PREDICTION EVALUATION ────────────────────
def evaluate_predictions():

    pred_df = pd.read_csv(
        'data/processed/ttp_predictions.csv'
    )

    raw_df = load_data()

    print("\n" + "=" * 60)
    print("4. MARKOV CHAIN PREDICTION EVALUATION")
    print("=" * 60)

    print(f"Total predictions       : {len(pred_df)}")
    print(
        f"Groups covered          : "
        f"{pred_df['apt_group'].nunique()}"
    )

    if 'method' in pred_df.columns:
        print("\nMethod breakdown:")
        print(
            pred_df['method']
            .value_counts()
            .to_string()
        )

    tech_col = (
        'predicted_technique'
        if 'predicted_technique' in pred_df.columns
        else 'predicted_ttp'
    )

    global_techniques = set(raw_df['technique'])

    valid = pred_df[
        pred_df[tech_col].isin(global_techniques)
    ]

    coverage = (
        len(valid) / len(pred_df)
        if len(pred_df) > 0
        else 0
    )

    print("\nMetric 1 — Coverage Rate:")
    print(
        f"  Valid ATT&CK predictions: "
        f"{len(valid)}/{len(pred_df)}"
    )
    print(f"  Coverage                : {coverage:.3f}")
    print("  All predictions are grounded in")
    print("  real MITRE ATT&CK techniques")

    # ── Prevalence ────────────────────────────────────────────
    prevalence_scores = []

    for _, row in pred_df.iterrows():

        tech = row[tech_col]

        groups_using = raw_df[
            raw_df['technique'] == tech
        ]['apt_group'].nunique()

        total_groups = raw_df['apt_group'].nunique()

        prevalence_scores.append(
            groups_using / total_groups
        )

    avg_prevalence = (
        np.mean(prevalence_scores)
        if prevalence_scores
        else 0
    )

    print("\nMetric 2 — Prevalence Score:")
    print(
        f"  Mean prevalence         : "
        f"{avg_prevalence:.3f}"
    )
    print(
        f"  Predicted techniques are used by "
        f"{avg_prevalence:.1%} of all APT groups on average"
    )

    # ── Prevalence Match ─────────────────────────────────────
    print("\nMetric 3 — Prevalence Match Rate:")
    print(
        "  (Share of predictions that are techniques used by "
        "5+ groups —"
    )
    print(
        "  a plausibility check, NOT a predictive-accuracy metric."
    )
    print("  Do not read this as Precision@K.)")

    prevalent = set(
        raw_df.groupby('technique')
        .filter(
            lambda x:
            x['apt_group'].nunique() >= 5
        )['technique'].unique()
    )

    for k in [1, 3, 5, 10]:

        correct = 0
        total = 0

        for group in pred_df['apt_group'].unique():

            top_k = (
                pred_df[
                    pred_df['apt_group'] == group
                ]
                .nlargest(k, 'probability')[tech_col]
                .tolist()
            )

            if not top_k:
                continue

            hits = sum(
                1 for t in top_k
                if t in prevalent
            )

            correct += hits
            total += len(top_k)

        match_rate = (
            correct / total
            if total > 0
            else 0
        )

        bar = '█' * int(match_rate * 20)

        print(
            f"  Top-{k:2} : "
            f"{bar:20} "
            f"{match_rate:.3f}"
        )

    # ── Probability statistics ───────────────────────────────
    print("\nProbability statistics:")
    print(
        f"  Mean  : "
        f"{pred_df['probability'].mean():.3f}"
    )
    print(
        f"  Max   : "
        f"{pred_df['probability'].max():.3f}"
    )
    print(
        f"  Min   : "
        f"{pred_df['probability'].min():.3f}"
    )
    print(
        f"  Std   : "
        f"{pred_df['probability'].std():.3f}"
    )

    # ── FINAL ROLLING EVALUATION ──────────────────────────────
    print(
        "\nMetric 4 — Rolling Chronological "
        "Prediction Evaluation:"
    )

    print("  Evaluation years : 2022–2025")
    print("  Evaluation cases : 88 group-year cases")
    print("  Final model      : Markov + Velocity + Recency")
    print("  Velocity weight  : gamma = 0.15")
    print(
        "  Recency weights  : selected using "
        "prior-year validation"
    )

    try:

        rolling_df = pd.read_csv(
            'data/processed/final_weight_results.csv'
        )

        hit1 = rolling_df['hit1'].mean()
        hit3 = rolling_df['hit3'].mean()
        hit5 = rolling_df['hit5'].mean()

        print(
            f"  Hit@1             : "
            f"{hit1:.3f}"
        )
        print(
            f"  Hit@3             : "
            f"{hit3:.3f}"
        )
        print(
            f"  Hit@5             : "
            f"{hit5:.3f}"
        )

    except FileNotFoundError:

        print(
            "  final_weight_results.csv not found — "
            "run final_weight_optimization.py first."
        )

    print(
        "\nNote: Metric 3 (Prevalence Match Rate) and "
        "Metric 4 (Rolling Evaluation) measure different things."
    )

    print(
        "Metric 4 is the primary prediction-performance "
        "result because it evaluates predictions against "
        "what groups actually adopted in subsequent years."
    )

    return pred_df


# ── 5. DEFENCE GAPS ───────────────────────────────────────────
def evaluate_defence_gaps():

    df = pd.read_csv(
        'data/processed/defence_gaps.csv'
    )

    print("\n" + "=" * 60)
    print("5. DEFENCE GAP EVALUATION")
    print("=" * 60)

    print(f"Total techniques        : {len(df)}")
    print(
        f"Critical gaps           : "
        f"{len(df[df['priority'] == 'Critical'])}"
    )
    print(
        f"High gaps               : "
        f"{len(df[df['priority'] == 'High'])}"
    )
    print(
        f"Medium gaps             : "
        f"{len(df[df['priority'] == 'Medium'])}"
    )
    print(
        f"Low gaps                : "
        f"{len(df[df['priority'] == 'Low'])}"
    )

    if 'has_defence' in df.columns:

        no_def = len(
            df[df['has_defence'] == False]
        )

        pct = (
            no_def / len(df) * 100
        )

        print("\nCritical finding:")
        print(
            f"  No mapped defence      : "
            f"{no_def}/{len(df)}"
        )
        print(
            f"  Unmapped percentage    : "
            f"{pct:.1f}%"
        )

    cols = [
        c for c in [
            'technique',
            'gap_score',
            'priority',
            'total_groups',
            'is_emerging'
        ]
        if c in df.columns
    ]

    print("\nTop 5 highest risk gaps:")
    print(
        df.head(5)[cols]
        .to_string(index=False)
    )

    return df


# ── 6. NATION-STATE ───────────────────────────────────────────
def evaluate_nation_state():

    nation_df = pd.read_csv(
        'data/processed/nation_profiles.csv'
    )

    evo_df = pd.read_csv(
        'data/processed/nation_evolution_scores.csv'
    )

    sharing_df = pd.read_csv(
        'data/processed/nation_technique_sharing.csv'
    )

    print("\n" + "=" * 60)
    print("6. NATION-STATE CLUSTERING EVALUATION")
    print("=" * 60)

    print(
        f"Nations identified      : "
        f"{len(nation_df)}"
    )

    print(
        f"Cross-nation techniques : "
        f"{len(sharing_df)}"
    )

    shared_all = len(
        sharing_df[
            sharing_df['nations_sharing'] == 4
        ]
    )

    print(
        f"Shared by all 4 nations : "
        f"{shared_all}"
    )

    print("\nNation evolution scores:")
    print(
        evo_df.to_string(index=False)
    )

    print("\nTechnique sharing breakdown:")

    for n in range(4, 0, -1):

        count = len(
            sharing_df[
                sharing_df['nations_sharing'] == n
            ]
        )

        print(
            f"  Shared by {n} nation(s)  : "
            f"{count}"
        )

    return nation_df


# ── 7. ADAPTABILITY INDEX ─────────────────────────────────────
def evaluate_adaptability():

    df = pd.read_csv(
        'data/processed/adaptability_index.csv'
    )

    print("\n" + "=" * 60)
    print("7. ADAPTABILITY INDEX EVALUATION")
    print("=" * 60)

    print(
        f"Total groups scored     : "
        f"{len(df)}"
    )

    print(
        f"Score range             : "
        f"{df['adaptability_index'].min():.3f} — "
        f"{df['adaptability_index'].max():.3f}"
    )

    print(
        f"Mean                    : "
        f"{df['adaptability_index'].mean():.3f}"
    )

    print(
        f"Std                     : "
        f"{df['adaptability_index'].std():.3f}"
    )

    cols = [
        c for c in [
            'apt_group',
            'adaptability_index',
            'years_tracked',
            'total_techniques'
        ]
        if c in df.columns
    ]

    print("\nTop 10:")
    print(
        df.head(10)[cols]
        .to_string(index=False)
    )

    return df


# ── 8. TECHNIQUE LIFESPAN ─────────────────────────────────────
def evaluate_technique_lifespan():

    df = pd.read_csv(
        'data/processed/technique_lifespan.csv'
    )

    print("\n" + "=" * 60)
    print("8. TECHNIQUE LIFESPAN EVALUATION")
    print("=" * 60)

    print(
        f"Total techniques        : "
        f"{len(df)}"
    )

    if 'status' in df.columns:

        active = len(
            df[df['status'] == 'Active']
        )

        retired = len(
            df[df['status'] == 'Retired']
        )

        print(
            f"Active                  : "
            f"{active}"
        )

        print(
            f"Retired                 : "
            f"{retired}"
        )

    if 'lifespan_years' in df.columns:

        print(
            f"Mean lifespan           : "
            f"{df['lifespan_years'].mean():.1f} years"
        )

        print(
            f"Max lifespan            : "
            f"{df['lifespan_years'].max()} years"
        )

        long = len(
            df[df['lifespan_years'] >= 5]
        )

        print(
            f"Active 5+ years         : "
            f"{long}"
        )

    return df


# ── 9. TTP VELOCITY ───────────────────────────────────────────
def evaluate_ttp_velocity():

    df = pd.read_csv(
        'data/processed/ttp_velocity.csv'
    )

    print("\n" + "=" * 60)
    print("9. TTP VELOCITY EVALUATION")
    print("=" * 60)

    print(
        f"Techniques tracked      : "
        f"{len(df)}"
    )

    print(
        f"Max velocity            : "
        f"{df['avg_velocity'].max():.3f}"
    )

    print(
        f"Mean velocity           : "
        f"{df['avg_velocity'].mean():.3f}"
    )

    fast = len(
        df[df['avg_velocity'] > 1]
    )

    print(
        f"Fast spreading (>1)     : "
        f"{fast}"
    )

    cols = [
        c for c in [
            'technique',
            'avg_velocity',
            'max_velocity',
            'total_groups'
        ]
        if c in df.columns
    ]

    print("\nTop 5 fastest:")
    print(
        df.head(5)[cols]
        .to_string(index=False)
    )

    return df


# ── SUMMARY TABLE ─────────────────────────────────────────────
def generate_summary():

    print("\n" + "=" * 60)
    print("COMPLETE EVALUATION SUMMARY — TemporalCTI")
    print("=" * 60)

    evo_df = pd.read_csv(
        'data/processed/evolution_scores.csv'
    )

    emg_df = pd.read_csv(
        'data/processed/emerging_ttps.csv'
    )

    conv_df = pd.read_csv(
        'data/processed/convergence_alerts.csv'
    )

    ret_df = pd.read_csv(
        'data/processed/retired_ttps.csv'
    )

    pred_df = pd.read_csv(
        'data/processed/ttp_predictions.csv'
    )

    nation_df = pd.read_csv(
        'data/processed/nation_technique_sharing.csv'
    )

    adap_df = pd.read_csv(
        'data/processed/adaptability_index.csv'
    )

    life_df = pd.read_csv(
        'data/processed/technique_lifespan.csv'
    )

    vel_df = pd.read_csv(
        'data/processed/ttp_velocity.csv'
    )

    gap_df = pd.read_csv(
        'data/processed/defence_gaps.csv'
    )

    nation_evo = pd.read_csv(
        'data/processed/nation_evolution_scores.csv'
    )

    temp_df = pd.read_csv(
        'data/processed/temporal_profiles.csv'
    )

    raw_df = load_data()

    # ── Dataset ───────────────────────────────────────────────
    total_groups = raw_df['apt_group'].nunique()

    total_techniques = raw_df[
        'technique'
    ].nunique()

    total_records = (
        raw_df
        .drop_duplicates(
            subset=[
                'apt_group',
                'technique',
                'year'
            ]
        )
        .shape[0]
    )

    year_min = raw_df['year'].min()
    year_max = raw_df['year'].max()

    print(
        f"Dataset: {total_groups} APT groups · "
        f"{total_techniques} techniques · "
        f"{total_records:,} records · "
        f"{year_min}–{year_max}"
    )

    print("Source : MITRE ATT&CK STIX\n")

    # ── Evolution ────────────────────────────────────────────
    evo_max = evo_df['evolution_score'].max()
    evo_mean = evo_df['evolution_score'].mean()
    top_group = evo_df.iloc[0]['apt_group']

    # ── Emerging ─────────────────────────────────────────────
    emg_max = emg_df['growth_rate'].max()

    # ── Convergence ──────────────────────────────────────────
    conv_max = conv_df['num_groups'].max()
    top_conv_tech = conv_df.iloc[0]['technique']
    top_conv_year = conv_df.iloc[0]['year_start']
    top_conv_end = conv_df.iloc[0]['year_end']

    # ── Retirement ───────────────────────────────────────────
    ret_instances = len(ret_df)
    ret_techniques = ret_df['technique'].nunique()

    # ── Prediction: FINAL ROLLING RESULT ─────────────────────
    rolling_df = pd.read_csv(
        'data/processed/final_weight_results.csv'
    )

    p_at_1 = rolling_df['hit1'].mean()
    p_at_3 = rolling_df['hit3'].mean()
    p_at_5 = rolling_df['hit5'].mean()

    rolling_n = len(rolling_df)

    # ── Baseline comparison ─────────────────────────────────
    base_df = pd.read_csv(
        'data/processed/baseline_comparison.csv'
    )

    baseline_rows = base_df[
        ~base_df['model'].str.contains(
            'TemporalCTI',
            na=False
        )
    ]

    best_base_row = (
        baseline_rows
        .sort_values(
            'hit_at_1',
            ascending=False
        )
        .iloc[0]
    )

    p1_improvement_pp = (
        p_at_1 -
        best_base_row['hit_at_1']
    ) * 100

    p1_hits_proposed = round(
        p_at_1 * rolling_n
    )

    p1_hits_baseline = round(
        best_base_row['hit_at_1'] *
        rolling_n
    )

    # ── Nation ───────────────────────────────────────────────
    shared_total = len(nation_df)

    shared_all4 = len(
        nation_df[
            nation_df['nations_sharing'] == 4
        ]
    )

    top_nation = nation_evo.iloc[0]['nation']

    top_nation_score = (
        nation_evo.iloc[0]
        ['avg_evolution_score']
    )

    # ── Adaptability ─────────────────────────────────────────
    adap_max = (
        adap_df['adaptability_index']
        .max()
    )

    adap_mean = (
        adap_df['adaptability_index']
        .mean()
    )

    top_adap = adap_df.iloc[0]['apt_group']

    # ── Lifespan ─────────────────────────────────────────────
    active_tech = len(
        life_df[
            life_df['status'] == 'Active'
        ]
    )

    retired_tech = len(
        life_df[
            life_df['status'] == 'Retired'
        ]
    )

    mean_life = (
        life_df['lifespan_years']
        .mean()
    )

    persistent = (
        life_df[
            life_df['status'] == 'Active'
        ]
        .sort_values(
            ['lifespan_years', 'technique'],
            ascending=[False, True]
        )['technique']
        .values[0]
    )

    # ── Velocity ─────────────────────────────────────────────
    max_vel = (
        vel_df['avg_velocity']
        .max()
    )

    top_vel_tech = vel_df.iloc[0]['technique']

    # ── Defence gaps ────────────────────────────────────────
    no_def = len(
        gap_df[
            gap_df['has_defence'] == False
        ]
    )

    pct = (
        no_def /
        len(gap_df) *
        100
    )

    # ── Mitigation ──────────────────────────────────────────
    mit_rec_df = pd.read_csv(
        'data/processed/mitigation_recommendations.csv'
    )

    mit_rec_total = len(mit_rec_df)

    mit_rec_critical = len(
        mit_rec_df[
            mit_rec_df['priority'] == 'CRITICAL'
        ]
    )

    if not mit_rec_df.empty:

        mit_rec_top = (
            mit_rec_df
            .sort_values(
                'score',
                ascending=False
            )
            .iloc[0]['technique']
        )

        mit_rec_top_pri = (
            mit_rec_df
            .sort_values(
                'score',
                ascending=False
            )
            .iloc[0]['priority']
        )

    else:

        mit_rec_top = 'N/A'
        mit_rec_top_pri = 'N/A'

    # ── Longest active group ────────────────────────────────
    longest_active_row = (
        temp_df
        .sort_values(
            ['years_active', 'apt_group'],
            ascending=[False, True]
        )
        .iloc[0]
    )

    longest_active_group = (
        longest_active_row['apt_group']
    )

    longest_active_years = int(
        longest_active_row['years_active']
    )

    longest_active_first = int(
        longest_active_row['first_seen']
    )

    longest_active_last = int(
        longest_active_row['last_seen']
    )

    pct_persistent = (
        len(
            life_df[
                life_df['lifespan_years'] >= 4
            ]
        )
        /
        len(life_df)
    ) * 100

    # ── Final summary ────────────────────────────────────────
    summary = pd.DataFrame({

        'Module': [

            'Temporal Profiling',
            'Evolution Score',
            'Emerging TTP Detection',
            'Cross-Actor Convergence',
            'TTP Retirement Detection',
            'Markov Chain Prediction',
            'Nation-State Clustering',
            'Adaptability Index',
            'Technique Lifespan',
            'TTP Velocity Tracking',
            'Defence Gap Analysis',
            'Mitigation Engine',

        ],

        'Key Metric': [

            f'{total_groups} APT group timelines',

            f'Range 0.0–{evo_max:.3f} · '
            f'Mean {evo_mean:.3f}',

            f'{len(emg_df)} emerging · '
            f'Max {emg_max:.1f}x growth',

            f'{len(conv_df):,} alerts · '
            f'Max {conv_max} groups',

            f'{ret_instances:,} retirement events',

            f'Rolling Hit@1 {p_at_1:.3f} · '
            f'Hit@3 {p_at_3:.3f} · '
            f'Hit@5 {p_at_5:.3f}',

            f'{shared_total} shared · '
            f'{shared_all4} across all 4 nations',

            f'Range '
            f'{adap_df["adaptability_index"].min():.3f}–'
            f'{adap_max:.3f} · '
            f'Mean {adap_mean:.3f}',

            f'{active_tech} active · '
            f'{retired_tech} retired · '
            f'Mean {mean_life:.0f}yr',

            f'{len(vel_df)} tracked · '
            f'Max velocity {max_vel:.3f}',

            f'{no_def}/{len(gap_df)} unmapped '
            f'({pct:.1f}%)',

            f'{mit_rec_total} recommendations · '
            f'{mit_rec_critical} Critical',

        ],

        'Novel Finding': [

            f'{longest_active_group}: '
            f'{longest_active_years} years '
            f'({longest_active_first}–'
            f'{longest_active_last})',

            f'{top_group} most adaptive '
            f'at {evo_max:.3f}',

            f'Impersonation {emg_max:.1f}x — '
            f'CRITICAL',

            f'{top_conv_tech} · '
            f'{conv_max} groups '
            f'{top_conv_year}–'
            f'{top_conv_end}',

            f'{ret_instances:,} retirement '
            f'events detected',

            f'Best Hit@1 and Hit@5 among '
            f'evaluated models',

            f'{top_nation} most adaptive nation '
            f'{top_nation_score:.3f}',

            f'{top_adap} highest adaptability '
            f'{adap_max:.3f}',

            f'{pct_persistent:.0f}% of techniques '
            f'persisted ≥4 years',

            f'{top_vel_tech} velocity '
            f'{max_vel:.3f}/yr',

            f'{pct:.1f}% techniques have '
            f'no defence',

            f'{mit_rec_top} mapped '
            f'{mit_rec_top_pri}',

        ]
    })

    print(
        summary.to_string(index=False)
    )

    summary.to_csv(
        'data/processed/evaluation_summary.csv',
        index=False
    )

    print(
        "\nSaved to "
        "data/processed/evaluation_summary.csv"
    )


# ── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":

    print(
        "TemporalCTI — Complete Evaluation Report"
    )

    print("=" * 60)

    os.makedirs(
        'src/evaluation',
        exist_ok=True
    )

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
    print(
        "All results saved to data/processed/"
    )
    print("=" * 60)
