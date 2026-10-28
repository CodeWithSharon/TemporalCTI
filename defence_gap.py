import sqlite3
import pandas as pd
import numpy as np
import os

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}

def load_mitre_defences():
    """
    Real MITRE ATT&CK mitigation mapping, extracted from the official STIX
    corpus (course-of-action objects + 'mitigates' relationships) by
    src/extraction/mitre_mitigations_extractor.py - not hand-typed.
    Returns {technique_name: [mitigation_name, ...]}.
    """
    path = 'data/processed/technique_mitigations.csv'
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} not found. Run "
            "src/extraction/mitre_mitigations_extractor.py first."
        )
    mdf = pd.read_csv(path)
    defences = {}
    for _, row in mdf.iterrows():
        if row['mitigation_count'] > 0:
            defences[row['technique']] = str(row['mitigation_names']).split(' | ')
    return defences

def load_data():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT * FROM apt_timeline", conn)
    conn.close()
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df

def analyse_defence_gaps(df):
    emerging_df = pd.read_csv('data/processed/emerging_ttps.csv')
    velocity_df = pd.read_csv('data/processed/ttp_velocity.csv')
    conv_df = pd.read_csv('data/processed/convergence_alerts.csv')
    mitre_defences = load_mitre_defences()

    results = []
    techniques = df['technique'].unique()

    for technique in techniques:
        tech_df = df[df['technique'] == technique]
        total_groups = tech_df['apt_group'].nunique()

        is_emerging = technique in emerging_df['technique'].values
        emerging_growth = 0
        if is_emerging:
            row = emerging_df[emerging_df['technique'] == technique]
            emerging_growth = float(row['growth_rate'].values[0])

        is_fast = technique in velocity_df['technique'].values
        velocity = 0
        if is_fast:
            row = velocity_df[velocity_df['technique'] == technique]
            velocity = float(row['avg_velocity'].values[0])

        convergence_count = len(conv_df[conv_df['technique'] == technique])

        has_defence = technique in mitre_defences
        defences = mitre_defences.get(technique, [])
        defence_count = len(defences)

        threat_score = (
            0.35 * min(emerging_growth / 7, 1.0) +
            0.25 * min(velocity / 2.5, 1.0) +
            0.25 * min(total_groups / 50, 1.0) +
            0.15 * min(convergence_count / 100, 1.0)
        )

        defence_score = min(defence_count / 3, 1.0) if has_defence else 0
        gap_score = round(threat_score - (defence_score * 0.3), 3)

        priority = 'Critical' if gap_score > 0.3 else \
                   'High' if gap_score > 0.15 else \
                   'Medium' if gap_score > 0.05 else 'Low'

        results.append({
            'technique': technique,
            'threat_score': round(threat_score, 3),
            'defence_score': round(defence_score, 3),
            'gap_score': round(gap_score, 3),
            'priority': priority,
            'total_groups': int(total_groups),
            'has_defence': has_defence,
            'available_defences': ' | '.join(defences) if defences else 'No mapped defence',
            'is_emerging': is_emerging,
            'convergence_alerts': int(convergence_count)
        })

    df_result = pd.DataFrame(results)
    # Deterministic tie-break: gap_score is built from several min(x/cap,1)
    # clamps, so ties are common (58 groups of ties spanning 316 of 465
    # rows, including two rows tied at 0.208 that land directly in the
    # printed top-15: "File and Directory Discovery" and "System
    # Information Discovery"). Add technique as ascending secondary key,
    # same pattern used everywhere else in the pipeline.
    df_result = df_result.sort_values(
        ['gap_score', 'technique'], ascending=[False, True]
    ).reset_index(drop=True)
    return df_result

if __name__ == "__main__":
    print("Defence Gap Analysis\n")
    print("=" * 50)

    df = load_data()
    results = analyse_defence_gaps(df)

    print(f"Total techniques analysed: {len(results)}")

    print(f"\nPriority breakdown:")
    print(results['priority'].value_counts())

    print(f"\nTop 15 Highest Defence Gaps:")
    print(results.head(15)[
        ['technique', 'gap_score', 'priority', 'total_groups', 'is_emerging', 'has_defence']
    ].to_string(index=False))

    print(f"\nTechniques with NO mapped defence:")
    no_defence = results[results['has_defence'] == False]
    print(f"Total: {len(no_defence)}")
    print(no_defence.head(10)[['technique', 'gap_score', 'total_groups']].to_string(index=False))

    results.to_csv('data/processed/defence_gaps.csv', index=False)
    print("\nSaved to data/processed/defence_gaps.csv")
