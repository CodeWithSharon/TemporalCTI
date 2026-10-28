import sqlite3
import pandas as pd
from collections import defaultdict

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}


def load_data(db_path='data/temporal_db/apt.db'):
    conn = sqlite3.connect(db_path)
    # SELECT DISTINCT on the (apt_group, technique, year) triple, same as
    # every other analysis module. The raw apt_timeline table has genuine
    # row-level duplication (the same triple can appear up to ~16 times,
    # averaging ~11x, likely one row per underlying STIX relationship
    # citation rather than per unique technique-use). Without DISTINCT this
    # printed "Total records: 48,405" - inconsistent with the 4,390 figure
    # used everywhere else in the pipeline. The alert numbers themselves
    # were never affected (num_groups already dedupes via .unique()), but
    # the printed total was misleading. This fixes the total to match.
    df = pd.read_sql_query(
        "SELECT DISTINCT apt_group, technique, year FROM apt_timeline", conn
    )
    conn.close()
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df


def detect_convergence(df, min_groups=3, window=2):
    convergence_alerts = []
    techniques = df['technique'].unique()
    for technique in techniques:
        tech_df = df[df['technique'] == technique].copy()
        tech_df['year'] = tech_df['year'].astype(int)
        years = sorted(tech_df['year'].unique())
        for year in years:
            window_df = tech_df[
                (tech_df['year'] >= year) &
                (tech_df['year'] <= year + window)
            ]
            groups = window_df['apt_group'].unique().tolist()
            if len(groups) >= min_groups:
                convergence_alerts.append({
                    'technique': technique,
                    'year_start': year,
                    'year_end': year + window,
                    'num_groups': len(groups),
                    'groups': ', '.join(groups)
                })
    alerts_df = pd.DataFrame(convergence_alerts)
    if not alerts_df.empty:
        alerts_df = alerts_df.drop_duplicates(
            subset=['technique', 'year_start']
        )
        # Deterministic tie-break: num_groups ties are near-universal here
        # (1,051 of 1,061 alerts fall in a tied group). Add technique and
        # year_start as ascending secondary keys, same pattern used
        # everywhere else in the pipeline.
        alerts_df = alerts_df.sort_values(
            ['num_groups', 'technique', 'year_start'],
            ascending=[False, True, True]
        )
    return alerts_df


def print_top_convergence(alerts_df, top_n=10):
    print(f"\nTop {top_n} Cross-Actor TTP Convergence Alerts:")
    print("=" * 60)
    for _, row in alerts_df.head(top_n).iterrows():
        print(f"\nTechnique: {row['technique']}")
        print(f"Period: {row['year_start']} - {row['year_end']}")
        print(f"Groups adopting: {row['num_groups']}")
        print(f"Groups: {row['groups']}")
        print("-" * 40)


if __name__ == "__main__":
    print("Loading data...")
    df = load_data()
    print(f"Total records: {len(df)}")
    print("Detecting cross-actor convergence...")
    alerts = detect_convergence(df, min_groups=3, window=2)
    print(f"Convergence alerts found: {len(alerts)}")
    print_top_convergence(alerts)
    alerts.to_csv('data/processed/convergence_alerts.csv', index=False)
    print("\nSaved to data/processed/convergence_alerts.csv")
