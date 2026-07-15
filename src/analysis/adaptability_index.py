import sqlite3
import pandas as pd
import numpy as np

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}

def load_data():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT * FROM apt_timeline", conn)
    conn.close()
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df

def calculate_adaptability_index(df):
    results = []
    groups = df['apt_group'].unique()

    for group in groups:
        group_df = df[df['apt_group'] == group]
        years = sorted(group_df['year'].unique())

        if len(years) < 2:
            continue

        # New technique adoption rate per year transition
        new_rates = []
        drop_rates = []
        for i in range(1, len(years)):
            prev = set(group_df[group_df['year'] == years[i-1]]['technique'])
            curr = set(group_df[group_df['year'] == years[i]]['technique'])
            total = len(prev.union(curr))
            if total > 0:
                new_rates.append(len(curr - prev) / total)
                drop_rates.append(len(prev - curr) / total)

        avg_new_rate = np.mean(new_rates) if new_rates else 0
        avg_drop_rate = np.mean(drop_rates) if drop_rates else 0

        # Temporal span — reward longer active groups
        year_span = years[-1] - years[0]
        span_score = min(year_span / 9, 1.0)

        # Technique volume — reward groups with more techniques
        total_techniques = group_df['technique'].nunique()
        volume_score = min(total_techniques / 100, 1.0)

        # Years active consistency
        consistency = min(len(years) / 8, 1.0)

        adaptability = round(
            0.30 * avg_new_rate +
            0.20 * avg_drop_rate +
            0.25 * span_score +
            0.15 * volume_score +
            0.10 * consistency,
            3
        )

        results.append({
            'apt_group': group,
            'adaptability_index': adaptability,
            'avg_new_rate': round(avg_new_rate, 3),
            'avg_drop_rate': round(avg_drop_rate, 3),
            'year_span': year_span,
            'years_tracked': len(years),
            'total_techniques': int(total_techniques)
        })

    df_result = pd.DataFrame(results)
    # Deterministic tie-break: adaptability_index values can tie across
    # groups with genuinely different underlying components (e.g.
    # MuddyWater and Threat Group-3390 both round to 0.646 from different
    # new/drop rates and years tracked). Sorting on the score alone leaves
    # row order dependent on df['apt_group'].unique()'s iteration order,
    # which isn't guaranteed alphabetical. Add apt_group as an ascending
    # secondary key, same pattern used everywhere else in the pipeline.
    df_result = df_result.sort_values(
        ['adaptability_index', 'apt_group'], ascending=[False, True]
    ).reset_index(drop=True)
    return df_result

if __name__ == "__main__":
    print("Calculating Adaptability Index...\n")
    df = load_data()
    results = calculate_adaptability_index(df)

    print("Top 15 Most Adaptable APT Groups:")
    print(results.head(15).to_string(index=False))

    print(f"\nIndex distribution:")
    print(f"  Max:  {results['adaptability_index'].max()}")
    print(f"  Min:  {results['adaptability_index'].min()}")
    print(f"  Mean: {results['adaptability_index'].mean():.3f}")
    print(f"  Std:  {results['adaptability_index'].std():.3f}")

    print(f"\nBottom 5:")
    print(results.tail(5).to_string(index=False))

    results.to_csv('data/processed/adaptability_index.csv', index=False)
    print("\nSaved to data/processed/adaptability_index.csv")
