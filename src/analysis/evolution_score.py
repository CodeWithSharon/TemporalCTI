import sqlite3
import pandas as pd
import numpy as np

GENERIC_TECHNIQUES = (
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
)

def get_ttps_by_year(apt_group):
    conn = sqlite3.connect('data/temporal_db/apt.db')
    query = """
        SELECT year, technique
        FROM apt_timeline
        WHERE apt_group = ?
        AND technique NOT IN ({})
        ORDER BY year
    """.format(','.join('?' * len(GENERIC_TECHNIQUES)))
    df = pd.read_sql_query(query, conn, params=[apt_group] + list(GENERIC_TECHNIQUES))
    conn.close()
    return df

def calculate_evolution_score(apt_group):
    df = get_ttps_by_year(apt_group)
    if df.empty or len(df['year'].unique()) < 2:
        return 0.0

    years = sorted(df['year'].unique())

    new_ttp_rates  = []
    drop_rates     = []
    diversity_scores = []

    for i in range(1, len(years)):
        prev_ttps    = set(df[df['year'] == years[i-1]]['technique'])
        curr_ttps    = set(df[df['year'] == years[i]]['technique'])
        new_ttps     = curr_ttps - prev_ttps
        dropped_ttps = prev_ttps - curr_ttps
        total        = len(prev_ttps.union(curr_ttps))
        if total > 0:
            new_ttp_rates.append(len(new_ttps) / total)
            drop_rates.append(len(dropped_ttps) / total)
        diversity_scores.append(min(len(curr_ttps) / 20, 1.0))

    avg_new_rate  = np.mean(new_ttp_rates)   if new_ttp_rates   else 0
    avg_drop_rate = np.mean(drop_rates)       if drop_rates      else 0
    avg_diversity = np.mean(diversity_scores) if diversity_scores else 0

    year_span   = years[-1] - years[0]
    consistency = min(len(years) / max(year_span, 1), 1.0)
    longevity   = min(year_span / 8, 1.0)

    # Maturity penalty — groups with < 3 years get reduced score
    # This prevents short-lived high-churn groups from dominating
    n_years = len(years)
    if n_years >= 4:
        maturity = 1.0
    elif n_years == 3:
        maturity = 0.6
    else:
        maturity = 0.2   # 2-year groups get significant penalty

    score = (0.30 * avg_new_rate +
             0.20 * avg_drop_rate +
             0.15 * avg_diversity +
             0.10 * consistency +
             0.15 * longevity +
             0.10 * maturity)

    return round(score, 3)

def rank_all_groups():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    groups = pd.read_sql_query(
        "SELECT DISTINCT apt_group FROM apt_timeline", conn
    )['apt_group'].tolist()
    conn.close()

    scores = []
    for group in groups:
        score = calculate_evolution_score(group)
        df    = get_ttps_by_year(group)
        years = sorted(df['year'].unique()) if not df.empty else []
        scores.append({
            'apt_group'       : group,
            'evolution_score' : score,
            'years_active'    : len(years),
            'total_techniques': df['technique'].nunique() if not df.empty else 0,
            'first_seen'      : years[0]  if years else 0,
            'last_seen'       : years[-1] if years else 0,
        })

    df = pd.DataFrame(scores)
    # Deterministic tie-break: 13 groups of ties exist (101 rows total,
    # including a 76-way tie at 0.0 for single-year groups). Add apt_group
    # as ascending secondary key, same pattern used everywhere else.
    df = df.sort_values(
        ['evolution_score', 'apt_group'], ascending=[False, True]
    )
    return df

if __name__ == "__main__":
    print("Calculating Evolution Scores...\n")
    rankings = rank_all_groups()

    print("Top 15 Most Adaptable APT Groups:")
    print(rankings.head(15).to_string(index=False))

    print(f"\nScore distribution:")
    print(f"  Max:  {rankings['evolution_score'].max()}")
    print(f"  Min:  {rankings['evolution_score'].min()}")
    print(f"  Mean: {rankings['evolution_score'].mean():.3f}")
    print(f"  Std:  {rankings['evolution_score'].std():.3f}")

    print("\nBottom 5 Least Adaptable:")
    print(rankings.tail(5).to_string(index=False))

    rankings.to_csv('data/processed/evolution_scores.csv', index=False)
    print("\nSaved to data/processed/evolution_scores.csv")
