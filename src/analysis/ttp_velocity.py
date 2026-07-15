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


def calculate_ttp_velocity(df):
    results = []
    techniques = df['technique'].unique()

    for technique in techniques:
        tech_df = df[df['technique'] == technique]
        years = sorted(tech_df['year'].unique())

        if len(years) < 2:
            continue

        yearly_groups = tech_df.groupby('year')['apt_group'].nunique()

        # Spread velocity — how fast technique moves group to group
        velocities = []
        for i in range(1, len(years)):
            prev_year = years[i-1]
            curr_year = years[i]
            year_gap = curr_year - prev_year
            prev_count = yearly_groups.get(prev_year, 0)
            curr_count = yearly_groups.get(curr_year, 0)
            if year_gap > 0 and prev_count > 0:
                velocity = (curr_count - prev_count) / year_gap
                velocities.append(velocity)

        avg_velocity = np.mean(velocities) if velocities else 0
        max_velocity = max(velocities) if velocities else 0

        # Peak year — the most recent year the technique hit its max
        # group-count. yearly_groups is indexed in ascending year order
        # (groupby sorts by default), so reversing it before idxmax()
        # makes ties resolve to the LATEST matching year instead of the
        # earliest. Previously this used list(...).index(max), which
        # always returns the first (earliest) match on a tie — silently
        # under-reporting recency for any technique that re-hit an
        # earlier peak (159 of 339 tracked techniques have such a tie,
        # including 3 of the printed top-15: Network Sniffing, Steal Web
        # Session Cookie, and Exfiltration Over Unencrypted Non-C2
        # Protocol all previously reported their earliest peak year
        # instead of their most recent one).
        peak_year = int(yearly_groups[::-1].idxmax()) if not yearly_groups.empty else 0

        # Spread score
        total_groups = tech_df['apt_group'].nunique()
        spread_rate = total_groups / len(years)

        results.append({
            'technique': technique,
            'avg_velocity': round(avg_velocity, 3),
            'max_velocity': round(max_velocity, 3),
            'peak_year': peak_year,
            'peak_groups': int(yearly_groups.max()),
            'total_groups': int(total_groups),
            'years_tracked': len(years),
            'spread_rate': round(spread_rate, 2)
        })

    df_result = pd.DataFrame(results)
    # Deterministic tie-break: many techniques share the same avg_velocity
    # (e.g. several tied at exactly 1.000 and 0.500), so sorting on
    # avg_velocity alone leaves the row order - and therefore which tied
    # techniques land in a "top 15" slice - dependent on iteration/
    # environment order. Add technique as an ascending secondary key,
    # same pattern used everywhere else in the pipeline.
    df_result = df_result.sort_values(
        ['avg_velocity', 'technique'], ascending=[False, True]
    ).reset_index(drop=True)
    return df_result


if __name__ == "__main__":
    print("Calculating TTP Velocity...\n")
    df = load_data()
    results = calculate_ttp_velocity(df)

    print(f"Total techniques tracked: {len(results)}")
    print(f"\nTop 15 Fastest Spreading Techniques:")
    print(results.head(15).to_string(index=False))

    print(f"\nVelocity distribution:")
    print(f"  Max velocity:  {results['avg_velocity'].max()}")
    print(f"  Mean velocity: {results['avg_velocity'].mean():.3f}")
    print(f"  Fast spreading (velocity > 1): {len(results[results['avg_velocity'] > 1])}")

    results.to_csv('data/processed/ttp_velocity.csv', index=False)
    print("\nSaved to data/processed/ttp_velocity.csv")
