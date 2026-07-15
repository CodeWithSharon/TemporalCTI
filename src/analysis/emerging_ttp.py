import sqlite3
import pandas as pd

GENERIC_TECHNIQUES = (
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
)

def detect_emerging_ttps(threshold=2, min_years=2, growth_rate_threshold=0.3):
    conn = sqlite3.connect('data/temporal_db/apt.db')
    query = """
        SELECT technique, year,
               COUNT(DISTINCT apt_group) as group_count
        FROM apt_timeline
        WHERE technique NOT IN ({})
        GROUP BY technique, year
        ORDER BY technique, year
    """.format(','.join('?' * len(GENERIC_TECHNIQUES)))
    df = pd.read_sql_query(query, conn, params=list(GENERIC_TECHNIQUES))
    conn.close()

    emerging = []
    for technique in df['technique'].unique():
        tech_data = df[df['technique'] == technique].sort_values('year')
        if len(tech_data) < min_years:
            continue

        years = tech_data['year'].tolist()
        counts = tech_data['group_count'].tolist()

        if len(counts) >= 2:
            growth = counts[-1] - counts[0]
            growth_rate = growth / max(counts[0], 1)

            # peak count — highest adoption at any point
            peak_count = max(counts)
            peak_year = years[counts.index(peak_count)]

            # acceleration — is adoption speeding up
            if len(counts) >= 3:
                recent_growth = counts[-1] - counts[-2]
                early_growth = counts[1] - counts[0]
                acceleration = recent_growth - early_growth
            else:
                acceleration = 0

            if growth >= threshold and growth_rate > growth_rate_threshold:
                emerging.append({
                    'technique': technique,
                    'start_year': years[0],
                    'end_year': years[-1],
                    'start_count': counts[0],
                    'end_count': counts[-1],
                    'peak_count': peak_count,
                    'peak_year': peak_year,
                    'growth': growth,
                    'growth_rate': round(growth_rate, 2),
                    'acceleration': acceleration,
                    'years_tracked': len(years)
                })

    emerging_df = pd.DataFrame(emerging)
    if not emerging_df.empty:
        # Deterministic tie-break: 14 techniques tie at growth_rate=2.0,
        # affecting rows 5-15 of the printed "Top 15" table. Add technique
        # as ascending secondary key, same pattern used everywhere else.
        emerging_df = emerging_df.sort_values(
            ['growth_rate', 'technique'], ascending=[False, True]
        ).reset_index(drop=True)

    return emerging_df

if __name__ == "__main__":
    print("Detecting Emerging TTPs...\n")
    emerging = detect_emerging_ttps()

    if not emerging.empty:
        print(f"Found {len(emerging)} emerging TTPs\n")
        print("Top 15 Fastest Growing:")
        print(emerging.head(15).to_string(index=False))

        print(f"\nDetection summary:")
        print(f"  Total emerging: {len(emerging)}")
        print(f"  Max growth rate: {emerging['growth_rate'].max()}x")
        print(f"  Mean growth rate: {emerging['growth_rate'].mean():.2f}x")

        emerging.to_csv('data/processed/emerging_ttps.csv', index=False)
        print("\nSaved to data/processed/emerging_ttps.csv")
    else:
        print("No emerging TTPs detected")
