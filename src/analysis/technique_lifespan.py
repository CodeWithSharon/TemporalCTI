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

def calculate_lifespan(df):
    results = []
    techniques = df['technique'].unique()

    for technique in techniques:
        tech_df = df[df['technique'] == technique]
        years = sorted(tech_df['year'].unique())
        groups = tech_df['apt_group'].nunique()

        first_seen = years[0]
        last_seen = years[-1]
        lifespan = last_seen - first_seen
        active_years = len(years)

        # Persistence score — still being used recently
        max_year = df['year'].max()
        recency = 1.0 if last_seen >= max_year - 1 else \
                  0.5 if last_seen >= max_year - 3 else 0.0

        # Adoption breadth — how many groups used it
        breadth = min(groups / 20, 1.0)

        persistence_score = round(
            0.4 * min(lifespan / 10, 1.0) +
            0.3 * recency +
            0.3 * breadth,
            3
        )

        results.append({
            'technique': technique,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'lifespan_years': lifespan,
            'active_years': active_years,
            'total_groups': groups,
            'persistence_score': persistence_score,
            'status': 'Active' if recency > 0 else 'Retired'
        })

    
    df_result = pd.DataFrame(results)
    df_result = df_result.sort_values(
    ['persistence_score', 'technique'], ascending=[False, True]
    ).reset_index(drop=True)
    return df_result

if __name__ == "__main__":
    print("Calculating Technique Lifespan...\n")
    df = load_data()
    results = calculate_lifespan(df)

    print(f"Total techniques analysed: {len(results)}")
    print(f"\nTop 15 Most Persistent Techniques:")
    print(results.head(15).to_string(index=False))

    print(f"\nStatus breakdown:")
    print(results['status'].value_counts())

    print(f"\nLifespan distribution:")
    print(f"  Max lifespan:  {results['lifespan_years'].max()} years")
    print(f"  Mean lifespan: {results['lifespan_years'].mean():.1f} years")
    print(f"  Techniques active 5+ years: {len(results[results['lifespan_years'] >= 5])}")

    results.to_csv('data/processed/technique_lifespan.csv', index=False)
    print("\nSaved to data/processed/technique_lifespan.csv")
