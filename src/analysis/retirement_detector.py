import sqlite3
import pandas as pd

GENERIC_TECHNIQUES = (
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
)


def detect_retired_ttps(inactive_years=2):
    conn = sqlite3.connect('data/temporal_db/apt.db')
    query = """
        SELECT apt_group, technique,
               MAX(year) as last_seen,
               MIN(year) as first_seen,
               COUNT(DISTINCT year) as years_active
        FROM apt_timeline
        WHERE technique NOT IN ({})
        GROUP BY apt_group, technique
    """.format(','.join('?' * len(GENERIC_TECHNIQUES)))
    df = pd.read_sql_query(query, conn, params=list(GENERIC_TECHNIQUES))
    conn.close()

    max_year = df['last_seen'].max()
    retired = df[
        df['last_seen'] <= (max_year - inactive_years)
    ].copy()
    retired['years_since_last_use'] = (
        max_year - retired['last_seen']
    )
    # Deterministic tie-break: many pairs share the same
    # years_since_last_use (e.g. 305 pairs tied at the max value), and
    # GROUP BY doesn't guarantee row order without ORDER BY. Add
    # apt_group/technique as ascending secondary keys, same pattern used
    # everywhere else in the pipeline, so the printed "Sample" and the
    # saved CSV are reproducible across environments/reruns.
    retired = retired.sort_values(
        ['years_since_last_use', 'apt_group', 'technique'],
        ascending=[False, True, True]
    )
    return retired


if __name__ == "__main__":
    print("Detecting Retired TTPs...\n")
    retired = detect_retired_ttps()
    print(f"Total retired TTP instances: {len(retired)}")
    print("\nSample:")
    print(retired.head(10).to_string(index=False))
    retired.to_csv('data/processed/retired_ttps.csv', index=False)
    print("\nSaved to data/processed/retired_ttps.csv")
