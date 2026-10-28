import sqlite3
import pandas as pd

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}

SHOW_SAMPLE_TIMELINES = True
NUM_SAMPLE_TIMELINES = 5


def get_all_groups(db_path='data/temporal_db/apt.db'):
    conn = sqlite3.connect(db_path)

    query = """
        SELECT DISTINCT apt_group
        FROM apt_timeline
        ORDER BY apt_group
    """

    groups = pd.read_sql_query(query, conn)
    conn.close()

    return groups['apt_group'].tolist()


def get_temporal_profile(apt_group, db_path='data/temporal_db/apt.db'):
    conn = sqlite3.connect(db_path)

    query = """
        SELECT DISTINCT apt_group, technique, year
        FROM apt_timeline
        WHERE apt_group = ?
        ORDER BY year
    """

    df = pd.read_sql_query(query, conn, params=(apt_group,))
    conn.close()

    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]

    return df


def build_yearly_timeline(apt_group, db_path='data/temporal_db/apt.db'):
    df = get_temporal_profile(apt_group, db_path)

    if df.empty:
        return {}

    timeline = {}

    for year in sorted(df['year'].unique()):
        techniques = (
            df[df['year'] == year]['technique']
            .drop_duplicates()
            .tolist()
        )

        timeline[year] = techniques

    return timeline


def print_timeline(apt_group):
    timeline = build_yearly_timeline(apt_group)

    if not timeline:
        print(f"No data found for {apt_group}")
        return

    print(f"\nTTP Timeline for {apt_group}")
    print("-" * 40)

    for year, techniques in timeline.items():
        print(f"{year}: {len(techniques)} techniques")

        for t in techniques:
            print(f"   - {t}")


def get_summary(apt_group):
    timeline = build_yearly_timeline(apt_group)

    if not timeline:
        return None

    total_unique = len(
        set(
            t
            for techniques in timeline.values()
            for t in techniques
        )
    )

    return {
        'apt_group': apt_group,
        'first_seen': min(timeline.keys()),
        'last_seen': max(timeline.keys()),
        'years_active': len(timeline),
        'total_unique_techniques': total_unique
    }


if __name__ == "__main__":

    groups = get_all_groups()

    print(f"\nTotal APT Groups Found: {len(groups)}")

    # Show only a few sample timelines
    if SHOW_SAMPLE_TIMELINES:
        print("\nDisplaying sample timelines...\n")

        for group in groups[:NUM_SAMPLE_TIMELINES]:
            print_timeline(group)

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)

    summaries = []

    for group in groups:
        s = get_summary(group)

        if s:
            summaries.append(s)

    df_summary = pd.DataFrame(summaries)

    print(df_summary.to_string(index=False))

    df_summary.to_csv(
        'data/processed/temporal_profiles.csv',
        index=False
    )

    print("\nSaved to data/processed/temporal_profiles.csv")
