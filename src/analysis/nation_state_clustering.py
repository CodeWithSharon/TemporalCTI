import sqlite3
import pandas as pd
import numpy as np

GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}

NATION_STATE_MAPPING = {
    'Russia': [
        'APT28', 'APT29', 'Turla', 'Sandworm Team', 'Gamaredon Group',
        'Star Blizzard', 'CURIUM', 'Indrik Spider', 'Dragonfly'
    ],
    'China': [
        'APT41', 'APT10', 'APT19', 'APT1', 'APT17', 'APT18',
        'APT30', 'APT40', 'Mustang Panda', 'Ke3chang', 'GALLIUM',
        'Aquatic Panda', 'Chimera', 'BRONZE BUTLER', 'menuPass',
        'Volt Typhoon', 'Earth Lusca', 'BlackTech', 'Winnti Group'
    ],
    'North Korea': [
        'Lazarus Group', 'Kimsuky', 'Andariel', 'APT38',
        'BlueNoroff', 'APT37', 'AppleJeus'
    ],
    'Iran': [
        'APT33', 'APT34', 'APT35', 'APT39', 'OilRig',
        'MuddyWater', 'Magic Hound', 'Fox Kitten', 'Leafminer',
        'POLONIUM'
    ],
    'Others': []
}

def get_nation(apt_group):
    for nation, groups in NATION_STATE_MAPPING.items():
        if nation == 'Others':
            continue
        if apt_group in groups:
            return nation
    return 'Others'

def load_data():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT * FROM apt_timeline", conn)
    conn.close()
    # apt_timeline contains duplicate (apt_group, technique, year) rows
    # from repeated extractor runs. Collapse to unique triples so every
    # downstream count (records, top techniques, distributions) reflects
    # real observations rather than re-inserted copies.
    df = df.drop_duplicates(subset=['apt_group', 'technique', 'year'])
    # Exclude generic STIX object-types (Tool, Malware, etc.) - these
    # aren't real MITRE ATT&CK techniques and were leaking into
    # top_techniques (e.g. "Tool" showing up for China/Iran/Others).
    # Same filter every other analysis module already applies.
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df

def build_nation_profiles(df):
    df['nation'] = df['apt_group'].apply(get_nation)
    nation_profiles = []
    for nation in NATION_STATE_MAPPING.keys():
        nation_df = df[df['nation'] == nation]
        if nation_df.empty:
            continue
        groups = nation_df['apt_group'].nunique()
        techniques = nation_df['technique'].nunique()
        total_records = len(nation_df)
        top_techniques = (
            nation_df.groupby('technique')['apt_group']
            .nunique()
            .reset_index()
            .sort_values(['apt_group', 'technique'], ascending=[False, True])
            .head(5)['technique']
            .tolist()
        )
        yearly = nation_df.groupby('year').size().to_dict()
        nation_profiles.append({
            'nation': nation,
            'total_groups': groups,
            'unique_techniques': techniques,
            'total_records': total_records,
            'top_techniques': ' | '.join(top_techniques),
            'most_active_year': max(yearly, key=yearly.get) if yearly else 0
        })
    return pd.DataFrame(nation_profiles)

def detect_technique_sharing(df):
    df['nation'] = df['apt_group'].apply(get_nation)
    sharing = []
    techniques = df['technique'].unique()
    for technique in techniques:
        tech_df = df[df['technique'] == technique]
        nations = tech_df['nation'].unique().tolist()
        nations = [n for n in nations if n != 'Others']
        if len(nations) >= 2:
            sharing.append({
                'technique': technique,
                'nations_sharing': len(nations),
                'nations': ' | '.join(sorted(nations)),
                'total_groups': tech_df['apt_group'].nunique()
            })
    sharing_df = pd.DataFrame(sharing)
    if not sharing_df.empty:
        sharing_df = sharing_df.sort_values(
            ['nations_sharing', 'technique'], ascending=[False, True]
        )
    return sharing_df

def nation_evolution_scores():
    evo_df = pd.read_csv('data/processed/evolution_scores.csv')
    evo_df['nation'] = evo_df['apt_group'].apply(get_nation)
    nation_scores = evo_df.groupby('nation').agg(
        avg_evolution_score=('evolution_score', 'mean'),
        max_evolution_score=('evolution_score', 'max'),
        group_count=('apt_group', 'count')
    ).round(3).reset_index()
    nation_scores = nation_scores.sort_values(
        'avg_evolution_score', ascending=False
    )
    return nation_scores

if __name__ == "__main__":
    print("Nation-State Clustering Analysis")
    print("=" * 50)

    df = load_data()
    df['nation'] = df['apt_group'].apply(get_nation)

    print(f"\nNation distribution:")
    print(df['nation'].value_counts())

    print("\nNation Profiles:")
    profiles = build_nation_profiles(df)
    print(profiles.to_string(index=False))

    print("\nTechnique Sharing Across Nations (top 10):")
    sharing = detect_technique_sharing(df)
    print(f"Total techniques shared across 2+ nations: {len(sharing)}")
    print(sharing.head(10).to_string(index=False))

    print("\nNation Evolution Scores:")
    scores = nation_evolution_scores()
    print(scores.to_string(index=False))

    profiles.to_csv('data/processed/nation_profiles.csv', index=False)
    sharing.to_csv('data/processed/nation_technique_sharing.csv', index=False)
    scores.to_csv('data/processed/nation_evolution_scores.csv', index=False)
    print("\nSaved all nation-state files")
