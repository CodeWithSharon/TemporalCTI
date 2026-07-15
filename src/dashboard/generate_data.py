import pandas as pd
import json
import os
import sys

def load_csv(path):
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()

# Use the single source of truth for nation attribution instead of a
# second hardcoded copy (the two had drifted — 20 groups were falling
# through to 'Unknown' in the dashboard that were correctly attributed
# in nation_state_clustering.py).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis'))
from nation_state_clustering import get_nation as _get_nation

def dashboard_nation(apt_group):
    nation = _get_nation(apt_group)
    return nation if nation != 'Others' else 'Others'

evo_df = load_csv('data/processed/evolution_scores.csv')
emerging_df = load_csv('data/processed/emerging_ttps.csv')
conv_df = load_csv('data/processed/convergence_alerts.csv')
nation_df = load_csv('data/processed/nation_profiles.csv')
mit_df = load_csv('data/processed/mitigation_recommendations.csv')
pred_df = load_csv('data/processed/ttp_predictions.csv')
apt_df = load_csv('data/processed/apt_techniques.csv')
sharing_df = load_csv('data/processed/nation_technique_sharing.csv')
adapt_df = load_csv('data/processed/adaptability_index.csv')
lifespan_df = load_csv('data/processed/technique_lifespan.csv')
velocity_df = load_csv('data/processed/ttp_velocity.csv')
gaps_df = load_csv('data/processed/defence_gaps.csv')
nation_evo_df = load_csv('data/processed/nation_evolution_scores.csv')

# APT Groups
apt_groups = []
for _, row in evo_df.iterrows():
    adapt_row = adapt_df[adapt_df['apt_group'] == row['apt_group']]
    adapt_score = float(adapt_row.iloc[0]['adaptability_index']) \
                  if not adapt_row.empty else 0.0
    apt_groups.append({
        'id': row['apt_group'],
        'name': row['apt_group'],
        'nation': dashboard_nation(row['apt_group']),
        'firstSeen': int(row['first_seen']),
        'lastSeen': int(row['last_seen']),
        'techniques': int(row['total_techniques']),
        'evolutionScore': round(float(row['evolution_score']) * 100, 1),
        'adaptabilityIndex': round(adapt_score * 100, 1),
        'yearsActive': int(row['years_active'])
    })

# TTP Timeline
timeline = apt_df.groupby('Year').size().reset_index(name='count')
ttp_timeline = [
    {'year': int(r['Year']), 'count': int(r['count'])}
    for _, r in timeline.iterrows()
]

# Emerging Threats
emerging = []
for _, row in emerging_df.iterrows():
    priority = 'Critical' if row['growth_rate'] > 3 else \
               'High' if row['growth_rate'] > 1 else 'Medium'
    emerging.append({
        'id': f"T-{row['technique'][:6].replace(' ','')}",
        'name': row['technique'],
        'growth': round(float(row['growth_rate']) * 100),
        'groups': int(row['end_count']),
        'firstSeen': int(row['start_year']),
        'lastSeen': int(row['end_year']),
        'risk': priority,
        'velocity': min(round(float(row['growth_rate']) * 20), 100),
        'growthRate': float(row['growth_rate']),
        'peakYear': int(row['peak_year']) if 'peak_year' in row else int(row['end_year']),
        'acceleration': int(row['acceleration']) if 'acceleration' in row else 0
    })

# Convergence
convergence = []
for _, row in conv_df.head(30).iterrows():
    convergence.append({
        'year': int(row['year_start']),
        'technique': row['technique'],
        'adoptions': int(row['num_groups']),
        'period': f"{row['year_start']}-{row['year_end']}",
        'groups': str(row['groups'])[:100] if isinstance(row['groups'], str) else ''
    })

# Nation Data
nations = []
for _, row in nation_df.iterrows():
    evo_row = nation_evo_df[nation_evo_df['nation'] == row['nation']]
    avg_evo = float(evo_row.iloc[0]['avg_evolution_score']) \
              if not evo_row.empty else 0.0
    nations.append({
        'nation': row['nation'],
        'groups': int(row['total_groups']),
        'avgTechniques': int(row['unique_techniques']),
        'records': int(row['total_records']),
        'topTechniques': row['top_techniques'],
        'mostActiveYear': int(row['most_active_year']),
        'avgEvolutionScore': round(avg_evo, 3)
    })

# Mitigations
mitigations = []
for _, row in mit_df.iterrows():
    mitigations.append({
        'technique': row['technique'],
        'mitigation': row['mitigations'],
        'priority': row['priority'],
        'score': float(row['score']),
        'source': row['source'],
        'controls': len(str(row['mitigations']).split('|'))
    })

# Predictions
predictions = []
tech_col = 'predicted_technique' if 'predicted_technique' in pred_df.columns \
           else 'predicted_ttp'
for _, row in pred_df.iterrows():
    method = row['method'] if 'method' in pred_df.columns else 'hybrid'
    predictions.append({
        'technique': row[tech_col],
        'aptGroup': row['apt_group'],
        'confidence': round(float(row['probability']) * 100, 1),
        'method': method,
        'trend': 'rising' if float(row['probability']) > 0.3 else 'emerging'
    })

# Defence Gaps
gaps = []
for _, row in gaps_df.head(30).iterrows():
    gaps.append({
        'technique': row['technique'],
        'risk': round(float(row['gap_score']) * 100),
        'gap': round(float(row['gap_score']) * 90),
        'priority': row['priority'],
        'totalGroups': int(row['total_groups']),
        'isEmerging': bool(row['is_emerging']) if 'is_emerging' in row else False,
        'hasDefence': bool(row['has_defence']) if 'has_defence' in row else False,
        'availableDefences': str(row['available_defences']) if 'available_defences' in row else 'None mapped'
    })

# Adaptability Index
adaptability = []
for _, row in adapt_df.head(50).iterrows():
    adaptability.append({
        'aptGroup': row['apt_group'],
        'adaptabilityIndex': round(float(row['adaptability_index']) * 100, 1),
        'avgNewRate': round(float(row['avg_new_rate']) * 100, 1),
        'avgDropRate': round(float(row['avg_drop_rate']) * 100, 1),
        'yearSpan': int(row['year_span']),
        'yearsTracked': int(row['years_tracked']),
        'totalTechniques': int(row['total_techniques'])
    })

# Technique Lifespan
lifespan = []
for _, row in lifespan_df.head(50).iterrows():
    lifespan.append({
        'technique': row['technique'],
        'firstSeen': int(row['first_seen']),
        'lastSeen': int(row['last_seen']),
        'lifespanYears': int(row['lifespan_years']),
        'totalGroups': int(row['total_groups']),
        'persistenceScore': round(float(row['persistence_score']) * 100, 1),
        'status': row['status']
    })

# TTP Velocity
velocity = []
for _, row in velocity_df.head(30).iterrows():
    velocity.append({
        'technique': row['technique'],
        'avgVelocity': round(float(row['avg_velocity']), 3),
        'maxVelocity': round(float(row['max_velocity']), 3),
        'peakYear': int(row['peak_year']),
        'peakGroups': int(row['peak_groups']),
        'totalGroups': int(row['total_groups']),
        'spreadRate': round(float(row['spread_rate']), 2)
    })

# Nation Technique Sharing
sharing = []
for _, row in sharing_df.head(30).iterrows():
    sharing.append({
        'technique': row['technique'],
        'nationsSharing': int(row['nations_sharing']),
        'nations': row['nations'],
        'totalGroups': int(row['total_groups'])
    })

all_data = {
    'APT_GROUPS': apt_groups,
    'TTP_TIMELINE': ttp_timeline,
    'EMERGING_THREATS': emerging,
    'CONVERGENCE_DATA': convergence,
    'NATION_DATA': nations,
    'MITIGATIONS': mitigations,
    'PREDICTIONS': predictions,
    'DEFENCE_GAPS': gaps,
    'ADAPTABILITY': adaptability,
    'TECHNIQUE_LIFESPAN': lifespan,
    'TTP_VELOCITY': velocity,
    'NATION_SHARING': sharing
}

# Write as JS file
js_content = "// AUTO-GENERATED FROM REAL DATA\n"
js_content += "// Run: python3 src/dashboard/generate_data.py\n\n"
for key, value in all_data.items():
    js_content += f"export const {key} = {json.dumps(value, indent=2)};\n\n"

with open('src/dashboard/real_data.js', 'w') as f:
    f.write(js_content)

print("Generated src/dashboard/real_data.js")
for key, value in all_data.items():
    print(f"  {key}: {len(value)} records")
