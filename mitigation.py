import pandas as pd
import os

_MITIGATIONS_CACHE = None

def _load_mitigations():
    """
    Real MITRE ATT&CK mitigation names per technique, extracted from the
    official STIX corpus by src/extraction/mitre_mitigations_extractor.py
    (course-of-action objects + 'mitigates' relationships) - replaces the
    previous 10-technique hand-typed dict.
    """
    global _MITIGATIONS_CACHE
    if _MITIGATIONS_CACHE is not None:
        return _MITIGATIONS_CACHE
    path = 'data/processed/technique_mitigations.csv'
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} not found. Run "
            "src/extraction/mitre_mitigations_extractor.py first."
        )
    mdf = pd.read_csv(path)
    mapping = {}
    for _, row in mdf.iterrows():
        if row['mitigation_count'] > 0:
            mapping[row['technique']] = str(row['mitigation_names']).split(' | ')
    _MITIGATIONS_CACHE = mapping
    return mapping

def get_mitigation(technique):
    mitigations = _load_mitigations()
    if technique in mitigations:
        return mitigations[technique]
    # MITRE genuinely publishes no mitigation for this technique (common for
    # Discovery-tactic techniques, which ATT&CK marks as detect-only).
    return [
        'No MITRE-published mitigation for this technique',
        'Apply principle of least privilege',
        'Prioritise detection/monitoring controls instead'
    ]

def generate_report():
    sources = [
        ('data/processed/emerging_ttps.csv', 'EMERGING'),
        ('data/processed/ttp_predictions.csv', 'PREDICTED')
    ]
    all_recommendations = []
    for path, source_type in sources:
        if not os.path.exists(path):
            print(f"Missing: {path}")
            continue
        df = pd.read_csv(path)
        tech_col = 'technique' if 'technique' in df.columns \
                   else 'predicted_technique'
        score_col = 'growth_rate' if 'growth_rate' in df.columns \
                    else 'probability'

        # FIX: sort by score first. emerging_ttps.csv already arrives
        # sorted by growth_rate, but ttp_predictions.csv is saved in
        # group-iteration order, not probability order - without this,
        # "top 10 predicted mitigations" was actually just the first two
        # groups' rows, not the 10 highest-confidence predictions.
        # Secondary sort key (technique name) makes tie-breaking
        # deterministic - many techniques share the same score (e.g. 11
        # emerging TTPs tied at growth_rate=2.0), so without a tie-breaker
        # which ones land in the top-10 cutoff was environment-dependent.
        df = df.sort_values([score_col, tech_col], ascending=[False, True])

        # FIX: growth_rate (emerging TTPs, ~1-7x) and probability
        # (predictions, ~0.01-1.6, mean ~0.17) live on different scales.
        # Reusing the same fixed cutoffs (>3.0 / >1.0) meant almost every
        # predicted mitigation collapsed into MEDIUM regardless of its
        # actual relative confidence. Use percentiles of each source's
        # own score distribution instead, so priority reflects where a
        # score sits relative to its own source, not an absolute number
        # borrowed from a differently-scaled metric.
        p90 = df[score_col].quantile(0.90)
        p50 = df[score_col].quantile(0.50)

        print(f"\n{source_type} TTP MITIGATIONS")
        print("=" * 50)
        for _, row in df.head(10).iterrows():
            technique = row[tech_col]
            score = row[score_col]
            mitigations = get_mitigation(technique)
            priority = "CRITICAL" if score >= p90 else \
                       "HIGH" if score >= p50 else "MEDIUM"
            print(f"\n[{priority}] {technique}")
            print(f"  Score: {score}")
            for m in mitigations:
                print(f"  → {m}")
            all_recommendations.append({
                'technique': technique,
                'source': source_type,
                'priority': priority,
                'score': score,
                'mitigations': ' | '.join(mitigations)
            })
    if all_recommendations:
        rec_df = pd.DataFrame(all_recommendations)
        rec_df.to_csv(
            'data/processed/mitigation_recommendations.csv',
            index=False
        )
        print("\nSaved to mitigation_recommendations.csv")

if __name__ == "__main__":
    generate_report()
