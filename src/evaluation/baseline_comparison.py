import sqlite3
import pandas as pd
import numpy as np
from collections import defaultdict
import random

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


# ─────────────────────────────────────────────
# Baseline 1: Random Prediction
# Randomly selects techniques not used by group
# ─────────────────────────────────────────────

def random_baseline(df, apt_group, top_n=5, seed=42):
    random.seed(seed)
    group_df  = df[df['apt_group'] == apt_group]
    existing  = set(group_df['technique'].unique())
    # BUG FIX: list(a_set) preserves Python's hash-randomized iteration
    # order, so random.sample() - even with a fixed seed - sampled a
    # different subset on every process run. sorted() makes the input
    # order deterministic so the fixed seed actually reproduces.
    all_techs = sorted(set(df['technique'].unique()) - existing)
    if len(all_techs) < top_n:
        return all_techs
    return random.sample(all_techs, top_n)


# ─────────────────────────────────────────────
# Baseline 2: Frequency-Only Prediction
# Recommends most globally popular techniques
# not yet used by the group
# ─────────────────────────────────────────────

def frequency_baseline(df, apt_group, top_n=5):
    group_df     = df[df['apt_group'] == apt_group]
    existing     = set(group_df['technique'].unique())
    total_groups = df['apt_group'].nunique()
    counts = df.groupby('technique')['apt_group'].nunique()
    # Deterministic tie-break: sort by (count desc, technique name asc) so
    # ties (e.g. Malicious File and Ingress Tool Transfer both at 86) always
    # resolve the same way regardless of pandas/numpy version or environment.
    all_techniques = counts.reset_index().sort_values(
        ['apt_group', 'technique'], ascending=[False, True]
    ).set_index('technique')['apt_group']
    predictions = []
    for technique, count in all_techniques.items():
        if technique not in existing:
            predictions.append(technique)
        if len(predictions) >= top_n:
            break
    return predictions


# ─────────────────────────────────────────────
# Held-out Evaluation for Any Baseline
# Train: < 2024  |  Test: >= 2024
# ─────────────────────────────────────────────

def evaluate_baseline(df, predict_fn, label):
    train_df = df[df['year'] < 2024]
    test_df  = df[df['year'] >= 2024]

    valid_groups = list(
        set(test_df['apt_group'].unique()) &
        set(train_df['apt_group'].unique())
    )

    hits  = {1: 0, 3: 0, 5: 0}
    total = 0

    for group in valid_groups:
        g_train  = train_df[train_df['apt_group'] == group]
        g_test   = test_df[test_df['apt_group'] == group]
        if g_train.empty or g_test.empty:
            continue

        new_ttps = set(g_test['technique'].unique()) - \
                   set(g_train['technique'].unique())
        if not new_ttps:
            continue

        predicted = predict_fn(train_df, group, top_n=5)
        if not predicted:
            continue

        for k in [1, 3, 5]:
            if any(p in new_ttps for p in predicted[:k]):
                hits[k] += 1
        total += 1

    if total == 0:
        return None

    return {
        'model'          : label,
        'total_groups'   : total,
        'precision_at_1' : round(hits[1] / total, 3),
        'precision_at_3' : round(hits[3] / total, 3),
        'precision_at_5' : round(hits[5] / total, 3),
    }


# ─────────────────────────────────────────────
# Load TemporalCTI Results for Comparison
# ─────────────────────────────────────────────

def load_temporalcti_results():
    val_df = pd.read_csv('data/processed/prediction_validation.csv')
    return {
        'model'          : 'TemporalCTI (Hybrid Markov)',
        'total_groups'   : int(val_df['total_groups'].iloc[0]),
        'precision_at_1' : float(val_df['precision_at_1'].iloc[0]),
        'precision_at_3' : float(val_df['precision_at_3'].iloc[0]),
        'precision_at_5' : float(val_df['precision_at_5'].iloc[0]),
    }


# ─────────────────────────────────────────────
# Print Comparison Table
# ─────────────────────────────────────────────

def print_comparison(results):
    print("\nBaseline Comparison — Held-out Validation (test: >= 2024)")
    print("=" * 65)
    print(f"  {'Model':<35} {'P@1':>6}  {'P@3':>6}  {'P@5':>6}  {'N':>4}")
    print("  " + "-" * 58)

    for r in results:
        if r is None:
            continue
        marker = " <-- proposed" if 'TemporalCTI' in r['model'] else ""
        print(f"  {r['model']:<35} "
              f"{r['precision_at_1']:>6.3f}  "
              f"{r['precision_at_3']:>6.3f}  "
              f"{r['precision_at_5']:>6.3f}  "
              f"{r['total_groups']:>4}"
              f"{marker}")

    print()
    # Improvement over best baseline
    baselines   = [r for r in results if r and 'TemporalCTI' not in r['model']]
    temporalcti = next((r for r in results if r and 'TemporalCTI' in r['model']), None)

    if baselines and temporalcti:
        best_baseline_p1 = max(r['precision_at_1'] for r in baselines)
        best_baseline_p5 = max(r['precision_at_5'] for r in baselines)
        # NOTE: reported as percentage-point (pp) difference, not relative %.
        # Relative % over a small baseline (P@1=0.051) produced a headline
        # "+151%" figure that, while mathematically correct, overstated the
        # practical size of the gain (5 vs 2 correct out of 39 groups).
        # Percentage points avoid that small-denominator inflation.
        pp_p1 = (temporalcti['precision_at_1'] - best_baseline_p1) * 100
        pp_p5 = (temporalcti['precision_at_5'] - best_baseline_p5) * 100
        n = temporalcti['total_groups']
        hits_proposed_p1 = round(temporalcti['precision_at_1'] * n)
        hits_baseline_p1 = round(best_baseline_p1 * n)
        print(f"  TemporalCTI improvement over best baseline:")
        print(f"    P@1: {pp_p1:+.1f} percentage points "
              f"({hits_proposed_p1}/{n} vs {hits_baseline_p1}/{n} correct)")
        print(f"    P@5: {pp_p5:+.1f} percentage points")

    print()
    print("  Note: Random baseline simulates uninformed prediction.")
    print("  Frequency baseline simulates popularity-based prediction.")
    print("  TemporalCTI uses temporal Markov transitions + global prior.")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("TemporalCTI — Baseline Comparison")
    print("=" * 65)

    df = load_data()
    print(f"Dataset: {df['apt_group'].nunique()} groups · "
          f"{df['technique'].nunique()} techniques\n")

    print("Evaluating Random baseline...")
    random_results = evaluate_baseline(
        df,
        lambda d, g, top_n: random_baseline(d, g, top_n),
        'Random'
    )

    print("Evaluating Frequency baseline...")
    freq_results = evaluate_baseline(
        df,
        lambda d, g, top_n: frequency_baseline(d, g, top_n),
        'Frequency (popularity)'
    )

    print("Loading TemporalCTI results...")
    temporalcti_results = load_temporalcti_results()

    results = [random_results, freq_results, temporalcti_results]
    print_comparison(results)

    # Save
    results_clean = [r for r in results if r is not None]
    pd.DataFrame(results_clean).to_csv(
        'data/processed/baseline_comparison.csv', index=False
    )
    print("Saved to data/processed/baseline_comparison.csv")
