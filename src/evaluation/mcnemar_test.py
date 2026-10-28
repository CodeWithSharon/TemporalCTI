"""
McNemar's test: original Markov (gamma=0) vs Markov + Velocity (gamma=0.15)
Compares paired top-1 correctness across the same held-out test groups.

Run from the project root:
    python3 src/evaluation/mcnemar_test.py
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'analysis'))

from markov_prediction import (
    build_global_transition_matrix, build_frequency_prior,
    build_train_only_velocity, hybrid_predict, load_data
)
import pandas as pd

try:
    from statsmodels.stats.contingency_tables import mcnemar
except ImportError:
    print("statsmodels not found. Install it with: pip install statsmodels --break-system-packages")
    sys.exit(1)


def per_group_top1(df, test_year_cutoff=2024, gamma=0.0):
    train_df = df[df['year'] < test_year_cutoff]
    test_df = df[df['year'] >= test_year_cutoff]
    valid_groups = [g for g in test_df['apt_group'].unique()
                     if g in train_df['apt_group'].unique()]

    train_global = build_global_transition_matrix(train_df)
    train_freq = build_frequency_prior(train_df)
    train_velocity = build_train_only_velocity(train_df) if gamma > 0 else None

    results = {}
    for group in valid_groups:
        g_train = train_df[train_df['apt_group'] == group]
        g_test = test_df[test_df['apt_group'] == group]
        if g_train.empty or g_test.empty:
            continue
        new_ttps = set(g_test['technique'].unique()) - set(g_train['technique'].unique())
        if not new_ttps:
            continue
        preds, method = hybrid_predict(
            train_df, group, train_global, train_freq, top_n=5,
            velocity_map=train_velocity, gamma=gamma,
            recency_map=None, delta=0.0
        )
        if not preds:
            continue
        predicted = [p[0] for p in preds]
        correct_top1 = 1 if predicted[0] in new_ttps else 0
        results[group] = correct_top1

    return results


def main():
    df = load_data()  # uses the same loader as markov_prediction.py itself

    print("Running original Markov (gamma=0.0)...")
    original = per_group_top1(df, gamma=0.0)

    print("Running Markov + Velocity (gamma=0.15)...")
    velocity = per_group_top1(df, gamma=0.15)

    common_groups = sorted(set(original.keys()) & set(velocity.keys()))
    print(f"\nGroups evaluated in both: {len(common_groups)}")

    both_right = both_wrong = orig_only = vel_only = 0
    rows = []
    for g in common_groups:
        o, v = original[g], velocity[g]
        rows.append({'group': g, 'correct_original': o, 'correct_velocity': v})
        if o == 1 and v == 1:
            both_right += 1
        elif o == 0 and v == 0:
            both_wrong += 1
        elif o == 1 and v == 0:
            orig_only += 1
        elif o == 0 and v == 1:
            vel_only += 1

    print("\nContingency table:")
    print(f"  Both correct         : {both_right}")
    print(f"  Both incorrect       : {both_wrong}")
    print(f"  Original only correct: {orig_only}")
    print(f"  Velocity only correct: {vel_only}")

    table = [[both_right, orig_only],
             [vel_only, both_wrong]]

    result = mcnemar(table, exact=True)
    print(f"\nMcNemar's test (exact):")
    print(f"  statistic = {result.statistic}")
    print(f"  p-value   = {result.pvalue:.4f}")

    if result.pvalue < 0.05:
        print("  -> Significant at alpha=0.05")
    else:
        print("  -> NOT significant at alpha=0.05")

    pd.DataFrame(rows).to_csv('data/processed/mcnemar_paired_results.csv', index=False)
    print("\nSaved per-group paired results to data/processed/mcnemar_paired_results.csv")


if __name__ == '__main__':
    main()
