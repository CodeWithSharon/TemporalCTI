import os
import sys
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import baseline_comparison as bc

from markov_prediction import (
    build_global_transition_matrix,
    build_frequency_prior,
    build_train_only_velocity,
    build_train_only_recency,
    hybrid_predict,
)

TEST_YEARS = [2022, 2023, 2024, 2025]

# Current best model
GAMMA = 0.15

# Recency weights to test
DELTAS = [0.00, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]

TOP_K = 5


def build_predictor(train_df, delta):
    """
    Build Markov + Frequency + Velocity + optional Recency
    using TRAIN DATA ONLY.
    """

    global_matrix = build_global_transition_matrix(train_df)
    freq_prior = build_frequency_prior(train_df)
    velocity_map = build_train_only_velocity(train_df)
    recency_map = (
        build_train_only_recency(train_df)
        if delta > 0
        else None
    )

    def predict(tdf, group, top_n):
        preds, _ = hybrid_predict(
            tdf,
            group,
            global_matrix,
            freq_prior,
            top_n=top_n,
            velocity_map=velocity_map,
            gamma=GAMMA,
            recency_map=recency_map,
            delta=delta,
        )
        return [t for t, _ in preds]

    return predict


def evaluate_year(df, test_year, delta):
    """
    Train on years < test_year.
    Test on test_year.
    Target = techniques newly observed for the group in test_year.
    """

    train_df = df[df["year"] < test_year]
    test_df = df[df["year"] == test_year]

    predictor = build_predictor(train_df, delta)

    rows = []

    common_groups = sorted(
        set(train_df["apt_group"]) &
        set(test_df["apt_group"])
    )

    for group in common_groups:

        train_group = train_df[
            train_df["apt_group"] == group
        ]

        test_group = test_df[
            test_df["apt_group"] == group
        ]

        historical = set(train_group["technique"])
        new_techniques = (
            set(test_group["technique"]) - historical
        )

        # No future adoption to predict
        if not new_techniques:
            continue

        pred = predictor(train_df, group, TOP_K)

        if not pred:
            continue

        row = {
            "test_year": test_year,
            "apt_group": group,
        }

        for k in [1, 3, 5]:
            row[f"hit@{k}"] = int(
                any(
                    p in new_techniques
                    for p in pred[:k]
                )
            )

        rows.append(row)

    return pd.DataFrame(rows)


def main():

    print("=" * 78)
    print("TemporalCTI - Recency Addition Experiment")
    print("=" * 78)

    df = bc.load_data()

    print(
        f"Dataset: {df['apt_group'].nunique()} groups, "
        f"{df['technique'].nunique()} techniques, "
        f"{len(df):,} records"
    )

    print()
    print(f"Fixed velocity weight: gamma = {GAMMA}")
    print(f"Testing recency delta: {DELTAS}")
    print()

    all_results = []

    for delta in DELTAS:

        print("-" * 78)
        print(f"Testing delta = {delta:.2f}")

        year_results = []

        for year in TEST_YEARS:

            result = evaluate_year(
                df,
                year,
                delta
            )

            if result.empty:
                print(
                    f"  {year}: no valid cases"
                )
                continue

            year_results.append(result)

            print(
                f"  {year}: "
                f"N={len(result)} | "
                f"Hit@1={result['hit@1'].mean():.3f} | "
                f"Hit@3={result['hit@3'].mean():.3f} | "
                f"Hit@5={result['hit@5'].mean():.3f}"
            )

        if not year_results:
            continue

        combined = pd.concat(
            year_results,
            ignore_index=True
        )

        row = {
            "delta": delta,
            "N": len(combined),
            "hit@1": combined["hit@1"].mean(),
            "hit@3": combined["hit@3"].mean(),
            "hit@5": combined["hit@5"].mean(),
        }

        all_results.append(row)

        print(
            f"  POOLED: "
            f"Hit@1={row['hit@1']:.3f} | "
            f"Hit@3={row['hit@3']:.3f} | "
            f"Hit@5={row['hit@5']:.3f}"
        )

    results_df = pd.DataFrame(all_results)

    print()
    print("=" * 78)
    print("FINAL RECENCY COMPARISON")
    print("=" * 78)

    print(
        results_df.round(3).to_string(
            index=False
        )
    )

    # Current model = delta 0
    baseline = results_df[
        results_df["delta"] == 0.00
    ].iloc[0]

    # Select primarily by Hit@1, then Hit@3
    best = results_df.sort_values(
        ["hit@1", "hit@3", "hit@5"],
        ascending=False
    ).iloc[0]

    print()
    print("=" * 78)
    print("BEST CONFIGURATION")
    print("=" * 78)

    print(
        f"Best delta: {best['delta']:.2f}"
    )

    print(
        f"Hit@1: {best['hit@1']:.3f} "
        f"(baseline {baseline['hit@1']:.3f})"
    )

    print(
        f"Hit@3: {best['hit@3']:.3f} "
        f"(baseline {baseline['hit@3']:.3f})"
    )

    print(
        f"Hit@5: {best['hit@5']:.3f} "
        f"(baseline {baseline['hit@5']:.3f})"
    )

    print()
    print(
        f"Hit@1 improvement: "
        f"{best['hit@1'] - baseline['hit@1']:+.3f}"
    )

    print(
        f"Hit@3 improvement: "
        f"{best['hit@3'] - baseline['hit@3']:+.3f}"
    )

    print(
        f"Hit@5 improvement: "
        f"{best['hit@5'] - baseline['hit@5']:+.3f}"
    )

    out_dir = os.path.join(
        bc.PROJECT_ROOT,
        "data",
        "processed"
    )

    os.makedirs(out_dir, exist_ok=True)

    output_file = os.path.join(
        out_dir,
        "recency_rolling_results.csv"
    )

    results_df.to_csv(
        output_file,
        index=False
    )

    print()
    print(
        f"Saved: {output_file}"
    )


if __name__ == "__main__":
    main()
