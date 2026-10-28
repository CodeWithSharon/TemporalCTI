import os
import sys
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

# Small, focused search only
GAMMAS = [0.10, 0.15, 0.20, 0.25, 0.30]
DELTAS = [0.10, 0.15, 0.20, 0.25, 0.30]

TOP_K = 5


def make_predictor(train_df, gamma, delta):
    global_matrix = build_global_transition_matrix(train_df)
    freq_prior = build_frequency_prior(train_df)
    velocity_map = build_train_only_velocity(train_df)
    recency_map = build_train_only_recency(train_df)

    def predict(group, top_n=TOP_K):
        preds, _ = hybrid_predict(
            train_df,
            group,
            global_matrix,
            freq_prior,
            top_n=top_n,
            velocity_map=velocity_map,
            gamma=gamma,
            recency_map=recency_map,
            delta=delta,
        )
        return [x for x, _ in preds]

    return predict


def evaluate(train_df, test_df, gamma, delta):
    predictor = make_predictor(train_df, gamma, delta)

    rows = []

    groups = sorted(
        set(train_df["apt_group"]) &
        set(test_df["apt_group"])
    )

    for group in groups:

        train_g = train_df[
            train_df["apt_group"] == group
        ]

        test_g = test_df[
            test_df["apt_group"] == group
        ]

        historical = set(train_g["technique"])

        target = (
            set(test_g["technique"]) -
            historical
        )

        if not target:
            continue

        pred = predictor(group)

        if not pred:
            continue

        rows.append({
            "group": group,
            "hit1": int(any(x in target for x in pred[:1])),
            "hit3": int(any(x in target for x in pred[:3])),
            "hit5": int(any(x in target for x in pred[:5])),
        })

    if not rows:
        return None

    return pd.DataFrame(rows)


def main():

    print("=" * 80)
    print("FINAL WEIGHT OPTIMIZATION")
    print("=" * 80)

    df = bc.load_data()

    print(
        f"Dataset: {df['apt_group'].nunique()} groups, "
        f"{df['technique'].nunique()} techniques, "
        f"{len(df):,} records"
    )

    # ---------------------------------------------------------
    # STEP 1:
    # For each test year, choose gamma/delta using ONLY
    # the previous year as validation.
    # ---------------------------------------------------------

    selected = {}

    print("\nVALIDATION-BASED WEIGHT SELECTION")
    print("-" * 80)

    for year in TEST_YEARS:

        validation_year = year - 1

        train_val = df[
            df["year"] < validation_year
        ]

        val_df = df[
            df["year"] == validation_year
        ]

        if train_val.empty or val_df.empty:
            continue

        best = None

        for gamma in GAMMAS:
            for delta in DELTAS:

                result = evaluate(
                    train_val,
                    val_df,
                    gamma,
                    delta
                )

                if result is None:
                    continue

                h1 = result["hit1"].mean()
                h3 = result["hit3"].mean()
                h5 = result["hit5"].mean()

                # Prioritize Hit@1, then Hit@3, then Hit@5
                score = (
                    h1 * 0.50 +
                    h3 * 0.30 +
                    h5 * 0.20
                )

                candidate = {
                    "gamma": gamma,
                    "delta": delta,
                    "hit1": h1,
                    "hit3": h3,
                    "hit5": h5,
                    "score": score,
                }

                if best is None or candidate["score"] > best["score"]:
                    best = candidate

        if best:
            selected[year] = best

            print(
                f"{year}: "
                f"gamma={best['gamma']:.2f}, "
                f"delta={best['delta']:.2f} | "
                f"validation Hit@1={best['hit1']:.3f}, "
                f"Hit@3={best['hit3']:.3f}, "
                f"Hit@5={best['hit5']:.3f}"
            )

    # ---------------------------------------------------------
    # STEP 2:
    # Evaluate the selected weights on the ACTUAL unseen year.
    # ---------------------------------------------------------

    print("\nFINAL UNSEEN TEST RESULTS")
    print("-" * 80)

    all_results = []

    for year in TEST_YEARS:

        if year not in selected:
            continue

        train_df = df[
            df["year"] < year
        ]

        test_df = df[
            df["year"] == year
        ]

        gamma = selected[year]["gamma"]
        delta = selected[year]["delta"]

        result = evaluate(
            train_df,
            test_df,
            gamma,
            delta
        )

        if result is None:
            continue

        result["year"] = year
        result["gamma"] = gamma
        result["delta"] = delta

        all_results.append(result)

        print(
            f"{year}: N={len(result)} | "
            f"gamma={gamma:.2f}, delta={delta:.2f} | "
            f"Hit@1={result['hit1'].mean():.3f} | "
            f"Hit@3={result['hit3'].mean():.3f} | "
            f"Hit@5={result['hit5'].mean():.3f}"
        )

    combined = pd.concat(
        all_results,
        ignore_index=True
    )

    print("\n" + "=" * 80)
    print("POOLED FINAL RESULT")
    print("=" * 80)

    h1 = combined["hit1"].mean()
    h3 = combined["hit3"].mean()
    h5 = combined["hit5"].mean()

    print(f"N = {len(combined)}")
    print(f"Hit@1 = {h1:.3f} ({h1*100:.1f}%)")
    print(f"Hit@3 = {h3:.3f} ({h3*100:.1f}%)")
    print(f"Hit@5 = {h5:.3f} ({h5*100:.1f}%)")

    print("\nSelected weights by year:")
    for year, x in selected.items():
        print(
            f"{year}: gamma={x['gamma']:.2f}, "
            f"delta={x['delta']:.2f}"
        )

    out = os.path.join(
        bc.PROJECT_ROOT,
        "data",
        "processed",
        "final_weight_results.csv"
    )

    combined.to_csv(out, index=False)

    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
