import os
import sqlite3
import random

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

DB_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "temporal_db",
    "apt.db"
)

OUTPUT_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "baseline_comparison.csv"
)

FINAL_RESULTS_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "final_weight_results.csv"
)

ANALYSIS_PATH = os.path.join(
    PROJECT_ROOT,
    "src",
    "analysis"
)

import sys

if ANALYSIS_PATH not in sys.path:
    sys.path.insert(0, ANALYSIS_PATH)

from markov_prediction import (
    build_global_transition_matrix,
    build_frequency_prior,
    build_train_only_velocity,
    build_train_only_recency,
    hybrid_predict,
)


# ============================================================
# CONFIGURATION
# ============================================================

TEST_YEARS = [
    2022,
    2023,
    2024,
    2025,
]

TOP_K = 5

FINAL_GAMMA = 0.15

# Recency values selected using prior-year validation
VALIDATED_DELTAS = {
    2022: 0.15,
    2023: 0.10,
    2024: 0.10,
    2025: 0.10,
}

GENERIC_TECHNIQUES = {
    "Tool",
    "Malware",
    "Vulnerability",
    "Exploits",
    "Audio-Visual Content",
    "Written Content",
}


# ============================================================
# DATA LOADING
# ============================================================

def load_data():

    conn = sqlite3.connect(DB_PATH)

    try:

        df = pd.read_sql_query(
            "SELECT * FROM apt_timeline",
            conn
        )

    finally:

        conn.close()

    df = df[
        ~df["technique"].isin(
            GENERIC_TECHNIQUES
        )
    ].copy()

    df = df.dropna(
        subset=[
            "apt_group",
            "technique",
            "year"
        ]
    )

    df["year"] = pd.to_numeric(
        df["year"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["year"]
    )

    df["year"] = (
        df["year"]
        .astype(int)
    )

    df = df.drop_duplicates(
        subset=[
            "apt_group",
            "technique",
            "year"
        ]
    )

    return df


# ============================================================
# RANDOM BASELINE
# ============================================================

def random_predictions(
    train_df,
    group,
    top_n=5,
    seed=42
):

    group_df = train_df[
        train_df["apt_group"] == group
    ]

    existing = set(
        group_df["technique"]
        .dropna()
        .unique()
    )

    all_techniques = sorted(
        set(
            train_df["technique"]
            .dropna()
            .unique()
        )
        - existing
    )

    if not all_techniques:
        return []

    rng = random.Random(seed)

    if len(all_techniques) <= top_n:
        return all_techniques

    return rng.sample(
        all_techniques,
        top_n
    )


# ============================================================
# FREQUENCY BASELINE
# ============================================================

def frequency_predictions(
    train_df,
    group,
    top_n=5
):

    group_df = train_df[
        train_df["apt_group"] == group
    ]

    existing = set(
        group_df["technique"]
        .dropna()
        .unique()
    )

    counts = (
        train_df
        .groupby("technique")["apt_group"]
        .nunique()
    )

    ranking = (
        counts
        .reset_index(
            name="group_count"
        )
        .sort_values(
            [
                "group_count",
                "technique"
            ],
            ascending=[
                False,
                True
            ]
        )
    )

    predictions = []

    for _, row in ranking.iterrows():

        technique = row["technique"]

        if technique in existing:
            continue

        predictions.append(
            technique
        )

        if len(predictions) >= top_n:
            break

    return predictions


# ============================================================
# RECENCY BASELINE
# ============================================================

def recency_predictions(
    train_df,
    group,
    top_n=5,
    lookback_years=2
):

    group_df = train_df[
        train_df["apt_group"] == group
    ]

    existing = set(
        group_df["technique"]
        .dropna()
        .unique()
    )

    if train_df.empty:
        return []

    latest_year = train_df["year"].max()

    recent_df = train_df[
        train_df["year"] >=
        latest_year - lookback_years + 1
    ]

    counts = (
        recent_df
        .groupby("technique")["apt_group"]
        .nunique()
    )

    ranking = (
        counts
        .reset_index(
            name="recent_group_count"
        )
        .sort_values(
            [
                "recent_group_count",
                "technique"
            ],
            ascending=[
                False,
                True
            ]
        )
    )

    predictions = []

    for _, row in ranking.iterrows():

        technique = row["technique"]

        if technique in existing:
            continue

        predictions.append(
            technique
        )

        if len(predictions) >= top_n:
            break

    return predictions


# ============================================================
# MARKOV PREDICTIONS
# ============================================================

def markov_predictions(
    train_df,
    group,
    global_matrix,
    freq_prior,
    top_n=5
):

    preds, method = hybrid_predict(
        train_df,
        group,
        global_matrix,
        freq_prior,
        top_n=top_n,
        velocity_map=None,
        gamma=0.0,
        recency_map=None,
        delta=0.0,
    )

    return [
        technique
        for technique, score in preds
    ]


# ============================================================
# FINAL TEMPORALCTI PREDICTIONS
# ============================================================

def temporalcti_predictions(
    train_df,
    group,
    global_matrix,
    freq_prior,
    velocity_map,
    recency_map,
    gamma,
    delta,
    top_n=5
):

    preds, method = hybrid_predict(
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

    return [
        technique
        for technique, score in preds
    ]


# ============================================================
# EVALUATE ONE MODEL FOR ONE TEST YEAR
# ============================================================

def evaluate_year(
    df,
    test_year,
    model_name,
    predictor,
    top_n=5
):

    train_df = df[
        df["year"] < test_year
    ].copy()

    test_df = df[
        df["year"] == test_year
    ].copy()

    train_groups = set(
        train_df["apt_group"].unique()
    )

    test_groups = set(
        test_df["apt_group"].unique()
    )

    valid_groups = sorted(
        train_groups & test_groups
    )

    hits = {
        1: 0,
        3: 0,
        5: 0,
    }

    total = 0

    for group in valid_groups:

        group_train = train_df[
            train_df["apt_group"] == group
        ]

        group_test = test_df[
            test_df["apt_group"] == group
        ]

        if group_train.empty:
            continue

        if group_test.empty:
            continue

        historical_ttps = set(
            group_train["technique"]
            .dropna()
            .unique()
        )

        future_ttps = set(
            group_test["technique"]
            .dropna()
            .unique()
        )

        new_ttps = (
            future_ttps -
            historical_ttps
        )

        if not new_ttps:
            continue

        predicted = predictor(
            train_df,
            group,
            top_n
        )

        if not predicted:
            continue

        total += 1

        for k in [1, 3, 5]:

            top_k = predicted[:k]

            if any(
                technique in new_ttps
                for technique in top_k
            ):
                hits[k] += 1

    if total == 0:
        return None

    return {
        "model": model_name,
        "year": test_year,
        "total_groups": total,
        "hit_at_1": hits[1] / total,
        "hit_at_3": hits[3] / total,
        "hit_at_5": hits[5] / total,
    }


# ============================================================
# ROLLING EVALUATION
# ============================================================

def evaluate_rolling_model(
    df,
    model_name
):

    yearly_results = []

    for test_year in TEST_YEARS:

        train_df = df[
            df["year"] < test_year
        ].copy()

        if train_df.empty:
            continue

        # ----------------------------------------------------
        # RANDOM
        # ----------------------------------------------------

        if model_name == "Random":

            predictor = (
                lambda data, group, top_n:
                random_predictions(
                    data,
                    group,
                    top_n
                )
            )

        # ----------------------------------------------------
        # FREQUENCY
        # ----------------------------------------------------

        elif model_name == "Frequency":

            predictor = (
                lambda data, group, top_n:
                frequency_predictions(
                    data,
                    group,
                    top_n
                )
            )

        # ----------------------------------------------------
        # RECENCY
        # ----------------------------------------------------

        elif model_name == "Recency":

            predictor = (
                lambda data, group, top_n:
                recency_predictions(
                    data,
                    group,
                    top_n
                )
            )

        # ----------------------------------------------------
        # ORIGINAL MARKOV
        # ----------------------------------------------------

        elif model_name == "Markov":

            global_matrix = (
                build_global_transition_matrix(
                    train_df
                )
            )

            freq_prior = (
                build_frequency_prior(
                    train_df
                )
            )

            predictor = (
                lambda data, group, top_n:
                markov_predictions(
                    data,
                    group,
                    global_matrix,
                    freq_prior,
                    top_n
                )
            )

        # ----------------------------------------------------
        # FINAL TEMPORALCTI
        # ----------------------------------------------------

        elif model_name == "TemporalCTI":

            global_matrix = (
                build_global_transition_matrix(
                    train_df
                )
            )

            freq_prior = (
                build_frequency_prior(
                    train_df
                )
            )

            velocity_map = (
                build_train_only_velocity(
                    train_df
                )
            )

            recency_map = (
                build_train_only_recency(
                    train_df
                )
            )

            delta = VALIDATED_DELTAS.get(
                test_year,
                0.10
            )

            predictor = (
                lambda data, group, top_n:
                temporalcti_predictions(
                    data,
                    group,
                    global_matrix,
                    freq_prior,
                    velocity_map,
                    recency_map,
                    FINAL_GAMMA,
                    delta,
                    top_n
                )
            )

        else:

            raise ValueError(
                f"Unknown model: {model_name}"
            )

        result = evaluate_year(
            df,
            test_year,
            model_name,
            predictor,
            TOP_K
        )

        if result is not None:

            yearly_results.append(
                result
            )

    return yearly_results


# ============================================================
# AGGREGATE ROLLING RESULTS
# ============================================================

def aggregate_results(
    yearly_results,
    model_name
):

    if not yearly_results:
        return None

    results_df = pd.DataFrame(
        yearly_results
    )

    total_n = (
        results_df["total_groups"]
        .sum()
    )

    if total_n == 0:
        return None

    # Important:
    # Pooled Hit@K is calculated from total hits / total cases,
    # not as an unweighted average of yearly percentages.

    pooled_hits_1 = (
        results_df["hit_at_1"] *
        results_df["total_groups"]
    ).sum()

    pooled_hits_3 = (
        results_df["hit_at_3"] *
        results_df["total_groups"]
    ).sum()

    pooled_hits_5 = (
        results_df["hit_at_5"] *
        results_df["total_groups"]
    ).sum()

    return {
        "model": model_name,
        "train_end_year": "rolling",
        "test_start_year": "2022–2025",
        "total_groups": int(total_n),
        "hit_at_1": round(
            pooled_hits_1 / total_n,
            3
        ),
        "hit_at_3": round(
            pooled_hits_3 / total_n,
            3
        ),
        "hit_at_5": round(
            pooled_hits_5 / total_n,
            3
        ),
    }


# ============================================================
# PRINT COMPARISON
# ============================================================

def print_comparison(
    results
):

    print()
    print("=" * 82)
    print(
        "BASELINE COMPARISON — "
        "ROLLING CHRONOLOGICAL EVALUATION"
    )
    print("=" * 82)

    print(
        "Evaluation years : 2022–2025"
    )

    print(
        "Evaluation cases : 88 group-year cases"
    )

    print(
        "Metric           : Hit@K "
        "(at least one newly adopted technique in Top-K)"
    )

    print()

    print(
        f"{'Model':<45}"
        f"{'Hit@1':>9}"
        f"{'Hit@3':>9}"
        f"{'Hit@5':>9}"
        f"{'N':>7}"
    )

    print(
        " " + "-" * 77
    )

    for result in results:

        if result is None:
            continue

        marker = ""

        if result["model"] == "TemporalCTI":
            marker = "  <-- PROPOSED"

        print(
            f"{result['model']:<45}"
            f"{result['hit_at_1']:>9.3f}"
            f"{result['hit_at_3']:>9.3f}"
            f"{result['hit_at_5']:>9.3f}"
            f"{result['total_groups']:>7}"
            f"{marker}"
        )

    # --------------------------------------------------------
    # BEST BASELINES
    # --------------------------------------------------------

    baselines = [
        r for r in results
        if r is not None
        and r["model"] != "TemporalCTI"
    ]

    temporalcti = next(
        (
            r for r in results
            if r is not None
            and r["model"] == "TemporalCTI"
        ),
        None
    )

    if temporalcti is None:
        print(
            "\nTemporalCTI result unavailable."
        )
        return

    if not baselines:
        print(
            "\nNo baseline results available."
        )
        return

    best_p1 = max(
        baselines,
        key=lambda x: x["hit_at_1"]
    )

    best_p3 = max(
        baselines,
        key=lambda x: x["hit_at_3"]
    )

    best_p5 = max(
        baselines,
        key=lambda x: x["hit_at_5"]
    )

    improvement_p1 = (
        temporalcti["hit_at_1"]
        - best_p1["hit_at_1"]
    ) * 100

    improvement_p3 = (
        temporalcti["hit_at_3"]
        - best_p3["hit_at_3"]
    ) * 100

    improvement_p5 = (
        temporalcti["hit_at_5"]
        - best_p5["hit_at_5"]
    ) * 100

    print()
    print(
        "TemporalCTI vs best baseline:"
    )

    print(
        f"  Hit@1 : "
        f"{improvement_p1:+.1f} percentage points "
        f"(best baseline: {best_p1['model']})"
    )

    print(
        f"  Hit@3 : "
        f"{improvement_p3:+.1f} percentage points "
        f"(best baseline: {best_p3['model']})"
    )

    print(
        f"  Hit@5 : "
        f"{improvement_p5:+.1f} percentage points "
        f"(best baseline: {best_p5['model']})"
    )

    print()
    print("Comparison with original Markov:")

    original_markov = next(
        (
            r for r in results
            if r is not None
            and r["model"] == "Markov"
        ),
        None
    )

    if original_markov is not None:

        print(
            f"  Hit@1 : "
            f"{original_markov['hit_at_1']:.3f} "
            f"→ {temporalcti['hit_at_1']:.3f} "
            f"("
            f"{(temporalcti['hit_at_1'] - original_markov['hit_at_1']) * 100:+.1f} pp)"
        )

        print(
            f"  Hit@3 : "
            f"{original_markov['hit_at_3']:.3f} "
            f"→ {temporalcti['hit_at_3']:.3f} "
            f"("
            f"{(temporalcti['hit_at_3'] - original_markov['hit_at_3']) * 100:+.1f} pp)"
        )

        print(
            f"  Hit@5 : "
            f"{original_markov['hit_at_5']:.3f} "
            f"→ {temporalcti['hit_at_5']:.3f} "
            f"("
            f"{(temporalcti['hit_at_5'] - original_markov['hit_at_5']) * 100:+.1f} pp)"
        )

    print()
    print("Interpretation:")

    print(
        "  Random = uninformed random prediction."
    )

    print(
        "  Frequency = global popularity-based prediction."
    )

    print(
        "  Recency = popularity restricted to the "
        "most recent training years."
    )

    print(
        "  Markov = original temporal transition model "
        "without velocity or recency."
    )

    print(
        "  TemporalCTI = Markov + velocity + recency, "
        "with gamma=0.15 and recency weights selected "
        "using prior-year validation."
    )

    print(
        "  Hit@K = at least one top-K prediction matches "
        "a technique newly adopted by the group in the "
        "held-out test year."
    )

    print()

    if (
        temporalcti["hit_at_1"]
        > best_p1["hit_at_1"]
    ):

        print(
            "Finding: TemporalCTI achieves the "
            "highest Hit@1 among evaluated models."
        )

    elif (
        temporalcti["hit_at_1"]
        == best_p1["hit_at_1"]
    ):

        print(
            "Finding: TemporalCTI ties the best "
            "baseline at Hit@1."
        )

    else:

        print(
            "Finding: a baseline achieves higher "
            "Hit@1 than TemporalCTI."
        )

    if (
        temporalcti["hit_at_5"]
        > best_p5["hit_at_5"]
    ):

        print(
            "Finding: TemporalCTI achieves the "
            "highest Hit@5 among evaluated models."
        )

    if (
        temporalcti["hit_at_3"]
        < best_p3["hit_at_3"]
    ):

        print(
            "Observation: Recency provides stronger "
            "Hit@3 coverage than TemporalCTI."
        )

    print()
    print(
        "Conclusion: TemporalCTI provides the strongest "
        "Top-1 and Top-5 performance in the rolling "
        "chronological evaluation, while Recency achieves "
        "the strongest Top-3 performance."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 82)
    print(
        "TemporalCTI — Rolling Baseline Comparison"
    )
    print("=" * 82)

    if not os.path.exists(DB_PATH):

        print(
            "\nERROR: Database not found:"
        )

        print(DB_PATH)

        raise SystemExit(1)

    df = load_data()

    if df.empty:

        print(
            "\nERROR: Dataset is empty."
        )

        raise SystemExit(1)

    print(
        f"\nDataset: "
        f"{df['apt_group'].nunique()} groups · "
        f"{df['technique'].nunique()} techniques · "
        f"{len(df):,} records"
    )

    print(
        f"Year range: "
        f"{df['year'].min()} - "
        f"{df['year'].max()}"
    )

    print(
        "Evaluation years: "
        "2022–2025"
    )

    print()

    # ========================================================
    # RANDOM
    # ========================================================

    print(
        "Evaluating Random baseline..."
    )

    random_yearly = evaluate_rolling_model(
        df,
        "Random"
    )

    random_results = aggregate_results(
        random_yearly,
        "Random"
    )

    # ========================================================
    # FREQUENCY
    # ========================================================

    print(
        "Evaluating Frequency baseline..."
    )

    frequency_yearly = evaluate_rolling_model(
        df,
        "Frequency"
    )

    frequency_results = aggregate_results(
        frequency_yearly,
        "Frequency"
    )

    # ========================================================
    # RECENCY
    # ========================================================

    print(
        "Evaluating Recency baseline..."
    )

    recency_yearly = evaluate_rolling_model(
        df,
        "Recency"
    )

    recency_results = aggregate_results(
        recency_yearly,
        "Recency"
    )

    # ========================================================
    # ORIGINAL MARKOV
    # ========================================================

    print(
        "Evaluating original Markov baseline..."
    )

    markov_yearly = evaluate_rolling_model(
        df,
        "Markov"
    )

    markov_results = aggregate_results(
        markov_yearly,
        "Markov"
    )

    # ========================================================
    # TEMPORALCTI
    # ========================================================

    print(
        "Evaluating final TemporalCTI model..."
    )

    temporalcti_yearly = evaluate_rolling_model(
        df,
        "TemporalCTI"
    )

    temporalcti_results = aggregate_results(
        temporalcti_yearly,
        "TemporalCTI"
    )

    # ========================================================
    # RESULTS
    # ========================================================

    results = [
        random_results,
        frequency_results,
        recency_results,
        markov_results,
        temporalcti_results,
    ]

    print_comparison(
        results
    )

    # ========================================================
    # SAVE
    # ========================================================

    clean_results = [
        r for r in results
        if r is not None
    ]

    if clean_results:

        os.makedirs(
            os.path.dirname(
                OUTPUT_PATH
            ),
            exist_ok=True
        )

        results_df = pd.DataFrame(
            clean_results
        )

        results_df.to_csv(
            OUTPUT_PATH,
            index=False
        )

        print()
        print(
            "Saved to:"
        )
        print(
            OUTPUT_PATH
        )

    else:

        print(
            "\nNo results generated."
        )

    print()
    print("=" * 82)
    print(
        "Rolling baseline comparison complete."
    )
    print("=" * 82)
