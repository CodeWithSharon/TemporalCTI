import os
import sys
import sqlite3
import random

import pandas as pd


# ============================================================
# IMPORT THE REAL, ABLATED MODEL
# ============================================================
#
# IMPORTANT FIX: this used to import build_model_signals/predict_group
# from mp.py - the old 5-signal "TemporalCTI" model that the original
# baseline run showed LOSING to a plain Markov baseline (P@1 0.103 vs
# 0.128). That model was discarded. The real, current model lives in
# markov_prediction.py: the original Markov model plus a velocity
# backoff term, individually ablation-tested and kept because it
# improved P@1 from 0.128 -> 0.231 (see gamma_sensitivity_analysis in
# that file). This import is now pointed at the correct file so this
# comparison reflects the actual proposed model, not a discarded one.

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

ANALYSIS_PATH = os.path.join(
    PROJECT_ROOT,
    "src",
    "analysis"
)

if ANALYSIS_PATH not in sys.path:
    sys.path.insert(
        0,
        ANALYSIS_PATH
    )

from markov_prediction import (
    build_global_transition_matrix,
    build_frequency_prior,
    build_train_only_velocity,
    hybrid_predict,
)

# Chosen gamma from the ablation in markov_prediction.py's
# gamma_sensitivity_analysis - P@1 improves up to gamma=0.15 and
# plateaus after that, so 0.15 is the smallest gamma reaching the
# plateau (see conversation history / paper methodology section).
FINAL_GAMMA = 0.15


# ============================================================
# CONFIGURATION
# ============================================================

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

VALIDATION_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "prediction_validation.csv"
)

TRAIN_END_YEAR = 2023
TEST_START_YEAR = 2024

TOP_K = 5

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

    conn = sqlite3.connect(
        DB_PATH
    )

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
# BASELINE 1 — RANDOM
# ============================================================

def random_baseline(
    df,
    apt_group,
    top_n=5,
    seed=42
):
    group_df = df[
        df["apt_group"] == apt_group
    ]

    existing = set(
        group_df["technique"]
        .dropna()
        .unique()
    )

    all_techniques = sorted(
        set(df["technique"].dropna().unique())
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
# BASELINE 2 — FREQUENCY / POPULARITY
# ============================================================

def frequency_baseline(
    df,
    apt_group,
    top_n=5
):
    group_df = df[
        df["apt_group"] == apt_group
    ]

    existing = set(
        group_df["technique"]
        .dropna()
        .unique()
    )

    counts = (
        df
        .groupby("technique")["apt_group"]
        .nunique()
    )

    ranking = (
        counts
        .reset_index(name="group_count")
        .sort_values(
            ["group_count", "technique"],
            ascending=[False, True]
        )
    )

    predictions = []

    for _, row in ranking.iterrows():

        technique = row["technique"]

        if technique in existing:
            continue

        predictions.append(technique)

        if len(predictions) >= top_n:
            break

    return predictions


# ============================================================
# BASELINE 3 — ORIGINAL MARKOV (frozen, pre-ablation model)
# ============================================================
#
# This is the row that was missing before: the plain Markov model with
# no velocity term (gamma=0.0), the frozen baseline every other signal
# was tested against in markov_prediction.py. Including it here is
# what makes the comparison honest - it's the most obvious baseline
# for a temporal-prediction task and was previously absent.

def make_markov_predict_fn(
    global_matrix,
    freq_prior,
    velocity_map=None,
    gamma=0.0
):
    """
    Returns a predict_fn(train_df, apt_group, top_n) -> [technique, ...]
    compatible with evaluate_baseline(), wrapping markov_prediction.py's
    hybrid_predict at a fixed gamma. gamma=0.0 (default) reproduces the
    original frozen model; gamma=FINAL_GAMMA gives the ablation-selected
    final model.
    """

    def _predict(train_df, apt_group, top_n):

        preds, method = hybrid_predict(
            train_df,
            apt_group,
            global_matrix,
            freq_prior,
            top_n=top_n,
            velocity_map=velocity_map,
            gamma=gamma,
        )

        return [technique for technique, score in preds]

    return _predict


# ============================================================
# HELD-OUT BASELINE EVALUATION
# ============================================================

def evaluate_baseline(
    df,
    predict_fn,
    label
):
    train_df = df[
        df["year"] <= TRAIN_END_YEAR
    ].copy()

    test_df = df[
        df["year"] >= TEST_START_YEAR
    ].copy()

    train_groups = set(train_df["apt_group"].unique())
    test_groups = set(test_df["apt_group"].unique())

    valid_groups = sorted(train_groups & test_groups)

    hits = {1: 0, 3: 0, 5: 0}
    total = 0

    for group in valid_groups:

        group_train = train_df[train_df["apt_group"] == group]
        group_test = test_df[test_df["apt_group"] == group]

        if group_train.empty:
            continue

        if group_test.empty:
            continue

        historical_ttps = set(
            group_train["technique"].dropna().unique()
        )

        future_ttps = set(
            group_test["technique"].dropna().unique()
        )

        new_ttps = future_ttps - historical_ttps

        if not new_ttps:
            continue

        predicted = predict_fn(
            train_df,
            group,
            TOP_K
        )

        if not predicted:
            continue

        total += 1

        for k in [1, 3, 5]:

            top_k = predicted[:k]

            if any(technique in new_ttps for technique in top_k):
                hits[k] += 1

    if total == 0:
        return None

    return {
        "model": label,
        "train_end_year": TRAIN_END_YEAR,
        "test_start_year": TEST_START_YEAR,
        "total_groups": total,
        "hit_at_1": round(hits[1] / total, 3),
        "hit_at_3": round(hits[3] / total, 3),
        "hit_at_5": round(hits[5] / total, 3),
    }


# ============================================================
# LOAD FINAL-MODEL VALIDATION RESULTS FROM markov_prediction.py's CSV
# ============================================================

def load_temporalcti_results():
    """
    Reads data/processed/prediction_validation.csv, which
    markov_prediction.py now writes using gamma=0.15 (the ablation-
    selected final model) - see held_out_validation(df, global_matrix,
    gamma=0.15) in that file's __main__ block. So these numbers already
    reflect Markov + velocity backoff, not the frozen baseline and not
    the old discarded 5-signal model.
    """

    try:
        val_df = pd.read_csv(VALIDATION_PATH)

    except FileNotFoundError:
        print("\nERROR:")
        print(f"Missing:\n{VALIDATION_PATH}")
        print("\nRun markov_prediction.py first:")
        print("python src/analysis/markov_prediction.py")
        return None

    if val_df.empty:
        print("\nERROR:")
        print("prediction_validation.csv is empty.")
        return None

    row = val_df.iloc[0]

    if "hit_at_1" in val_df.columns:
        hit1 = float(row["hit_at_1"])
        hit3 = float(row["hit_at_3"])
        hit5 = float(row["hit_at_5"])

    elif "precision_at_1" in val_df.columns:
        hit1 = float(row["precision_at_1"])
        hit3 = float(row["precision_at_3"])
        hit5 = float(row["precision_at_5"])

    else:
        print("\nERROR:")
        print("Could not find Hit@K columns in validation file.")
        return None

    # Real, current model name - not the old "Temporal Multi-Signal"
    # label, since that system was discarded during ablation.
    model_name = f"TemporalCTI (Markov + Velocity, gamma={FINAL_GAMMA})"

    if "model" in val_df.columns:
        stored_model = str(row["model"])
        if stored_model.strip():
            model_name = stored_model

    if "total_groups" in val_df.columns:
        total_groups = int(row["total_groups"])
    else:
        total_groups = 0

    return {
        "model": model_name,
        "train_end_year": TRAIN_END_YEAR,
        "test_start_year": TEST_START_YEAR,
        "total_groups": total_groups,
        "hit_at_1": hit1,
        "hit_at_3": hit3,
        "hit_at_5": hit5,
    }


# ============================================================
# FALLBACK — RECOMPUTE FINAL MODEL DIRECTLY IF CSV IS MISSING
# ============================================================

def evaluate_temporalcti_direct(
    df,
    top_n=5
):
    """
    Directly evaluates the real final model (Markov + velocity backoff,
    gamma=0.15) using ONLY training data to build every signal - no
    leakage from the test period. This replaces the old fallback that
    called into mp.py's build_model_signals/predict_group (the
    discarded 5-signal model); that no longer reflects the proposed
    model and has been removed.
    """

    train_df = df[df["year"] <= TRAIN_END_YEAR].copy()
    test_df = df[df["year"] >= TEST_START_YEAR].copy()

    if train_df.empty or test_df.empty:
        return None

    train_global = build_global_transition_matrix(train_df)
    train_freq = build_frequency_prior(train_df)
    train_velocity = build_train_only_velocity(train_df)

    predict_fn = make_markov_predict_fn(
        train_global,
        train_freq,
        velocity_map=train_velocity,
        gamma=FINAL_GAMMA,
    )

    result = evaluate_baseline(
        df,
        predict_fn,
        f"TemporalCTI (Markov + Velocity, gamma={FINAL_GAMMA})",
    )

    return result


# ============================================================
# COMPARISON
# ============================================================

def print_comparison(results):

    print()
    print("=" * 78)
    print("BASELINE COMPARISON — HELD-OUT TEMPORAL VALIDATION")
    print("=" * 78)
    print(f"Training period : <= {TRAIN_END_YEAR}")
    print(f"Testing period  : >= {TEST_START_YEAR}")
    print()

    print(
        f"{'Model':<42}"
        f"{'Hit@1':>8}"
        f"{'Hit@3':>8}"
        f"{'Hit@5':>8}"
        f"{'N':>6}"
    )

    print(" " + "-" * 72)

    for result in results:

        if result is None:
            continue

        marker = ""

        if "TemporalCTI" in result["model"]:
            marker = "  <-- PROPOSED"

        print(
            f"{result['model']:<42}"
            f"{result['hit_at_1']:>8.3f}"
            f"{result['hit_at_3']:>8.3f}"
            f"{result['hit_at_5']:>8.3f}"
            f"{result['total_groups']:>6}"
            f"{marker}"
        )

    # ========================================================
    # SEPARATE BASELINES FROM THE PROPOSED MODEL
    # ========================================================
    #
    # Anything not named "TemporalCTI" is a baseline - this now
    # includes Random, Frequency, AND the original (frozen) Markov
    # model, so "best baseline" below is computed against the full,
    # honest set including the one that used to be missing.

    baselines = [
        result for result in results
        if result is not None and "TemporalCTI" not in result["model"]
    ]

    temporalcti = next(
        (
            result for result in results
            if result is not None and "TemporalCTI" in result["model"]
        ),
        None
    )

    if not baselines:
        print("\nNo baseline results available.")
        return

    if temporalcti is None:
        print("\nTemporalCTI validation results not available.")
        return

    best_p1 = max(baselines, key=lambda x: x["hit_at_1"])
    best_p3 = max(baselines, key=lambda x: x["hit_at_3"])
    best_p5 = max(baselines, key=lambda x: x["hit_at_5"])

    improvement_p1 = (temporalcti["hit_at_1"] - best_p1["hit_at_1"]) * 100
    improvement_p3 = (temporalcti["hit_at_3"] - best_p3["hit_at_3"]) * 100
    improvement_p5 = (temporalcti["hit_at_5"] - best_p5["hit_at_5"]) * 100

    print()
    print("TemporalCTI improvement over best baseline:")

    print(
        f"  Hit@1 : {improvement_p1:+.1f} percentage points "
        f"(best: {best_p1['model']})"
    )

    print(
        f"  Hit@3 : {improvement_p3:+.1f} percentage points "
        f"(best: {best_p3['model']})"
    )

    print(
        f"  Hit@5 : {improvement_p5:+.1f} percentage points "
        f"(best: {best_p5['model']})"
    )

    print()
    print("Interpretation:")
    print("  Random baseline = uninformed prediction.")
    print("  Frequency baseline = global popularity-based prediction.")
    print("  Markov (original) = the frozen model every added signal")
    print("    was ablation-tested against.")
    print(
        f"  TemporalCTI = Markov + velocity backoff (gamma={FINAL_GAMMA}), "
        f"kept because it was the one signal, of two independently"
    )
    print("    tested (velocity, recency), that actually improved Hit@1")
    print("    over the frozen Markov baseline.")
    print(
        "  Hit@K = at least one top-K prediction matches a newly "
        "adopted technique."
    )
    print()

    if temporalcti["hit_at_1"] > best_p1["hit_at_1"]:
        print("Finding: TemporalCTI achieves the strongest Top-1 predictive performance.")

    elif temporalcti["hit_at_1"] == best_p1["hit_at_1"]:
        print("Finding: TemporalCTI ties the best baseline at Top-1.")

    else:
        print("Finding: A baseline achieves stronger Top-1 performance than TemporalCTI.")

    if (
        temporalcti["hit_at_3"] < best_p3["hit_at_3"]
        or temporalcti["hit_at_5"] < best_p5["hit_at_5"]
    ):
        print(
            "Observation: A frequency/popularity baseline may provide "
            "stronger broader Top-K coverage."
        )

    print()
    print(
        "Conclusion: TemporalCTI is evaluated against Random, Frequency, "
        "and the original (pre-ablation) Markov model using the same "
        "strict temporal split. Velocity was kept because it improved "
        "Hit@1 in isolation; recency was tested the same way and "
        "discarded because it did not."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 78)
    print("TemporalCTI — Baseline Comparison")
    print("=" * 78)

    print("\nLoading dataset...")

    if not os.path.exists(DB_PATH):
        print("\nERROR: Database not found:")
        print(DB_PATH)
        raise SystemExit(1)

    df = load_data()

    if df.empty:
        print("\nERROR: Dataset is empty.")
        raise SystemExit(1)

    print(
        f"Dataset: {df['apt_group'].nunique()} groups · "
        f"{df['technique'].nunique()} techniques · "
        f"{len(df):,} records"
    )

    print(f"Year range: {df['year'].min()} - {df['year'].max()}")
    print(f"Training period : <= {TRAIN_END_YEAR}")
    print(f"Testing period  : >= {TEST_START_YEAR}")

    # ========================================================
    # RANDOM BASELINE
    # ========================================================

    print("\nEvaluating Random baseline...")

    random_results = evaluate_baseline(
        df,
        lambda data, group, top_n: random_baseline(data, group, top_n),
        "Random"
    )

    # ========================================================
    # FREQUENCY BASELINE
    # ========================================================

    print("Evaluating Frequency baseline...")

    frequency_results = evaluate_baseline(
        df,
        lambda data, group, top_n: frequency_baseline(data, group, top_n),
        "Frequency (popularity)"
    )

    # ========================================================
    # ORIGINAL MARKOV BASELINE (previously missing)
    # ========================================================

    print("Evaluating original Markov baseline (gamma=0, frozen)...")

    train_df_for_markov = df[df["year"] <= TRAIN_END_YEAR].copy()
    markov_global = build_global_transition_matrix(train_df_for_markov)
    markov_freq = build_frequency_prior(train_df_for_markov)

    markov_original_predict_fn = make_markov_predict_fn(
        markov_global,
        markov_freq,
        velocity_map=None,
        gamma=0.0,
    )

    markov_original_results = evaluate_baseline(
        df,
        markov_original_predict_fn,
        "Markov (original, frozen baseline)"
    )

    # ========================================================
    # TEMPORALCTI (Markov + Velocity, the real final model)
    # ========================================================

    print("Loading TemporalCTI held-out validation...")

    temporalcti_results = load_temporalcti_results()

    if temporalcti_results is None:
        print("\nAttempting direct TemporalCTI validation...")
        temporalcti_results = evaluate_temporalcti_direct(df, top_n=TOP_K)

    # ========================================================
    # COMBINE RESULTS
    # ========================================================

    results = [
        random_results,
        frequency_results,
        markov_original_results,
        temporalcti_results,
    ]

    print_comparison(results)

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    clean_results = [result for result in results if result is not None]

    if clean_results:

        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

        results_df = pd.DataFrame(clean_results)
        results_df.to_csv(OUTPUT_PATH, index=False)

        print()
        print("Saved to:")
        print(OUTPUT_PATH)

    else:
        print("\nNo results generated.")

    print()
    print("=" * 78)
    print("Baseline comparison complete.")
    print("=" * 78)
