import sqlite3
import pandas as pd
import numpy as np
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

GENERIC_TECHNIQUES = {
    'Tool',
    'Malware',
    'Vulnerability',
    'Exploits',
    'Audio-Visual Content',
    'Written Content',
}

# Final TemporalCTI weights
FINAL_GAMMA = 0.15

# Recency weights selected during prior-year validation
VALIDATED_DELTAS = {
    2022: 0.15,
    2023: 0.10,
    2024: 0.10,
    2025: 0.10,
}

DEFAULT_DELTA = 0.10


# ============================================================
# DATA LOADING
# ============================================================

def load_data():

    conn = sqlite3.connect(
        'data/temporal_db/apt.db'
    )

    try:
        df = pd.read_sql_query(
            "SELECT * FROM apt_timeline",
            conn
        )
    finally:
        conn.close()

    df = df[
        ~df['technique'].isin(
            GENERIC_TECHNIQUES
        )
    ].copy()

    df = df.dropna(
        subset=[
            'apt_group',
            'technique',
            'year'
        ]
    )

    df['year'] = pd.to_numeric(
        df['year'],
        errors='coerce'
    )

    df = df.dropna(
        subset=['year']
    )

    df['year'] = df['year'].astype(int)

    df = df.drop_duplicates(
        subset=[
            'apt_group',
            'technique',
            'year'
        ]
    )

    return df


# ============================================================
# MARKOV TRANSITION MODEL
# ============================================================

def build_global_transition_matrix(df):

    transitions = defaultdict(
        lambda: defaultdict(int)
    )

    for _, group_df in df.groupby(
        'apt_group'
    ):

        years = sorted(
            group_df['year'].unique()
        )

        if len(years) < 2:
            continue

        for i in range(
            len(years) - 1
        ):

            curr = set(
                group_df[
                    group_df['year'] == years[i]
                ]['technique']
            )

            nxt = set(
                group_df[
                    group_df['year'] == years[i + 1]
                ]['technique']
            )

            new = nxt - curr

            for src in curr:
                for tgt in new:
                    transitions[src][tgt] += 1

    global_matrix = {}

    for src, tgts in transitions.items():

        total = sum(
            tgts.values()
        )

        if total == 0:
            continue

        global_matrix[src] = {
            tgt: cnt / total
            for tgt, cnt in tgts.items()
        }

    return global_matrix


def build_local_transition_matrix(
    group_df
):

    transitions = defaultdict(
        lambda: defaultdict(int)
    )

    years = sorted(
        group_df['year'].unique()
    )

    if len(years) < 2:
        return {}

    for i in range(
        len(years) - 1
    ):

        curr = set(
            group_df[
                group_df['year'] == years[i]
            ]['technique']
        )

        nxt = set(
            group_df[
                group_df['year'] == years[i + 1]
            ]['technique']
        )

        new = nxt - curr

        for src in curr:
            for tgt in new:
                transitions[src][tgt] += 1

    local_matrix = {}

    for src, tgts in transitions.items():

        total = sum(
            tgts.values()
        )

        if total == 0:
            continue

        local_matrix[src] = {
            tgt: cnt / total
            for tgt, cnt in tgts.items()
        }

    return local_matrix


# ============================================================
# FREQUENCY PRIOR
# ============================================================

def build_frequency_prior(df):

    total_groups = (
        df['apt_group'].nunique()
    )

    if total_groups == 0:
        return {}

    counts = (
        df.groupby('technique')
        ['apt_group']
        .nunique()
    )

    return (
        counts / total_groups
    ).to_dict()


# ============================================================
# VELOCITY SIGNAL
# ============================================================

def build_train_only_velocity(
    train_df
):
    """
    Computes technique adoption velocity using
    ONLY the supplied training period.

    Training years are divided into an early half
    and a late half.

    velocity =
        late distinct-group adoption
        -
        early distinct-group adoption

    The result is min-max normalized to [0, 1].
    """

    if train_df.empty:
        return {}

    years = sorted(
        train_df['year'].unique()
    )

    if len(years) < 2:
        return {}

    mid = max(
        1,
        len(years) // 2
    )

    early_years = years[:mid]
    late_years = years[mid:]

    if not late_years:
        return {}

    early_counts = (
        train_df[
            train_df['year'].isin(
                early_years
            )
        ]
        .groupby('technique')
        ['apt_group']
        .nunique()
    )

    late_counts = (
        train_df[
            train_df['year'].isin(
                late_years
            )
        ]
        .groupby('technique')
        ['apt_group']
        .nunique()
    )

    all_techniques = (
        set(early_counts.index)
        |
        set(late_counts.index)
    )

    raw = {
        technique:
            late_counts.get(
                technique,
                0
            )
            -
            early_counts.get(
                technique,
                0
            )
        for technique in all_techniques
    }

    if not raw:
        return {}

    max_v = max(
        raw.values()
    )

    min_v = min(
        raw.values()
    )

    if max_v == min_v:
        return {
            technique: 0.0
            for technique in raw
        }

    return {
        technique:
            (value - min_v)
            /
            (max_v - min_v)
        for technique, value
        in raw.items()
    }


# ============================================================
# RECENCY SIGNAL
# ============================================================

def build_train_only_recency(
    train_df
):
    """
    Computes technique freshness using ONLY
    the supplied training period.

    Each technique receives a score based on
    the most recent year in which it was observed.

    Scores are min-max normalized to [0, 1].
    """

    if train_df.empty:
        return {}

    years = sorted(
        train_df['year'].unique()
    )

    if len(years) < 2:
        return {}

    last_seen = (
        train_df
        .groupby('technique')
        ['year']
        .max()
    )

    min_year = min(years)
    max_year = max(years)

    if min_year == max_year:
        return {
            technique: 0.0
            for technique
            in last_seen.index
        }

    return {
        technique:
            (year - min_year)
            /
            (max_year - min_year)
        for technique, year
        in last_seen.items()
    }


# ============================================================
# TEMPORALCTI MARKOV SCORING
# ============================================================

def temporalcti_markov_predict(
    group_df,
    global_matrix,
    freq_prior,
    top_n=5,
    alpha=0.3,
    beta=0.07,
    velocity_map=None,
    gamma=FINAL_GAMMA,
    recency_map=None,
    delta=DEFAULT_DELTA,
):
    """
    Core TemporalCTI prediction.

    Base:
        Local Markov + Global Markov + Frequency prior

    Temporal enhancements:
        + Velocity
        + Recency

    Final score:

        Markov/frequency score
            -> velocity adjustment
            -> recency adjustment

    gamma controls velocity.
    delta controls recency.
    """

    years = sorted(
        group_df['year'].unique()
    )

    if len(years) < 2:
        return [], 'insufficient_data'

    local_matrix = (
        build_local_transition_matrix(
            group_df
        )
    )

    max_year = group_df['year'].max()

    recent_ttps = set(
        group_df[
            group_df['year'] == max_year
        ]['technique']
    )

    existing = set(
        group_df['technique']
        .unique()
    )

    scores = defaultdict(float)

    # --------------------------------------------------------
    # MARKOV TRANSITION SCORE
    # --------------------------------------------------------

    for ttp in recent_ttps:

        local_row = (
            local_matrix.get(
                ttp,
                {}
            )
        )

        global_row = (
            global_matrix.get(
                ttp,
                {}
            )
        )

        candidates = (
            set(local_row.keys())
            |
            set(global_row.keys())
        )

        for target in candidates:

            if target in existing:
                continue

            local_probability = (
                local_row.get(
                    target,
                    0.0
                )
            )

            global_probability = (
                global_row.get(
                    target,
                    0.0
                )
            )

            scores[target] += (
                (1 - alpha)
                * local_probability
                +
                alpha
                * global_probability
            )

    # --------------------------------------------------------
    # FREQUENCY BACKOFF CANDIDATES
    # --------------------------------------------------------

    for target in freq_prior:

        if target in existing:
            continue

        if target not in scores:
            scores[target] = 0.0

    if not scores:
        return [], 'markov_no_candidates'

    # --------------------------------------------------------
    # FREQUENCY PRIOR
    # --------------------------------------------------------

    for target in scores:

        scores[target] = (
            (1 - beta)
            * scores[target]
            +
            beta
            * freq_prior.get(
                target,
                0.0
            )
        )

    # --------------------------------------------------------
    # VELOCITY SIGNAL
    # --------------------------------------------------------

    if (
        gamma > 0
        and velocity_map
    ):

        for target in scores:

            scores[target] = (
                (1 - gamma)
                * scores[target]
                +
                gamma
                * velocity_map.get(
                    target,
                    0.0
                )
            )

    # --------------------------------------------------------
    # RECENCY SIGNAL
    # --------------------------------------------------------

    if (
        delta > 0
        and recency_map
    ):

        for target in scores:

            scores[target] = (
                (1 - delta)
                * scores[target]
                +
                delta
                * recency_map.get(
                    target,
                    0.0
                )
            )

    # --------------------------------------------------------
    # DETERMINISTIC RANKING
    # --------------------------------------------------------

    ranked = sorted(
        scores.items(),
        key=lambda x: (
            -x[1],
            x[0]
        )
    )[:top_n]

    return ranked, 'temporalcti'


# ============================================================
# SIMILARITY FALLBACK
# ============================================================

def similarity_predict(
    df,
    apt_group,
    top_n=5
):

    target_ttps = set(
        df[
            df['apt_group'] == apt_group
        ]['technique']
        .unique()
    )

    similarities = {}

    for group, group_df in df.groupby(
        'apt_group'
    ):

        if group == apt_group:
            continue

        other_ttps = set(
            group_df['technique']
            .unique()
        )

        union = (
            target_ttps
            |
            other_ttps
        )

        if union:

            similarities[group] = (
                len(
                    target_ttps
                    &
                    other_ttps
                )
                /
                len(union)
            )

    top_peers = sorted(
        similarities.items(),
        key=lambda x: (
            -x[1],
            x[0]
        )
    )[:3]

    if not top_peers:
        return frequency_predict(
            df,
            apt_group,
            top_n
        )

    scores = defaultdict(float)

    existing = set(
        df[
            df['apt_group'] == apt_group
        ]['technique']
        .unique()
    )

    for peer, similarity in top_peers:

        peer_df = df[
            df['apt_group'] == peer
        ]

        latest_year = (
            peer_df['year'].max()
        )

        recent = set(
            peer_df[
                peer_df['year'] ==
                latest_year
            ]['technique']
        )

        for technique in (
            recent - existing
        ):

            scores[technique] += (
                similarity
            )

    if scores:

        ranked = sorted(
            scores.items(),
            key=lambda x: (
                -x[1],
                x[0]
            )
        )[:top_n]

        return ranked, 'similarity'

    return frequency_predict(
        df,
        apt_group,
        top_n
    )


# ============================================================
# FREQUENCY FALLBACK
# ============================================================

def frequency_predict(
    df,
    apt_group,
    top_n=5
):

    group_df = df[
        df['apt_group'] == apt_group
    ]

    existing = set(
        group_df['technique']
        .unique()
    )

    total_groups = (
        df['apt_group'].nunique()
    )

    if total_groups == 0:
        return [], 'frequency'

    counts = (
        df.groupby('technique')
        ['apt_group']
        .nunique()
    )

    ranking = (
        counts
        .reset_index(
            name='group_count'
        )
        .sort_values(
            [
                'group_count',
                'technique'
            ],
            ascending=[
                False,
                True
            ]
        )
    )

    predictions = []

    for _, row in ranking.iterrows():

        technique = row['technique']

        if technique in existing:
            continue

        predictions.append(
            (
                technique,
                round(
                    row['group_count']
                    /
                    total_groups,
                    3
                )
            )
        )

        if len(predictions) >= top_n:
            break

    return predictions, 'frequency'


# ============================================================
# TEMPORALCTI HYBRID PREDICTOR
# ============================================================

def hybrid_predict(
    df,
    apt_group,
    global_matrix,
    freq_prior,
    top_n=5,
    alpha=None,
    beta=0.07,
    velocity_map=None,
    gamma=FINAL_GAMMA,
    recency_map=None,
    delta=DEFAULT_DELTA,
):
    """
    Final TemporalCTI hybrid prediction.

    Tier 1:
        >= 2 years
        Markov + Velocity + Recency

    Tier 2:
        1-year groups
        Similarity prediction

    Tier 3:
        Frequency fallback

    alpha:
        >= 4 years -> 0.3
        2-3 years  -> 0.7
    """

    group_df = df[
        df['apt_group'] == apt_group
    ]

    years = sorted(
        group_df['year'].unique()
    )

    n_years = len(years)

    # --------------------------------------------------------
    # MARKOV + TEMPORAL SIGNALS
    # --------------------------------------------------------

    if n_years >= 2:

        if alpha is None:

            effective_alpha = (
                0.3
                if n_years >= 4
                else 0.7
            )

        else:

            effective_alpha = alpha

        predictions, method = (
            temporalcti_markov_predict(
                group_df,
                global_matrix,
                freq_prior,
                top_n=top_n,
                alpha=effective_alpha,
                beta=beta,
                velocity_map=velocity_map,
                gamma=gamma,
                recency_map=recency_map,
                delta=delta,
            )
        )

        if predictions:
            return predictions, method

    # --------------------------------------------------------
    # DATA-SPARSE FALLBACK
    # --------------------------------------------------------

    return similarity_predict(
        df,
        apt_group,
        top_n
    )


# ============================================================
# TRAIN-ONLY TEMPORAL SIGNALS
# ============================================================

def build_temporal_signals(
    train_df,
    gamma=FINAL_GAMMA,
    delta=DEFAULT_DELTA
):

    velocity_map = (
        build_train_only_velocity(
            train_df
        )
        if gamma > 0
        else None
    )

    recency_map = (
        build_train_only_recency(
            train_df
        )
        if delta > 0
        else None
    )

    return (
        velocity_map,
        recency_map
    )


# ============================================================
# HELD-OUT VALIDATION
# ============================================================

def held_out_validation(
    df,
    test_year_cutoff=2024,
    gamma=FINAL_GAMMA,
    delta=DEFAULT_DELTA
):

    print(
        f"\nTemporalCTI Held-out Validation "
        f"(train: <{test_year_cutoff}, "
        f"test: >={test_year_cutoff})"
    )

    print("=" * 60)

    train_df = df[
        df['year'] < test_year_cutoff
    ].copy()

    test_df = df[
        df['year'] >= test_year_cutoff
    ].copy()

    if train_df.empty or test_df.empty:

        print(
            "No train/test data available."
        )

        return None

    train_groups = set(
        train_df['apt_group'].unique()
    )

    test_groups = set(
        test_df['apt_group'].unique()
    )

    valid_groups = sorted(
        train_groups & test_groups
    )

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

    velocity_map, recency_map = (
        build_temporal_signals(
            train_df,
            gamma=gamma,
            delta=delta
        )
    )

    hits = {
        1: 0,
        3: 0,
        5: 0,
    }

    total = 0

    method_counts = defaultdict(int)

    for group in valid_groups:

        group_train = train_df[
            train_df['apt_group'] == group
        ]

        group_test = test_df[
            test_df['apt_group'] == group
        ]

        if (
            group_train.empty
            or group_test.empty
        ):
            continue

        historical = set(
            group_train['technique']
            .unique()
        )

        future = set(
            group_test['technique']
            .unique()
        )

        new_ttps = (
            future - historical
        )

        if not new_ttps:
            continue

        predictions, method = (
            hybrid_predict(
                train_df,
                group,
                global_matrix,
                freq_prior,
                top_n=5,
                velocity_map=velocity_map,
                gamma=gamma,
                recency_map=recency_map,
                delta=delta,
            )
        )

        if not predictions:
            continue

        predicted = [
            technique
            for technique, score
            in predictions
        ]

        method_counts[method] += 1

        total += 1

        for k in [1, 3, 5]:

            if any(
                technique in new_ttps
                for technique
                in predicted[:k]
            ):

                hits[k] += 1

    if total == 0:

        print(
            "No valid groups."
        )

        return None

    hit_at_1 = (
        hits[1] / total
    )

    hit_at_3 = (
        hits[3] / total
    )

    hit_at_5 = (
        hits[5] / total
    )

    print(
        f"\nResults "
        f"({total} groups evaluated):"
    )

    print(
        f"  Hit@1 : "
        f"{hit_at_1:.3f}"
        f" ({hits[1]}/{total})"
    )

    print(
        f"  Hit@3 : "
        f"{hit_at_3:.3f}"
        f" ({hits[3]}/{total})"
    )

    print(
        f"  Hit@5 : "
        f"{hit_at_5:.3f}"
        f" ({hits[5]}/{total})"
    )

    print("\nMethod breakdown:")

    for method, count in sorted(
        method_counts.items()
    ):

        print(
            f"  {method:<25}"
            f": {count}"
        )

    return {
        'total_groups': total,
        'hit_at_1': round(
            hit_at_1,
            3
        ),
        'hit_at_3': round(
            hit_at_3,
            3
        ),
        'hit_at_5': round(
            hit_at_5,
            3
        ),
        'method_counts':
            dict(method_counts),
    }


# ============================================================
# ROLLING TEMPORALCTI EVALUATION
# ============================================================

def rolling_temporalcti_evaluation(
    df,
    test_years=None,
    top_n=5
):

    if test_years is None:

        test_years = [
            2022,
            2023,
            2024,
            2025,
        ]

    results = []

    for test_year in test_years:

        print(
            f"\nEvaluating TemporalCTI "
            f"for {test_year}..."
        )

        train_df = df[
            df['year'] < test_year
        ].copy()

        test_df = df[
            df['year'] == test_year
        ].copy()

        if (
            train_df.empty
            or test_df.empty
        ):
            continue

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

        # Same train-only temporal signals
        # used by baseline_comparison.py
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
            DEFAULT_DELTA
        )

        train_groups = set(
            train_df['apt_group'].unique()
        )

        test_groups = set(
            test_df['apt_group'].unique()
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
                train_df['apt_group'] == group
            ]

            group_test = test_df[
                test_df['apt_group'] == group
            ]

            historical = set(
                group_train['technique']
                .unique()
            )

            future = set(
                group_test['technique']
                .unique()
            )

            new_ttps = (
                future - historical
            )

            if not new_ttps:
                continue

            predictions, method = (
                hybrid_predict(
                    train_df,
                    group,
                    global_matrix,
                    freq_prior,
                    top_n=top_n,
                    velocity_map=velocity_map,
                    gamma=FINAL_GAMMA,
                    recency_map=recency_map,
                    delta=delta,
                )
            )

            if not predictions:
                continue

            predicted = [
                technique
                for technique, score
                in predictions
            ]

            total += 1

            for k in [1, 3, 5]:

                if any(
                    technique in new_ttps
                    for technique
                    in predicted[:k]
                ):

                    hits[k] += 1

        if total == 0:
            continue

        results.append({
            'year': test_year,
            'total_groups': total,
            'hit_at_1':
                hits[1] / total,
            'hit_at_3':
                hits[3] / total,
            'hit_at_5':
                hits[5] / total,
            'gamma':
                FINAL_GAMMA,
            'delta':
                delta,
        })

    return pd.DataFrame(
        results
    )


# ============================================================
# PREDICT ALL GROUPS
# ============================================================

def predict_all_groups(
    df,
    global_matrix=None,
    freq_prior=None,
    gamma=FINAL_GAMMA,
    delta=DEFAULT_DELTA,
):

    if global_matrix is None:

        global_matrix = (
            build_global_transition_matrix(
                df
            )
        )

    if freq_prior is None:

        freq_prior = (
            build_frequency_prior(
                df
            )
        )

    velocity_map = (
        build_train_only_velocity(
            df
        )
        if gamma > 0
        else None
    )

    recency_map = (
        build_train_only_recency(
            df
        )
        if delta > 0
        else None
    )

    all_predictions = []

    for group in sorted(
        df['apt_group']
        .dropna()
        .unique()
    ):

        predictions, method = (
            hybrid_predict(
                df,
                group,
                global_matrix,
                freq_prior,
                top_n=5,
                velocity_map=velocity_map,
                gamma=gamma,
                recency_map=recency_map,
                delta=delta,
            )
        )

        for technique, score in predictions:

            all_predictions.append({
                'apt_group':
                    group,

                'predicted_technique':
                    technique,

                'probability':
                    round(
                        float(score),
                        3
                    ),

                'method':
                    method,

                'gamma':
                    gamma,

                'delta':
                    delta,
            })

    return pd.DataFrame(
        all_predictions
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TemporalCTI — Final Prediction Model")
    print("=" * 70)

    print(
        "\nModel:"
    )

    print(
        "  Markov transitions"
    )

    print(
        "  + Velocity"
        f" (gamma={FINAL_GAMMA})"
    )

    print(
        "  + Recency"
    )

    print(
        "  Final model: "
        "Markov + Velocity + Recency"
    )

    print(
        "\nGeneric techniques filtered."
    )

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    df = load_data()

    print(
        f"\nDataset:"
        f" {df['apt_group'].nunique()} groups"
        f" · {df['technique'].nunique()} techniques"
        f" · {len(df):,} observations"
    )

    print(
        f"Year range:"
        f" {df['year'].min()}–"
        f"{df['year'].max()}"
    )

    # --------------------------------------------------------
    # BUILD BASE MODEL
    # --------------------------------------------------------

    print(
        "\nBuilding global Markov transition matrix..."
    )

    global_matrix = (
        build_global_transition_matrix(
            df
        )
    )

    freq_prior = (
        build_frequency_prior(
            df
        )
    )

    print(
        f"  Transition sources:"
        f" {len(global_matrix):,}"
    )

    # --------------------------------------------------------
    # SAMPLE PREDICTIONS
    # --------------------------------------------------------

    test_groups = [
        'APT29',
        'Lazarus Group',
        'APT41',
        'APT28',
        'Kimsuky',
    ]

    print(
        "\nGenerating sample TemporalCTI predictions..."
    )

    for group in test_groups:

        if group not in set(
            df['apt_group']
            .unique()
        ):
            continue

        predictions, method = (
            hybrid_predict(
                df,
                group,
                global_matrix,
                freq_prior,
                top_n=5,
                velocity_map=
                    build_train_only_velocity(
                        df
                    ),
                gamma=FINAL_GAMMA,
                recency_map=
                    build_train_only_recency(
                        df
                    ),
                delta=DEFAULT_DELTA,
            )
        )

        print(
            "\n" + "=" * 55
        )

        print(
            f"Group: {group}"
        )

        print(
            f"Method: {method}"
        )

        print("=" * 55)

        if not predictions:

            print(
                "  No predictions available."
            )

            continue

        for rank, (
            technique,
            score
        ) in enumerate(
            predictions,
            1
        ):

            print(
                f"  {rank}. "
                f"{technique:<45}"
                f" {score:.3f}"
            )

    # --------------------------------------------------------
    # ROLLING EVALUATION
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "Rolling TemporalCTI Evaluation"
    )

    print("=" * 70)

    rolling_results = (
        rolling_temporalcti_evaluation(
            df
        )
    )

    if not rolling_results.empty:

        print(
            "\nYear-wise results:"
        )

        print(
            rolling_results[
                [
                    'year',
                    'total_groups',
                    'hit_at_1',
                    'hit_at_3',
                    'hit_at_5',
                    'gamma',
                    'delta',
                ]
            ].to_string(
                index=False
            )
        )

        total_n = (
            rolling_results[
                'total_groups'
            ].sum()
        )

        pooled_hit1 = (
            (
                rolling_results[
                    'hit_at_1'
                ]
                *
                rolling_results[
                    'total_groups'
                ]
            ).sum()
            /
            total_n
        )

        pooled_hit3 = (
            (
                rolling_results[
                    'hit_at_3'
                ]
                *
                rolling_results[
                    'total_groups'
                ]
            ).sum()
            /
            total_n
        )

        pooled_hit5 = (
            (
                rolling_results[
                    'hit_at_5'
                ]
                *
                rolling_results[
                    'total_groups'
                ]
            ).sum()
            /
            total_n
        )

        print(
            "\nPooled rolling results:"
        )

        print(
            f"  Hit@1 : {pooled_hit1:.3f}"
        )

        print(
            f"  Hit@3 : {pooled_hit3:.3f}"
        )

        print(
            f"  Hit@5 : {pooled_hit5:.3f}"
        )

        print(
            f"  N     : {int(total_n)}"
        )

        # Save validation results
        validation_output = pd.DataFrame([
            {
                'model':
                    'TemporalCTI',
                'evaluation':
                    'Rolling 2022-2025',
                'total_groups':
                    int(total_n),
                'hit_at_1':
                    round(
                        pooled_hit1,
                        3
                    ),
                'hit_at_3':
                    round(
                        pooled_hit3,
                        3
                    ),
                'hit_at_5':
                    round(
                        pooled_hit5,
                        3
                    ),
                'gamma':
                    FINAL_GAMMA,
                'delta':
                    'year-specific',
            }
        ])

        validation_output.to_csv(
            'data/processed/'
            'prediction_validation.csv',
            index=False
        )

        print(
            "\nSaved:"
            " data/processed/"
            "prediction_validation.csv"
        )

    # --------------------------------------------------------
    # ALL-GROUP PREDICTIONS
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "Generating predictions for all groups..."
    )

    all_predictions = (
        predict_all_groups(
            df,
            global_matrix,
            freq_prior,
            gamma=FINAL_GAMMA,
            delta=DEFAULT_DELTA,
        )
    )

    print(
        f"\nTotal predictions:"
        f" {len(all_predictions):,}"
    )

    if not all_predictions.empty:

        print(
            "Groups covered:"
            f" {all_predictions['apt_group'].nunique()}"
        )

        print(
            "\nMethod breakdown:"
        )

        for method, count in (
            all_predictions[
                'method'
            ]
            .value_counts()
            .items()
        ):

            percentage = (
                count
                /
                len(all_predictions)
                *
                100
            )

            print(
                f"  {method:<25}"
                f": {count:4d}"
                f" ({percentage:.1f}%)"
            )

    all_predictions.to_csv(
        'data/processed/'
        'ttp_predictions.csv',
        index=False
    )

    print(
        "\nSaved:"
        " data/processed/"
        "ttp_predictions.csv"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "TemporalCTI prediction complete."
    )

    print("=" * 70)
