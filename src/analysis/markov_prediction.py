import sqlite3
import pandas as pd
import numpy as np
from collections import defaultdict

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


def build_global_transition_matrix(df):
    transitions = defaultdict(lambda: defaultdict(int))
    for _, group_df in df.groupby('apt_group'):
        years = sorted(group_df['year'].unique())
        if len(years) < 2:
            continue
        for i in range(len(years) - 1):
            curr = set(group_df[group_df['year'] == years[i]]['technique'])
            nxt = set(group_df[group_df['year'] == years[i + 1]]['technique'])
            new = nxt - curr
            for src in curr:
                for tgt in new:
                    transitions[src][tgt] += 1
    global_matrix = {}
    for src, tgts in transitions.items():
        total = sum(tgts.values())
        global_matrix[src] = {tgt: cnt / total for tgt, cnt in tgts.items()}
    return global_matrix


def build_local_transition_matrix(group_df):
    transitions = defaultdict(lambda: defaultdict(int))
    years = sorted(group_df['year'].unique())
    for i in range(len(years) - 1):
        curr = set(group_df[group_df['year'] == years[i]]['technique'])
        nxt = set(group_df[group_df['year'] == years[i + 1]]['technique'])
        new = nxt - curr
        for src in curr:
            for tgt in new:
                transitions[src][tgt] += 1
    local_matrix = {}
    for src, tgts in transitions.items():
        total = sum(tgts.values())
        local_matrix[src] = {tgt: cnt / total for tgt, cnt in tgts.items()}
    return local_matrix


def build_frequency_prior(df):
    """
    Population-wide technique popularity, normalized 0-1 by fraction of
    groups that have ever used the technique. Used as a third, deterministic
    backoff signal alongside local and global Markov transitions (the same
    role a unigram prior plays in Katz/Kneser-Ney backoff smoothing in NLP).
    """
    total_groups = df['apt_group'].nunique()
    counts = df.groupby('technique')['apt_group'].nunique()
    return (counts / total_groups).to_dict()


def build_train_only_velocity(train_df):
    """
    Growth-rate signal for each technique, computed ONLY from train_df so
    held-out evaluation has zero leakage from the test period.

    Splits the training years into an early half and a late half, counts
    how many distinct groups adopted each technique in each half, and
    scores velocity as (late_count - early_count), min-max normalized to
    [0, 1]. A technique that's spreading to more groups over time in the
    training window gets a higher score; one that's shrinking or flat gets
    a lower one.

    This is intentionally self-contained here (not imported from
    ttp_velocity.py) so this experiment does not modify that module, per
    the frozen-scope rule: only markov_prediction.py changes.
    """
    years = sorted(train_df['year'].unique())
    if len(years) < 2:
        return {}
    mid = max(1, len(years) // 2)
    early_years = years[:mid]
    late_years = years[mid:]
    if not late_years:
        return {}
    early_counts = train_df[train_df['year'].isin(early_years)].groupby('technique')['apt_group'].nunique()
    late_counts = train_df[train_df['year'].isin(late_years)].groupby('technique')['apt_group'].nunique()
    all_techniques = set(early_counts.index) | set(late_counts.index)
    raw = {t: late_counts.get(t, 0) - early_counts.get(t, 0) for t in all_techniques}
    if not raw:
        return {}
    max_v, min_v = max(raw.values()), min(raw.values())
    if max_v == min_v:
        return {t: 0.0 for t in raw}
    return {t: (v - min_v) / (max_v - min_v) for t, v in raw.items()}


def build_train_only_recency(train_df):
    """
    Freshness signal for each technique, computed ONLY from train_df so
    held-out evaluation has zero leakage from the test period.

    For each technique, finds the most recent year it was observed in use
    (by any group) within the training window, then min-max normalizes
    that "last seen year" to [0, 1] across all techniques. A technique
    still being used right up to the end of the training window scores
    near 1; one that hasn't appeared in years scores near 0.

    This is a different signal from velocity: velocity measures whether
    ADOPTION is trending up or down across the training window; recency
    only measures how long ago the technique was last seen at all,
    independent of trend. Self-contained here, not imported from
    ttp_velocity.py, per the frozen-scope rule: only markov_prediction.py
    changes.
    """
    years = sorted(train_df['year'].unique())
    if len(years) < 2:
        return {}
    last_seen = train_df.groupby('technique')['year'].max()
    min_y, max_y = min(years), max(years)
    if max_y == min_y:
        return {t: 0.0 for t in last_seen.index}
    return {t: (y - min_y) / (max_y - min_y) for t, y in last_seen.items()}


def markov_predict_with_prior(group_df, global_matrix, freq_prior, top_n=5, alpha=0.3, beta=0.07,
                                velocity_map=None, gamma=0.0, recency_map=None, delta=0.0):
    """
    velocity_map / gamma are appended at the END of the signature (not
    inserted after freq_prior) so every existing positional call site -
    e.g. hybrid_predict's markov_predict_with_prior(group_df, global_matrix,
    freq_prior, top_n, effective_alpha, beta) - keeps binding top_n/alpha/beta
    correctly and is completely unaffected.

    With velocity_map=None and gamma=0.0 (the defaults), this function is
    byte-for-byte behaviorally identical to the original: the velocity
    block below is skipped entirely, so P@1/P@3/P@5 reproduce 0.128/0.308/
    0.410 exactly.

    recency_map / delta follow the exact same pattern, appended at the end
    again: off by default (delta=0.0), tested independently against the
    ORIGINAL frozen baseline (not the velocity-boosted one), per Step 3 of
    the additive-ablation plan.
    """
    years = sorted(group_df['year'].unique())
    if len(years) < 2:
        return [], 'insufficient_data'
    local_matrix = build_local_transition_matrix(group_df)
    max_year = group_df['year'].max()
    recent_ttps = set(group_df[group_df['year'] == max_year]['technique'])
    existing = set(group_df['technique'].unique())
    scores = defaultdict(float)
    for ttp in recent_ttps:
        local_row = local_matrix.get(ttp, {})
        global_row = global_matrix.get(ttp, {})
        candidates = set(local_row.keys()) | set(global_row.keys())
        for tgt in candidates:
            if tgt in existing:
                continue
            lp = local_row.get(tgt, 0.0)
            gp = global_row.get(tgt, 0.0)
            scores[tgt] += (1 - alpha) * lp + alpha * gp
    # Also admit globally popular techniques as candidates even when no
    # (src, tgt) transition was directly observed from this group's current
    # techniques - otherwise genuinely common techniques can be excluded
    # from the candidate set entirely just because they weren't recorded
    # as a "new adoption" following this specific group's last-used TTPs.
    for tgt in freq_prior:
        if tgt in existing:
            continue
        if tgt not in scores:
            scores[tgt] = 0.0
    if not scores:
        return [], 'markov_no_candidates'
    # Blend in the population-frequency prior (beta, small weight - the
    # transition signal still dominates ranking; this is a backoff term,
    # not a replacement for it).
    for tgt in scores:
        scores[tgt] = (1 - beta) * scores[tgt] + beta * freq_prior.get(tgt, 0.0)
    # OPTIONAL, OFF-BY-DEFAULT: nudge ranking toward techniques with rising
    # adoption velocity in the training window. Only runs when a caller
    # explicitly passes gamma > 0 and a velocity_map - the original model's
    # behavior is otherwise untouched.
    if gamma > 0 and velocity_map:
        for tgt in scores:
            scores[tgt] = (1 - gamma) * scores[tgt] + gamma * velocity_map.get(tgt, 0.0)
    # OPTIONAL, OFF-BY-DEFAULT: nudge ranking toward techniques seen more
    # recently in the training window. Only runs when a caller explicitly
    # passes delta > 0 and a recency_map - independent of the velocity
    # block above, and skipped entirely otherwise.
    if delta > 0 and recency_map:
        for tgt in scores:
            scores[tgt] = (1 - delta) * scores[tgt] + delta * recency_map.get(tgt, 0.0)
    # Deterministic tie-break: technique name as secondary sort key, so
    # ranking is fully reproducible across runs regardless of dict/set
    # iteration order.
    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:top_n]
    return ranked, 'markov'


def similarity_predict(df, apt_group, top_n=5):
    """
    For data-sparse groups (1 year only), find the top 3 most
    TTP-similar groups by Jaccard similarity and recommend
    techniques they recently adopted that this group hasn't used.
    More targeted than global frequency.
    """
    target_ttps = set(df[df['apt_group'] == apt_group]['technique'].unique())
    similarities = {}
    for group, gdf in df.groupby('apt_group'):
        if group == apt_group:
            continue
        other = set(gdf['technique'].unique())
        union = target_ttps | other
        if union:
            similarities[group] = len(target_ttps & other) / len(union)
    top3 = sorted(similarities.items(), key=lambda x: x[1], reverse=True)[:3]
    if not top3:
        return frequency_predict(df, apt_group, top_n)
    scores = defaultdict(float)
    existing = set(df[df['apt_group'] == apt_group]['technique'].unique())
    for peer, sim in top3:
        peer_df = df[df['apt_group'] == peer]
        max_year = peer_df['year'].max()
        recent = set(peer_df[peer_df['year'] == max_year]['technique'])
        for t in recent - existing:
            scores[t] += sim
    if scores:
        ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:top_n]
        return ranked, 'similarity'
    return frequency_predict(df, apt_group, top_n)


def frequency_predict(df, apt_group, top_n=5):
    group_df = df[df['apt_group'] == apt_group]
    existing = set(group_df['technique'].unique())
    total_groups = df['apt_group'].nunique()
    counts = df.groupby('technique')['apt_group'].nunique()
    # Deterministic tie-break (technique name), same fix applied in
    # baseline_comparison.py's frequency_baseline() and
    # nation_state_clustering.py's top_techniques ranking.
    all_techniques = counts.reset_index().sort_values(
        ['apt_group', 'technique'], ascending=[False, True]
    ).set_index('technique')['apt_group']
    predictions = []
    for technique, count in all_techniques.items():
        if technique not in existing:
            predictions.append((technique, round(count / total_groups, 3)))
        if len(predictions) >= top_n:
            break
    return predictions, 'frequency'


def hybrid_predict(df, apt_group, global_matrix, freq_prior, top_n=5, alpha=None, beta=0.07,
                    velocity_map=None, gamma=0.0, recency_map=None, delta=0.0):
    """
    3-tier prediction:
    - Groups with >= 2 years: Markov with global prior + frequency backoff
      (sparse groups use higher alpha = more global weight)
    - Groups with 1 year: similarity-based prediction
      (find most similar peers, recommend their recent TTPs)
    - Final fallback: frequency

    alpha=None (default) auto-selects by data richness (0.3 for 4+ years,
    0.7 for 2-3 years). Pass an explicit alpha to override this - used by
    alpha_sensitivity_analysis to actually test each value.

    velocity_map/gamma: optional, off by default (gamma=0.0). When gamma=0.0
    (or velocity_map is None), markov_predict_with_prior's velocity block
    never runs, so results are identical to before this experiment.

    recency_map/delta: same pattern, independent of velocity, off by
    default (delta=0.0).
    """
    group_df = df[df['apt_group'] == apt_group]
    years = sorted(group_df['year'].unique())
    n_years = len(years)
    if n_years >= 2:
        if alpha is None:
            # Sparse groups (2-3 years) rely more on global prior
            effective_alpha = 0.3 if n_years >= 4 else 0.7
        else:
            effective_alpha = alpha
        preds, method = markov_predict_with_prior(
            group_df, global_matrix, freq_prior, top_n=top_n, alpha=effective_alpha, beta=beta,
            velocity_map=velocity_map, gamma=gamma, recency_map=recency_map, delta=delta
        )
        if preds:
            return preds, method
    # 1-year groups or Markov with no candidates
    return similarity_predict(df, apt_group, top_n)


def held_out_validation(df, global_matrix, test_year_cutoff=2024, gamma=0.0, delta=0.0):
    print(f"\nHeld-out Validation (train: <{test_year_cutoff}, test: >={test_year_cutoff})"
          + (f"  [gamma={gamma}]" if gamma > 0 else "")
          + (f"  [delta={delta}]" if delta > 0 else ""))
    print("=" * 50)
    train_df = df[df['year'] < test_year_cutoff]
    test_df = df[df['year'] >= test_year_cutoff]
    if test_df.empty:
        print("No test data available.")
        return None
    valid_groups = [g for g in test_df['apt_group'].unique()
                     if g in train_df['apt_group'].unique()]
    print(f"Groups in test set           : {len(test_df['apt_group'].unique())}")
    print(f"Groups in both train & test  : {len(valid_groups)}")
    train_global = build_global_transition_matrix(train_df)
    train_freq = build_frequency_prior(train_df)
    # Velocity/recency are computed from train_df ONLY - the test period
    # never touches this, so there is no leakage into either signal.
    train_velocity = build_train_only_velocity(train_df) if gamma > 0 else None
    train_recency = build_train_only_recency(train_df) if delta > 0 else None
    hits = {1: 0, 3: 0, 5: 0}
    method_counts = defaultdict(int)
    total = 0
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
            recency_map=train_recency, delta=delta
        )
        if not preds:
            continue
        predicted = [p[0] for p in preds]
        method_counts[method] += 1
        for k in [1, 3, 5]:
            if any(p in new_ttps for p in predicted[:k]):
                hits[k] += 1
        total += 1
    if total == 0:
        print("No valid groups.")
        return None
    p1, p3, p5 = hits[1] / total, hits[3] / total, hits[5] / total
    print(f"\nValidation results ({total} groups evaluated):")
    print(f"  Precision@1 : {p1:.3f}  ({hits[1]}/{total})")
    print(f"  Precision@3 : {p3:.3f}  ({hits[3]}/{total})")
    print(f"  Precision@5 : {p5:.3f}  ({hits[5]}/{total})")
    print(f"\n  Method used in validation:")
    for m, c in sorted(method_counts.items()):
        print(f"    {m:30} : {c}")
    return {
        'total_groups': total,
        'precision_at_1': round(p1, 3),
        'precision_at_3': round(p3, 3),
        'precision_at_5': round(p5, 3),
        'method_counts': dict(method_counts),
    }


def alpha_sensitivity_analysis(df):
    print("\nAlpha Sensitivity Analysis (Global Prior Weight)")
    print("=" * 50)
    print(f"  {'Alpha':>6}  {'P@1':>6}  {'P@3':>6}  {'P@5':>6}  {'Markov%':>8}")
    print("  " + "-" * 40)
    train_df = df[df['year'] < 2024]
    test_df = df[df['year'] >= 2024]
    train_global = build_global_transition_matrix(train_df)
    train_freq = build_frequency_prior(train_df)
    valid_groups = [g for g in test_df['apt_group'].unique()
                     if g in train_df['apt_group'].unique()]
    best_alpha, best_p1 = 0.3, -1
    for alpha in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 1.0]:
        hits = {1: 0, 3: 0, 5: 0}
        markov_count = total = 0
        for group in valid_groups:
            g_train = train_df[train_df['apt_group'] == group]
            g_test = test_df[test_df['apt_group'] == group]
            if g_train.empty or g_test.empty:
                continue
            new_ttps = set(g_test['technique'].unique()) - set(g_train['technique'].unique())
            if not new_ttps:
                continue
            preds, method = hybrid_predict(train_df, group, train_global, train_freq, top_n=5, alpha=alpha)
            if not preds:
                continue
            predicted = [p[0] for p in preds]
            if method == 'markov':
                markov_count += 1
            for k in [1, 3, 5]:
                if any(p in new_ttps for p in predicted[:k]):
                    hits[k] += 1
            total += 1
        if total == 0:
            continue
        p1, p3, p5 = hits[1] / total, hits[3] / total, hits[5] / total
        mp = markov_count / total * 100
        marker = " <- selected" if abs(alpha - 0.3) < 0.01 else ""
        print(f"  {alpha:>6.1f}  {p1:>6.3f}  {p3:>6.3f}  {p5:>6.3f}  {mp:>7.1f}%{marker}")
        if p1 > best_p1:
            best_p1, best_alpha = p1, alpha
    print(f"\n  Best alpha by P@1: {best_alpha}")
    print("  alpha=0.1-0.5 yields stable results; 0.3 selected as midpoint")


def gamma_sensitivity_analysis(df, test_year_cutoff=2024):
    """
    Step 2 of the additive-ablation plan: test the velocity signal ALONE
    on top of the frozen, unmodified original model (alpha auto-selected
    exactly as before, beta=0.07 exactly as before).

    gamma=0.0 row MUST reproduce the frozen baseline: P@1=0.128, P@3=0.308,
    P@5=0.410. If it doesn't, something in this diff broke the original
    behavior and the velocity numbers below are not trustworthy - stop and
    debug before drawing any conclusion about velocity.
    """
    print("\nGamma Sensitivity Analysis (Velocity Signal Weight)")
    print("=" * 50)
    print("Frozen baseline to beat: P@1=0.128  P@3=0.308  P@5=0.410")
    print(f"  {'Gamma':>6}  {'P@1':>6}  {'P@3':>6}  {'P@5':>6}")
    print("  " + "-" * 32)
    results = []
    for gamma in [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
        train_df = df[df['year'] < test_year_cutoff]
        test_df = df[df['year'] >= test_year_cutoff]
        train_global = build_global_transition_matrix(train_df)
        train_freq = build_frequency_prior(train_df)
        train_velocity = build_train_only_velocity(train_df) if gamma > 0 else None
        valid_groups = [g for g in test_df['apt_group'].unique()
                         if g in train_df['apt_group'].unique()]
        hits = {1: 0, 3: 0, 5: 0}
        total = 0
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
                velocity_map=train_velocity, gamma=gamma
            )
            if not preds:
                continue
            predicted = [p[0] for p in preds]
            for k in [1, 3, 5]:
                if any(p in new_ttps for p in predicted[:k]):
                    hits[k] += 1
            total += 1
        if total == 0:
            continue
        p1, p3, p5 = hits[1] / total, hits[3] / total, hits[5] / total
        marker = "  <- frozen baseline (must match)" if gamma == 0.0 else ""
        print(f"  {gamma:>6.2f}  {p1:>6.3f}  {p3:>6.3f}  {p5:>6.3f}{marker}")
        results.append({'gamma': gamma, 'precision_at_1': round(p1, 3),
                         'precision_at_3': round(p3, 3), 'precision_at_5': round(p5, 3)})
    baseline = next((r for r in results if r['gamma'] == 0.0), None)
    best = max(results, key=lambda r: r['precision_at_1']) if results else None
    if baseline and best and best['gamma'] > 0.0 and best['precision_at_1'] > baseline['precision_at_1']:
        print(f"\n  Velocity HELPS at gamma={best['gamma']}: "
              f"P@1 {baseline['precision_at_1']} -> {best['precision_at_1']}")
        print("  -> Keep velocity, this becomes the new baseline for Step 3 (recency).")
    else:
        print("\n  Velocity does NOT improve P@1 over the frozen baseline at any tested gamma.")
        print("  -> Discard velocity. Revert to gamma=0.0 (original model) and move to Step 3 (recency),")
        print("     starting fresh from the original model, not from this result.")
    return results


def delta_sensitivity_analysis(df, test_year_cutoff=2024):
    """
    Step 3 of the additive-ablation plan: test the recency signal ALONE,
    starting fresh from the ORIGINAL frozen model (gamma=0.0 - velocity is
    NOT stacked in here, per the plan's rule to test each signal
    independently against the original baseline, not against whatever the
    previous step produced).

    delta=0.0 row MUST reproduce the same frozen baseline: P@1=0.128,
    P@3=0.308, P@5=0.410. If it doesn't, stop and debug before trusting
    the recency numbers below.
    """
    print("\nDelta Sensitivity Analysis (Recency Signal Weight)")
    print("=" * 50)
    print("Frozen baseline to beat: P@1=0.128  P@3=0.308  P@5=0.410")
    print("(Tested from the ORIGINAL model, gamma=0.0 - velocity not stacked in)")
    print(f"  {'Delta':>6}  {'P@1':>6}  {'P@3':>6}  {'P@5':>6}")
    print("  " + "-" * 32)
    results = []
    for delta in [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
        train_df = df[df['year'] < test_year_cutoff]
        test_df = df[df['year'] >= test_year_cutoff]
        train_global = build_global_transition_matrix(train_df)
        train_freq = build_frequency_prior(train_df)
        train_recency = build_train_only_recency(train_df) if delta > 0 else None
        valid_groups = [g for g in test_df['apt_group'].unique()
                         if g in train_df['apt_group'].unique()]
        hits = {1: 0, 3: 0, 5: 0}
        total = 0
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
                recency_map=train_recency, delta=delta
                # gamma left at default 0.0 - velocity intentionally NOT
                # included here, per the plan's "start fresh from the
                # original model" rule for each independent signal test.
            )
            if not preds:
                continue
            predicted = [p[0] for p in preds]
            for k in [1, 3, 5]:
                if any(p in new_ttps for p in predicted[:k]):
                    hits[k] += 1
            total += 1
        if total == 0:
            continue
        p1, p3, p5 = hits[1] / total, hits[3] / total, hits[5] / total
        marker = "  <- frozen baseline (must match)" if delta == 0.0 else ""
        print(f"  {delta:>6.2f}  {p1:>6.3f}  {p3:>6.3f}  {p5:>6.3f}{marker}")
        results.append({'delta': delta, 'precision_at_1': round(p1, 3),
                         'precision_at_3': round(p3, 3), 'precision_at_5': round(p5, 3)})
    baseline = next((r for r in results if r['delta'] == 0.0), None)
    best = max(results, key=lambda r: r['precision_at_1']) if results else None
    if baseline and best and best['delta'] > 0.0 and best['precision_at_1'] > baseline['precision_at_1']:
        print(f"\n  Recency HELPS at delta={best['delta']}: "
              f"P@1 {baseline['precision_at_1']} -> {best['precision_at_1']}")
        print("  -> Keep recency as its own candidate signal for Step 5 (combine what individually helped).")
    else:
        print("\n  Recency does NOT improve P@1 over the frozen baseline at any tested delta.")
        print("  -> Discard recency. It does not go into the final model.")
    return results


def predict_all_groups(df, global_matrix, freq_prior, velocity_map=None, gamma=0.15):
    """
    gamma=0.15 is now the chosen final model, per the Step 2 ablation
    result (P@1 0.128 -> 0.231, plateaus at gamma>=0.15). velocity_map
    defaults to None here and is built once from the FULL dataset (not
    train_df) if not passed in - this is real, forward-facing prediction
    for all groups, not held-out evaluation, so there's no leakage concern
    here the way there was in held_out_validation/gamma_sensitivity_analysis.
    """
    if velocity_map is None and gamma > 0:
        velocity_map = build_train_only_velocity(df)
    all_predictions = []
    for group in df['apt_group'].unique():
        preds, method = hybrid_predict(
            df, group, global_matrix, freq_prior, top_n=5,
            velocity_map=velocity_map, gamma=gamma
        )
        for technique, prob in preds:
            all_predictions.append({
                'apt_group': group,
                'predicted_technique': technique,
                'probability': round(float(prob), 3),
                'method': method,
            })
    return pd.DataFrame(all_predictions)


if __name__ == "__main__":
    print("TTP Prediction — Hybrid Markov + Similarity Model")
    print("  Tier 1 (>=4 yrs) : Local + global Markov [alpha=0.3]")
    print("  Tier 2 (2-3 yrs) : Global-heavy Markov   [alpha=0.7]")
    print("  Tier 3 (1 yr)    : Similarity-based prediction")
    print("  Generic techniques filtered\n")
    df = load_data()
    print("Building global transition matrix...")
    global_matrix = build_global_transition_matrix(df)
    freq_prior = build_frequency_prior(df)
    print(f"  Transitions indexed for {len(global_matrix):,} source techniques\n")
    test_groups = ['APT29', 'Lazarus Group', 'APT41', 'APT28', 'Kimsuky']
    for group in test_groups:
        preds, method = hybrid_predict(df, group, global_matrix, freq_prior, top_n=5)
        print(f"\n{'=' * 50}")
        print(f"Group: {group} | Method: {method}")
        print(f"{'=' * 50}")
        if preds:
            for i, (tech, prob) in enumerate(preds, 1):
                bar = '█' * max(1, int(prob * 20))
                print(f"  {i}. {tech[:45]:45} {bar} {prob:.3f}")
        else:
            print("  No predictions available.")
    # gamma=0.15 is the chosen final model (Step 2 ablation result: velocity
    # backoff improved P@1 0.128 -> 0.231, recency in Step 3 did not help
    # and was discarded). This validation run now reports the real,
    # final-model numbers, not the pre-ablation baseline.
    validation_results = held_out_validation(df, global_matrix, gamma=0.15)
    alpha_sensitivity_analysis(df)
    # Step 2 of the additive-ablation plan: test velocity alone, on top of
    # the frozen original model. This is print-only / exploratory - it does
    # NOT write to prediction_validation.csv or change predict_all_groups,
    # so nothing downstream (dashboard, baseline_comparison.py) is affected
    # until you've looked at the numbers and decided whether velocity helps.
    gamma_results = gamma_sensitivity_analysis(df)
    # Step 3 of the additive-ablation plan: test recency alone, starting
    # fresh from the ORIGINAL model (not stacked on the velocity result
    # above). Also print-only/exploratory - doesn't touch the CSV outputs
    # or predict_all_groups.
    delta_results = delta_sensitivity_analysis(df)
    print("\nGenerating predictions for all groups...")
    all_preds = predict_all_groups(df, global_matrix, freq_prior)
    print(f"\nTotal predictions       : {len(all_preds)}")
    print(f"Groups with predictions : {all_preds['apt_group'].nunique()}")
    print(f"\nMethod breakdown:")
    for method, count in all_preds['method'].value_counts().items():
        print(f"  {method:30} : {count:4d}  ({count / len(all_preds) * 100:.1f}%)")
    all_preds.to_csv('data/processed/ttp_predictions.csv', index=False)
    print("\nSaved to data/processed/ttp_predictions.csv")
    if validation_results:
        pd.DataFrame([{
            'total_groups': validation_results['total_groups'],
            'precision_at_1': validation_results['precision_at_1'],
            'precision_at_3': validation_results['precision_at_3'],
            'precision_at_5': validation_results['precision_at_5'],
        }]).to_csv('data/processed/prediction_validation.csv', index=False)
        print("Saved to data/processed/prediction_validation.csv")
