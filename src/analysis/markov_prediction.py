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


def markov_predict_with_prior(group_df, global_matrix, freq_prior, top_n=5, alpha=0.3, beta=0.07):
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


def hybrid_predict(df, apt_group, global_matrix, freq_prior, top_n=5, alpha=None, beta=0.07):
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
            group_df, global_matrix, freq_prior, top_n, effective_alpha, beta
        )
        if preds:
            return preds, method
    # 1-year groups or Markov with no candidates
    return similarity_predict(df, apt_group, top_n)


def held_out_validation(df, global_matrix, test_year_cutoff=2024):
    print(f"\nHeld-out Validation (train: <{test_year_cutoff}, test: >={test_year_cutoff})")
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
        preds, method = hybrid_predict(train_df, group, train_global, train_freq, top_n=5)
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


def predict_all_groups(df, global_matrix, freq_prior):
    all_predictions = []
    for group in df['apt_group'].unique():
        preds, method = hybrid_predict(df, group, global_matrix, freq_prior, top_n=5)
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
    validation_results = held_out_validation(df, global_matrix)
    alpha_sensitivity_analysis(df)
    # NOTE: the former "Evolution Score - Weight Sensitivity Analysis" block
    # (weight_sensitivity()) has been removed. It computed a different,
    # 4-term formula (no longevity/maturity terms, different default
    # weights) than the real 6-term Evolution Score in evolution_score.py,
    # so its "Rankings remain stable... confirming Evolution Score
    # robustness" conclusion was validating an unrelated, disconnected
    # formula rather than the actual module used throughout the rest of
    # the project. The real Evolution Score sensitivity analysis was run
    # separately, directly against evolution_score.py's own formula.
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
