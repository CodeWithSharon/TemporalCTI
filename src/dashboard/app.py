import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import os
GENERIC_TECHNIQUES = {
    'Tool', 'Malware', 'Vulnerability', 'Exploits',
    'Audio-Visual Content', 'Written Content',
}
st.set_page_config(
    page_title="TemporalCTI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');
html, body, [class*="css"] {
    background-color: #080c14;
    color: #cbd5e1;
    font-family: 'IBM Plex Sans', sans-serif;
}
.stApp { background-color: #080c14; }
section[data-testid="stSidebar"] {
    background-color: #0b0f1a !important;
    border-right: 1px solid #1a2744;
}
section[data-testid="stSidebar"] * { color: #b6c4d6 !important; }
h1, h2, h3, h4 { color: #f1f5f9 !important; font-family: 'IBM Plex Sans', sans-serif !important; font-weight: 600 !important; }
p, li, span { color: #b6c4d6; }
div[data-testid="metric-container"] {
    background: #0d1424 !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 6px !important;
    padding: 16px !important;
}
div[data-testid="metric-container"] label,
div[data-testid="metric-container"] label p,
div[data-testid="stMetricLabel"],
div[data-testid="stMetricLabel"] p,
div[data-testid="stMetricLabel"] div {
    color: #93acc8 !important;
    -webkit-text-fill-color: #93acc8 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11.5px !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
    opacity: 1 !important;
}
div[data-testid="metric-container"] div[data-testid="stMetricValue"],
div[data-testid="stMetricValue"],
div[data-testid="stMetricValue"] > div,
div[data-testid="stMetricValue"] span {
    color: #6ee0ff !important;
    -webkit-text-fill-color: #6ee0ff !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 31px !important;
    font-weight: 700 !important;
    opacity: 1 !important;
}
div[data-testid="metric-container"] div[data-testid="stMetricDelta"],
div[data-testid="stMetricDelta"],
div[data-testid="stMetricDelta"] div,
div[data-testid="stMetricDelta"] span {
    color: #5eea9a !important;
    -webkit-text-fill-color: #5eea9a !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    opacity: 1 !important;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #1a2744 !important;
    border-radius: 6px !important;
}
div[data-testid="stDataFrame"] * { color: #cbd5e1 !important; }
div[data-testid="stExpander"] {
    background: #0d1424 !important;
    border: 1px solid #1a2744 !important;
    border-radius: 6px !important;
}
div[data-testid="stExpander"] summary { color: #e2e8f0 !important; }
div[data-testid="stExpander"] summary p { color: #e2e8f0 !important; }
div[data-baseweb="select"] > div {
    background: #0d1424 !important;
    border-color: #1a2744 !important;
    color: #e2e8f0 !important;
}
div[data-baseweb="select"] span { color: #e2e8f0 !important; }
label[data-testid="stWidgetLabel"] p {
    color: #93acc8 !important;
    font-weight: 600 !important;
}
div[data-testid="stAlert"] { border-radius: 6px !important; }
div[data-testid="stAlert"] p { color: #f1f5f9 !important; }
code {
    background: #0d1424 !important;
    color: #6ee0ff !important;
    font-family: 'IBM Plex Mono', monospace !important;
}
section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 2px; }
section[data-testid="stSidebar"] div[role="radiogroup"] label {
    background: transparent;
    border-radius: 6px;
    padding: 9px 12px !important;
    margin: 0 !important;
    width: 100%;
    transition: background 0.15s ease;
    cursor: pointer;
}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover { background: #131c2e; }
section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child { display: none; }
section[data-testid="stSidebar"] div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
    font-family: 'IBM Plex Sans', sans-serif !important;
    font-size: 13.5px !important;
    color: #aebfd4 !important;
    font-weight: 500;
}
section[data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
    background: rgba(110,224,255,0.12) !important;
    border-left: 2px solid #6ee0ff;
}
section[data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] div[data-testid="stMarkdownContainer"] p {
    color: #6ee0ff !important;
    font-weight: 600;
}
.soc-card {
    background: #0d1424;
    border: 1px solid #1a2744;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 10px;
}
.soc-card-accent-red    { border-left: 3px solid #ef4444; }
.soc-card-accent-orange { border-left: 3px solid #f97316; }
.soc-card-accent-yellow { border-left: 3px solid #eab308; }
.soc-card-accent-blue   { border-left: 3px solid #6ee0ff; }
.soc-card-accent-purple { border-left: 3px solid #a78bfa; }
.soc-card-accent-green  { border-left: 3px solid #22c55e; }
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.badge-critical { background: rgba(239,68,68,0.18); color: #ff6b6b; border: 1px solid #ef444460; }
.badge-high     { background: rgba(249,115,22,0.18); color: #ffa057; border: 1px solid #f9731660; }
.badge-medium   { background: rgba(234,179,8,0.18);  color: #ffd84d; border: 1px solid #eab30860; }
.badge-low      { background: rgba(34,197,94,0.18);  color: #5eea9a; border: 1px solid #22c55e60; }
.badge-info     { background: rgba(110,224,255,0.18); color: #6ee0ff; border: 1px solid #6ee0ff60; }
.section-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10.5px;
    font-weight: 700;
    color: #7d96b8;
    text-transform: uppercase;
    letter-spacing: 2px;
    border-bottom: 1px solid #1a2744;
    padding-bottom: 8px;
    margin-bottom: 16px;
}
.status-dot-green { display:inline-block; width:8px; height:8px; background:#22c55e; border-radius:50%; margin-right:6px; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.ttp-tag {
    display: inline-block;
    background: #131c2e;
    border: 1px solid #1e3a5f;
    color: #cbd5e1;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 12px;
    margin: 2px;
    font-family: 'IBM Plex Mono', monospace;
}
.nation-card {
    background: #0d1424;
    border: 1px solid #1a2744;
    border-radius: 6px;
    padding: 16px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)
PLOT_LAYOUT = dict(
    plot_bgcolor='#0d1424',
    paper_bgcolor='#0d1424',
    font_color='#aebfd4',
    font_family='IBM Plex Sans',
    margin=dict(l=10, r=10, t=40, b=10),
)
GRID = dict(gridcolor='#1e3a5f', zerolinecolor='#1e3a5f')
def apply_theme(fig, height=350):
    fig.update_layout(**PLOT_LAYOUT, height=height)
    fig.update_xaxes(**GRID)
    fig.update_yaxes(**GRID)
    return fig
@st.cache_data
def load_db():
    conn = sqlite3.connect('data/temporal_db/apt.db')
    df = pd.read_sql_query("SELECT DISTINCT apt_group, technique, year FROM apt_timeline", conn)
    conn.close()
    df = df[~df['technique'].isin(GENERIC_TECHNIQUES)]
    return df
@st.cache_data
def load_csv(filename):
    path = f'data/processed/{filename}'
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()
df            = load_db()
evo_df        = load_csv('evolution_scores.csv')
emerging_df   = load_csv('emerging_ttps.csv')
conv_df       = load_csv('convergence_alerts.csv')
retire_df     = load_csv('retired_ttps.csv')
pred_df       = load_csv('ttp_predictions.csv')
mit_df        = load_csv('mitigation_recommendations.csv')
nation_df     = load_csv('nation_profiles.csv')
nation_evo_df = load_csv('nation_evolution_scores.csv')
adapt_df      = load_csv('adaptability_index.csv')
lifespan_df   = load_csv('technique_lifespan.csv')
velocity_df   = load_csv('ttp_velocity.csv')
gaps_df       = load_csv('defence_gaps.csv')
baseline_df   = load_csv('baseline_comparison.csv')
NATION_COLORS = {
    "Russia":      "#ef4444",
    "China":       "#f97316",
    "North Korea": "#eab308",
    "Iran":        "#a78bfa",
    "Others":      "#5c6f8a"
}
TOTAL_RECORDS   = len(df)
DEFENCE_TOTAL   = len(gaps_df) if not gaps_df.empty else 0
DEFENCE_UNMAPPED = len(gaps_df[gaps_df['has_defence'] == False]) if not gaps_df.empty and 'has_defence' in gaps_df.columns else 0
DEFENCE_UNMAPPED_PCT = (DEFENCE_UNMAPPED / DEFENCE_TOTAL * 100) if DEFENCE_TOTAL else 0.0
with st.sidebar:
    st.markdown("""
    <div style='padding: 8px 0 20px 0;'>
        <div style='font-family: IBM Plex Mono, monospace; color: #6ee0ff;
                    font-size: 16px; font-weight: 700; letter-spacing: 2px;'>
            TemporalCTI
        </div>
        <div style='font-size: 10px; color: #7d96b8; letter-spacing: 1.5px;
                    text-transform: uppercase; margin-top: 2px;'>
            Threat Intelligence Platform
        </div>
        <div style='margin-top: 10px; font-size: 11px; color: #7d96b8;'>
            <span class='status-dot-green'></span>
            <span style='color: #5eea9a; font-family: IBM Plex Mono, monospace;
                         font-size: 10px; font-weight: 600;'>SYSTEM OPERATIONAL</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("<div class='section-label' style='margin-bottom:6px;'>Navigation</div>", unsafe_allow_html=True)
    page = st.radio("Navigation menu", [
        "Overview", "Threat Actors", "Emerging Threats", "Convergence Analysis",
        "Evolution Scores", "Nation-State", "Mitigation Centre", "Predictions",
        "Defence Gaps", "Adaptability Index", "Technique Lifespan", "TTP Velocity"
    ], label_visibility="collapsed")
    st.markdown("<div style='border-top:1px solid #1a2744; margin: 16px 0;'></div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style='font-family: IBM Plex Mono, monospace; font-size: 10.5px; color: #7d96b8; line-height: 2;'>
        <div style='color:#93acc8; font-size:9px; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:6px; font-weight:700;'>Dataset</div>
        APT Groups &nbsp;&nbsp;&nbsp; <span style='color:#d6e2f0; font-weight:600;'>{df['apt_group'].nunique()}</span><br>
        Techniques &nbsp;&nbsp;&nbsp;&nbsp; <span style='color:#d6e2f0; font-weight:600;'>{df['technique'].nunique()}</span><br>
        Records &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span style='color:#d6e2f0; font-weight:600;'>{TOTAL_RECORDS:,}</span><br>
        Period &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span style='color:#d6e2f0; font-weight:600;'>2017–2026</span><br>
        Source &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span style='color:#6ee0ff; font-weight:600;'>MITRE ATT&CK</span>
    </div>
    """, unsafe_allow_html=True)
if page == "Overview":
    st.markdown("""
    <div style='margin-bottom: 4px;'>
        <span style='font-family: IBM Plex Mono, monospace; font-size: 10.5px;
                     color: #7d96b8; text-transform: uppercase; letter-spacing: 2px; font-weight:700;'>
            Security Operations Centre
        </span>
    </div>
    <h1 style='margin-top: 0; font-size: 28px;'>Threat Intelligence Overview</h1>
    """, unsafe_allow_html=True)
    emg_critical = len(emerging_df[emerging_df['growth_rate'] > 3]) if not emerging_df.empty else 0
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("APT Groups",    f"{df['apt_group'].nunique()}",  "MITRE ATT&CK")
    c2.metric("Techniques",    f"{df['technique'].nunique()}",  "Unique TTPs")
    c3.metric("Total Records", f"{TOTAL_RECORDS:,}",            "Relationships")
    c4.metric("Emerging TTPs", f"{len(emerging_df)}",           f"{emg_critical} Critical")
    c5.metric("Defence Gaps",  f"{DEFENCE_UNMAPPED}/{DEFENCE_TOTAL}", f"{DEFENCE_UNMAPPED_PCT:.1f}% unmapped")
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    col1, col2 = st.columns([3, 2])
    with col1:
        st.markdown("<div class='section-label'>TTP Activity 2017–2026</div>", unsafe_allow_html=True)
        yearly = df.groupby('year')['technique'].count().reset_index()
        yearly.columns = ['Year', 'Records']
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=yearly['Year'], y=yearly['Records'],
            marker_color='#1d4ed8', marker_line_color='#6ee0ff',
            marker_line_width=0.5, name='TTP Records'
        ))
        fig.add_trace(go.Scatter(
            x=yearly['Year'], y=yearly['Records'],
            mode='lines+markers',
            line=dict(color='#6ee0ff', width=2),
            marker=dict(color='#6ee0ff', size=6), name='Trend'
        ))
        apply_theme(fig, 300)
        fig.update_layout(showlegend=False)
        fig.update_yaxes(title_text='TTP Records')
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("<div class='section-label'>Active Alerts</div>", unsafe_allow_html=True)
        alerts = []
        if not emerging_df.empty:
            top_emerging = emerging_df.nlargest(2, 'growth_rate')
            for _, r in top_emerging.iterrows():
                rate = float(r['growth_rate'])
                lvl = "CRITICAL" if rate > 3 else "HIGH"
                cls = "critical" if rate > 3 else "high"
                alerts.append((lvl, f"{r['technique']} {rate:.1f}x growth — {int(r['end_count'])} groups", cls))
        if not conv_df.empty:
            alerts.append(("HIGH", f"{len(conv_df):,} convergence alerts", "high"))
        alerts.append(("HIGH", f"{DEFENCE_UNMAPPED_PCT:.1f}% techniques unmapped", "high"))
        if not emerging_df.empty and len(emerging_df) > 2:
            third = emerging_df.nlargest(3, 'growth_rate').iloc[2]
            alerts.append(("MEDIUM", f"{third['technique']} {float(third['growth_rate']):.1f}x growth", "medium"))
        for level, msg, cls in alerts:
            acc = "red" if cls == "critical" else "orange" if cls == "high" else "yellow"
            st.markdown(f"""
            <div class='soc-card soc-card-accent-{acc}' style='padding:10px 14px; margin-bottom:6px;'>
                <span class='badge badge-{cls}'>{level}</span>
                <span style='color:#e2e8f0; font-size:12.5px; margin-left:8px;'>{msg}</span>
            </div>""", unsafe_allow_html=True)
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Framework Modules</div>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Convergence Alerts",  f"{len(conv_df):,}"   if not conv_df.empty   else "0", "Cross-actor")
    c2.metric("Retired TTPs",        f"{len(retire_df):,}" if not retire_df.empty else "0", "Inactive")
    c3.metric("Predictions",         f"{len(pred_df):,}"   if not pred_df.empty   else "0",
              f"{pred_df['apt_group'].nunique() if not pred_df.empty else 0} groups")
    mit_critical_count = len(mit_df[mit_df['priority'].str.contains('CRITICAL', na=False)]) if not mit_df.empty else 0
    c4.metric("Mitigation Controls", f"{len(mit_df)}" if not mit_df.empty else "0", f"{mit_critical_count} Critical")
elif page == "Threat Actors":
    st.markdown("<div class='section-label'>Threat Actor Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>APT Group Profiler</h1>", unsafe_allow_html=True)
    groups   = sorted(df['apt_group'].unique())
    selected = st.selectbox("Select Threat Actor", groups)
    group_df  = df[df['apt_group'] == selected].drop_duplicates(subset=['technique', 'year'])
    evo_row   = evo_df[evo_df['apt_group']   == selected] if not evo_df.empty   else pd.DataFrame()
    adapt_row = adapt_df[adapt_df['apt_group'] == selected] if not adapt_df.empty else pd.DataFrame()
    evo_score   = float(evo_row.iloc[0]['evolution_score'])    if not evo_row.empty   else 0.0
    adapt_score = float(adapt_row.iloc[0]['adaptability_index']) if not adapt_row.empty else 0.0
    total_ttps  = int(evo_row.iloc[0]['total_techniques']) if not evo_row.empty else group_df['technique'].nunique()
    years       = sorted(group_df['year'].unique())
    threat_level = "CRITICAL" if evo_score > 0.6 else "HIGH" if evo_score > 0.4 else "MEDIUM"
    tl_cls = "critical" if threat_level == "CRITICAL" else "high" if threat_level == "HIGH" else "medium"
    acc    = "red" if tl_cls == "critical" else "orange" if tl_cls == "high" else "yellow"
    st.markdown(f"""
    <div class='soc-card soc-card-accent-{acc}' style='margin-bottom:20px;'>
        <span class='badge badge-{tl_cls}'>{threat_level}</span>
        <span style='color:#f1f5f9; font-size:15px; font-weight:700; margin-left:10px;'>{selected}</span>
        <span style='color:#93acc8; font-size:12px; margin-left:12px; font-family: IBM Plex Mono, monospace;'>
            Active {years[0] if years else 'N/A'} — {years[-1] if years else 'N/A'}
        </span>
    </div>""", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total TTPs",      total_ttps)
    c2.metric("Evolution Score", f"{evo_score:.3f}")
    c3.metric("Adaptability",    f"{adapt_score:.3f}")
    c4.metric("Years Active",    f"{len(years)}")
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    col1, col2 = st.columns([3, 2])
    with col1:
        st.markdown("<div class='section-label'>TTP Timeline</div>", unsafe_allow_html=True)
        yearly = group_df.groupby('year')['technique'].nunique().reset_index()
        yearly.columns = ['Year', 'Techniques']
        fig = go.Figure(go.Scatter(
            x=yearly['Year'], y=yearly['Techniques'],
            mode='lines+markers', fill='tozeroy',
            fillcolor='rgba(110,224,255,0.08)',
            line=dict(color='#6ee0ff', width=2),
            marker=dict(color='#6ee0ff', size=7, line=dict(color='#080c14', width=2))
        ))
        apply_theme(fig, 280)
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("<div class='section-label'>Techniques by Year</div>", unsafe_allow_html=True)
        for year in sorted(group_df['year'].unique(), reverse=True):
            techs = group_df[
                group_df['year'] == year
            ]['technique'].drop_duplicates().tolist()
            with st.expander(f"{year}  ·  {len(techs)} techniques"):
                if techs:
                    tags = "".join([f"<span class='ttp-tag'>{t}</span>" for t in techs])
                    st.markdown(tags, unsafe_allow_html=True)
                else:
                    st.markdown("<span style='color:#93acc8; font-size:12px;'>No mapped ATT&CK techniques this year (generic entries excluded)</span>", unsafe_allow_html=True)
elif page == "Emerging Threats":
    st.markdown("<div class='section-label'>Threat Detection</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Emerging TTP Radar</h1>", unsafe_allow_html=True)
    if not emerging_df.empty:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Emerging Techniques", len(emerging_df))
        c2.metric("Max Growth Rate",  f"{emerging_df['growth_rate'].max():.1f}x")
        c3.metric("Mean Growth Rate", f"{emerging_df['growth_rate'].mean():.2f}x")
        c4.metric("Critical Alerts",  len(emerging_df[emerging_df['growth_rate'] > 3]))
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("<div class='section-label'>Growth Rate Ranking</div>", unsafe_allow_html=True)
            fig = px.bar(
                emerging_df.head(15).iloc[::-1],
                x='growth_rate', y='technique', orientation='h',
                color='growth_rate',
                color_continuous_scale=[[0,'#1d4ed8'],[0.5,'#f97316'],[1,'#ef4444']],
            )
            fig.update_coloraxes(showscale=False)
            apply_theme(fig, 420)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Alert Feed</div>", unsafe_allow_html=True)
            for _, row in emerging_df.iterrows():
                rate = float(row['growth_rate'])
                cls  = "critical" if rate > 3 else "high" if rate > 1 else "medium"
                lbl  = "CRITICAL" if rate > 3 else "HIGH"  if rate > 1 else "MEDIUM"
                acc  = "red" if cls == "critical" else "orange" if cls == "high" else "yellow"
                st.markdown(f"""
                <div class='soc-card soc-card-accent-{acc}' style='padding:10px 14px; margin-bottom:6px;'>
                    <div style='display:flex; justify-content:space-between; align-items:center;'>
                        <span class='badge badge-{cls}'>{lbl}</span>
                        <span style='font-family:IBM Plex Mono,monospace; color:#6ee0ff; font-size:13px; font-weight:700;'>{rate}x</span>
                    </div>
                    <div style='color:#f1f5f9; font-size:13px; margin-top:5px; font-weight:600;'>{row['technique']}</div>
                    <div style='font-family:IBM Plex Mono,monospace; color:#93acc8; font-size:10.5px; margin-top:3px;'>
                        {int(row['start_year'])} → {int(row['end_year'])} &nbsp;·&nbsp; {int(row['end_count'])} groups
                    </div>
                </div>""", unsafe_allow_html=True)
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>Full Dataset</div>", unsafe_allow_html=True)
        st.dataframe(emerging_df, use_container_width=True)
elif page == "Convergence Analysis":
    st.markdown("<div class='section-label'>Cross-Actor Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>TTP Convergence Analysis</h1>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Alerts",       f"{len(conv_df):,}"                              if not conv_df.empty else "0")
    c2.metric("Max Group Overlap",  f"{conv_df['num_groups'].max()}"                 if not conv_df.empty else "0")
    c3.metric("Mean Group Overlap", f"{conv_df['num_groups'].mean():.1f}"            if not conv_df.empty else "0")
    c4.metric("High Convergence",   f"{len(conv_df[conv_df['num_groups']>20])}"      if not conv_df.empty else "0")
    if not conv_df.empty:
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("<div class='section-label'>Convergence Over Time</div>", unsafe_allow_html=True)
            fig = px.scatter(
                conv_df.head(50), x='year_start', y='num_groups',
                size='num_groups', hover_name='technique', color='num_groups',
                color_continuous_scale=[[0,'#1d4ed8'],[0.5,'#a78bfa'],[1,'#ef4444']],
            )
            fig.update_coloraxes(showscale=False)
            apply_theme(fig, 350)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Top Events</div>", unsafe_allow_html=True)
            for _, row in conv_df.head(10).iterrows():
                groups_count = int(row['num_groups'])
                cls = "critical" if groups_count > 30 else "high" if groups_count > 15 else "medium"
                acc = "red" if cls == "critical" else "orange" if cls == "high" else "yellow"
                st.markdown(f"""
                <div class='soc-card soc-card-accent-{acc}' style='padding:10px 14px; margin-bottom:6px;'>
                    <div style='color:#f1f5f9; font-size:13px; font-weight:600;'>{row['technique']}</div>
                    <div style='font-family:IBM Plex Mono,monospace; color:#93acc8; font-size:10.5px; margin-top:3px;'>
                        {int(row['year_start'])}–{int(row['year_end'])} &nbsp;·&nbsp;
                        <span style='color:#c4a6ff;'>{groups_count} groups converging</span>
                    </div>
                </div>""", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>All Convergence Alerts</div>", unsafe_allow_html=True)
        st.dataframe(conv_df, use_container_width=True)
elif page == "Evolution Scores":
    st.markdown("<div class='section-label'>Adversary Analytics</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Evolution Score Rankings</h1>", unsafe_allow_html=True)
    if not evo_df.empty:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Groups Scored", len(evo_df))
        c2.metric("Max Score",     f"{evo_df['evolution_score'].max():.3f}")
        c3.metric("Mean Score",    f"{evo_df['evolution_score'].mean():.3f}")
        c4.metric("Std Deviation", f"{evo_df['evolution_score'].std():.3f}")
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("<div class='section-label'>Top 20 Most Adaptive</div>", unsafe_allow_html=True)
            top20 = evo_df.head(20).sort_values('evolution_score')
            fig = go.Figure(go.Bar(
                x=top20['evolution_score'], y=top20['apt_group'], orientation='h',
                marker=dict(
                    color=top20['evolution_score'],
                    colorscale=[[0,'#1d4ed8'],[0.5,'#a78bfa'],[1,'#ef4444']],
                    showscale=False
                )
            ))
            apply_theme(fig, 520)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Score Distribution</div>", unsafe_allow_html=True)
            fig = px.histogram(evo_df, x='evolution_score', nbins=20, color_discrete_sequence=['#6ee0ff'])
            apply_theme(fig, 240)
            st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Full Rankings</div>", unsafe_allow_html=True)
        evo_display = evo_df.copy()
        for col in ['first_seen', 'last_seen']:
            if col in evo_display.columns:
                evo_display[col] = evo_display[col].astype(int).astype(str)
        st.dataframe(evo_display, use_container_width=True)
elif page == "Nation-State":
    st.markdown("<div class='section-label'>Geopolitical Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Nation-State Behavioral Analysis</h1>", unsafe_allow_html=True)
    if not nation_df.empty:
        cols = st.columns(len(nation_df))
        for i, (_, row) in enumerate(nation_df.iterrows()):
            color = NATION_COLORS.get(row['nation'], '#5c6f8a')
            cols[i].markdown(f"""
            <div class='nation-card' style='border-left: 3px solid {color};'>
                <div style='font-family:IBM Plex Mono,monospace; font-size:22px; font-weight:700; color:{color};'>{row['total_groups']}</div>
                <div style='font-size:11px; font-weight:700; color:#cbd5e1; margin-top:4px;'>{row['nation']}</div>
                <div style='font-family:IBM Plex Mono,monospace; font-size:10px; color:#93acc8; margin-top:2px;'>{row['total_records']} records</div>
            </div>""", unsafe_allow_html=True)
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("<div class='section-label'>APT Group Distribution</div>", unsafe_allow_html=True)
            pie_data = nation_df[nation_df['nation'] != 'Others']
            fig = px.pie(
                pie_data, values='total_groups', names='nation',
                color='nation', color_discrete_map=NATION_COLORS, hole=0.4
            )
            fig.update_traces(
                textinfo='percent+label',
                textfont_color='#f1f5f9',
                showlegend=True
            )
            fig.update_layout(
                legend=dict(
                    font=dict(color='#cbd5e1', size=11),
                    bgcolor='rgba(13,20,36,0.8)',
                    bordercolor='#1a2744',
                    borderwidth=1
                )
            )
            apply_theme(fig, 320)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Avg Evolution Score by Nation</div>", unsafe_allow_html=True)
            if not nation_evo_df.empty:
                fig = px.bar(
                    nation_evo_df.sort_values('avg_evolution_score', ascending=True),
                    x='avg_evolution_score', y='nation', orientation='h',
                    color='nation', color_discrete_map=NATION_COLORS
                )
                fig.update_layout(showlegend=False)
                apply_theme(fig, 320)
                st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Nation Profiles</div>", unsafe_allow_html=True)
        st.dataframe(nation_df, use_container_width=True)
        if not nation_evo_df.empty:
            st.markdown("<div class='section-label'>Evolution Scores</div>", unsafe_allow_html=True)
            st.dataframe(nation_evo_df, use_container_width=True)
elif page == "Mitigation Centre":
    st.markdown("<div class='section-label'>Defensive Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Mitigation Recommendations</h1>", unsafe_allow_html=True)
    if not mit_df.empty:
        critical_mit = mit_df[mit_df['priority'].str.contains('CRITICAL', na=False)]
        high_mit     = mit_df[mit_df['priority'].str.contains('HIGH',     na=False)]
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Controls", len(mit_df))
        c2.metric("Critical",       len(critical_mit))
        c3.metric("High Priority",  len(high_mit))
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        for priority_label in ['CRITICAL', 'HIGH', 'MEDIUM']:
            subset = mit_df[mit_df['priority'].str.contains(priority_label, na=False)]
            if subset.empty:
                continue
            cls = priority_label.lower()
            acc = "red" if cls == "critical" else "orange" if cls == "high" else "yellow"
            st.markdown(f"<div class='section-label'>{priority_label} Priority</div>", unsafe_allow_html=True)
            for _, row in subset.iterrows():
                mit_items = str(row['mitigations']).split(' | ')
                mit_html  = "".join([f"<div style='color:#cbd5e1; font-size:12px; padding:3px 0;'>→ {m}</div>" for m in mit_items])
                with st.expander(f"{row['technique']}  ·  Score {row['score']}"):
                    st.markdown(f"""
                    <div style='margin-bottom:10px;'>
                        <span class='badge badge-{cls}'>{priority_label}</span>
                        <span style='font-family:IBM Plex Mono,monospace; color:#93acc8;
                                     font-size:11px; margin-left:10px;'>Source: {row['source']}</span>
                    </div>
                    {mit_html}""", unsafe_allow_html=True)
elif page == "Predictions":
    st.markdown("<div class='section-label'>Predictive Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Markov Chain TTP Predictions</h1>", unsafe_allow_html=True)
    if not pred_df.empty:
        tech_col = 'predicted_technique' if 'predicted_technique' in pred_df.columns else 'predicted_ttp'
        # Markov + Velocity Backoff (gamma=0.15) is the real, ablation-
        # selected model baked into predict_all_groups() by default - see
        # markov_prediction.py. The metric widget renders the value at a
        # large fixed font size (31px) regardless of string length, so
        # even "Markov + Velocity (γ=0.15)" (27 chars) still got clipped
        # with an ellipsis. Shortened to fit, with gamma and the
        # similarity-fallback detail both moved into the delta line.
        has_similarity = 'method' in pred_df.columns and \
            pred_df['method'].astype(str).str.contains('similarity', case=False).any()
        method_label = "Markov+Velocity"
        method_note = "γ=0.15 + similarity fallback" if has_similarity else "γ=0.15"
        global_techniques = set(df['technique'])
        valid_preds = pred_df[pred_df[tech_col].isin(global_techniques)]
        coverage_rate = (len(valid_preds) / len(pred_df)) if len(pred_df) else 0.0
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Predictions", f"{len(pred_df):,}")
        c2.metric("Groups Covered",    pred_df['apt_group'].nunique())
        c3.metric("Coverage Rate",     f"{coverage_rate:.3f}")
        c4.metric("Method",            method_label, method_note)
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        if not baseline_df.empty:
            st.markdown("<div class='section-label'>Held-Out Validation (Precision@K)</div>", unsafe_allow_html=True)
            st.dataframe(baseline_df, use_container_width=True)
            st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        selected_group = st.selectbox("Filter by APT Group", ["All"] + sorted(pred_df['apt_group'].unique()))
        display_df = pred_df if selected_group == "All" else pred_df[pred_df['apt_group'] == selected_group]
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("<div class='section-label'>Top Predictions by Probability</div>", unsafe_allow_html=True)
            cap = display_df['probability'].quantile(0.95)
            top = (
                display_df[display_df['probability'] <= cap]
                .sort_values(['probability', tech_col], ascending=[False, True])
                .head(15)
                .iloc[::-1]
            )
            fig = go.Figure(go.Bar(
                x=top['probability'], y=top[tech_col], orientation='h',
                marker=dict(
                    color=top['probability'],
                    colorscale=[[0,'#1d4ed8'],[1,'#a78bfa']],
                    showscale=False
                )
            ))
            apply_theme(fig, 420)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Prediction Table</div>", unsafe_allow_html=True)
            st.dataframe(
                display_df[[tech_col, 'apt_group', 'probability']]
                    .sort_values(['probability', tech_col], ascending=[False, True])
                    .head(20),
                use_container_width=True
            )
elif page == "Defence Gaps":
    st.markdown("<div class='section-label'>Defence Coverage Analysis</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Defence Gap Analysis</h1>", unsafe_allow_html=True)
    if not gaps_df.empty:
        no_defence = gaps_df[gaps_df['has_defence'] == False] if 'has_defence' in gaps_df.columns else gaps_df
        critical_g = gaps_df[gaps_df['priority'] == 'Critical']
        high_g     = gaps_df[gaps_df['priority'] == 'High']
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Techniques Analysed", len(gaps_df))
        c2.metric("Critical Gaps",       len(critical_g))
        c3.metric("High Priority Gaps",  len(high_g))
        c4.metric("No Defence Mapped",   f"{len(no_defence)}/{len(gaps_df)}")
        no_defence_pct = (len(no_defence) / len(gaps_df) * 100) if len(gaps_df) else 0.0
        st.markdown(f"""
        <div class='soc-card soc-card-accent-red' style='margin: 16px 0;'>
            <span class='badge badge-critical'>CRITICAL FINDING</span>
            <span style='color:#f1f5f9; font-size:13px; margin-left:10px; font-weight:500;'>
                {len(no_defence)} out of {len(gaps_df)} techniques ({no_defence_pct:.1f}%) have no MITRE ATT&CK-published mitigation
            </span>
        </div>""", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("<div class='section-label'>Top Gaps by Risk Score</div>", unsafe_allow_html=True)
            fig = px.bar(
                gaps_df.head(15).iloc[::-1],
                x='gap_score', y='technique', orientation='h',
                color='priority',
                color_discrete_map={
                    'Critical': '#ef4444', 'High': '#f97316',
                    'Medium':   '#eab308', 'Low':  '#22c55e'
                }
            )
            apply_theme(fig, 420)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Priority Breakdown</div>", unsafe_allow_html=True)
            pc = gaps_df['priority'].value_counts().reset_index()
            pc.columns = ['Priority', 'Count']
            fig = px.pie(
                pc, values='Count', names='Priority', color='Priority',
                color_discrete_map={
                    'Critical': '#ef4444', 'High': '#f97316',
                    'Medium':   '#eab308', 'Low':  '#22c55e'
                }, hole=0.4
            )
            fig.update_traces(textfont_color='#f1f5f9')
            apply_theme(fig, 420)
            st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Full Gap Analysis</div>", unsafe_allow_html=True)
        st.dataframe(gaps_df, use_container_width=True)
elif page == "Adaptability Index":
    st.markdown("<div class='section-label'>Adversary Behaviour Analytics</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Adaptability Index</h1>", unsafe_allow_html=True)
    if not adapt_df.empty:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Groups Scored", len(adapt_df))
        c2.metric("Max Index",     f"{adapt_df['adaptability_index'].max():.3f}")
        c3.metric("Mean Index",    f"{adapt_df['adaptability_index'].mean():.3f}")
        c4.metric("Std Dev",       f"{adapt_df['adaptability_index'].std():.3f}")
        excluded_count = df['apt_group'].nunique() - len(adapt_df)
        st.markdown(f"""
        <div class='soc-card soc-card-accent-blue' style='margin:8px 0 16px 0; padding:10px 14px;'>
            <span style='color:#93acc8; font-size:12px;'>
                ℹ️ Covers groups with 2+ years of activity only.
                {excluded_count} single-year groups are excluded — insufficient temporal data
                to compute meaningful year-over-year churn rates.
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div class='section-label'>Top 20 Most Adaptable Groups</div>", unsafe_allow_html=True)
        top20 = adapt_df.head(20).iloc[::-1]
        fig = go.Figure(go.Bar(
            x=top20['adaptability_index'], y=top20['apt_group'], orientation='h',
            marker=dict(
                color=top20['adaptability_index'],
                colorscale=[[0,'#1d4ed8'],[0.5,'#a78bfa'],[1,'#ef4444']],
                showscale=False
            )
        ))
        apply_theme(fig, 520)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Full Data</div>", unsafe_allow_html=True)
        st.dataframe(adapt_df, use_container_width=True)
elif page == "Technique Lifespan":
    st.markdown("<div class='section-label'>Technique Persistence Analysis</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>Technique Lifespan Tracker</h1>", unsafe_allow_html=True)
    if not lifespan_df.empty:
        active  = lifespan_df[lifespan_df['status'] == 'Active']
        retired = lifespan_df[lifespan_df['status'] == 'Retired']
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Techniques", len(lifespan_df))
        c2.metric("Active",           len(active))
        c3.metric("Retired",          len(retired))
        c4.metric("Mean Lifespan",    f"{lifespan_df['lifespan_years'].mean():.1f} yrs")
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("<div class='section-label'>Top 15 Longest-Lived Techniques</div>", unsafe_allow_html=True)
            top = (
                lifespan_df
                .sort_values(['lifespan_years', 'technique'], ascending=[False, True])
                .head(15)
                .iloc[::-1]
            )
            fig = px.bar(
                top, x='lifespan_years', y='technique', orientation='h',
                color='status',
                color_discrete_map={'Active': '#22c55e', 'Retired': '#ef4444'}
            )
            apply_theme(fig, 420)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown("<div class='section-label'>Active vs Retired</div>", unsafe_allow_html=True)
            fig = px.pie(
                values=[len(active), len(retired)], names=['Active', 'Retired'],
                color_discrete_sequence=['#22c55e', '#ef4444'], hole=0.4
            )
            fig.update_traces(textfont_color='#f1f5f9')
            apply_theme(fig, 280)
            st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Full Dataset</div>", unsafe_allow_html=True)
        lifespan_display = lifespan_df.copy()
        for col in ['first_seen', 'last_seen']:
            if col in lifespan_display.columns:
                lifespan_display[col] = lifespan_display[col].astype(int).astype(str)
        st.dataframe(lifespan_display, use_container_width=True)
elif page == "TTP Velocity":
    st.markdown("<div class='section-label'>Threat Propagation Analysis</div>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top:0'>TTP Velocity Tracker</h1>", unsafe_allow_html=True)
    if not velocity_df.empty:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Techniques Tracked", len(velocity_df))
        c2.metric("Max Velocity",       f"{velocity_df['avg_velocity'].max():.3f}")
        c3.metric("Mean Velocity",      f"{velocity_df['avg_velocity'].mean():.3f}")
        c4.metric("Fast Spreading",     len(velocity_df[velocity_df['avg_velocity'] > 1]))
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>Top 15 Fastest Spreading Techniques</div>", unsafe_allow_html=True)
        top15 = velocity_df.head(15).iloc[::-1]
        fig = go.Figure(go.Bar(
            x=top15['avg_velocity'], y=top15['technique'], orientation='h',
            marker=dict(
                color=top15['avg_velocity'],
                colorscale=[[0,'#1d4ed8'],[0.5,'#f97316'],[1,'#ef4444']],
                showscale=False
            )
        ))
        apply_theme(fig, 420)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("<div class='section-label'>Velocity Data</div>", unsafe_allow_html=True)
        st.dataframe(velocity_df, use_container_width=True)
