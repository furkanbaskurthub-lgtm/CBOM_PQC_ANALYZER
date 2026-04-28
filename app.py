"""
PQC-Ready Analyzer - Streamlit Dashboard
Kullanıcı dostu web arayüzü
"""

import streamlit as st
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import tempfile
from collections import Counter
from pathlib import Path
from datetime import datetime

from main import PQCReadyAnalyzer
from run_repo_batch import run_batch_scan
from models.crypto_schema import calculate_risk_score, NIST_PQC_RISK_MAP
from utils.dataset_builder import DEFAULT_INSTRUCTION, build_instruction_records
from utils.repo_batch import list_scan_profiles


ANALYZER_BUILD = "2026-04-25-decision-layer"


# Sayfa konfigürasyonu
st.set_page_config(
    page_title="PQC-Ready Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS Styling
st.markdown("""
    <style>
    .main {
        padding-top: 0rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .risk-critical { color: #d32f2f; font-weight: bold; }
    .risk-high { color: #f57c00; font-weight: bold; }
    .risk-medium { color: #fbc02d; font-weight: bold; }
    .risk-low { color: #388e3c; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)


def initialize_session():
    """Session state'i başlat"""
    if (
        "analyzer" not in st.session_state
        or st.session_state.get("analyzer_build") != ANALYZER_BUILD
    ):
        st.session_state.analyzer = PQCReadyAnalyzer()
        st.session_state.analyzer_build = ANALYZER_BUILD

    if "cbom_results" not in st.session_state:
        st.session_state.cbom_results = {}

    if "current_cbom" not in st.session_state:
        st.session_state.current_cbom = None

    if "current_labeled_assets" not in st.session_state:
        st.session_state.current_labeled_assets = []

    if "current_decision_split" not in st.session_state:
        st.session_state.current_decision_split = {
            "training": [],
            "review": [],
            "policy_drop": [],
            "quality_reject": [],
            "dropped": [],
        }

    if "last_batch_summary" not in st.session_state:
        st.session_state.last_batch_summary = None


def create_algorithm_distribution_chart(cbom):
    """Algoritma dağılımı pasta grafiği oluştur"""
    if not cbom.crypto_assets:
        return None
    
    algo_names = [a.algorithm.name for a in cbom.crypto_assets]
    algo_counts = pd.Series(algo_names).value_counts()
    
    fig = px.pie(
        values=algo_counts.values,
        names=algo_counts.index,
        title="Tespit Edilen Algoritmaların Dağılımı",
        hole=0.3
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig


def create_pqc_readiness_chart(cbom):
    """PQC Readiness gösterge tablosu"""
    total = len(cbom.crypto_assets)
    pqc_ready = sum(1 for a in cbom.crypto_assets if a.algorithm.is_pqc_safe)
    not_ready = total - pqc_ready
    
    fig = go.Figure(data=[
        go.Bar(
            x=['PQC Ready', 'Not Ready'],
            y=[pqc_ready, not_ready],
            marker_color=['#4caf50', '#f44336'],
            text=[pqc_ready, not_ready],
            textposition='auto'
        )
    ])
    
    fig.update_layout(
        title="PQC Hazırlık Durumu",
        xaxis_title="",
        yaxis_title="Algoritma Sayısı",
        height=400,
        showlegend=False
    )
    
    return fig


def create_risk_distribution_chart(cbom):
    """Risk seviyesi dağılımı"""
    risk_levels = {
        "critical": sum(1 for a in cbom.crypto_assets if a.risk_level == "critical"),
        "high": sum(1 for a in cbom.crypto_assets if a.risk_level == "high"),
        "medium": sum(1 for a in cbom.crypto_assets if a.risk_level == "medium"),
        "low": sum(1 for a in cbom.crypto_assets if a.risk_level == "low"),
    }
    
    colors = {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#fbc02d",
        "low": "#388e3c"
    }

    fig = go.Figure(data=[
        go.Bar(
            x=list(risk_levels.keys()),
            y=list(risk_levels.values()),
            marker_color=[colors[k] for k in risk_levels.keys()],
            text=list(risk_levels.values()),
            textposition='auto'
        )
    ])

    fig.update_layout(
        title="Risk Seviyesi Dağılımı",
        xaxis_title="Risk Seviyesi",
        yaxis_title="Sayı",
        height=400,
        showlegend=False
    )

    return fig


def display_algorithm_table(cbom):
    """Algoritmaları tablo olarak göster"""
    algorithms = []

    for asset in cbom.crypto_assets:
        risk = calculate_risk_score(asset.algorithm.name, asset.algorithm.key_length)

        algorithms.append({
            "Algoritma": asset.algorithm.name,
            "Tür": asset.algorithm.type.value,
            "Anahtar Uzunluğu": asset.algorithm.key_length or "N/A",
            "PQC Ready": "✅ Evet" if asset.algorithm.is_pqc_safe else "❌ Hayır",
            "Risk Skoru": round(risk.final_risk, 1),
            "Risk Seviyesi": asset.risk_level.upper(),
            "Güven": f"{round(asset.confidence * 100)}%"
        })

    df = pd.DataFrame(algorithms)
    if df.empty:
        return df

    def color_risk(val):
        if "CRITICAL" in val:
            return "background-color: #ffcccc"
        if "HIGH" in val:
            return "background-color: #ffe5cc"
        if "MEDIUM" in val:
            return "background-color: #ffffcc"
        return "background-color: #ccffcc"

    styled_df = df.style.map(color_risk, subset=pd.IndexSlice[:, ["Risk Seviyesi"]])
    return styled_df


def display_recommendations(report):
    """Tavsiyeler sektionu"""
    recommendations = report["recommendations"]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Genel Risk Skoru", f"{recommendations['overall_score']:.1f}/100")

    with col2:
        st.metric("Kritik Sorunlar", len(recommendations["critical_issues"]))

    with col3:
        st.metric("Yüksek Öncelik", len(recommendations["high_priority"]))

    with col4:
        st.metric("Toplam Bileşen", len(report["assets"]))

    st.divider()

    if recommendations["critical_issues"]:
        st.subheader("🚨 Kritik Sorunlar")
        for issue in recommendations["critical_issues"]:
            with st.expander(f"⚠️ {issue['algorithm']} - Risk: {issue['current_risk']:.1f}"):
                st.error(issue["recommendation"])
                if issue["mitigation"]:
                    st.info(f"**Çözüm:** {issue['mitigation']}")

    if recommendations["high_priority"]:
        st.subheader("⚠️ Yüksek Öncelik")
        for issue in recommendations["high_priority"]:
            with st.expander(f"🔴 {issue['algorithm']} - Risk: {issue['current_risk']:.1f}"):
                st.warning(issue["recommendation"])
                if issue["mitigation"]:
                    st.info(f"**Çözüm:** {issue['mitigation']}")

    if recommendations["medium_priority"]:
        st.subheader("ℹ️ Orta Öncelik")
        for issue in recommendations["medium_priority"]:
            with st.expander(f"🟡 {issue['algorithm']} - Risk: {issue['current_risk']:.1f}"):
                st.warning(issue["recommendation"])

    if recommendations["low_priority"]:
        st.subheader("✅ Düşük Risk")
        for issue in recommendations["low_priority"]:
            with st.expander(f"🟢 {issue['algorithm']} - Risk: {issue['current_risk']:.1f}"):
                st.success(issue["recommendation"])


def create_field_confidence_chart(labeled_assets):
    """Field confidence ortalamasını görselleştir."""
    if not labeled_assets:
        return None

    fields = ["algorithm", "category", "key_length", "mode", "padding", "usage"]
    averages = []

    for field in fields:
        values = [asset.validation.field_scores.get(field, 0.0) for asset in labeled_assets]
        avg = sum(values) / len(values) if values else 0.0
        averages.append(round(avg, 3))

    fig = go.Figure(data=[
        go.Bar(
            x=fields,
            y=averages,
            marker_color="#1f77b4",
            text=averages,
            textposition="auto",
        )
    ])

    fig.update_layout(
        title="V2 Field Confidence Ortalamaları",
        xaxis_title="Alan",
        yaxis_title="Ortalama Güven",
        yaxis=dict(range=[0, 1]),
        height=380,
        showlegend=False,
    )
    return fig


def display_v2_label_table(labeled_assets):
    """V2 label sonuçlarını tablo halinde üret."""
    rows = []
    for asset in labeled_assets:
        rows.append({
            "Asset ID": asset.asset_id,
            "Algorithm": asset.algorithm,
            "Family": asset.family,
            "Category": asset.category.value,
            "PQC Status": asset.pqc_status.value,
            "Confidence": round(asset.confidence, 3),
            "Key Length State": asset.key_length.state.value,
            "Mode State": asset.mode.state.value,
            "Padding State": asset.padding.state.value,
            "Validation": "OK" if asset.validation.is_valid else "ISSUE",
            "Issue Count": len(asset.validation.issues),
        })
    return pd.DataFrame(rows)


def display_validation_issues(labeled_assets):
    """Validation issue detaylarını göster."""
    severity_rank = {"high": 3, "medium": 2, "low": 1}

    def classify_issue_severity(issue_name: str) -> str:
        issue = issue_name.lower()
        if any(k in issue for k in ["cross_algorithm", "invalid", "contamination"]):
            return "high"
        if any(k in issue for k in ["removed", "not_allowed", "not_supported"]):
            return "medium"
        return "low"

    issue_rows = []
    for asset in labeled_assets:
        for issue in asset.validation.issues:
            sev = classify_issue_severity(issue)
            issue_rows.append(
                {
                    "Algorithm": asset.algorithm,
                    "Issue": issue,
                    "Severity": sev,
                    "Severity Score": severity_rank[sev],
                    "Asset ID": asset.asset_id,
                }
            )

    if not issue_rows:
        st.success("Validation engine issue tespit etmedi.")
        return

    issue_df = pd.DataFrame(issue_rows)
    counts = issue_df["Severity"].value_counts().to_dict()
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("High", counts.get("high", 0))
    with c2:
        st.metric("Medium", counts.get("medium", 0))
    with c3:
        st.metric("Low", counts.get("low", 0))

    selected = st.multiselect(
        "Severity filtresi",
        options=["high", "medium", "low"],
        default=["high", "medium", "low"],
    )

    filtered_df = issue_df[issue_df["Severity"].isin(selected)] if selected else issue_df.iloc[0:0]

    if filtered_df.empty:
        st.info("Seçilen filtrede issue yok.")
        return

    st.dataframe(
        filtered_df[["Algorithm", "Issue", "Severity", "Severity Score", "Asset ID"]],
        use_container_width=True,
    )

    any_issue = False
    for asset in labeled_assets:
        filtered_issues = [
            issue
            for issue in asset.validation.issues
            if classify_issue_severity(issue) in selected
        ]
        if not filtered_issues:
            continue
        any_issue = True
        with st.expander(f"{asset.algorithm} - {len(filtered_issues)} issue"):
            st.write("**Issues**")
            for issue in filtered_issues:
                sev = classify_issue_severity(issue)
                st.write(f"- [{sev}] {issue}")
            if asset.evidence:
                st.write("**Evidence**")
                for ev in asset.evidence[:3]:
                    location = f"{ev.file_path}:{ev.line_start}" if ev.line_start else ev.file_path
                    st.write(f"- {location} | {ev.detector}")
                    if ev.snippet:
                        st.code(ev.snippet)

    if not any_issue:
        st.info("Seçili filtre için detay gösterilecek issue yok.")


def get_decision_summary(labeled_assets):
    """Decision katmanı özet metriklerini üret."""
    total = len(labeled_assets)
    include_count = sum(1 for a in labeled_assets if a.decision and a.decision.include)
    review_count = sum(
        1
        for a in labeled_assets
        if a.decision and (not a.decision.include) and a.decision.final_action.value == "require_review"
    )
    dropped_count = sum(
        1
        for a in labeled_assets
        if a.decision and (not a.decision.include) and a.decision.final_action.value != "require_review"
    )
    drop_rate = (dropped_count / total * 100.0) if total else 0.0
    avg_quality = (
        sum(a.decision.quality_score for a in labeled_assets if a.decision) / total
        if total
        else 0.0
    )
    return {
        "total": total,
        "included": include_count,
        "review": review_count,
        "dropped": dropped_count,
        "drop_rate": round(drop_rate, 2),
        "avg_quality": round(avg_quality, 2),
    }


def create_quality_histogram(labeled_assets):
    """Quality score histogram."""
    scores = [a.decision.quality_score for a in labeled_assets if a.decision]
    if not scores:
        return None
    fig = px.histogram(
        x=scores,
        nbins=10,
        title="Quality Score Dağılımı",
        labels={"x": "Quality Score", "y": "Count"},
    )
    fig.update_layout(height=360)
    return fig


def create_severity_distribution_decision_chart(labeled_assets):
    """Max severity dağılımı grafiği."""
    severities = [a.decision.max_severity.value for a in labeled_assets if a.decision]
    if not severities:
        return None
    counts = Counter(severities)
    order = ["high", "medium", "low"]
    values = [counts.get(k, 0) for k in order]
    fig = go.Figure(
        data=[
            go.Bar(
                x=order,
                y=values,
                marker_color=["#d32f2f", "#f57c00", "#388e3c"],
                text=values,
                textposition="auto",
            )
        ]
    )
    fig.update_layout(title="Decision Max Severity Dağılımı", height=360, showlegend=False)
    return fig


def get_decision_table(labeled_assets):
    """Decision katmanı için açıklanabilir tablo."""
    rows = []
    for asset in labeled_assets:
        decision = asset.decision
        if not decision:
            continue
        rows.append(
            {
                "Algorithm": asset.algorithm,
                "Include": "yes" if decision.include else "no",
                "Final Action": decision.final_action.value,
                "Max Severity": decision.max_severity.value,
                "Quality Score": decision.quality_score,
                "Quality Tier": decision.quality_tier.value,
                "Unknown Ratio": round(decision.unknown_ratio, 3),
                "Issue Count": decision.issue_count,
                "Evidence Count": decision.evidence_count,
                "Reasons": ", ".join(decision.reasons) if decision.reasons else "none",
            }
        )
    return pd.DataFrame(rows)


def main():
    """Ana uygulama"""
    initialize_session()
    
    # Header
    st.title("🔐 PQC-Ready Analyzer")
    st.markdown("*Post-Quantum Cryptography Hazırlık Analiz Aracı*")
    
    # Sidebar
    with st.sidebar:
        st.header("📁 Dosya Seçimi")

        analysis_mode = st.radio(
            "Analiz modu",
            options=["single-file", "github-repo"],
            format_func=lambda x: "Tek Dosya" if x == "single-file" else "GitHub Repo (Batch)",
            horizontal=False,
        )
        
        uploaded_file = st.file_uploader(
            "Dosya yükle",
            type=["bin", "out", "exe", "dll", "py", "c", "cpp", "java", "txt"],
            help="Binary, kaynak kod veya metin dosyası yükle"
        )

        repo_url = ""
        selected_profile = "fineract-java"
        batch_workers = 4
        repo_ref = ""
        llm_candidate_only = True
        llm_min_confidence = 0.85
        llm_max_snippets = 2
        run_batch_button = False

        if analysis_mode == "github-repo":
            st.subheader("🔗 GitHub Repo")
            repo_url = st.text_input(
                "GitHub URL",
                placeholder="https://github.com/apache/fineract",
                help="Sadece GitHub HTTPS URL desteklenir",
            ).strip()
            repo_ref = st.text_input(
                "Branch/Tag (opsiyonel)",
                placeholder="main",
                help="Boş bırakılırsa default branch kullanılır",
            ).strip()

            profile_names = list_scan_profiles("config/scan_profiles.json")
            if not profile_names:
                profile_names = ["fineract-java", "default-source"]

            selected_profile = st.selectbox(
                "Tarama profili",
                options=profile_names,
                index=0 if "fineract-java" in profile_names else 0,
            )

            batch_workers = int(
                st.number_input(
                    "Worker sayısı",
                    min_value=1,
                    max_value=32,
                    value=4,
                    step=1,
                )
            )

            llm_candidate_only = st.checkbox(
                "Hızlı LLM modu (aday dosyalar)",
                value=True,
                help="LLM'i sadece statik bulgu olan/şüpheli dosyalarda çalıştırır.",
            )

            llm_min_confidence = float(
                st.slider(
                    "LLM aday confidence eşiği",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.85,
                    step=0.05,
                    help="Candidate modunda static confidence bu eşikten düşükse LLM çalışır.",
                )
            )

            llm_max_snippets = int(
                st.number_input(
                    "LLM max snippet / dosya",
                    min_value=1,
                    max_value=6,
                    value=2,
                    step=1,
                )
            )

            run_batch_button = st.button("🚀 Repo Batch Analizi", use_container_width=True)
        
        use_llm = st.checkbox(
            "LLM Analizini Kullan",
            value=False,
            help="Kaynak kod için LLM analizi etkinleştir (OpenAI API gerekli)"
        )
        
        analyze_button = st.button("🔍 Analiz Başlat", use_container_width=True)
        
        st.divider()
        
        st.subheader("ℹ️ Bilgi")
        st.info("""
        **PQC-Ready Analyzer** şunları yapar:
        
        - 🔎 Kriptografik algoritmaları tespit eder
        - 📊 NIST PQC standartlarına göre risk puanı hesaplar
        - 📋 CycloneDX formatında CBOM oluşturur
        - 💡 PQC yükseltme önerileri sunar
        """)
    
    # Ana içerik - Repo batch modu
    if analysis_mode == "github-repo" and run_batch_button:
        if not repo_url:
            st.error("GitHub URL girin.")
        else:
            with st.spinner("Repo klonlanıyor ve batch analiz çalışıyor... 🔄"):
                try:
                    # URL mode uses CLI-compatible function through temporary clone and quality gate pipeline.
                    from run_repo_batch import _clone_repo_to_temp

                    repo_root, temp_clone_dir = _clone_repo_to_temp(repo_url, repo_ref, clone_depth=1)
                    try:
                        summary = run_batch_scan(
                            repo_root=repo_root,
                            profile_name=selected_profile,
                            use_llm=use_llm,
                            output_dir="output",
                            workers=batch_workers,
                            llm_candidate_only=llm_candidate_only,
                            llm_min_confidence=llm_min_confidence,
                            llm_max_snippets=llm_max_snippets,
                        )
                        summary["repo_url"] = repo_url
                        summary["ref"] = repo_ref
                        st.session_state.last_batch_summary = summary
                        st.success("✅ Repo batch analizi tamamlandı!")
                    finally:
                        import shutil

                        shutil.rmtree(temp_clone_dir, ignore_errors=True)
                except Exception as e:
                    st.error(f"❌ Repo batch analiz hatası: {str(e)}")

    # Ana içerik - Tek dosya modu
    if analysis_mode == "single-file" and analyze_button and uploaded_file:
        # Dosyayı kaydet
        temp_dir = Path(tempfile.gettempdir()) / "pqc-ready-analyzer"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / uploaded_file.name
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        with st.spinner("Analiz ediliyor... 🔄"):
            try:
                # Her analizde analyzer'ı taze oluştur; eski session nesnesinden kaynaklı stale kodu engeller.
                st.session_state.analyzer = PQCReadyAnalyzer()
                st.session_state.analyzer_build = ANALYZER_BUILD
                cbom = st.session_state.analyzer.analyze_target(str(temp_path), use_llm)
                labeled_assets = st.session_state.analyzer.generate_labeled_assets(cbom)
                decision_split = st.session_state.analyzer.split_labeled_assets_by_decision(labeled_assets)
                st.session_state.current_cbom = cbom
                st.session_state.current_labeled_assets = labeled_assets
                st.session_state.current_decision_split = decision_split
                st.success("✅ Analiz tamamlandı!")
            except Exception as e:
                st.error(f"❌ Analiz hatası: {str(e)}")
                return
    
    # Sonuçlar göster
    if st.session_state.current_cbom:
        cbom = st.session_state.current_cbom
        labeled_assets = st.session_state.current_labeled_assets
        decision_split = st.session_state.current_decision_split
        report = st.session_state.analyzer.generate_report(cbom)
        
        # Sekmeler
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
            [
                "📊 Özet",
                "🔍 Algoritma Detayları",
                "🧬 V2 Etiketler",
                "🧭 Decision Gate",
                "📈 Grafikler",
                "💼 Tavsiyeler",
                "📥 İndir",
            ]
        )
        
        with tab1:
            st.header("Analiz Özeti")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Risk Skoru",
                    f"{cbom.risk_score:.1f}",
                    delta="🔴" if cbom.risk_score > 60 else ("🟡" if cbom.risk_score > 40 else "🟢")
                )
            
            with col2:
                st.metric(
                    "PQC Hazır",
                    f"{report['statistics']['pqc_ready']}/{report['statistics']['total_crypto_components']}"
                )
            
            with col3:
                st.metric(
                    "Toplam Bileşen",
                    report['statistics']['total_crypto_components']
                )
            
            with col4:
                st.metric(
                    "Tarama Tarihi",
                    datetime.fromisoformat(report['statistics']['scan_date']).strftime("%d.%m.%Y")
                )
            
            st.subheader("Hedef Bilgileri")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Dosya:** {cbom.target_file}")
                st.write(f"**Tür:** {cbom.target_type}")
            
            with col2:
                st.write(f"**CBOM Ref:** {cbom.bom_ref}")
                st.write(f"**Versiyon:** {cbom.version}")
        
        with tab2:
            st.header("Tespit Edilen Algoritmaları Detaylı")
            
            styled_df = display_algorithm_table(cbom)
            st.dataframe(styled_df, use_container_width=True)
            
            st.subheader("NIST PQC Standart Referansı")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**PQC Standardlarına Uygun:**")
                pqc_algorithms = [algo for algo, info in NIST_PQC_RISK_MAP.items() 
                                 if info["pqc"] > 50]
                for algo in pqc_algorithms:
                    st.write(f"✅ {algo}")
            
            with col2:
                st.write("**Legacy/Risk Altındaki Algoritmalar:**")
                legacy_algorithms = [algo for algo, info in NIST_PQC_RISK_MAP.items() 
                                    if info["pqc"] < 50 and info["base"] > 50]
                for algo in legacy_algorithms:
                    st.write(f"❌ {algo}")
        
        with tab3:
            st.header("V2 Label ve Validation")

            total_assets = len(labeled_assets)
            valid_assets = sum(1 for a in labeled_assets if a.validation.is_valid)
            invalid_assets = total_assets - valid_assets
            avg_conf = sum(a.confidence for a in labeled_assets) / total_assets if total_assets else 0.0

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("V2 Asset", total_assets)
            with c2:
                st.metric("Valid", valid_assets)
            with c3:
                st.metric("Issue İçeren", invalid_assets)
            with c4:
                st.metric("Ortalama Güven", f"{avg_conf:.2f}")

            label_df = display_v2_label_table(labeled_assets)
            if not label_df.empty:
                st.dataframe(label_df, use_container_width=True)

            chart = create_field_confidence_chart(labeled_assets)
            if chart:
                st.plotly_chart(chart, use_container_width=True)

            st.subheader("Validation Issues")
            display_validation_issues(labeled_assets)

        with tab4:
            st.header("Decision Layer ve Quality Gate")

            summary = get_decision_summary(labeled_assets)
            m1, m2, m3, m4, m5, m6 = st.columns(6)
            with m1:
                st.metric("Toplam", summary["total"])
            with m2:
                st.metric("Training", summary["included"])
            with m3:
                st.metric("Review", summary["review"])
            with m4:
                st.metric("Policy Drop", len(decision_split.get("policy_drop", [])))
            with m5:
                st.metric("Quality Reject", len(decision_split.get("quality_reject", [])))
            with m6:
                st.metric("Dropped", summary["dropped"])

            st.metric("Drop Rate", f"{summary['drop_rate']}%")

            st.metric("Ortalama Quality", f"{summary['avg_quality']}/100")

            tier_options = ["high_quality", "medium_quality", "low_quality"]
            selected_tiers = st.multiselect("Quality tier filtresi", options=tier_options, default=tier_options)

            decision_df = get_decision_table(labeled_assets)
            if not decision_df.empty and selected_tiers:
                decision_df = decision_df[decision_df["Quality Tier"].isin(selected_tiers)]

            if decision_df.empty:
                st.info("Seçilen kalite tier filtresinde kayıt yok.")
            else:
                st.dataframe(decision_df, use_container_width=True)

            c1, c2 = st.columns(2)
            with c1:
                h = create_quality_histogram(labeled_assets)
                if h:
                    st.plotly_chart(h, use_container_width=True)
            with c2:
                s = create_severity_distribution_decision_chart(labeled_assets)
                if s:
                    st.plotly_chart(s, use_container_width=True)

            before_after = pd.DataFrame(
                [
                    {"Set": "Before Filtering", "Count": len(labeled_assets)},
                    {"Set": "Training", "Count": len(decision_split.get("training", []))},
                    {"Set": "Review", "Count": len(decision_split.get("review", []))},
                    {"Set": "Policy Drop", "Count": len(decision_split.get("policy_drop", []))},
                    {"Set": "Quality Reject", "Count": len(decision_split.get("quality_reject", []))},
                    {"Set": "Dropped", "Count": len(decision_split.get("dropped", []))},
                ]
            )
            bf = px.bar(before_after, x="Set", y="Count", title="Before/After Filtering")
            st.plotly_chart(bf, use_container_width=True)

        with tab5:
            st.header("Görsel Analiz")
            
            col1, col2 = st.columns(2)
            
            with col1:
                fig1 = create_algorithm_distribution_chart(cbom)
                if fig1:
                    st.plotly_chart(fig1, use_container_width=True)
            
            with col2:
                fig2 = create_pqc_readiness_chart(cbom)
                st.plotly_chart(fig2, use_container_width=True)
            
            col3, col4 = st.columns(2)
            
            with col3:
                fig3 = create_risk_distribution_chart(cbom)
                st.plotly_chart(fig3, use_container_width=True)
        
        with tab6:
            st.header("Risk Puanlama ve Tavsiyeler")
            display_recommendations(report)
        
        with tab7:
            st.header("Sonuç İndir")
            
            # CBOM JSON
            cbom_json = json.dumps(
                json.loads(cbom.model_dump_json()),
                indent=2,
                ensure_ascii=False
            )
            
            st.download_button(
                label="📥 CBOM (JSON) İndir",
                data=cbom_json,
                file_name=f"cbom_{cbom.bom_ref}.json",
                mime="application/json"
            )
            
            # Rapor JSON
            report_json = json.dumps(report, indent=2, ensure_ascii=False)
            
            st.download_button(
                label="📊 Rapor (JSON) İndir",
                data=report_json,
                file_name=f"report_{cbom.bom_ref}.json",
                mime="application/json"
            )

            labeled_json = json.dumps(
                [asset.model_dump() for asset in labeled_assets],
                indent=2,
                ensure_ascii=False,
            )

            st.download_button(
                label="🧬 V2 Labels (JSON) İndir",
                data=labeled_json,
                file_name=f"labels_v2_{cbom.bom_ref}.json",
                mime="application/json",
            )

            records = build_instruction_records(labeled_assets, instruction=DEFAULT_INSTRUCTION)
            jsonl_data = "\n".join(
                json.dumps(record.model_dump(), ensure_ascii=True)
                for record in records
            )

            st.download_button(
                label="🤖 Instruction Dataset (JSONL) İndir",
                data=jsonl_data,
                file_name=f"dataset_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )

            training_records = build_instruction_records(decision_split.get("training", []), instruction=DEFAULT_INSTRUCTION)
            training_jsonl = "\n".join(json.dumps(record.model_dump(), ensure_ascii=True) for record in training_records)
            st.download_button(
                label="✅ Training Dataset (JSONL) İndir",
                data=training_jsonl,
                file_name=f"dataset_training_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )

            review_records = build_instruction_records(decision_split.get("review", []), instruction=DEFAULT_INSTRUCTION)
            review_jsonl = "\n".join(json.dumps(record.model_dump(), ensure_ascii=True) for record in review_records)
            st.download_button(
                label="🕵️ Review Dataset (JSONL) İndir",
                data=review_jsonl,
                file_name=f"dataset_review_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )

            policy_drop_records = build_instruction_records(decision_split.get("policy_drop", []), instruction=DEFAULT_INSTRUCTION)
            policy_drop_jsonl = "\n".join(json.dumps(record.model_dump(), ensure_ascii=True) for record in policy_drop_records)
            st.download_button(
                label="🛑 Policy Drop Dataset (JSONL) İndir",
                data=policy_drop_jsonl,
                file_name=f"dataset_policy_drop_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )

            quality_reject_records = build_instruction_records(decision_split.get("quality_reject", []), instruction=DEFAULT_INSTRUCTION)
            quality_reject_jsonl = "\n".join(json.dumps(record.model_dump(), ensure_ascii=True) for record in quality_reject_records)
            st.download_button(
                label="⚖️ Quality Reject Dataset (JSONL) İndir",
                data=quality_reject_jsonl,
                file_name=f"dataset_quality_reject_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )

            dropped_records = build_instruction_records(decision_split.get("dropped", []), instruction=DEFAULT_INSTRUCTION)
            dropped_jsonl = "\n".join(json.dumps(record.model_dump(), ensure_ascii=True) for record in dropped_records)
            st.download_button(
                label="🗑️ Dropped Dataset (JSONL) İndir",
                data=dropped_jsonl,
                file_name=f"dataset_dropped_{cbom.bom_ref}.jsonl",
                mime="application/json",
            )
            
            # CSV
            csv_data = '\n'.join([
                "Algoritma,Tür,Anahtar Uzunluğu,PQC,Risk Skoru,Seviye",
                *[f"{a.algorithm.name},{a.algorithm.type.value},{a.algorithm.key_length or 'N/A'},"
                  f"{a.algorithm.is_pqc_safe},{calculate_risk_score(a.algorithm.name).final_risk:.1f},"
                  f"{a.risk_level}"
                  for a in cbom.crypto_assets]
            ])
            
            st.download_button(
                label="📄 CSV İndir",
                data=csv_data,
                file_name=f"crypto_assets_{cbom.bom_ref}.csv",
                mime="text/csv"
            )
    
    else:
        st.info("👈 Sol taraftan bir dosya seçerek analiz başlatın")

    if st.session_state.last_batch_summary:
        st.divider()
        st.header("Repo Batch Sonucu")
        summary = st.session_state.last_batch_summary

        assets_total = summary.get("assets_total", 0)
        use_llm = summary.get("use_llm", False)
        llm_candidate_only = summary.get("llm_candidate_only", False)

        if assets_total == 0:
            if use_llm and llm_candidate_only:
                st.warning(
                    "Bu çalışmada statik aday bulunmadığı için LLM büyük ihtimalle hiç devreye girmedi. "
                    "QuickFIX gibi zayıf kripto sinyalli repolarda hızlı mod sıfır sonuç verebilir. "
                    "Hızlı LLM modunu kapatıp yeniden deneyin veya confidence eşiğini düşürün."
                )
            elif use_llm:
                st.warning(
                    "LLM açık olmasına rağmen hiçbir kripto varlık bulunamadı. Bu repo gerçekten kripto içermiyor olabilir "
                    "ya da mevcut statik kurallar bu repo tipine yeterince uymuyor olabilir."
                )
            else:
                st.warning(
                    "Hiç kripto varlık bulunamadı. Bu repo için mevcut statik kuralların kapsamı yetersiz olabilir."
                )

        b1, b2, b3, b4, b5, b6 = st.columns(6)
        with b1:
            st.metric("Seçilen Dosya", summary.get("files_selected", 0))
        with b2:
            st.metric("Training", summary.get("training", 0))
        with b3:
            st.metric("Review", summary.get("review", 0))
        with b4:
            st.metric("Policy Drop", summary.get("policy_drop", 0))
        with b5:
            st.metric("Quality Reject", summary.get("quality_reject", 0))
        with b6:
            st.metric("Dropped", summary.get("dropped", 0))

        st.json(summary)


if __name__ == "__main__":
    main()
