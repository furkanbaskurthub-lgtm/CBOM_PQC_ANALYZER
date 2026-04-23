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
from pathlib import Path
from datetime import datetime

from main import PQCReadyAnalyzer
from models.crypto_schema import calculate_risk_score, NIST_PQC_RISK_MAP


ANALYZER_BUILD = "2026-04-15-bcrypt-fix"


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
    
    # Renk kuralları
    def color_risk(val):
        if "CRITICAL" in val:
            return "background-color: #ffcccc"
        elif "HIGH" in val:
            return "background-color: #ffe5cc"
        elif "MEDIUM" in val:
            return "background-color: #ffffcc"
        else:
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
    
    # Detaylı Tavsiyeler
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


def main():
    """Ana uygulama"""
    initialize_session()
    
    # Header
    st.title("🔐 PQC-Ready Analyzer")
    st.markdown("*Post-Quantum Cryptography Hazırlık Analiz Aracı*")
    
    # Sidebar
    with st.sidebar:
        st.header("📁 Dosya Seçimi")
        
        uploaded_file = st.file_uploader(
            "Dosya yükle",
            type=["bin", "out", "exe", "dll", "py", "c", "cpp", "java", "txt"],
            help="Binary, kaynak kod veya metin dosyası yükle"
        )
        
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
    
    # Ana içerik
    if analyze_button and uploaded_file:
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
                st.session_state.current_cbom = cbom
                st.success("✅ Analiz tamamlandı!")
            except Exception as e:
                st.error(f"❌ Analiz hatası: {str(e)}")
                return
    
    # Sonuçlar göster
    if st.session_state.current_cbom:
        cbom = st.session_state.current_cbom
        report = st.session_state.analyzer.generate_report(cbom)
        
        # Sekmeler
        tab1, tab2, tab3, tab4, tab5 = st.tabs(
            ["📊 Özet", "🔍 Algoritma Detayları", "📈 Grafikler", "💼 Tavsiyeler", "📥 İndir"]
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
        
        with tab4:
            st.header("Risk Puanlama ve Tavsiyeler")
            display_recommendations(report)
        
        with tab5:
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


if __name__ == "__main__":
    main()
