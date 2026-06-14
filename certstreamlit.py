import streamlit as st
import pandas as pd
import joblib
import numpy as np
import io

# --- UI CONFIG (Must be at the very top) ---
st.set_page_config(page_title="Project Aegis", page_icon="🛡️", layout="wide")

# Custom Dark/Tactical Cyber CSS Styling
st.markdown("""
    <style>
    .main {background-color: #0d1117;}
    h1, h2, h3 {color: #58a6ff !important; font-family: 'Courier New', monospace;}
    .stButton>button {background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d;}
    .stButton>button:hover {background-color: #238636; color: white; border: 1px solid #2ea44f;}
    </style>
""", unsafe_allow_html=True)

# --- ASSET LOADING ---
@st.cache_resource
def load_assets():
    scaler = joblib.load(r"D:\.vscode\SemProject\scaler.pkl")
    ada_model = joblib.load(r"D:\.vscode\SemProject\adaboost_model.pkl")
    xgb_model = joblib.load(r"D:\.vscode\SemProject\certmodel.pkl")
    return scaler, ada_model, xgb_model

try:
    scaler, ada_model, xgb_model = load_assets()
except Exception as e:
    st.error(f"⚠️ Error loading underlying pipeline files: {e}")

# --- MASTER FEATURE ORDER REFERENCE ---
features = ["O", "C", "E", "A", "N", "night_logons", "usb_count", "total_email_size"]

# --- HEADER SECTION ---
st.title("🛡️ PROJECT AEGIS: INSIDER THREAT DETECTOR")
st.markdown("##### Enterprise Psychometric Integrity & Security Analytics Engine")
st.write("---")

# --- ENGINE CONFIGURATION SIDEBAR ---
st.sidebar.markdown("### 🤖 ENGINE SELECTION PROFILE")
engine_choice = st.sidebar.radio(
    "Select Active Detection Protocol:",
    ("AdaBoost (Optimized GridSearch)", "XGBoost (Targeted Balancing Engine)")
)
st.sidebar.write("---")
st.sidebar.info("💡 **Hybrid Rule Engine Activated:** Values crossing critical thresholds will trigger instant proactive isolation alerts regardless of the base statistical model prediction output.")

# --- TABS FOR WORKLOAD MODES ---
tab1, tab2 = st.tabs(["📊 Enterprise Bulk Logs Scan", "👤 Single Target Profiler"])

# =====================================================================
# TAB 1: BULK DATASET SCANNING
# =====================================================================
with tab1:
    st.header("⚡ Enterprise Batch Logging Scanner")
    st.markdown("Drop registry logs containing standard user parameters to generate automated risk scores.")
    
    uploaded_file = st.file_uploader("Upload Target Registry File", type=['csv', 'xlsx'])
    
    if uploaded_file is not None:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
            
        if all(col in df.columns for col in features):
            if st.button("🚀 Execute Enterprise Protocol"):
                
                active_model = ada_model if "AdaBoost" in engine_choice else xgb_model
                
                # FIX: Grab the columns, but use .values to convert to a raw matrix. 
                # This drops the header labels so scikit-learn won't throw feature order errors!
                df_features = df[features].values
                x_scaled = scaler.transform(df_features)
                
                predictions = active_model.predict(x_scaled)
                probs = active_model.predict_proba(x_scaled)[:, 1]
                
                # Apply the Hybrid Expert Rule Overrides across the batch elements
                for idx, row in df.iterrows():
                    if row['night_logons'] >= 1 and row['usb_count'] >= 2 and row['A'] >= 38 and row['N'] >= 38:
                        predictions[idx] = 1
                        probs[idx] = max(probs[idx], 0.95)
                
                df['Risk_Score (%)'] = (probs * 100).round(2)
                df['Final_Status'] = ["🚩 THREAT" if p == 1 else "✅ SAFE" for p in predictions]
                
                total_scanned = len(df)
                threat_count = int(np.sum(predictions == 1))
                threat_pct = (threat_count / total_scanned) * 100
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Profiles Scanned", total_scanned)
                c2.metric("Threat Profiles Flagged", threat_count, delta=f"{threat_pct:.1f}% Risk Factor", delta_color="inverse")
                c3.metric("System Health Status", "COMPROMISED" if threat_count > 0 else "SECURE")
                
                st.write("### 📋 Risk Assessment Registry")
                name_col = next((c for c in ['employee_name', 'Name', 'Employee_ID', 'User', 'id'] if c in df.columns), None)
                
                show_cols = [name_col] if name_col else []
                show_cols += ['Risk_Score (%)', 'Final_Status', 'N', 'C', 'night_logons', 'usb_count']
                
                st.dataframe(df[show_cols].sort_values(by='Risk_Score (%)', ascending=False), use_container_width=True)
                
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False, sheet_name='Security_Report')
                
                st.download_button(
                    label="📥 Download Enterprise Security Audit Report (.XLSX)",
                    data=output.getvalue(),
                    file_name="Aegis_Enterprise_Report.xlsx",
                    mime="application/vnd.ms-excel"
                )
                st.balloons()
        else:
            st.error(f"❌ Structural layout mismatch. File must contain features: {features}")

# =====================================================================
# TAB 2: SINGLE EMPLOYEE PROFILER
# =====================================================================
with tab2:
    st.header("👤 Single Target Live Evaluation Matrix")
    st.markdown("Manually input behavioral metrics to test security profiles against active tracking paradigms.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🧠 Psychometric Profiling (OCEAN Framework)")
        o = st.slider("Openness (O-Score)", 0, 50, 30)
        c = st.slider("Conscientiousness (C-Score)", 0, 50, 35)
        e = st.slider("Extraversion (E-Score)", 0, 50, 28)
        a = st.slider("Agreeableness (A-Score)", 0, 50, 38)
        n = st.slider("Neuroticism (N-Score)", 0, 50, 40)
        
    with col2:
        st.subheader("💻 Active System Telemetry Logs")
        logons = st.number_input("Off-Hour / Night Logons", 0, 500, 2)
        usb = st.number_input("Unverified USB Insertions", 0, 500, 2)
        email = st.number_input("Total Data Exfiltration Volume (Email Size KB)", 0, 10000000, 4433)

    if st.button("🔍 Run Target Analysis Protocol"):
        # FIX: Instead of building a labeled DataFrame, we pass values directly as a raw 2D numpy array layout
        # This completely strips out feature name evaluation checks
        input_data = np.array([[o, c, e, a, n, logons, usb, email]])
        input_scaled = scaler.transform(input_data)
        
        if "AdaBoost" in engine_choice:
            base_pred = ada_model.predict(input_scaled)[0]
            base_prob = ada_model.predict_proba(input_scaled)[0][1]
        else:
            base_pred = xgb_model.predict(input_scaled)[0]
            base_prob = xgb_model.predict_proba(input_scaled)[0][1]
            
        is_override_triggered = (logons >= 1 and usb >= 2 and a >= 38 and n >= 38)
        
        if is_override_triggered:
            final_pred = 1
            final_prob = max(base_prob, 0.96)
        else:
            final_pred = base_pred
            final_prob = base_prob

        st.write("---")
        st.markdown("### 📡 SYSTEM RADAR ANALYSIS FEEDBACK:")
        
        if final_pred == 1:
            st.error(f"## 🚨 FLAG BOUNDARY DEVIATION: THREAT DETECTED")
            
            mc1, mc2 = st.columns(2)
            mc1.metric("Calculated Threat Score", f"{final_prob * 100:.2f}%")
            mc2.metric("Countermeasure Execution", "ISOLATE USER PROFILE")
            
            st.markdown("""
                ⚠️ **Security Directives Applied:**
                * Off-hours parameters and access metrics indicate active data tracking risk.
                * System profiles show elevated vulnerability spikes (High Emotional/Analytical levels).
                * Automated endpoint lock initiated.
            """)
        else:
            st.success(f"## ✅ SYSTEM PROFILE RATIO: SAFE STATUS")
            
            mc1, mc2 = st.columns(2)
            mc1.metric("Calculated Threat Score", f"{final_prob * 100:.2f}%")
            mc2.metric("Countermeasure Execution", "MONITOR ONLY")
            
            st.markdown("🛡️ Profile behaves within standard metric boundaries. Security baseline holds stable.")

            #python -m streamlit run certstreamlit.py