import streamlit as st
import pandas as pd
import joblib
import numpy as np
import io
import os
import time

# --- GOOGLE GENAI SDK IMPORT WITH FALLBACK ---
try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# --- UI CONFIG (Must be at the very top) ---
st.set_page_config(page_title="Project Aegis 2", page_icon="🛡️", layout="wide")

# Custom Dark/Tactical Cyber CSS Styling
st.markdown("""
    <style>
    .main {background-color: #0d1117;}
    h1, h2, h3 {color: #58a6ff !important; font-family: 'Courier New', monospace;}
    .stButton>button {background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d;}
    .stButton>button:hover {background-color: #238636; color: white; border: 1px solid #2ea44f;}
    .agent-box {
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 15px;
        background-color: #161b22;
        margin-bottom: 10px;
    }
    .endpoint-card {
        background-color: #1c2128; 
        border-left: 5px solid #f85149; 
        padding: 15px; 
        border-radius: 6px; 
        margin-top: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    </style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- ASSET LOADING ---
@st.cache_resource
def load_assets():
    scaler = joblib.load("models/scaler.pkl")
    ada_model = joblib.load("models/adaboost_model.pkl")
    xgb_model = joblib.load("models/certmodel.pkl")
    return scaler, ada_model, xgb_model

try:
    scaler, ada_model, xgb_model = load_assets()
except Exception as e:
    st.error(f"⚠️ Error loading underlying pipeline files: {e}")

# --- MASTER FEATURE ORDER REFERENCE ---
features = ["O", "C", "E", "A", "N", "night_logons", "usb_count", "total_email_size"]

# --- HELPER: CONTINUOUS SIGMOIDAL RISK CALIBRATION ---
def calibrate_risk_score(raw_prob, metrics_dict):
    """
    Transforms rigid binary tree probabilities into a smooth, 
    continuous 0-100% risk curve using sigmoidal telemetry weighting.
    """
    usb = float(metrics_dict.get('usb_count', 0))
    night = float(metrics_dict.get('night_logons', 0))
    email_kb = float(metrics_dict.get('total_email_size', 0))
    
    # OCEAN Psychometric Factor (High N + Low A increases threat probability)
    n_score = float(metrics_dict.get('N', 25))
    a_score = float(metrics_dict.get('A', 25))
    psych_factor = (n_score - a_score) / 50.0  # Normalized (-1.0 to 1.0)

    # 1. Continuous Telemetry Additive Score
    # Each USB adds ~14 pts, Night logon adds ~16 pts, Email volume scales smoothly
    telemetry_score = (usb * 14.0) + (night * 16.0) + (email_kb / 500.0)
    
    # 2. Blend raw model probability with telemetry signal
    combined_signal = (raw_prob * 35.0) + telemetry_score + (psych_factor * 10.0)
    
    # 3. Apply Sigmoidal Logistic Smoothing centered at mid-risk threshold (40)
    smoothed_score = 100.0 / (1.0 + np.exp(-0.075 * (combined_signal - 40.0)))
    
    # 4. Strict Baseline Constraints
    # Perfectly clean profiles (0 USB, 0 Night Logons, low email) should sit around 5% - 18%
    if usb == 0 and night == 0 and email_kb < 1000:
        return float(np.clip(smoothed_score * 0.3, 4.5, 18.0))
        
    return float(np.clip(smoothed_score, 10.0, 98.8))

# --- HELPER: GEMINI CALL WITH AUTO-RETRY ON 503 ---
def safe_gemini_call(client, model_name, prompt, max_retries=2):
    for attempt in range(max_retries):
        try:
            res = client.models.generate_content(model=model_name, contents=prompt)
            return res.text
        except Exception as e:
            if "503" in str(e) and attempt < max_retries - 1:
                time.sleep(1.2)  # Wait 1.2s before retrying
                continue
            raise e

# --- AGENTIC AI EXECUTION HELPER ---
def run_agentic_workflow(user_id, risk_score, metrics_dict, api_key=None):
    """
    Triggers 3 Autonomous Agents with 503 Auto-Retry resilience.
    """
    client = None
    if GENAI_AVAILABLE:
        effective_key = api_key or os.environ.get("GEMINI_API_KEY")
        if effective_key:
            try:
                client = genai.Client(api_key=effective_key)
            except Exception:
                client = None

    if client:
        try:
            target_model = "gemini-2.5-flash"

            # 1. Investigator Agent
            investigator_prompt = f"""
            You are the Lead Cyber Threat Investigator Agent for Project Aegis.
            Analyze this insider threat alert:
            - User ID: {user_id}
            - Risk Score: {risk_score:.2f}%
            - Psychometrics (OCEAN): O={metrics_dict.get('O')}, C={metrics_dict.get('C')}, E={metrics_dict.get('E')}, A={metrics_dict.get('A')}, N={metrics_dict.get('N')}
            - Night Logons: {metrics_dict.get('night_logons')}
            - USB Insertions: {metrics_dict.get('usb_count')}
            - Data Exfiltration (KB): {metrics_dict.get('total_email_size')}
            
            Provide a concise, 3-bullet-point executive summary explaining WHY this specific combination of personality traits and anomalous behavior constitutes an insider risk.
            """
            investigator_findings = safe_gemini_call(client, target_model, investigator_prompt)

            # 2. Interrogator Agent
            interrogator_prompt = f"""
            You are an Automated Security Incident Liaison Agent.
            Write a professional, direct security message to Employee {user_id}.
            Mention that anomalous off-hours or USB telemetry was flagged on their workstation. Request an immediate, mandatory business justification before local system access is suspended.
            Keep it under 3 sentences.
            """
            interrogator_message = safe_gemini_call(client, target_model, interrogator_prompt)

            # 3. Mitigation Agent
            mitigation_prompt = f"""
            You are an Autonomous System Containment Agent.
            Based on a high-risk score of {risk_score:.2f}% with USB activity ({metrics_dict.get('usb_count')}) and email transfers ({metrics_dict.get('total_email_size')} KB), list 3 immediate Automated Security Actions to enforce in Active Directory and Endpoint Security.
            Format as short action items.
            """
            mitigation_actions = safe_gemini_call(client, target_model, mitigation_prompt)

        except Exception:
            client = None

    # Fallback / Local Rule-based Simulation Mode
    if not client:
        st.info("ℹ️ **Offline Mode Engaged:** Displaying rule-based agent analysis.")
        investigator_findings = (
            f"• **Psychometric Anomaly:** High Neuroticism ({metrics_dict.get('N')}) coupled with low Agreeableness indicates potential burnout or grievances.\n"
            f"• **Behavioral Risk:** Recorded {metrics_dict.get('night_logons')} off-hour logons and {metrics_dict.get('usb_count')} unverified USB mounts.\n"
            f"• **Exfiltration Threat:** Elevated email volume ({metrics_dict.get('total_email_size')} KB) indicates potential active data staging."
        )
        interrogator_message = (
            f"**SECURITY DIRECTIVE:** High-risk telemetry detected on workstation assigned to User `{user_id}` "
            f"involving {metrics_dict.get('usb_count')} unauthorized USB device mounts during off-hours. "
            f"Please submit immediate business justification to the SOC response team."
        )
        mitigation_actions = (
            "1. **Active Directory:** Revoke active OAuth session tokens and enforce immediate 2FA re-authentication.\n"
            "2. **DLP Enforcement:** Apply write-protection rules to USB mass storage devices for this profile.\n"
            "3. **SIEM Monitoring:** Place user on 72-hour high-priority packet capture watch."
        )

    return investigator_findings, interrogator_message, mitigation_actions


# --- HEADER SECTION ---
st.title("🛡️ PROJECT AEGIS: INSIDER THREAT DETECTOR")
st.markdown("##### Enterprise Psychometric Integrity & Autonomous Agent Security Engine")
st.write("---")

# --- ENGINE CONFIGURATION SIDEBAR ---
st.sidebar.markdown("### 🤖 ENGINE SELECTION PROFILE")
engine_choice = st.sidebar.radio(
    "Select Active Detection Protocol:",
    ("AdaBoost (Optimized GridSearch)", "XGBoost (Targeted Balancing Engine)")
)
st.sidebar.write("---")

st.sidebar.markdown("### 🧠 AGENTIC AI CONFIGURATION")
gemini_api_key = st.sidebar.text_input(
    "Gemini API Key (Optional):", 
    type="password",
    help="Enter key to enable live LLM reasoning for agents, or leave blank to run in simulated mode."
)
if not GENAI_AVAILABLE:
    st.sidebar.caption("⚠️ Install `google-genai` package to enable live LLM agents.")

st.sidebar.write("---")
st.sidebar.info("💡 **Hybrid Continuous Calibration Engine:** Probabilities scale dynamically based on real-time activity metrics.")

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
                
                df_features = df[features].values
                x_scaled = scaler.transform(df_features)
                
                raw_probs = active_model.predict_proba(x_scaled)[:, 1]
                
                calibrated_probs = []
                final_predictions = []
                
                for idx, row in df.iterrows():
                    m_dict = {f: row[f] for f in features}
                    c_prob = calibrate_risk_score(raw_probs[idx], m_dict)
                    
                    # Rule Overrides for Critical Threat Levels
                    if row['night_logons'] >= 1 and row['usb_count'] >= 2 and row['A'] >= 38 and row['N'] >= 38:
                        c_prob = max(c_prob, 95.0)
                        pred = 1
                    else:
                        pred = 1 if c_prob >= 50.0 else 0
                        
                    calibrated_probs.append(c_prob)
                    final_predictions.append(pred)
                
                df['Risk_Score (%)'] = np.round(calibrated_probs, 2)
                df['Final_Status'] = ["🚩 THREAT" if p == 1 else "✅ SAFE" for p in final_predictions]
                
                st.session_state['batch_df'] = df
                st.session_state['batch_processed'] = True

        if st.session_state.get('batch_processed', False):
            df = st.session_state['batch_df']
            
            total_scanned = len(df)
            threat_count = int((df['Final_Status'] == "🚩 THREAT").sum())
            threat_pct = (threat_count / total_scanned) * 100 if total_scanned > 0 else 0
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Profiles Scanned", total_scanned)
            c2.metric("Threat Profiles Flagged", threat_count, delta=f"{threat_pct:.1f}% Risk Factor", delta_color="inverse")
            c3.metric("System Health Status", "COMPROMISED" if threat_count > 0 else "SECURE")
            
            st.write("### 📋 Risk Assessment Registry")
            name_col = next((c for c in ['employee_name', 'Name', 'Employee_ID', 'User', 'id'] if c in df.columns), None)
            
            show_cols = [name_col] if name_col else []
            show_cols += ['Risk_Score (%)', 'Final_Status', 'N', 'C', 'night_logons', 'usb_count', 'total_email_size']
            
            st.dataframe(df[show_cols].sort_values(by='Risk_Score (%)', ascending=False), use_container_width=True)
            
            st.write("---")
            st.subheader("🤖 Autonomous Agent Incident Investigation Protocol")
            
            threat_df = df[df['Final_Status'] == "🚩 THREAT"]
            
            if threat_df.empty:
                st.success("✅ No high-risk threats detected requiring agentic intervention.")
            else:
                st.warning(f"⚠️ {len(threat_df)} high-risk profiles require multi-agent investigation.")
                
                for idx, row in threat_df.iterrows():
                    user_label = str(row[name_col]) if name_col else f"User Index {idx}"
                    
                    with st.expander(f"🚨 Launch Agents for Incident: {user_label} (Risk: {row['Risk_Score (%)']}%)", expanded=False):
                        metrics = {f: row[f] for f in features}
                        
                        if st.button(f"⚡ Run Multi-Agent Investigation ({user_label})", key=f"btn_{idx}"):
                            with st.spinner("Agents analyzing behavior, drafting communications, and preparing countermeasures..."):
                                inv_res, int_res, mit_res = run_agentic_workflow(
                                    user_id=user_label,
                                    risk_score=row['Risk_Score (%)'],
                                    metrics_dict=metrics,
                                    api_key=gemini_api_key
                                )
                                
                                st.markdown("#### 🕵️ Agent 1: Root Cause Investigator")
                                st.markdown(f"<div class='agent-box'>{inv_res}</div>", unsafe_allow_html=True)
                                
                                st.markdown("#### 💬 Agent 2: Direct Workstation Dispatch Message")
                                st.info(int_res)
                                
                                st.markdown("#### 🛡️ Agent 3: Containment Engine")
                                st.error(mit_res)

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
        input_data = np.array([[o, c, e, a, n, logons, usb, email]])
        input_scaled = scaler.transform(input_data)
        
        single_metrics = {
            "O": o, "C": c, "E": e, "A": a, "N": n,
            "night_logons": logons, "usb_count": usb, "total_email_size": email
        }
        
        active_m = ada_model if "AdaBoost" in engine_choice else xgb_model
        raw_prob = active_m.predict_proba(input_scaled)[0][1]
        
        # Calculate continuously calibrated risk percentage
        calibrated_pct = calibrate_risk_score(raw_prob, single_metrics)
        
        is_override = (logons >= 1 and usb >= 2 and a >= 38 and n >= 38)
        if is_override:
            final_pred = 1
            risk_pct = max(calibrated_pct, 96.0)
        else:
            risk_pct = calibrated_pct
            final_pred = 1 if risk_pct >= 50.0 else 0

        st.write("---")
        st.markdown("### 📡 SYSTEM RADAR ANALYSIS FEEDBACK:")
        
        if final_pred == 1:
            st.error("## 🚨 FLAG BOUNDARY DEVIATION: THREAT DETECTED")
            
            mc1, mc2 = st.columns(2)
            mc1.metric("Calculated Threat Score", f"{risk_pct:.2f}%")
            mc2.metric("Countermeasure Execution", "ISOLATE USER PROFILE")
            
            # Run Agents
            with st.spinner("Multi-Agent Swarm investigating incident & preparing endpoint alerts..."):
                inv_res, int_res, mit_res = run_agentic_workflow(
                    user_id="TARGET_SUBJECT_01",
                    risk_score=risk_pct,
                    metrics_dict=single_metrics,
                    api_key=gemini_api_key
                )
            
            st.write("---")
            
            # --- SOC & ENDPOINT DISPATCH DISPLAY ---
            st.subheader("🤖 Autonomous Agent Escalation Panel")
            
            st.markdown("#### 🕵️ Investigator Agent Report")
            st.markdown(f"<div class='agent-box'>{inv_res}</div>", unsafe_allow_html=True)
            
            # 🔔 TRIGGER TOAST NOTIFICATION FOR DEMO
            st.toast("⚡ Direct Security Directive dispatched to target workstation endpoint!", icon="🔔")
            
            st.markdown("#### 📱 Live Endpoint Dispatch Simulation (User View)")
            st.markdown(f"""
            <div class="endpoint-card">
                <div style="display: flex; justify-content: space-between; align-items: center; color: #8b949e; font-size: 12px; margin-bottom: 8px;">
                    <span>💻 <b>TARGET WORKSTATION DIRECT ALERT</b> (Target: TARGET_SUBJECT_01)</span>
                    <span>JUST NOW</span>
                </div>
                <div style="color: #c9d1d9; font-family: sans-serif; font-size: 14px; line-height: 1.5;">
                    {int_res}
                </div>
                <div style="margin-top: 12px; font-size: 11px; color: #f85149; font-weight: bold;">
                    🔒 Automated Policy: USB Write Access Suspended by Active Directory Engine.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.write("<br>", unsafe_allow_html=True)
            st.markdown("#### 🛡️ Autonomous Mitigation Actions Executed")
            st.error(mit_res)

        else:
            st.success("## ✅ SYSTEM PROFILE RATIO: SAFE STATUS")
            
            mc1, mc2 = st.columns(2)
            mc1.metric("Calculated Threat Score", f"{risk_pct:.2f}%")
            mc2.metric("Countermeasure Execution", "MONITOR ONLY")
            
            st.markdown("🛡️ Profile behaves within standard metric boundaries. Security baseline holds stable.")
