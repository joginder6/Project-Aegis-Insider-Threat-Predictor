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
    usb = float(metrics_dict.get('usb_count', 0))
    night = float(metrics_dict.get('night_logons', 0))
    email_kb = float(metrics_dict.get('total_email_size', 0))
    
    n_score = float(metrics_dict.get('N', 25))
    a_score = float(metrics_dict.get('A', 25))
    psych_factor = (n_score - a_score) / 50.0

    telemetry_score = (usb * 14.0) + (night * 16.0) + (email_kb / 500.0)
    combined_signal = (raw_prob * 35.0) + telemetry_score + (psych_factor * 10.0)
    smoothed_score = 100.0 / (1.0 + np.exp(-0.075 * (combined_signal - 40.0)))
    
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
                time.sleep(1.2)
                continue
            raise e

# --- AGENTIC AI EXECUTION HELPER ---
def run_agentic_workflow(user_id, risk_score, metrics_dict, api_key=None):
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

            interrogator_prompt = f"""
            You are an Automated Security Incident Liaison Agent.
            Write a professional, direct security message to Employee {user_id}.
            Mention that anomalous off-hours or USB telemetry was flagged on their workstation. Request an immediate, mandatory business justification before local system access is suspended.
            Keep it under 3 sentences.
            """
            interrogator_message = safe_gemini_call(client, target_model, interrogator_prompt)

            mitigation_prompt = f"""
            You are an Autonomous System Containment Agent.
            Based on a high-risk score of {risk_score:.2f}% with USB activity ({metrics_dict.get('usb_count')}) and email transfers ({metrics_dict.get('total_email_size')} KB), list 3 immediate Automated Security Actions to enforce in Active Directory and Endpoint Security.
            Format as short action items.
            """
            mitigation_actions = safe_gemini_call(client, target_model, mitigation_prompt)

        except Exception:
            client = None

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

# --- SIDEBAR CONFIGURATION ---
st.sidebar.markdown("### 👥 USER ROLE PERSPECTIVE")
user_role = st.sidebar.selectbox(
    "Select Access Role View:",
    ("Admin / SOC Lead", "Security Investigator", "Standard Employee (User)")
)
st.sidebar.write("---")

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

# =====================================================================
# ROLE 1: ADMIN / SOC LEAD VIEW
# =====================================================================
if user_role == "Admin / SOC Lead":
    st.header("🔑 Admin & SOC Lead Command Portal")
    st.markdown("Full system management, fleet log ingest, model engine telemetry, and total record exports.")

    uploaded_file = st.file_uploader("Upload Target Registry Log File", type=['csv', 'xlsx'])
    
    if uploaded_file is not None:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
            
        if all(col in df.columns for col in features):
            if st.button("🚀 Execute Enterprise Batch Scanning"):
                active_model = ada_model if "AdaBoost" in engine_choice else xgb_model
                
                df_features = df[features].values
                x_scaled = scaler.transform(df_features)
                raw_probs = active_model.predict_proba(x_scaled)[:, 1]
                
                calibrated_probs = []
                final_predictions = []
                
                for idx, row in df.iterrows():
                    m_dict = {f: row[f] for f in features}
                    c_prob = calibrate_risk_score(raw_probs[idx], m_dict)
                    
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
        c2.metric("Threat Profiles Flagged", threat_count, delta=f"{threat_pct:.1f}% Fleet Risk Factor", delta_color="inverse")
        c3.metric("System Health Status", "COMPROMISED" if threat_count > 0 else "SECURE")
        
        st.write("### 📋 Executive Fleet Registry")
        name_col = next((c for c in ['employee_name', 'Name', 'Employee_ID', 'User', 'id'] if c in df.columns), None)
        show_cols = [name_col] if name_col else []
        show_cols += ['Risk_Score (%)', 'Final_Status', 'N', 'C', 'night_logons', 'usb_count', 'total_email_size']
        st.dataframe(df[show_cols].sort_values(by='Risk_Score (%)', ascending=False), use_container_width=True)

        # --- ELITE BOUNTY GOAL: COMPLETE ALL-RECORD & REVIEW EXPORT ---
        st.write("---")
        st.subheader("📥 Elite Master Threat & Audit Export Protocol")
        st.markdown("Download full telemetry records including psychometric indicators, risk scores, and full system reviews.")
        
        full_export_buffer = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📄 Export Complete Fleet Logs & Risk Scores (CSV)",
            data=full_export_buffer,
            file_name="Project_Aegis_Complete_Fleet_Audit.csv",
            mime="text/csv"
        )

# =====================================================================
# ROLE 2: SECURITY INVESTIGATOR VIEW
# =====================================================================
elif user_role == "Security Investigator":
    st.header("🕵️ Security Investigator Deep Dive Portal")
    st.markdown("Focus on feature importance, continuous risk breakdown metrics, and running multi-agent forensic investigations.")

    if st.session_state.get('batch_processed', False):
        df = st.session_state['batch_df']
        name_col = next((c for c in ['employee_name', 'Name', 'Employee_ID', 'User', 'id'] if c in df.columns), None)
        
        st.subheader("📈 Model Feature Importance & Threat Distribution")
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.markdown("**Risk Score Distribution Across Scanned Users**")
            st.bar_chart(df['Risk_Score (%)'].value_counts(bins=10))

        with col_chart2:
            st.markdown(f"**Feature Importance ({engine_choice.split(' ')[0]})**")
            active_m = ada_model if "AdaBoost" in engine_choice else xgb_model
            if hasattr(active_m, 'feature_importances_'):
                feat_imp = pd.DataFrame({
                    'Feature': features,
                    'Importance': active_m.feature_importances_
                }).sort_values('Importance', ascending=True)
                st.bar_chart(feat_imp.set_index('Feature'))

        st.write("---")
        st.subheader("🤖 Autonomous Multi-Agent Incident Investigation")
        threat_df = df[df['Final_Status'] == "🚩 THREAT"]
        
        if threat_df.empty:
            st.success("✅ No threats flagged for multi-agent escalation.")
        else:
            for idx, row in threat_df.iterrows():
                user_label = str(row[name_col]) if name_col else f"User Index {idx}"
                
                with st.expander(f"🚨 Deep Forensic Investigation: {user_label} (Risk: {row['Risk_Score (%)']}%)", expanded=False):
                    metrics = {f: row[f] for f in features}
                    
                    if st.button(f"⚡ Launch Agent Swarm ({user_label})", key=f"inv_btn_{idx}"):
                        with st.spinner("Analyzing behavioral logs and drafting countermeasures..."):
                            inv_res, int_res, mit_res = run_agentic_workflow(
                                user_id=user_label,
                                risk_score=row['Risk_Score (%)'],
                                metrics_dict=metrics,
                                api_key=gemini_api_key
                            )
                            
                            st.markdown("#### 🕵️ Investigator Agent Findings")
                            st.markdown(f"<div class='agent-box'>{inv_res}</div>", unsafe_allow_html=True)
                            
                            st.markdown("#### 💬 Draft Workstation Directive")
                            st.info(int_res)
                            
                            st.markdown("#### 🛡️ Autonomous Mitigations Enforced")
                            st.error(mit_res)

                            # --- ELITE BOUNTY GOAL: DETAILED INCIDENT DOSSIER EXPORT ---
                            incident_report = f"""PROJECT AEGIS 2 - INVESTIGATOR DOSSIER
===========================================
Target ID: {user_label}
Risk Score: {row['Risk_Score (%)']}%
Status: HIGH THREAT

INVESTIGATOR FINDINGS:
{inv_res}

DISPATCH MESSAGE:
{int_res}

MITIGATION ACTIONS ENFORCED:
{mit_res}
"""
                            st.download_button(
                                label=f"💾 Export Forensic Dossier ({user_label})",
                                data=incident_report,
                                file_name=f"Forensic_Dossier_{user_label}.txt",
                                mime="text/plain",
                                key=f"inv_dl_{idx}"
                            )
    else:
        st.info("💡 Please switch to Admin View and upload/scan fleet logs to generate investigation data.")

# =====================================================================
# ROLE 3: STANDARD EMPLOYEE (USER) VIEW
# =====================================================================
else:
    st.header("💻 Workstation Endpoint Security Notice (User Interface)")
    st.markdown("Simulated local machine UI displaying direct endpoint notices dispatched from the SOC.")
    
    st.markdown("""
    <div class="endpoint-card">
        <div style="display: flex; justify-content: space-between; align-items: center; color: #8b949e; font-size: 12px; margin-bottom: 8px;">
            <span>💻 <b>WORKSTATION SECURITY ALERT</b> (Target: USER_CURRENT_SESSION)</span>
            <span>STATUS: ACTIVE DIRECTIVE</span>
        </div>
        <div style="color: #c9d1d9; font-family: sans-serif; font-size: 14px; line-height: 1.5;">
            Anomalous off-hours telemetry and USB device activity were recorded on your workstation. Please submit mandatory business justification to the SOC response team.
        </div>
        <div style="margin-top: 12px; font-size: 11px; color: #f85149; font-weight: bold;">
            🔒 Policy Enforcement: External media write access restricted by Active Directory.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.write("<br>", unsafe_allow_html=True)
    st.subheader("📝 Submit Business Justification Response")
    user_reply = st.text_area("Provide explanation for off-hour USB activity:")
    if st.button("Submit Justification to SOC"):
        st.success("✅ Justification logged and routed to Security Investigator team.")
