# Project Aegis — Hybrid Insider Threat Detection Platform
**Hackathon Project**

*A cybersecurity platform that combines Behavioral Psychometrics and System Logs with an Autonomous AI Agent Swarm to predict, alert, and contain insider threats before data exfiltration occurs.*

# The Problem
Traditional security tools only monitor system logs (USB usage, logons). They produce high false-positive rates—falsely accusing innocent employees or missing quiet malicious actors due to rigid ML decision trees.

## Key Features & Architecture
**Psychometrics + Telemetry**: Fuses OCEAN personality traits (stress, burnout) with system logs (USB mounts, off-hours logins, email sizes) to detect human intent.

**Continuous Risk Engine**: Converts harsh binary ML jumps into a calibrated 0–100% Risk Score with zero-day hard overrides.

**Agentic AI Swarm (Google Gemini)**: Triggers automatically when Risk Score ≥50%:

**Investigator Agent**: Generates root-cause summaries for SOC analysts.

**Interrogator Agent**: Pops up direct warning notifications on the user's workstation.

**Containment Agent**: Triggers Active Directory isolation policies.

**Dual-Mode Dashboard**: Features Enterprise Bulk Log Scanning (.csv/.xlsx) and an interactive Single Target Profiler.

# Societal Impact
**Fair Workplaces**: Protects innocent employees from wrongful termination caused by biased AI.

**Mental Health Support**: Identifies severe employee burnout early for HR intervention rather than cold punishment.

**Public Safety**: Safeguards critical infrastructure, hospitals, and citizen data from insider leaks.

# Quick Start
*Bash*
git clone https://github.com/joginder6/Project-Aegis-Insider-Threat-Predictor.git

cd Project-Aegis-Insider-Threat-Predictor

pip install -r requirements.txt

python -m streamlit run app.py 
