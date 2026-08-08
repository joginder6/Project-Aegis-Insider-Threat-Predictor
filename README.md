# 🛡️ Project Aegis 2 — Hybrid Insider Threat Detection Platform

[![Live App](https://img.shields.io/badge/Render-Live%20Demo-brightgreen?style=for-the-badge&logo=render)](https://project-aegis-insider-threat-predictor.onrender.com)

A state-of-the-art cybersecurity platform combining **Behavioral Psychometrics**, **System Telemetry Logs**, and an **Autonomous AI Agent Swarm** to predict, investigate, and mitigate insider threats before exfiltration occurs.

---

## 🌐 Live Application
* **Live App Link:** [https://project-aegis-insider-threat-predictor.onrender.com](https://project-aegis-insider-threat-predictor.onrender.com)

---

## 🚀 How to Test & Use the Platform

### 1. Admin / SOC View (Bulk Analysis & Triage)
1. Download the **CERT Dataset CSV sample file** provided in this repository (`/data` or root folder).
2. Open the **Live App** link above.
3. In the **Admin View / Enterprise Scanner**, upload the CERT Dataset CSV file.
4. Run the batch scan to view real-time calibrated **0–100% Risk Scores**, continuous threat curves, and automated threat tier classifications.

### 2. Investigator View (Agentic AI Swarm Execution)
1. Open the sidebar in the Streamlit app.
2. Enter your **Google Gemini API Key** (or use the configured environment variable).
   * *Gemini API Key can be found on GOOGLE API STUDIO*`
3. Select any target employee profile or high-risk alert (Risk Score ≥ 50%) to trigger the multi-agent investigation workflow.

---

## 🎯 Bounties & Tasks Execution Guide

Project Aegis fulfills specific cybersecurity, AI safety, and automated governance bounties:

### 🎯 Bounty Task 1: Zero-Day & Hard Risk Overrides
* **Objective:** Ensure critical threat indicators trigger immediate action without waiting for ML probability thresholds.
* **How to Test:** In the Single Target Profiler or batch logs, simulate unauthorized massive data transfers, mass USB writes, or off-hours privilege escalation. Observe how zero-day rules directly override the standard probability score to instantly trigger Level-3 isolation protocols.

### 🎯 Bounty Task 2: Multi-Agent AI Swarm Triage
* **Objective:** Automate root-cause investigation and mitigate analyst fatigue.
* **How to Test:** Select a flagged user profile (Risk Score ≥ 50%) in the Investigator View with your Gemini API key active.
  * **🕵️ Investigator Agent:** Generates comprehensive, human-readable root-cause dossiers and forensic timelines.
  * **❓ Interrogator Agent:** Simulates direct, non-adversarial workstation prompts to verify user intent and evaluate psychological stressors.
  * **🧱 Containment Agent:** Recommends or executes active containment steps (e.g., AD account lock, network port isolation, or session revocation).

### 🎯 Bounty Task 3: Ethical AI & Psychometric Fairness
* **Objective:** Mitigate bias and differentiate between malicious intent and severe employee burnout.
* **How to Test:** Analyze user profiles exhibiting high OCEAN stress/burnout scores alongside benign activity. Verify how the continuous risk engine calibrated with psychometric features routes burned-out employees to HR intervention paths rather than initiating punitive security actions.

### 🎯 Bounty Task 4: Forensic Report & Master Dossier Export
* **Objective:** Provide actionable, exportable evidence for SOC team handoffs and legal audits.
* **How to Test:** Complete an agent investigation on any high-risk target and click **Export Forensic Dossier / Master CSV** to generate a audit-ready report.

---

## 🏗️ Architecture & Core Components

```text
[ SYSTEM LOGS + OCEAN PSYCHOMETRICS ]
                 │
                 ▼
[ CONTINUOUS RISK ENGINE (0–100%) ]
                 │
      ┌──────────┴──────────┐
  < 50% Risk            ≥ 50% Risk
      │                     │
[ LOW THREAT ]      [ AI AGENT SWARM (GEMINI) ]
                     ├── 🕵️ Investigator Agent (Dossier)
                     ├── ❓ Interrogator Agent (User Dialog)
                     └── 🧱 Containment Agent (AD Isolation)
