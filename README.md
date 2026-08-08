# 🛡️ Machine Learning-Based XSS Honeypot

### A Hybrid Machine Learning & Rule-Based Honeypot for Detecting, Monitoring and Analyzing Reflected and Stored Cross-Site Scripting Attacks

<p align="center">

**Cybersecurity Research Project | Web Application Security | Machine Learning | Threat Detection**

</p>

---

## 📌 Project Overview

The **Machine Learning-Based XSS Honeypot** is a web-based cybersecurity research system designed to detect, capture, monitor, and analyze **Reflected Cross-Site Scripting (XSS)** and **Stored Cross-Site Scripting (XSS)** attacks within a controlled and isolated environment.

The system combines **Machine Learning-based classification** with traditional **Keyword and Regular Expression (Regex) detection** to create a hybrid threat detection mechanism.

Instead of relying only on predefined attack signatures, the system analyzes submitted payloads using multiple detection techniques and records valuable attack information for further cybersecurity analysis.

The project was developed as a **Computer Researching Project** for the **Pearson BTEC HND in Computing** program at **CINEC Campus**.

---

## 🎯 Project Objectives

The primary objectives of this project are to:

- 🎯 Design and develop a controlled web-based honeypot environment for detecting Reflected and Stored XSS attacks.
- 🤖 Implement a hybrid detection mechanism combining Machine Learning and Keyword/Regex-based detection.
- 🔍 Capture, monitor, and analyze malicious payloads and attacker activity.
- 🗄️ Record attack-related information for security analysis and research.
- 📊 Provide an administrator dashboard for monitoring detected threats.
- 🌐 Integrate threat intelligence information to enrich attack analysis.
- 🔔 Generate real-time alerts for suspicious and malicious activity.
- 🎓 Support cybersecurity education, research, and secure software development practices.

---

## 🚨 Problem Statement

Cross-Site Scripting remains a major web application security threat. Traditional security mechanisms frequently depend on predefined signatures, rules, or known attack patterns.

This can create challenges when dealing with:

- Modified XSS payloads
- Obfuscated payloads
- Previously unseen attack patterns
- Suspicious inputs that do not exactly match predefined signatures
- Limited visibility into attacker behavior

The project addresses this problem by combining **honeypot technology, rule-based detection, Machine Learning, attack logging, and threat intelligence** within a controlled research environment.

---

## 💡 Proposed Solution

The developed honeypot provides intentionally vulnerable web interfaces that simulate vulnerable application components.

Users can interact with:

- 🔴 **Reflected XSS Search Page**
- 🟠 **Stored XSS Comment Page**

Submitted input is passed through a processing pipeline where it is analyzed using:

```text
👤 User Input
       │
       ▼
⚙️ Payload Pre-processing
       │
       ├───────────────────────┐
       │                       │
       ▼                       ▼
🔎 Keyword / Regex       🤖 Machine Learning
   Detection                 Detection
       │                       │
       └───────────┬───────────┘
                   │
                   ▼
        🔀 Hybrid Threat Detection
                   │
                   ▼
          🚨 Malicious / Benign
                   │
                   ▼
             🗄️ Attack Logging
                   │
                   ▼
          🌐 Threat Intelligence
                   │
                   ▼
          📊 Administrator Dashboard
                   │
                   ▼
             🔔 Real-Time Alerts
