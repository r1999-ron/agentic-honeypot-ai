# 🕵️‍♂️ Agentic Honeypot for Scam Detection & Intelligence Extraction

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)

An AI-powered agentic honeypot system that detects scam intent, autonomously engages scammers in realistic multi-turn conversations, extracts actionable fraud intelligence, and reports results to the GUVI evaluation endpoint.

---

## 🚀 Problem Overview
Online scams (UPI fraud, bank impersonation, phishing) are increasingly adaptive. Static rule-based systems fail because scammers change tactics dynamically. This project implements an **Agentic Honeypot** that:

* **Detects** scam intent early using LLM-backed pattern recognition.
* **Engages** scammers autonomously using a believable, non-technical persona.
* **Extracts** high-value intelligence: UPI IDs, Phone numbers, Bank accounts, and Phishing links.
* **Reports** findings via a mandatory final callback once engagement completes.

---

## 🏗️ System Architecture



1.  **Incoming Message:** Analyzed for urgency and scam keywords.
2.  **Session Tracking:** Once flagged, the session is locked into "Honeypot Mode."
3.  **Agentic AI:** Generates human-like, "clueless" responses to keep the scammer talking.
4.  **Intel Extraction:** Regex and NER extract fraud indicators in real-time.
5.  **Final Callback:** Data is sent to the evaluation endpoint once the "Stability Check" is met.

---

## 🧠 Core Design Principles

| Principle | Description |
| :--- | :--- |
| **Session-Level Detection** | If one message is a scam, the whole session is treated as a scam to maintain persona consistency. |
| **Agentic Persona** | Acts as a polite, slightly confused Indian user to lower the scammer's guard. |
| **Incremental Intel** | Intelligence is accumulated across turns; it doesn't just look at the last message. |
| **Intelligent Finalization** | Ends when info stops flowing or `MAX_TURNS` is reached to prevent infinite loops. |

---


