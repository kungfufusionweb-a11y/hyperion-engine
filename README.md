# 🛡️ Hyperion Engine

> **AI-Powered DevSecOps Vulnerability Scanner & Visual Threat Modeling Platform**  
> *Built for the Alibaba Cloud AI Hackathon Pakistan 2026 (Open Innovation Track)*

---

## 📌 Overview

**Hyperion Engine** is an intelligent DevSecOps security analysis tool that bridges static code analysis with generative AI reasoning. By combining Python Abstract Syntax Tree (AST) code parsing with structured LLM prompt pipelines, Hyperion Engine automatically detects critical vulnerabilities, maps security risks, visualizes potential attack vectors, and generates production-ready remediated code patches.

---

## ✨ Key Features

* **🔍 AST-Assisted Code Parsing:** Pre-processes source code to extract structure, token streams, and abstract syntax trees prior to LLM analysis.
* **🎯 CVSS & OWASP Top 10 Mapping:** Detects flaws and assigns standardized CVSS v3.1 scores alongside official OWASP category classifications.
* **📊 Visual Attack Path Modeling:** Renders dynamic Graphviz threat flows and interactive Plotly charts illustrating vulnerability severity distribution.
* **💡 Side-by-Side Remediation Viewer:** Generates side-by-side git diff views displaying original vulnerable code vs. refactored secure code.
* **📄 Automated Audit PDF Reports:** Compiles security scan results, code diffs, and remediation steps into downloadable executive PDF documents.

---

## 🏗️ Architecture

```text
  ┌─────────────────────────┐
  │   Source Code Input     │
  └────────────┬────────────┘
               │
               ▼
  ┌─────────────────────────┐
  │  Python AST Code Parser │
  └────────────┬────────────┘
               │
               ▼
  ┌─────────────────────────┐
  │   LLM Security Engine   │
  │ (Structured JSON Output)│
  └────────────┬────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
  ┌───────────┐ ┌───────────┐
  │ Visuals   │ │ Code Diff │
  │ (Graphviz/│ │ & PDF     │
  │  Plotly)  │ │ Reports   │
  └─────┬─────┘ └─────┬─────┘
        │             │
        └──────┬──────┘
               ▼
  ┌─────────────────────────┐
  │   Streamlit Dashboard   │
  └─────────────────────────┘