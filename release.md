# 🚀 HackGPT Enterprise Release Notes — Version 2026.07.beta.4

We are excited to announce the release of **HackGPT Enterprise Version 2026.07.beta.4**! This release introduces the Advanced SOC (Security Operations Center) Analysis Engine, native SIEM Integrations, and expanded Threat Model compliance mapping to include the latest OWASP Top 10 guidelines and major 2024–2026 CVE detection rules.

---

## 🌟 What's New in Version 2026.07.beta.4

### 1. Advanced Security Operations Center (SOC) Analysis Module
* **Multi-Format Log Parser & Normalizer**: Ingests, normalizes, and auto-detects formats for standard RFC Syslog, structured application JSON, Common Event Format (CEF), firewall packet filtering logs, and generic CSV/key-value outputs.
* **Indicator of Compromise (IOC) Extractor**: Leverages regex patterns to extract threat indicators, assess confidence levels, assign threat scores, and categorize:
  * IPv4 & IPv6 addresses (with benign/RFC 1918 private range filters)
  * FQDN Domains (with TLD reputation tracking)
  * File hashes (MD5, SHA-1, SHA-256)
  * CVE references
  * Suspicious URLs, emails, registry keys, and file paths
* **MITRE ATT&CK Technique Mapper**: Scans event payloads against a signature database to automatically map activities to corresponding MITRE ATT&CK Enterprise techniques, including tactics such as Initial Access, Execution, Privilege Escalation, Defense Evasion, Lateral Movement, C2, Exfiltration, and Impact.
* **Sliding-Window Alert Correlation Engine**: Detects specific attack patterns by grouping and deduplicating related events within configurable time windows:
  * SSH/Auth brute force attacks (T1110)
  * Port scanning & network service discovery (T1046)
  * Suspicious scripting & interpreter commands (powershell, cmd, bash) (T1059)
  * Command & Control beaconing (T1071)
  * Data exfiltration over web/alternative protocols (T1048)
  * Privilege escalation attempts (UAC bypass, sudo, setuid) (T1548)
  * Evasion and log tampering activity (T1070)
  * OS credential dumping (mimikatz, SAM/NTDS) (T1003)
  * Active ransomware / destructive payloads (T1486)
* **Statistical Anomaly Detector**: Applies z-score analysis to identify anomalous deviations from established baseline patterns:
  * Hourly event volume spikes
  * Host IP diversity (unusual counts of unique sources)
  * Elevated authentication and processing error rates
  * Off-hours network activity patterns
* **Incident Timeline Reconstructor**: Builds a unified chronological timeline mapping events sequentially across the Cyber Kill Chain.
* **Incident Response Playbooks**: Generates prioritized playbook response runs (including steps, estimated duration, and ownership groups) tailored to the specific threat categories identified.
* **Executive Reporting & Exporting**: Produces a summary report containing risk score assessments, executive summaries, statistics, and tables, with options to export to JSON.

### 2. Native SIEM Integration Connectors
* **Splunk Connector**:
  * Pulls logs via Splunk REST API search job creation (`/services/search/jobs` and results retrieval `/services/search/jobs/{sid}/results`).
  * Forwards correlated alerts to Splunk HTTP Event Collector (HEC) via the `sourcetype` `hackgpt:soc:alert` to `services/collector/event`.
* **QRadar Connector**:
  * Ingests event logs by executing Ariel Query Language (AQL) search jobs via QRadar REST API (`/api/ariel/searches`).
  * Forwards alerts to QRadar API endpoint (`/api/custom_events`) to register them as custom security offenses.
* **Elasticsearch Connector**:
  * Pulls logs using Elasticsearch search Query DSL (`/_search`).
  * Posts alert JSON payloads to index `/hackgpt-soc-alerts/_doc`.
* **Generic Webhook Connector**:
  * Pushes notifications to incoming webhooks like Slack, MS Teams, or custom SOAR solutions.
  * Auto-formats rich markdown messaging blocks for Slack/Teams, or sends full alert JSON structure depending on destination host name.
* **SIEM Connector Manager**:
  * Registers, queries, and tests multiple active connections concurrently.
  * Dispatches correlated alerts to all active integrations in a single routing pipeline.
* **Simulation Mode**:
  * If a connector has `is_mock=True` or the API token contains `"mock"`, the connector runs in simulation mode, yielding realistic search events and mock successful HTTP responses for offline validation.

### 3. Expanded Vulnerability & Compliance Engine (OWASP & CVEs up to July 2026)
* **OWASP API Security Top 10 (2023)**: Added **BOLA (Broken Object Level Authorization)** and **SSRF (Server-Side Request Forgery)**.
* **OWASP Top 10 for LLM Applications (2025/2026)**: Added **Prompt Injection (LLM01)**, **Insecure Output Handling (LLM02)**, and **Excessive Agency (LLM08)**.
* **OWASP Top 10 Additions**: Added **Software and Data Integrity Failures (A08:2021)** and **Security Logging and Monitoring Failures (A09:2021)**.
* Added MITRE ATT&CK technique **T1195 (Supply Chain Compromise)** and **T1611 (Escape to Host)**.
* Integrated signature alerts and custom exploitation payloads for:
  * **CVE-2024-3094 (XZ Utils Supply Chain Backdoor)**
  * **CVE-2024-21626 (runc Container Escape/breakout)**
  * **CVE-2024-4577 (PHP CGI Remote Code Execution)**
  * **LLM Prompt Injection / Jailbreaks (ignore previous instructions, Dan mode, etc.)**

### 4. Consolidated Documentation & Unit Tests
* Created `/doc` folder and moved platform documentation files (`release.md`, `PROJECT_SUMMARY.md`, `ENTERPRISE_INTEGRATION_SUMMARY.md`, and `IMPROVEMENT_ROADMAP.md`) inside it for a cleaner repository structure.
* Built comprehensive test suites verifying log parsers, IOC extractors, anomaly trackers, correlation engines, and SIEM connectors.

---

## 🛠️ Quick Start with version 2026.07.beta.4

1. **Launch Interactive SOC Console**:
   ```bash
   python advance_hackgpt.py
   ```
   Select option **`16`** from the main menu.

2. **Configure SIEM Connections**:
   Inside the SOC console, select option **`5`** to register Splunk, QRadar, Elasticsearch, or Webhooks.

3. **Query & Analyze Logs**:
   Select option **`6`** to query registered SIEM systems directly and execute correlation runs.

4. **Verify Installation**:
   ```bash
   pytest tests/unit/ -v
   ```
