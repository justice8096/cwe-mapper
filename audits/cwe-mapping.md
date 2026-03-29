# CWE Mapping Report
## cwe-mapper

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite — CWE Mapper
**Commit**: bbe38a9
**Prior Commit Audited**: 45261b4
**Branch**: master
**Frameworks**: OWASP Top 10 2021, OWASP LLM Top 10 2025, NIST SP 800-53, EU AI Act, ISO 27001:2022, SOC 2, MITRE ATT&CK v15, MITRE ATLAS v4
**Audit Type**: POST-FIX Re-audit

---

## Overview

This re-audit maps all CWEs from the prior scan and tracks remediation status. Of the 11 CWEs identified in the initial audit, 8 have been fully closed. The remaining 3 are informational or accepted residual risks. No new CWEs were introduced by the fix commits.

---

## CWE Status Table

| CWE | Name | Prior Severity | Current Status |
|-----|------|---------------|----------------|
| CWE-400 | Uncontrolled Resource Consumption | HIGH | CLOSED — 10 MB stdin limit applied to all 3 scripts |
| CWE-617 | Reachable Assertion (runtime crash) | HIGH | CLOSED — mappings list built before results dict |
| CWE-1333 | Inefficient Regular Expression Complexity (ReDoS) | MEDIUM | CLOSED — CSRF regex uses `{0,500}` bounded quantifier |
| CWE-390 | Detection of Error Condition Without Action | MEDIUM | CLOSED — Warning printed to stderr on regex compile error |
| CWE-276 | Incorrect Default Permissions | LOW | CLOSED — `permissions: contents: read` in lint.yml |
| CWE-1104 | Use of Unmaintained Third-Party Components | LOW | CLOSED — CI actions SHA-pinned |
| CWE-116 | Improper Encoding / Output Neutralization | MEDIUM | RESIDUAL — name from hardcoded dict, not user-controlled |
| CWE-693 | Protection Mechanism Failure (no SBOM) | INFO | OPEN — zero runtime deps; low risk |
| CWE-710 | Coding Standards Violation (version mismatch) | INFO | CLOSED — evals.json aligned to ATT&CK v15 / ATLAS v4 |
| CWE-710 | Coding Standards Violation (contradictory lint flags) | INFO | CLOSED — `--ignore=E501` removed; zero violations |
| CWE-345 | Insufficient Verification of Data Authenticity | MEDIUM | PARTIAL — fix commits signed; historical audit series unsigned |
| CWE-1188 | Insecure Default Initialization of Resource (CI perms) | MEDIUM | CLOSED — `permissions: contents: read` applied |

**Closed**: 8 | **Residual/Accepted**: 1 | **Open**: 1 | **Partial**: 1

---

## Per-CWE Framework Mapping

### CWE-400 — Uncontrolled Resource Consumption
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration |
| OWASP LLM Top 10 2025 | LLM04 — Model Denial of Service |
| NIST SP 800-53 | SC-5 (Denial of Service Protection), SI-10, SI-12 |
| EU AI Act | Article 15 — Accuracy, Robustness and Cybersecurity |
| ISO 27001:2022 | A8.6 (Capacity Management) |
| SOC 2 | CC6.1, CC7.2 |
| MITRE ATT&CK v15 | T1499 (Endpoint Denial of Service) |
| MITRE ATLAS v4 | AML.T0029 (Denial of ML Service) |

---

### CWE-617 — Reachable Assertion / UnboundLocalError Runtime Crash
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration |
| OWASP LLM Top 10 2025 | LLM09 — Overreliance |
| NIST SP 800-53 | SI-10 (Input Validation), SA-11 (Developer Security Testing) |
| EU AI Act | Article 15 — Accuracy, Robustness and Cybersecurity |
| ISO 27001:2022 | A8.1 (Software Quality) |
| SOC 2 | CC7.1, CC3.2 |
| MITRE ATT&CK v15 | T1499.004 (Application or System Exploitation) |
| MITRE ATLAS v4 | AML.T0043 (Denial of ML Service via Crash) |

---

### CWE-1333 — Inefficient Regular Expression Complexity (ReDoS)
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration |
| OWASP LLM Top 10 2025 | LLM04 — Model Denial of Service |
| NIST SP 800-53 | SC-5, SI-10 |
| EU AI Act | Article 15 — Accuracy, Robustness and Cybersecurity |
| ISO 27001:2022 | A8.1 |
| SOC 2 | CC6.1 |
| MITRE ATT&CK v15 | T1499 |
| MITRE ATLAS v4 | AML.T0029 |

---

### CWE-390 — Detection of Error Condition Without Action
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A09 — Security Logging and Monitoring Failures |
| OWASP LLM Top 10 2025 | LLM09 — Overreliance |
| NIST SP 800-53 | AU-12 (Audit Generation), SI-4 (Monitoring), SI-11 (Error Handling) |
| EU AI Act | Article 13 — Transparency and Provision of Information |
| ISO 27001:2022 | A8.15 (Logging), A8.16 (Monitoring Activities) |
| SOC 2 | CC7.2, CC4.1 |
| MITRE ATT&CK v15 | T1562.006 (Indicator Blocking) |
| MITRE ATLAS v4 | AML.T0015 (Evade ML Model) |

---

### CWE-276 — Incorrect Default Permissions
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration |
| OWASP LLM Top 10 2025 | LLM03 — Supply Chain Vulnerabilities |
| NIST SP 800-53 | CM-6 (Configuration Settings), AC-6 (Least Privilege) |
| EU AI Act | Article 15 |
| ISO 27001:2022 | A8.2 (Privileged Access Rights) |
| SOC 2 | CC6.3, CC6.6 |
| MITRE ATT&CK v15 | T1078 (Valid Accounts) |
| MITRE ATLAS v4 | AML.T0010 (ML Supply Chain Compromise) |

---

### CWE-1104 — Use of Unmaintained Third-Party Components (mutable CI tags)
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A06 — Vulnerable and Outdated Components |
| OWASP LLM Top 10 2025 | LLM03 — Supply Chain Vulnerabilities |
| NIST SP 800-53 | SI-2 (Flaw Remediation), SA-12 (Supply Chain Protection) |
| EU AI Act | Article 15 |
| ISO 27001:2022 | A8.6 |
| SOC 2 | CC3.2, CC9.2 |
| MITRE ATT&CK v15 | T1195.001 (Supply Chain Compromise) |
| MITRE ATLAS v4 | AML.T0010 |

---

### CWE-116 — Improper Encoding or Escaping of Output
**Status**: RESIDUAL — accepted

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A03 — Injection |
| OWASP LLM Top 10 2025 | LLM02 — Insecure Output Handling |
| NIST SP 800-53 | SI-10, SI-15 (Information Output Filtering) |
| EU AI Act | Article 15 |
| ISO 27001:2022 | A8.1 |
| SOC 2 | CC6.1, CC6.7 |
| MITRE ATT&CK v15 | T1059 |
| MITRE ATLAS v4 | AML.T0018 (Backdoor ML Model) |

---

### CWE-693 — Protection Mechanism Failure (no SBOM)
**Status**: OPEN / INFO

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A06 — Vulnerable and Outdated Components |
| OWASP LLM Top 10 2025 | LLM03 — Supply Chain Vulnerabilities |
| NIST SP 800-53 | SA-12 (Supply Chain Protection), CM-8 (Component Inventory) |
| EU AI Act | Article 13 — Transparency |
| ISO 27001:2022 | A8.6 |
| SOC 2 | CC3.2 |
| MITRE ATT&CK v15 | T1195 |
| MITRE ATLAS v4 | AML.T0010 |

---

### CWE-710 — Coding Standards Violations (both instances)
**Status**: CLOSED (both instances)

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration / A09 — Logging Failures |
| OWASP LLM Top 10 2025 | LLM09 — Overreliance |
| NIST SP 800-53 | SA-8 (Security Engineering), CM-6, CM-2 |
| EU AI Act | Article 9 (Risk Management), Article 13 (Transparency) |
| ISO 27001:2022 | A8.25 (Secure Development Life Cycle), A8.8 |
| SOC 2 | CC3.1, CC7.1 |
| MITRE ATT&CK v15 | — |
| MITRE ATLAS v4 | — |

---

### CWE-345 — Insufficient Verification of Data Authenticity (unsigned commits)
**Status**: PARTIAL — fix commits signed; historical unsigned audit series remains

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A08 — Software and Data Integrity Failures |
| OWASP LLM Top 10 2025 | LLM03 — Supply Chain Vulnerabilities |
| NIST SP 800-53 | SI-7 (Software Integrity), SA-12 |
| EU AI Act | Article 15 |
| ISO 27001:2022 | A8.32 (Change Management), A8.20 |
| SOC 2 | CC7.1, CC8.1 |
| MITRE ATT&CK v15 | T1195.003 |
| MITRE ATLAS v4 | AML.T0010 |

---

### CWE-1188 — Insecure Default Initialization of Resource (CI permissions)
**Status**: CLOSED

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A05 — Security Misconfiguration |
| OWASP LLM Top 10 2025 | LLM03 — Supply Chain Vulnerabilities |
| NIST SP 800-53 | CM-6, AC-6 |
| EU AI Act | Article 15 |
| ISO 27001:2022 | A8.9 (Configuration Management) |
| SOC 2 | CC6.3, CC6.6 |
| MITRE ATT&CK v15 | T1078.004 (Valid Accounts: Cloud Accounts) |
| MITRE ATLAS v4 | AML.T0010 |

---

## Aggregated Framework Impact Summary

### OWASP Top 10 2021 — Prior vs. Re-audit

| Category | Prior CWEs | Status |
|----------|-----------|--------|
| A03 — Injection | CWE-116 | Residual (accepted) |
| A05 — Security Misconfiguration | CWE-400, CWE-617, CWE-276, CWE-710, CWE-1188, CWE-1333 | Mostly CLOSED |
| A06 — Vulnerable and Outdated Components | CWE-1104, CWE-693 | CLOSED / Open (info) |
| A08 — Software and Data Integrity Failures | CWE-345 | PARTIAL |
| A09 — Security Logging and Monitoring | CWE-390, CWE-710 | CLOSED |

**Categories affected (re-audit)**: 5 of 10 (same count; severity reduced)

---

### OWASP LLM Top 10 2025

| Category | CWEs | Status |
|----------|------|--------|
| LLM02 — Insecure Output Handling | CWE-116 | Residual |
| LLM03 — Supply Chain Vulnerabilities | CWE-276, CWE-1104, CWE-693, CWE-345, CWE-1188 | Mostly CLOSED |
| LLM04 — Model Denial of Service | CWE-400, CWE-1333 | CLOSED |
| LLM09 — Overreliance | CWE-617, CWE-390, CWE-710 | CLOSED |

**Categories affected**: 4 of 10 (unchanged count; severity substantially reduced)

---

### NIST SP 800-53

| Control | CWEs | Re-audit Status |
|---------|------|----------------|
| AC-6 (Least Privilege) | CWE-276, CWE-1188 | CLOSED |
| AU-12 (Audit Generation) | CWE-390 | CLOSED |
| CM-6 (Configuration Settings) | CWE-276, CWE-1188, CWE-710 | CLOSED |
| CM-8 (Component Inventory) | CWE-693 | Open (info) |
| SA-8 / SA-12 (Supply Chain / Security Engineering) | CWE-710, CWE-1104, CWE-693, CWE-345 | Mostly CLOSED |
| SC-5 (Denial of Service Protection) | CWE-400, CWE-1333 | CLOSED |
| SI-2 (Flaw Remediation) | CWE-1104 | CLOSED |
| SI-4 (System Monitoring) | CWE-390 | CLOSED |
| SI-7 (Integrity Verification) | CWE-345 | PARTIAL |
| SI-10 (Input Validation) | CWE-617, CWE-1333, CWE-116 | CLOSED / Residual |
| SI-11 (Error Handling) | CWE-390 | CLOSED |

**Controls affected**: 11 (same as prior; most now CLOSED)

---

### EU AI Act

| Article | CWEs | Status |
|---------|------|--------|
| Article 9 (Risk Management) | CWE-710 | CLOSED |
| Article 13 (Transparency) | CWE-390, CWE-693, CWE-710 | CLOSED / Open (info) |
| Article 15 (Robustness/Cybersecurity) | CWE-400, CWE-617, CWE-1333, CWE-116, CWE-276, CWE-1104, CWE-345, CWE-1188 | Mostly CLOSED |

**Articles affected**: 3 (same; most CWEs now CLOSED)

---

### ISO 27001:2022

| Control | CWEs | Status |
|---------|------|--------|
| A8.1 | CWE-400, CWE-617, CWE-1333, CWE-116 | CLOSED / Residual |
| A8.2 | CWE-276 | CLOSED |
| A8.6 | CWE-1104, CWE-693 | CLOSED / Open (info) |
| A8.9 | CWE-1188 | CLOSED |
| A8.15 / A8.16 | CWE-390 | CLOSED |
| A8.25 | CWE-710 | CLOSED |
| A8.32 | CWE-345 | PARTIAL |

**Controls affected**: 7 (same; mostly CLOSED)

---

### SOC 2 and MITRE Frameworks

| Framework | Prior Criteria/Techniques | Re-audit |
|-----------|--------------------------|----------|
| SOC 2 — Criteria affected | 7 | 7 (same; mostly resolved) |
| MITRE ATT&CK v15 — Techniques | 6 | 6 (same mapping; risks reduced) |
| MITRE ATLAS v4 — Techniques | 5 | 5 (same mapping; risks reduced) |

---

## Compliance Gap Prioritization (Re-audit)

| Priority | CWE | Status | Action |
|----------|-----|--------|--------|
| 1 (Resolved) | CWE-617 | CLOSED | map-to-frameworks crash fixed |
| 2 (Resolved) | CWE-400 | CLOSED | 10 MB stdin limit applied |
| 3 (Resolved) | CWE-1333 / CWE-1104 | CLOSED | Bounded regex + SHA-pinned CI |
| 4 (Partial) | CWE-345 | PARTIAL | Fix commits signed; branch policy unverified |
| 5 (Open) | CWE-693 | OPEN (info) | SBOM optional at current scale |
| 6 (Residual) | CWE-116 | ACCEPTED | Not user-exploitable in current paths |

**Result: PASS** — All blocking and high-severity CWEs closed. Framework coverage maintained at 11 CWEs mapped to 8 frameworks.
