# SAST/DAST Scan Report
## cwe-mapper

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite — SAST/DAST Scanner
**Commit**: bbe38a9 (style: fix flake8 violations — blank lines, unused imports, f-strings, line length)
**Prior Commit Audited**: 45261b4
**Branch**: master
**Scope**: All Python scripts, GitHub Actions workflow, evals/evals.json
**DAST**: N/A — no web-facing components (confirmed by SECURITY.md)
**Audit Type**: POST-FIX Re-audit

---

## Executive Summary

This re-audit follows the prior CONDITIONAL PASS (2026-03-29, commit 45261b4). All eight HIGH and MEDIUM findings from the initial scan have been fully resolved. The two HIGH findings (CWE-617 runtime crash, CWE-400 unbounded stdin) are confirmed fixed and functional-tested. The four MEDIUM findings (CWE-1333 ReDoS, CWE-390 silent errors, CWE-276 CI permissions, CWE-1104 mutable action tags) are fully remediated. The two INFO findings (CWE-710 version mismatch, CWE-710 contradictory lint flags) are confirmed resolved. The one residual MEDIUM finding (CWE-116, Markdown injection surface) remains unchanged but is accepted — the `name` field is sourced from a hardcoded internal dict, not caller-supplied input.

| Severity | Prior Count | Re-audit Count |
|----------|------------|----------------|
| CRITICAL | 0 | 0 |
| HIGH | 2 | 0 |
| MEDIUM | 3 | 1 (residual, accepted) |
| LOW | 2 | 0 |
| INFO | 3 | 1 (open) |
| **Total** | **10** | **2** |

**Overall Result: PASS**

---

## Finding 001 — RESOLVED (was HIGH)

**ID**: SAST-001
**CWE**: CWE-400 — Uncontrolled Resource Consumption
**Prior Location**: `identify-cwes.py:269`, `map-to-frameworks.py:366`, `generate-matrix.py:293`
**Status**: FIXED

All three scripts now apply a 10 MB read cap with explicit error handling:

```python
MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MB
code = sys.stdin.read(MAX_INPUT_BYTES)
if len(code) == MAX_INPUT_BYTES:
    print("Error: Input exceeds 10 MB maximum", file=sys.stderr)
    sys.exit(1)
```

Verification: All three scripts confirmed to contain this pattern in the current commit.
CWE-400 — **CLOSED**.

---

## Finding 002 — RESOLVED (was HIGH)

**ID**: SAST-002
**CWE**: CWE-617 — Reachable Assertion / UnboundLocalError runtime crash
**Prior Location**: `map-to-frameworks.py:391-401`
**Status**: FIXED

The self-referencing dict comprehension that caused `UnboundLocalError` on every non-empty run has been replaced. The `mappings` list is now built separately before being referenced in the `results` dict:

```python
mappings = [map_cwe(cwe) for cwe in validated_cwes]
results = {
    'cwe_count': len(validated_cwes),
    'mappings': mappings,
    'frameworks': {
        framework: sorted(set(
            item
            for mapping in mappings
            for item in mapping.get(framework, [])
        ))
        for framework in [
            'owasp_2021', 'owasp_llm', 'nist', 'eu_ai_act',
            'iso_27001', 'soc2', 'mitre_attack', 'mitre_atlas',
        ]
    },
}
```

Functional test confirmed: `echo '[89, 502, 798]' | python map-to-frameworks.py` produces valid JSON output. The blocking crash is resolved.
CWE-617 — **CLOSED**.

---

## Finding 003 — RESOLVED (was MEDIUM)

**ID**: SAST-003
**CWE**: CWE-1333 — Inefficient Regular Expression Complexity (ReDoS)
**Prior Location**: `identify-cwes.py:119` — CSRF regex with `.*` unbounded quantifier
**Status**: FIXED

The CSRF regex pattern has been updated to use a bounded `{0,500}` quantifier, consistent with all other patterns in the CWE_PATTERNS block. Current source confirms no unbounded `.*` in any CSRF detection pattern. All other patterns in the detection library already used bounded quantifiers with `# CWE-1333:` inline comments.

CWE-1333 — **CLOSED**.

---

## Finding 004 — RESOLVED (was MEDIUM)

**ID**: SAST-004
**CWE**: CWE-390 — Detection of Error Condition Without Action
**Prior Location**: `identify-cwes.py:261-262`
**Status**: FIXED

The silent `except re.error: continue` has been replaced with an explicit warning to stderr:

```python
except re.error as exc:
    print(f"Warning: Invalid regex for CWE-{cwe_id}: {exc}", file=sys.stderr)
    continue
```

CWE-390 — **CLOSED**.

---

## Finding 005 — RESIDUAL / ACCEPTED (was MEDIUM)

**ID**: SAST-005
**Severity**: MEDIUM (accepted residual risk)
**CWE**: CWE-116 — Improper Encoding or Escaping of Output
**Location**: `generate-matrix.py:212`
**Status**: UNCHANGED — accepted

The `name` embedded into Markdown headings is sourced from `CWE_MAPPINGS[cwe_id]['name']` — a hardcoded internal dict — not from any caller-supplied field. The `finding['name']` key from the caller-supplied JSON is not used; the canonical name always comes from the internal mapping. The injection surface is therefore not user-controlled in the current code paths.

**If caller-supplied names are ever used**: Strip or escape Markdown special characters (`|`, `` ` ``, leading `#`) before embedding.

This finding is retained as documentation of a latent pattern but does not block the PASS verdict.

---

## Finding 006 — RESOLVED (was LOW)

**ID**: SAST-006
**CWE**: CWE-276 — Incorrect Default Permissions
**Prior Location**: `lint.yml` — no `permissions:` block
**Status**: FIXED

`lint.yml` now has a top-level `permissions: contents: read` stanza:

```yaml
permissions:
  contents: read
```

CWE-276 — **CLOSED**.

---

## Finding 007 — RESOLVED (was LOW)

**ID**: SAST-007
**CWE**: CWE-1104 — Use of Unmaintained Third-Party Components (mutable action tags)
**Prior Location**: `lint.yml:8-9`
**Status**: FIXED

Both actions are now SHA-pinned with version comments:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5
```

CWE-1104 — **CLOSED**.

---

## Finding 008 — INFO (unchanged)

**ID**: SAST-008
**CWE**: CWE-693 — Protection Mechanism Failure (no SBOM)
**Status**: OPEN / INFO

No SBOM in CycloneDX or SPDX format. The project has zero runtime dependencies (Python stdlib only), so the practical risk is low. Generating a minimal SBOM is recommended before public distribution.

---

## Finding 009 — RESOLVED (was INFO)

**ID**: SAST-009
**CWE**: CWE-710 — Coding Standards Violation (version mismatch)
**Prior Location**: `evals/evals.json`
**Status**: FIXED

`evals.json` has been updated to align with ATT&CK v15 and ATLAS v4, matching the declarations in SKILL.md. Version inconsistency eliminated.

CWE-710 (versions) — **CLOSED**.

---

## Finding 010 — RESOLVED (was INFO)

**ID**: SAST-010
**CWE**: CWE-710 — Coding Standards Violation (contradictory lint flags)
**Prior Location**: `lint.yml:11`
**Status**: FIXED

`--ignore=E501` removed from the flake8 invocation. The CI lint command is now:

```
pip install flake8 && flake8 skills/cwe-mapper/scripts/ --max-line-length=120
```

All flake8 violations (unused imports, blank lines, f-strings, line length) have been corrected in source. Zero violations confirmed.

CWE-710 (lint flags) — **CLOSED**.

---

## Injection Pattern Scan Summary

| Pattern Class | Files Scanned | Instances | Notes |
|---------------|--------------|-----------|-------|
| SQL Injection | All | 0 | No DB connections |
| Command Injection (subprocess shell=True) | All | 0 | No subprocess usage |
| Path Traversal | All | 0 | No file operations on user paths |
| XSS / HTML Injection | All | 0 | No HTML rendering |
| eval/exec on user input | All | 0 | No eval/exec calls |
| Pickle / deserialization | All | 0 | No deserialization of external data |
| Hardcoded secrets / API keys | All | 0 | No credentials present |
| ReDoS-vulnerable regex | identify-cwes.py | 0 | CWE-1333 fixed — all patterns bounded |
| Unbounded stdin read | All 3 scripts | 0 | CWE-400 fixed — 10 MB limit applied |

---

## DAST Assessment

Not applicable. No web components, no servers, no network listeners (per SECURITY.md). All scripts operate on stdin/stdout only.

---

## Overall Result: PASS

All blocking and high-severity findings resolved. Zero new findings introduced by the fix commits. Residual CWE-116 is not user-exploitable under current code paths. The tool is functional: the map-to-frameworks.py crash (CWE-617) that prevented any framework-mapping output is confirmed fixed.
