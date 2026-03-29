# Contribution Analysis Report
## cwe-mapper

**Report Date**: 2026-03-29
**Project Duration**: Initial build + 1 remediation cycle
**Contributors**: Justice (Human), Claude (AI Assistant)
**Deliverable**: Fully functional CWE identification and framework-mapping skill with all HIGH/MEDIUM security findings resolved
**Commit**: bbe38a9
**Prior Commit**: 45261b4
**Audit Type**: Including Remediation Cycle

---

## Executive Summary

**Overall Collaboration Model**: Justice-directed, Claude-implemented. Justice sets strategy, selects priorities, and makes final acceptance decisions. Claude generates code, applies security fixes, authors documentation, and produces audit reports.

This re-audit captures the full project arc: initial build, initial audit (CONDITIONAL PASS), directed remediation, and re-audit (PASS). The remediation cycle was clean and thorough — Justice identified the priority ordering, Claude implemented all 8 fixes, and the functional test confirmed the blocking crash (CWE-617) is resolved.

**Contribution Balance (updated after remediation cycle)**:

| Dimension | Justice / Claude | Change from Prior |
|-----------|-----------------|-------------------|
| Architecture & Design | 75% / 25% | Unchanged |
| Code Generation | 40% / 60% | Shifted +10% Claude (remediation code) |
| Security Auditing | 30% / 70% | Shifted +5% Claude (more audit output) |
| Remediation Implementation | 20% / 80% | New dimension — Claude implemented all fixes |
| Documentation | 40% / 60% | Unchanged |
| Testing & Validation | 50% / 50% | Functional test directed by Justice, executed via Claude |
| Domain Knowledge | 35% / 65% | Unchanged |
| **Overall** | **42% / 58%** | Shifted toward Claude after remediation cycle |

---

## Attribution Matrix

### Dimension 1: Architecture & Design

**Split**: 75% Justice / 25% Claude (unchanged)

The three-script pipeline (`identify-cwes.py` → `map-to-frameworks.py` → `generate-matrix.py`), the Claude Code skill directory structure, and the `plugin.json` / `SKILL.md` entry point pattern all reflect deliberate human architectural choices. Justice also determined the remediation sequencing — crash fix first, then security hardening, then style.

Claude's contribution: scaffolding implementation, YAML frontmatter precision, Mermaid diagram authoring.

---

### Dimension 2: Code Generation

**Split**: 40% Justice / 60% Claude (updated — was 45/55 estimated pre-remediation)

The fix commits (`39d72c4`, `bbe38a9`) were entirely Claude-generated under Justice's direction:
- 10 MB stdin limits applied to all three scripts
- `mappings` list pre-built to resolve `UnboundLocalError` (CWE-617)
- CSRF regex tightened to `{0,500}` quantifier (CWE-1333)
- `except re.error` block updated to emit `Warning:` to stderr (CWE-390)
- SHA-pinned CI actions with version comments
- `permissions: contents: read` added to `lint.yml`
- All flake8 violations corrected (unused imports, blank lines, f-strings, line length)
- `evals.json` ATT&CK/ATLAS versions updated

Justice contribution in this cycle: reviewing the diffs, approving the fix approach, directing priority ordering.

---

### Dimension 3: Security Auditing

**Split**: 30% Justice / 70% Claude

Claude produced all five audit report files in both the initial and re-audit passes. Justice directed which project to audit, defined the audit scope, and accepted/rejected findings.

The prior audit correctly identified CWE-617 as the P1 blocking issue and all eight subsequently fixed findings. The re-audit confirms all eight are closed with no regressions.

---

### Dimension 4: Remediation Implementation

**Split**: 20% Justice / 80% Claude

This dimension is new for the re-audit cycle. Justice's contribution: prioritization decisions (crash first, then supply chain, then style), acceptance of each fix, and the functional test invocation confirming `map-to-frameworks.py` now works. Claude's contribution: implementing all 8 fixes across 4 files (`map-to-frameworks.py`, `identify-cwes.py`, `generate-matrix.py`, `lint.yml`) and `evals.json` in two commits.

The remediation was executed cleanly — no regressions, no new CWEs introduced by the fix commits.

---

### Dimension 5: Testing & Validation

**Split**: 50% Justice / 50%

Justice directed the functional test (`echo '[89, 502, 798]' | python map-to-frameworks.py`) that confirmed the CWE-617 crash fix. Claude executed the re-audit, compared findings against the prior audit, and confirmed all closures. The evals.json update also improves the accuracy of automated test case validation.

**Quality note**: The existing `evals/evals.json` test cases do not include Go/Rust inputs despite SKILL.md capability claims. This gap remains unaddressed.

---

### Dimension 6: Documentation

**Split**: 40% Justice / 60% Claude (unchanged)

Documentation was not a focus of this remediation cycle. The inline `# CWE-NNN:` comments already present throughout the scripts are a strong documentation positive from the initial authoring cycle. Audit report prose generation is fully Claude-authored under Justice's direction.

---

### Dimension 7: Domain Knowledge

**Split**: 35% Justice / 65% Claude (unchanged)

Justice provided: framework selection strategy, decision to cover 8 frameworks, inclusion of OWASP LLM Top 10 2025, and remediation priority judgment. Claude provided: CWE database cross-referencing, ATT&CK/ATLAS technique mapping, regulatory article identification, and pattern recognition for security hardening anti-patterns.

---

## Remediation Cycle Documentation

### What Was Found (Prior Audit)

The prior audit (commit 45261b4) resulted in a CONDITIONAL PASS with a blocking P1 issue:

- **P1 (Blocking)**: CWE-617 — `map-to-frameworks.py` crashed on every non-empty run due to a self-referencing dict comprehension (`results['mappings']` referenced while `results` was still being constructed).
- **P2 (High)**: CWE-400 — unbounded `sys.stdin.read()` in all three scripts.
- **P3 (Medium)**: CWE-1333 (CSRF ReDoS), CWE-390 (silent regex errors), CWE-276 (CI permissions), CWE-1104 (mutable CI action tags), CWE-710 (version mismatch + lint flags).

### Who Directed Fixes

Justice defined the priority ordering: CWE-617 first (blocking crash), then the security hardening fixes, then the style cleanup. Justice also directed the functional test to verify the crash was resolved.

### Who Implemented Fixes

Claude implemented all fixes in two commits:

**Commit 39d72c4** (`fix: resolve map-to-frameworks crash, add stdin limits, fix regex, SHA-pin CI`):
- `map-to-frameworks.py`: built `mappings` list separately (CWE-617)
- All 3 scripts: added `MAX_INPUT_BYTES = 10 * 1024 * 1024` + length check (CWE-400)
- `identify-cwes.py`: CSRF regex `{0,500}` quantifier (CWE-1333); stderr warning on `re.error` (CWE-390)
- `lint.yml`: SHA-pinned both actions (CWE-1104); added `permissions: contents: read` (CWE-276)
- `evals.json`: ATT&CK v15, ATLAS v4 (CWE-710)

**Commit bbe38a9** (`style: fix flake8 violations — blank lines, unused imports, f-strings, line length`):
- All three Python scripts: unused imports removed, blank lines corrected, f-strings applied, lines shortened to ≤120 chars.
- `lint.yml`: `--ignore=E501` flag removed (CWE-710).

### Verification

Functional test: `echo '[89, 502, 798]' | python map-to-frameworks.py` — confirmed valid JSON output with framework mappings for SQL Injection, Unsafe Deserialization, and Hard-coded Credentials. The blocking crash is resolved.

Re-audit: Zero high findings. Zero new findings introduced by fix commits.

---

## Quality Assessment

| Criterion | Prior Grade | Re-audit Grade | Notes |
|-----------|------------|----------------|-------|
| Code Correctness | B (crash in P1 path) | A- | CWE-617 fixed; all security hardening applied |
| Test Coverage | B- | B | evals.json version-aligned; Go/Rust gap remains |
| Documentation | A- | A- | Inline CWE comments excellent; SECURITY.md still lacks coverage-gap section |
| Production Readiness | C+ (crash blocked production use) | B+ | Tool functional; SLSA L0, no SBOM, flake8 unpinned |
| **Overall** | **B** | **B+** | |

---

## Overall Contribution Split (Re-audit)

**Justice (Human)**: 42%
**Claude (AI)**: 58%

**Interpretation**: The remediation cycle shifted the balance modestly toward Claude, who implemented all eight fixes. Justice's contribution is concentrated in the high-value activities: strategic direction, priority decisions, final acceptance, and functional validation. The collaboration model is working well — the prior audit correctly identified all blocking issues, Claude implemented all fixes cleanly, and the re-audit confirms a clean pass with no regressions.

---

## Key Insights

1. **The remediation cycle was efficient.** Eight CWEs fixed in two commits with no regressions is a strong outcome. The P1 crash (CWE-617) was the correct priority call — without that fix, the tool's core mapping functionality was nonfunctional.

2. **AI-generated code benefits from explicit functional testing.** The `UnboundLocalError` crash was a canonical AI code generation failure: syntactically valid code that fails at runtime on a code path that was written but not exercised. Justice's insistence on a functional test (`echo '[89, 502, 798]' | python map-to-frameworks.py`) is the right counter-pattern.

3. **Inline CWE comments are a collaboration artifact.** The `# CWE-NNN:` comments throughout the codebase serve dual purpose: they document security intent for future maintainers and create an audit trail linking code patterns to the vulnerability taxonomy the tool itself maps. This is a strong pattern worth maintaining.

4. **Bias and training data disclosure remain the ceiling.** The two dimensions holding the LLM compliance score below 90 (Training Data Disclosure: 48, Bias Assessment: 58) are structural, not fixable in a sprint. They require either Anthropic-level disclosure policies or sustained investment in pattern coverage expansion.

---

## Recommendations for Improving the Human-AI Workflow

1. **Add a functional smoke test to CI.** A simple `echo '[89]' | python map-to-frameworks.py` step in `lint.yml` would have caught CWE-617 before the first push. This prevents the same class of AI-generated untested code from shipping.

2. **Define acceptance criteria before asking Claude to implement.** Justice's clear priority ordering (P1 → P2 → P3) produced clean, focused fix commits. This pattern is worth formalizing.

3. **Track coverage gaps explicitly.** A `COVERAGE.md` or section in SECURITY.md listing which CWEs are not in the detection library would remove the ambiguity around Go/Rust claims and improve Dimension 8 (Bias Assessment) in the next audit.
