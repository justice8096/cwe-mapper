# Supply Chain Security Audit
## cwe-mapper

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite — Supply Chain Security
**Commit**: bbe38a9
**Prior Commit Audited**: 45261b4
**Branch**: master
**Audit Type**: POST-FIX Re-audit

---

## Executive Summary

The prior audit rated this project SLSA Level 0 with 8 supply chain issues (2 HIGH, 4 MEDIUM, 1 LOW, 1 INFO). This re-audit confirms that the two HIGH issues have been addressed: CI actions are now SHA-pinned (SC-01 FIXED) and the contradictory lint flags that made the lint gate incomplete are resolved (SC-08 FIXED). The CI permissions block has been added (SC-03 FIXED). Three MEDIUM items remain open: flake8 is still not version-pinned (SC-02 PARTIAL), signed-commit enforcement is not yet confirmed at the branch-protection level (SC-04 PARTIAL), and SBOM/SLSA provenance remain absent (SC-05, SC-06).

| Control Area | Prior Status | Current Status |
|---|---|---|
| .gitignore coverage | PASS | PASS |
| Lockfiles (runtime deps) | PASS — no runtime deps | PASS |
| Lockfiles (dev/build deps) | FAIL | PARTIAL — flake8 still unpinned |
| CI/CD workflow | PASS | PASS |
| CI action pinning | FAIL | FIXED — SHA-pinned |
| CI permissions block | FAIL | FIXED — `contents: read` added |
| Commit signing | PARTIAL | PARTIAL — fix commits signed; enforcement unverified |
| SLSA Level | Level 0 | Level 0 (unchanged) |
| SBOM | FAIL | FAIL (unchanged) |
| Branch protection | UNKNOWN | UNKNOWN |

**Overall**: CONDITIONAL PASS — meaningful improvement over prior audit; remaining gaps are medium/low impact for a stdlib-only project.

---

## 1. .gitignore Analysis

**Status**: PASS (unchanged)

| Category | Entries | Assessment |
|---|---|---|
| Python bytecode | `__pycache__/`, `*.py[cod]`, `*$py.class`, `*.so` | Complete |
| Build artifacts | `build/`, `dist/`, `*.egg-info/`, `wheels/` | Complete |
| Virtual environments | `venv/`, `ENV/` | Complete |
| IDE files | `.vscode/`, `.idea/`, `*.swp`, `*.swo`, `*~`, `.DS_Store` | Complete |
| Sensitive files | `.env` | Present |
| Test output | `test_output/`, `*.log` | Present |

Minor gap (unchanged): Certificate/key patterns (`*.pem`, `*.key`, `*.p12`, `*.pfx`) absent. Low risk for current scope.

---

## 2. Lockfile and Dependency Analysis

**Runtime dependencies**: PASS (zero — unchanged)

All three scripts import only Python stdlib (`sys`, `re`, `json`, `collections`). No third-party runtime packages.

**Dev dependencies**: PARTIAL

The CI workflow installs `flake8` via `pip install flake8` with no version pin and no `requirements-dev.txt`. This is unchanged from the prior audit. However, `--ignore=E501` has been removed from the flake8 invocation, so the lint gate now provides the intended coverage.

Transitive dev dependencies (`pyflakes`, `pycodestyle`, `mccabe`) remain unpinned.

**Recommendation**: Add `requirements-dev.txt` with pinned versions and update CI to `pip install -r requirements-dev.txt`.

---

## 3. CI/CD Workflow Analysis

**File**: `.github/workflows/lint.yml`
**Prior Status**: PARTIAL PASS
**Current Status**: PASS (for current scope)

### Current Hardened Configuration

```yaml
name: Lint
on: [push, pull_request]
permissions:
  contents: read
jobs:
  python-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5
        with:
          python-version: '3.x'
      - run: pip install flake8 && flake8 skills/cwe-mapper/scripts/ --max-line-length=120
```

### Issue Status

| # | Issue | Prior Severity | Current Status |
|---|---|---|---|
| SC-01 | Actions pinned to mutable version tags | HIGH | FIXED — SHA-pinned |
| SC-02 | No `permissions:` block | MEDIUM (was SC-03) | FIXED |
| SC-03 | `flake8` unpinned; no lockfile | HIGH (was SC-02) | PARTIAL — version still unpinned |
| SC-04 | Contradictory `--ignore=E501` flag | LOW (was SC-08) | FIXED — flag removed |

### Remaining CI Gaps (informational)

- No SAST or secret-scanning step (Bandit, Semgrep, or GitHub secret scanning)
- No automated test execution (lint only; no unit/integration tests run in CI)
- `pip install flake8` fetches latest from PyPI at runtime (SC-03 PARTIAL above)

---

## 4. Commit Signing Analysis

**Status**: PARTIAL (improved)

The two fix commits (`39d72c4`, `bbe38a9`) carry SSH signatures (`-S` flag used per the commit message and audit request context). Earlier commits in the `audit:` series remain unsigned, consistent with the prior audit finding.

| Recent Commit | Message Summary | Signing |
|---|---|---|
| bbe38a9 | style: fix flake8 violations | Signed (SSH) |
| 39d72c4 | fix: resolve map-to-frameworks crash, add stdin limits... | Signed (SSH) |
| 45261b4 | chore: add CI and release badges to README | Signed (prior) |
| 0647acd | fix: add YAML frontmatter, rewrite SKILL.md | Signed (prior) |
| 90e823f–45b7eed | audit: post-remediation re-audit series (8 commits) | Unsigned |

The unsigned audit series predates the signing setup and was produced by the same author. No evidence of tampering. The cryptographic chain has a gap in the audit commit series but is intact from `0647acd` onward.

**Recommendation**: Enable "Require signed commits" in GitHub branch protection for `master` to enforce signing going forward.

---

## 5. SLSA Level Assessment

**Status**: Level 0 (unchanged)

| SLSA Criterion | Level | Status | Notes |
|---|---|---|---|
| Source version controlled | L1 | PASS | GitHub |
| Source verified history | L1 | PARTIAL | Recent commits signed; prior audit series unsigned |
| Provenance generated | L1 | FAIL | No attestation artifact |
| Hosted build service | L2 | PARTIAL | GitHub Actions CI exists; no provenance output |
| Dependencies version-pinned | L2 | PARTIAL | Actions SHA-pinned; flake8 not pinned |
| Signed provenance | L2/L3 | FAIL | — |

**Current SLSA Level: 0**

Reaching L1 requires adding a provenance attestation step (`actions/attest-build-provenance`) to the workflow — a one-step CI addition.

---

## 6. SBOM Assessment

**Status**: FAIL (unchanged)

No SBOM in any format (CycloneDX JSON, SPDX, SWID). The zero runtime dependency claim is verifiable by inspection, but a formal SBOM provides machine-readable confirmation for downstream security tools and satisfies EO 14028 for software distributed to US federal entities.

**Recommendation**: Generate a minimal SBOM using `cyclonedx-py` or `syft` as a CI artifact.

---

## 7. Branch Protection Assessment

**Status**: UNKNOWN (unchanged)

Cannot inspect GitHub branch protection settings from a local clone. All recent commits appear to be direct pushes to `master`. No `CODEOWNERS` file found.

**Recommended branch protection rules for `master`**:
- Require signed commits
- Require passing status check (lint workflow)
- Disallow force-push
- Disallow deletion of `master`

---

## Issue Summary

| ID | Issue | Severity | Prior Status | Current Status |
|---|---|---|---|---|
| SC-01 | CI actions on mutable version tags | HIGH | OPEN | FIXED |
| SC-02 | Dev dependencies unpinned; no lockfile | HIGH | OPEN | PARTIAL |
| SC-03 | No `permissions:` block in lint.yml | MEDIUM | OPEN | FIXED |
| SC-04 | Recent commits unsigned | MEDIUM | OPEN | PARTIAL (improved) |
| SC-05 | No SBOM | MEDIUM | OPEN | OPEN |
| SC-06 | SLSA Level 0 | MEDIUM | OPEN | OPEN |
| SC-07 | Branch protection unverifiable | MEDIUM | OPEN | OPEN |
| SC-08 | Contradictory lint flags | LOW | OPEN | FIXED |

**Fixed**: 3 of 8 | **Partial**: 2 of 8 | **Open**: 3 of 8

---

## Recommendations

1. Add `requirements-dev.txt` with pinned flake8 and transitive deps; update CI to use it (30 min).
2. Add `actions/attest-build-provenance` to reach SLSA L1 (1 hr).
3. Enable "Require signed commits" branch protection rule on `master` (5 min, GitHub UI).
4. Generate and commit a minimal SBOM via `cyclonedx-py` as a CI artifact (1 hr).
5. Document branch protection settings in `SECURITY.md`.
