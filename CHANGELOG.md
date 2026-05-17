<!-- SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to this skill are tracked here. Per the [Skill Versioning and Addendum Framework](https://github.com/justice8096/SecondBrainData/blob/main/SoftwarePractices/Skill-Versioning-and-Addendum-Framework.md), every change is classified by driver so downstream audit-artifact consumers can assess whether prior outputs need addendum filings.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with **change-driver tags** appended per entry:

- `[authority]` — underlying regulation, standard, or evidence base changed
- `[defect]` — typo, broken citation, misspelled term, wrong CFR number, factual error
- `[structural]` — section restructure, new locale, new lifespan layer, new domain, new severity scale
- `[voice]` — wording refinement, tone adjustment, ambiguity fix, accessibility improvement

All four drivers affect admissibility / persuasive weight of downstream artifacts. Every change is tracked equally.

## [Unreleased]

## [1.1.0] — 2026-05-17

Skill Versioning and Addendum Framework integration. Aligns cwe-mapper with the framework piloted in dyscalculia-support-skill v1.3.0–v1.3.2 and applied across seven sibling skill repos (dyslexia v1.3.0, LLMComplianceSkill v1.2.0, ai-compliance-extractors v1.1.0, post-commit-audit v1.2.0, supply-chain-security v1.1.0, sast-dast-scanner v1.1.0). **This is the 8th and final in-scope skill** in [Master Task List § 17](https://github.com/justice8096/SecondBrainData) — completes the framework rollout.

Documentation/governance release — no behavior changes to CWE identification, framework mapping, or compliance matrix generation.

### Added `[structural]`
- `CHANGELOG.md` (this file) adopting the four-driver classification with retroactive entries for v1.0.0 and v1.0.1.
- **Audit-Artifact Provenance Block** required at the top of every generated `cwe-mapping.md` report. Captures skill version, commit hash, generation date, target-project repo + commit, sources-current-as-of, framework versions (all 8), CWE List version, changelog URL. cwe-mapper is the framework-routing skill for the entire security audit pipeline — its outputs feed downstream legal/compliance reasoning, so reproducibility matters most here.

### Added `[authority]`
- Inline "*Sources current as of 2026-05*" markers + authority-version pin block in `skills/cwe-mapper/SKILL.md`. Pins all 8 frameworks plus the upstream CWE list:
  - CWE List 4.16 (2024-11) — official list at cwe.mitre.org; verify each CWE entry is current before signing audit
  - OWASP Top 10:2021 (web application risks)
  - OWASP Top 10 for LLM Applications v1.1 (2024-10)
  - NIST SP 800-53 Rev. 5 (2020-09) + 5.1.1 update (2023-12)
  - EU AI Act (Regulation (EU) 2024/1689) Articles 15 / 35 / 37 (in force 2024-08-01, full applicability 2026-08-02)
  - ISO/IEC 27001:2022 Annex A controls
  - SOC 2 (AICPA Trust Services Criteria 2017 + 2022 updates) — CC6, CC7
  - MITRE ATT&CK v17.1 (2025-04)
  - MITRE ATLAS v4.7.0 (2025-01)

### Process notes
- `.claude-plugin/plugin.json` version 1.0.1 → 1.1.0.
- License remains MIT (consistent across LICENSE file + plugin.json).
- **Framework rollout complete.** All 8 in-scope skills in MTL § 17 are now on the framework: dyscalculia (pilot), dyslexia, LLMComplianceSkill, ai-compliance-extractors, post-commit-audit, supply-chain-security, sast-dast-scanner, cwe-mapper.

## [1.0.1] — 2026-03-29 (retroactively documented)

### Fixed `[defect]`
- Correct Go/Rust capability claims in SKILL.md; added requirements-dev.txt (commit `e2afcf7`).

## [1.0.0] — 2026-03-29 (retroactively documented)

### Added `[structural]`
- Initial release of cwe-mapper skill. Three capabilities: (1) CWE Identification — pattern-match code or vulnerability reports to CWE IDs with confidence scoring; (2) Framework Mapping — map each CWE to entries across 8 frameworks (OWASP Top 10 2021, OWASP LLM Top 10 2025, NIST SP 800-53 Rev. 5, EU AI Act Arts. 15/35/37, ISO 27001:2022, SOC 2 TSC, MITRE ATT&CK, MITRE ATLAS); (3) Compliance Matrix Generation — CWE × framework grid for prioritizing remediation by regulatory exposure. Scripts: `identify-cwes.py`, `map-to-frameworks.py`, `generate-matrix.py`. Reference tables: `cwe-owasp-mapping.md`, `cwe-mitre-mapping.md`, `cwe-regulatory-mapping.md`.
- Self-audit artifacts in `audits/` (SAST/DAST scan, supply-chain audit, cwe-mapping of this skill, LLM compliance report, contribution analysis, AUDIT_SUMMARY.txt, POSTFIX_SUMMARY.txt).

---

## Change-driver workflow

When making a change:

1. **Classify the driver** — one of `[authority]`, `[defect]`, `[structural]`, `[voice]`.
2. **Cite the trigger** — for `[authority]`: name the framework version that changed (e.g., MITRE ATT&CK v17.2). For `[defect]`: describe what was wrong. For `[structural]`/`[voice]`: explain why.
3. **Estimate addendum burden** — would any prior generated `cwe-mapping.md` need addendum filings as a result of this change? cwe-mapper's outputs feed the entire security audit pipeline; even small framework changes here can cascade.

## Audit-artifact provenance

Every generated `cwe-mapping.md` must begin with a provenance block of the form:

```
Generated YYYY-MM-DD by cwe-mapper vX.Y.Z (<skill-git-short-hash>)
Target project: <repo-name> @ <commit-short-hash> on branch <branch-name>
Sources current as of YYYY-MM except where individual sections note otherwise.
CWE List version: 4.16 (2024-11)
Framework versions: OWASP Top 10:2021, OWASP LLM Top 10 v1.1 (2024-10),
                    NIST SP 800-53 Rev. 5 (2020-09 + 5.1.1 2023-12),
                    EU AI Act Arts. 15/35/37 (Reg. (EU) 2024/1689),
                    ISO/IEC 27001:2022, SOC 2 (AICPA TSC 2017+2022),
                    MITRE ATT&CK v17.1, MITRE ATLAS v4.7.0
Skill changelog: https://github.com/justice8096/cwe-mapper/blob/master/CHANGELOG.md
```

## Related framework documentation

- [Skill Versioning and Addendum Framework](https://github.com/justice8096/SecondBrainData/blob/main/SoftwarePractices/Skill-Versioning-and-Addendum-Framework.md) — the cross-skill engineering principle this CHANGELOG implements.
- [Master Task List entry 17](https://github.com/justice8096/SecondBrainData) — **rollout complete**: this is the 8th and final in-scope skill.
- [Orchestrator: post-commit-audit](https://github.com/justice8096/post-commit-audit) — calls this skill as one of three Phase-1 scanners.
- [Sister skills on framework](https://github.com): [dyscalculia-support-skill](https://github.com/justice8096/dyscalculia-support-skill), [dyslexia-support-skill](https://github.com/justice8096/dyslexia-support-skill), [LLMComplianceSkill](https://github.com/justice8096/LLMComplianceSkill), [ai-compliance-extractors](https://github.com/justice8096/ai-compliance-extractors), [post-commit-audit](https://github.com/justice8096/post-commit-audit), [supply-chain-security](https://github.com/justice8096/supply-chain-security), [sast-dast-scanner](https://github.com/justice8096/sast-dast-scanner).
