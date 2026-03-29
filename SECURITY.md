# Security Policy

## Reporting Vulnerabilities

To report a security vulnerability in this project, please **do not open a
public GitHub issue**. Instead, email the maintainer directly or use GitHub's
private vulnerability reporting feature (Security > Advisories > Report a
vulnerability) on the repository page.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation if known

Expect an acknowledgement within 72 hours and a resolution timeline within
14 days for confirmed issues.

## Scope

This project consists of:
- **Python scripts** (`skills/cwe-mapper/scripts/`) — CWE pattern matching,
  framework mapping, and compliance matrix generation
- **Markdown reference files** (`skills/cwe-mapper/references/`) — static
  mapping tables with no executable components
- **Documentation** — README, SKILL.md, and audit files

There are **no web components, no servers, no network listeners, and no
user-facing web interfaces** in this project. All scripts are intended to run
locally in a trusted environment or within a Claude Code skill context.

## Known Limitations

The following limitations are inherent to the design of this tool and should
be understood before relying on its output for compliance decisions:

1. **False positives and false negatives in pattern matching** — The CWE
   identification scripts use static pattern matching. They may flag code
   that is not actually vulnerable (false positives) or miss vulnerabilities
   that require deeper semantic or dataflow analysis (false negatives). All
   findings should be verified by a qualified security professional.

2. **Framework mappings are approximate** — The mappings between CWEs and
   regulatory frameworks (OWASP, NIST, EU AI Act, ISO 27001, SOC 2, MITRE)
   represent a best-effort interpretation. Framework requirements are complex,
   context-dependent, and subject to interpretation. **Compliance determinations
   must be reviewed by a qualified security or compliance professional** before
   being used in an official audit, assessment, or regulatory filing.

3. **CWE database is a snapshot** — The CWE Top 25 list and associated
   metadata bundled in this repository reflect the 2024 release. The MITRE
   CWE database is updated periodically; new weaknesses may be added, rankings
   may change, and descriptions may be revised. This tool may not reflect the
   latest revisions. Always cross-reference findings against the current
   authoritative source at https://cwe.mitre.org/.

4. **No runtime or dynamic analysis** — This tool performs static analysis
   only. Vulnerabilities that manifest only at runtime, through specific
   environmental conditions, or through interactions between components may
   not be detected.

## Dependencies

- **Python 3.x only** — No third-party runtime dependencies are required for
  the core scripts. The scripts use only the Python standard library.
- The CI lint workflow uses `flake8` as a development dependency only; it is
  not required to run the skill.

## Out of Scope

The following are outside the threat model for this project and will not be
addressed as security vulnerabilities:

- Vulnerabilities in the target code being analyzed (by definition, the tool
  is designed to find these, not fix them)
- Accuracy disputes about specific CWE-to-framework mappings (file a regular
  issue for mapping corrections)
- Markdown rendering issues in third-party viewers
