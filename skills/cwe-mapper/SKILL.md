---
name: cwe-mapper
description: >
  This skill should be used when the user asks to identify CWEs in code,
  classify a vulnerability by weakness type, map security findings to
  compliance frameworks, or generate a compliance impact matrix. Trigger
  phrases include: "what CWE is this", "classify this vulnerability",
  "map this finding to OWASP/NIST/ISO/SOC 2", "generate a compliance
  matrix", "which regulations does this affect", "security audit of this
  code", "CWE analysis", "weakness enumeration".
---

# CWE Mapper

A skill for identifying Common Weakness Enumeration (CWE) IDs from source
code or vulnerability reports, mapping findings to eight regulatory and
threat-intelligence frameworks, and generating a compliance impact matrix.

---

## Workflow Overview

```
1. Analyze input        ->  Parse code or vulnerability report
2. Identify CWEs        ->  Pattern match -> CWE ID + confidence score
3. Map to frameworks    ->  CWE -> OWASP / NIST / EU AI Act / ISO / SOC 2 / MITRE
4. Generate matrix      ->  Produce CWE x framework compliance table
```

---

## Capabilities

### 1. CWE Identification

Analyze source code or a written vulnerability description to assign one or
more CWE IDs. For each finding, produce:

| Field | Description |
|-------|-------------|
| `cwe_id` | Numeric CWE identifier (e.g., 89) |
| `name` | Official MITRE name |
| `severity` | Critical / High / Medium / Low |
| `confidence` | High / Medium / Low based on pattern specificity |
| `evidence` | Exact line(s) and surrounding context |
| `remediation` | Concise fix guidance |

Detection targets all 25 entries from CWE Top 25 (2024). See
`references/cwe-top25-2024.md` for the complete list with per-language
detection patterns and remediation notes.

**Language-specific patterns covered:**

- **JavaScript / TypeScript** — DOM XSS via unsafe HTML sinks, dynamic code
  execution patterns, prototype pollution, insecure deserialization gadgets
- **Python** — unsafe deserialization (CWE-502), subprocess injection,
  server-side template injection in common templating libraries,
  unsafe ORM/query construction in web frameworks
- **Java** — XXE via unparsed XML processors, JNDI injection, unsafe
  reflection, known deserialization gadget chains
- **Go** — concurrent map access without synchronization, unchecked interface
  conversions, unsafe pointer operations
- **Rust** — unsafe block misuse at FFI boundaries, lifetime violations in
  unsafe code, type-reinterpretation errors

### 2. Framework Mapping

Map each identified CWE to all applicable entries across eight frameworks.
See `references/cwe-owasp-mapping.md`, `references/cwe-mitre-mapping.md`, and
`references/cwe-regulatory-mapping.md` for the full cross-reference tables.

**Supported frameworks:**

| Framework | Scope |
|-----------|-------|
| OWASP Top 10 2021 | A01-A10 web application risk categories |
| OWASP LLM Top 10 2025 | LLM01-LLM10 AI/LLM-specific risks |
| NIST SP 800-53 Rev. 5 | AC, SI, SC, CM, IA control families |
| EU AI Act (2024) | Articles 15, 35, 37 (risk, documentation, transparency) |
| ISO 27001:2022 | Annex A controls (A5, A6, A8) |
| SOC 2 | Trust Service Criteria CC6, CC7 |
| MITRE ATT&CK | Tactics and techniques for initial access through exfiltration |
| MITRE ATLAS | AI/ML adversarial technique mappings |

### 3. Compliance Matrix Generation

Produce a CWE x framework table that shows, for each finding, which
framework entries are implicated. Use the table to prioritize remediation
by regulatory exposure.

Example matrix structure (abbreviated):

```
| CWE | Name                    | OWASP | NIST   | EU AI Act | ISO 27001 | SOC 2  |
|-----|-------------------------|-------|--------|-----------|-----------|--------|
| 89  | SQL Injection           | A03   | SI-10  | Art. 15   | A8.1      | CC7.1  |
| 502 | Unsafe Deserialization  | A08   | SI-10  | Art. 15   | A8.1      | CC6.1  |
| 798 | Hard-coded Credentials  | A05   | IA-5   | Art. 37   | A5.1      | CC6.1  |
| 306 | Missing Authentication  | A07   | AC-2   | Art. 35   | A6.1      | CC6.1  |
```

---

## Scripts

Three automation scripts are available in `scripts/`. Run them from the repo
root or pipe input via stdin.

### `scripts/identify-cwes.py`

Accepts source code on stdin and outputs a JSON array of findings.

```bash
cat vulnerable.py | python skills/cwe-mapper/scripts/identify-cwes.py
```

Output shape:

```json
[
  {
    "cwe_id": 502,
    "name": "Deserialization of Untrusted Data",
    "severity": "HIGH",
    "confidence": "HIGH",
    "line": 3,
    "evidence": "<redacted for documentation — see script output>",
    "remediation": "Use safe serialization formats; validate and sign data before deserializing."
  }
]
```

### `scripts/map-to-frameworks.py`

Accepts a JSON array of CWE IDs on stdin and outputs framework mappings.

```bash
echo '[89, 502, 798]' | python skills/cwe-mapper/scripts/map-to-frameworks.py
```

### `scripts/generate-matrix.py`

Accepts a JSON findings array (output of `identify-cwes.py`) on stdin and
writes a Markdown compliance matrix to stdout.

```bash
cat findings.json | python skills/cwe-mapper/scripts/generate-matrix.py > compliance-matrix.md
```

Combine all three in a pipeline:

```bash
cat target.py \
  | python skills/cwe-mapper/scripts/identify-cwes.py \
  | tee findings.json \
  | python skills/cwe-mapper/scripts/generate-matrix.py > matrix.md
```

---

## Reference Files

| File | Contents |
|------|----------|
| `references/cwe-top25-2024.md` | Full CWE Top 25 (2024) — severity, OWASP mapping, per-language detection patterns, and remediation guidance |
| `references/cwe-owasp-mapping.md` | CWE -> OWASP Top 10 2021 and OWASP LLM Top 10 2025 cross-reference |
| `references/cwe-mitre-mapping.md` | CWE -> MITRE ATT&CK tactic/technique and MITRE ATLAS technique mappings |
| `references/cwe-regulatory-mapping.md` | CWE -> NIST SP 800-53, EU AI Act, ISO 27001, and SOC 2 detailed control mappings |

---

## Usage Examples

### Identify CWEs in pasted code

```
Analyze the following code for security weaknesses and list CWE IDs
with confidence scores:

[paste code]
```

### Map specific CWEs to frameworks

```
Map CWE-89 and CWE-502 to NIST SP 800-53 controls and ISO 27001 Annex A.
```

### Generate a full compliance matrix

```
Generate a compliance matrix for these findings across OWASP, NIST,
EU AI Act, ISO 27001, and SOC 2: CWE-89, CWE-502, CWE-862, CWE-798.
```

### Ask about regulatory exposure

```
Which EU AI Act articles are triggered by CWE-20 (Improper Input Validation)?
```

### Get remediation guidance

```
How do I fix CWE-502? Show me secure alternatives.
```

---

## Confidence Scoring

Assign confidence based on evidence quality:

| Confidence | Criteria |
|------------|----------|
| High | Exact vulnerable API call with untrusted input confirmed in context |
| Medium | Pattern match present but input trust level is ambiguous |
| Low | Structural indicator only — manual review required to confirm exploitability |

---

## Output Format

Default output for a CWE analysis response:

1. **Summary table** — one row per finding: CWE ID, name, severity, confidence, line
2. **Per-finding detail** — evidence snippet, affected frameworks, remediation
3. **Compliance matrix** — CWE x framework grid if three or more findings
4. **Prioritization note** — highlight Critical/High findings first; note any
   frameworks with multiple triggered controls

---

## Authoritative Sources

- MITRE CWE Database: https://cwe.mitre.org/
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP LLM Top 10 2025: https://genai.owasp.org/
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- EU AI Act: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689
- MITRE ATT&CK: https://attack.mitre.org/
- MITRE ATLAS: https://atlas.mitre.org/

---

**Framework versions**: OWASP Top 10 2021, OWASP LLM Top 10 2025, NIST SP 800-53 Rev. 5,
EU AI Act 2024, ISO 27001:2022, SOC 2 2022, MITRE ATT&CK v15, MITRE ATLAS v4.
