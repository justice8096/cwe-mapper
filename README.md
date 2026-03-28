# CWE Mapper: Security Vulnerability Classification & Regulatory Mapping

A Claude Code skill for identifying, classifying, and mapping code vulnerabilities to CWE IDs, OWASP categories, and regulatory frameworks.

## Overview

CWE Mapper helps security teams and developers:
- **Identify vulnerabilities** in code using pattern matching and AST analysis
- **Classify findings** to Common Weakness Enumeration (CWE) IDs with confidence scores
- **Map to compliance frameworks** including OWASP, NIST, EU AI Act, ISO 27001, SOC 2, and MITRE ATT&CK
- **Generate compliance matrices** showing regulatory impact of discovered vulnerabilities

## Key Features

- **CWE Top 25 (2024)** detection patterns for the most dangerous software weaknesses
- **Multi-framework mapping**: OWASP Top 10 2021, OWASP LLM Top 10 2025, NIST SP 800-53, EU AI Act, ISO 27001, SOC 2, MITRE ATT&CK/ATLAS
- **Language-specific guidance** for JavaScript/TypeScript, Python, Java, Go, Rust
- **Compliance matrix generation** showing which regulations are affected and which controls apply
- **Pattern-based detection** with line-level evidence and confidence scores

## Usage

### Quick Start

Ask Claude to identify vulnerabilities and map them:

```
Can you identify security issues in this code and map them to CWE IDs
and regulatory frameworks?

[paste code]
```

Or provide a vulnerability report for mapping:

```
I found these CWEs in my codebase: CWE-89, CWE-502, CWE-798.
What are the compliance implications across NIST, ISO 27001, and SOC 2?
```

### Common Triggers

- "What CWE is this vulnerability?"
- "Classify this security finding"
- "Map this bug to regulatory frameworks"
- "Generate a compliance matrix for these findings"
- "Which regulations does CWE-89 affect?"
- "Show me the OWASP/NIST mapping for this weakness"

## Project Structure

```
cwe-mapper/
├── skills/cwe-mapper/
│   ├── SKILL.md                 # Comprehensive skill guide (entry point)
│   ├── references/              # Detailed framework mappings
│   │   ├── cwe-top25-2024.md    # CWE Top 25 with detection patterns
│   │   ├── cwe-owasp-mapping.md # CWE → OWASP mapping
│   │   ├── cwe-mitre-mapping.md # CWE → MITRE ATT&CK/ATLAS
│   │   └── cwe-regulatory-mapping.md # Multi-framework mappings
│   └── scripts/
│       ├── identify-cwes.py      # Pattern-based CWE detection
│       ├── map-to-frameworks.py  # Framework mapping engine
│       └── generate-matrix.py    # Compliance matrix generator
├── evals/
│   └── evals.json               # Test cases and evaluations
└── .claude-plugin/
    └── plugin.json              # Plugin configuration
```

## Reference Files

- **cwe-top25-2024.md**: Detailed guide to MITRE's Top 25 Most Dangerous CWEs with detection patterns
- **cwe-owasp-mapping.md**: Cross-reference between CWE IDs and OWASP Top 10 2021/LLM Top 10
- **cwe-mitre-mapping.md**: MITRE ATT&CK and ATLAS technique mappings
- **cwe-regulatory-mapping.md**: NIST, EU AI Act, ISO 27001, SOC 2 control mappings

## Language Support

- **JavaScript/TypeScript**: DOM XSS, eval() injection, prototype pollution, npm package vulnerabilities
- **Python**: pickle deserialization, subprocess injection, SSTI, Django/Flask specific issues
- **Java**: XXE, JNDI injection, unsafe reflection, deserialization gadgets
- **Go**: goroutine race conditions, unsafe pointer usage, type assertion issues
- **Rust**: unsafe blocks, FFI boundary issues, lifetime violations

## Regulatory Frameworks

### Supported Mappings

1. **OWASP Top 10 2021** (A01-A10)
2. **OWASP LLM Top 10 2025** (LLM01-LLM10)
3. **NIST SP 800-53** (AC, SI, SC, CM controls)
4. **EU AI Act** (Risk Articles 15, 35, 37)
5. **ISO 27001** (Information Security Management)
6. **SOC 2** (Trust Service Criteria)
7. **MITRE ATT&CK** (Tactics and Techniques)
8. **MITRE ATLAS** (AI/ML specific attacks)

## Installation

1. Copy the `cwe-mapper` skill to your Claude skills directory
2. Run Claude Code with `--skills cwe-mapper`
3. Or use within any Claude context that has skill access

## Examples

### Example 1: Identify CWEs in Code

```python
# Vulnerable Python code
import pickle
user_data = request.get_json()
obj = pickle.loads(user_data['data'])
```

Claude identifies: CWE-502 (Deserialization), maps to OWASP A08, NIST SI-10, EU AI Act Art 15

### Example 2: Generate Compliance Matrix

Given findings: CWE-89 (SQL Injection), CWE-862 (Missing Auth), CWE-416 (Use After Free)

Claude generates matrix showing:
- Which OWASP items are affected (A03, A07, etc.)
- Which NIST controls apply (SI-10, AC-6, etc.)
- EU AI Act articles triggered
- SOC 2 criteria impacted

## Author

Justice

## License

MIT License - See LICENSE file for details

## References

- MITRE CWE: https://cwe.mitre.org/
- OWASP Top 10: https://owasp.org/Top10/
- NIST SP 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- EU AI Act: https://ec.europa.eu/commission/presscorner/api/files/document/default/files/document_files/2024/03/COM_2021_573_EN_Act_part1_v2.pdf
