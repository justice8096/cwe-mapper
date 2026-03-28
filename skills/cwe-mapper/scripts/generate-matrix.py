#!/usr/bin/env python3
"""
Compliance Matrix Generator
Generates a compliance impact matrix from CWE findings.

Usage:
    cat findings.json | python generate-matrix.py > compliance-matrix.md
    python generate-matrix.py < findings.json

Input JSON format:
[
  {"cwe_id": 89, "name": "SQL Injection", "severity": "CRITICAL", "count": 2},
  {"cwe_id": 502, "name": "Deserialization", "severity": "HIGH", "count": 1}
]

Output: Markdown table showing regulatory impact
"""

import sys
import json
from collections import defaultdict

CWE_MAPPINGS = {
    20: {
        'name': 'Improper Input Validation',
        'owasp_2021': ['A03'],
        'nist': ['SI-10', 'CM-6'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC2', 'CC6'],
    },
    22: {
        'name': 'Path Traversal',
        'owasp_2021': ['A01'],
        'nist': ['AC-3'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC2', 'CC5'],
    },
    78: {
        'name': 'OS Command Injection',
        'owasp_2021': ['A03'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
    },
    79: {
        'name': 'Cross-site Scripting (XSS)',
        'owasp_2021': ['A03'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
    },
    89: {
        'name': 'SQL Injection',
        'owasp_2021': ['A03'],
        'nist': ['SI-10', 'CM-6'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
    },
    94: {
        'name': 'Code Injection',
        'owasp_2021': ['A03'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
    },
    287: {
        'name': 'Improper Authentication',
        'owasp_2021': ['A07'],
        'nist': ['IA-2', 'IA-5'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': ['A9.2'],
        'soc2': ['CC6'],
    },
    306: {
        'name': 'Missing Authentication for Critical Function',
        'owasp_2021': ['A01'],
        'nist': ['AC-2'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC6'],
    },
    327: {
        'name': 'Broken Cryptography',
        'owasp_2021': ['A02', 'A05'],
        'nist': ['SC-13'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.13'],
        'soc2': ['CC9'],
    },
    352: {
        'name': 'Cross-Site Request Forgery',
        'owasp_2021': ['A01'],
        'nist': ['SI-10'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
    },
    434: {
        'name': 'Unrestricted File Upload',
        'owasp_2021': ['A04'],
        'nist': ['CM-3', 'SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.5'],
        'soc2': ['CC5'],
    },
    502: {
        'name': 'Unsafe Deserialization',
        'owasp_2021': ['A08'],
        'nist': ['SI-7', 'SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['PI1', 'CC6'],
    },
    611: {
        'name': 'XML External Entity (XXE)',
        'owasp_2021': ['A05', 'A08'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': [],
        'soc2': [],
    },
    798: {
        'name': 'Hard-coded Credentials',
        'owasp_2021': ['A05'],
        'nist': ['IA-5'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.4'],
        'soc2': ['CC6'],
    },
    862: {
        'name': 'Missing Authorization',
        'owasp_2021': ['A01'],
        'nist': ['AC-6', 'AC-2'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC6'],
    },
    918: {
        'name': 'Server-Side Request Forgery (SSRF)',
        'owasp_2021': ['A10'],
        'nist': ['SC-7'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
    },
}

def generate_matrix(findings: list) -> str:
    """Generate compliance matrix markdown."""
    output = []
    output.append('# Security Findings Compliance Impact Matrix\n')
    output.append(f'**Generated**: {len(findings)} findings analyzed\n')

    # Summary by severity
    severity_counts = defaultdict(int)
    owasp_items = set()
    nist_controls = set()
    eu_ai_articles = set()
    iso_controls = set()
    soc2_criteria = set()

    for finding in findings:
        cwe_id = finding.get('cwe_id')
        severity = finding.get('severity', 'UNKNOWN')
        count = finding.get('count', 1)

        if cwe_id in CWE_MAPPINGS:
            severity_counts[severity] += count
            mapping = CWE_MAPPINGS[cwe_id]

            owasp_items.update(mapping.get('owasp_2021', []))
            nist_controls.update(mapping.get('nist', []))
            eu_ai_articles.update(mapping.get('eu_ai_act', []))
            iso_controls.update(mapping.get('iso_27001', []))
            soc2_criteria.update(mapping.get('soc2', []))

    output.append('## Summary\n')
    output.append('| Severity | Count |\n')
    output.append('|----------|-------|\n')
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            output.append(f'| {severity} | {count} |\n')

    # Framework impact
    output.append('\n## Regulatory Framework Impact\n')
    output.append(f'- **OWASP Top 10 2021**: {len(owasp_items)} categories affected\n')
    output.append(f'- **NIST SP 800-53**: {len(nist_controls)} controls affected\n')
    output.append(f'- **EU AI Act**: {len(eu_ai_articles)} articles affected\n')
    output.append(f'- **ISO 27001**: {len(iso_controls)} controls affected\n')
    output.append(f'- **SOC 2**: {len(soc2_criteria)} criteria affected\n')

    # Detailed findings
    output.append('\n## Findings by CWE\n')
    for finding in sorted(findings, key=lambda x: x.get('cwe_id', 0)):
        cwe_id = finding.get('cwe_id')
        if cwe_id not in CWE_MAPPINGS:
            continue

        mapping = CWE_MAPPINGS[cwe_id]
        name = mapping['name']
        severity = finding.get('severity', 'UNKNOWN')
        count = finding.get('count', 1)

        output.append(f'\n### CWE-{cwe_id}: {name}\n')
        output.append(f'**Severity**: {severity} | **Instances**: {count}\n\n')

        output.append('**Regulatory Mapping**:\n')
        output.append('| Framework | Controls/Items |\n')
        output.append('|-----------|----------------|\n')

        if mapping.get('owasp_2021'):
            output.append(f"| OWASP 2021 | {', '.join(mapping['owasp_2021'])} |\n")
        if mapping.get('nist'):
            output.append(f"| NIST 800-53 | {', '.join(mapping['nist'])} |\n")
        if mapping.get('eu_ai_act'):
            output.append(f"| EU AI Act | {', '.join(mapping['eu_ai_act'])} |\n")
        if mapping.get('iso_27001'):
            output.append(f"| ISO 27001 | {', '.join(mapping['iso_27001'])} |\n")
        if mapping.get('soc2'):
            output.append(f"| SOC 2 | {', '.join(mapping['soc2'])} |\n")

    # Cross-framework summary
    output.append('\n## Framework Compliance Checklist\n')
    output.append('\n### OWASP Top 10 2021\n')
    output.append('| Item | Affected | Controls |\n')
    output.append('|------|----------|----------|\n')
    for item in sorted(owasp_items):
        output.append(f'| {item} | YES | See findings above |\n')

    output.append('\n### NIST SP 800-53 Controls\n')
    output.append('| Control | Affected | Findings |\n')
    output.append('|---------|----------|----------|\n')
    for control in sorted(nist_controls):
        output.append(f'| {control} | YES | See findings above |\n')

    output.append('\n### EU AI Act Articles\n')
    output.append('| Article | Requirement | Status |\n')
    output.append('|---------|-------------|--------|\n')
    for article in sorted(eu_ai_articles):
        output.append(f'| {article} | Risk Assessment/Documentation | **NON-COMPLIANT** |\n')

    output.append('\n### ISO 27001 Controls\n')
    output.append('| Control | Category | Status |\n')
    output.append('|---------|----------|--------|\n')
    for control in sorted(iso_controls):
        output.append(f'| {control} | Technological | **REQUIRES REMEDIATION** |\n')

    output.append('\n### SOC 2 Criteria\n')
    output.append('| Criteria | Definition | Status |\n')
    output.append('|----------|------------|--------|\n')
    for criteria in sorted(soc2_criteria):
        output.append(f'| {criteria} | See SOC 2 definition | **AT RISK** |\n')

    # Remediation priority
    output.append('\n## Remediation Priority\n')
    output.append('\n1. **Critical CWEs** (Fix Immediately)\n')
    for finding in findings:
        if finding.get('severity') == 'CRITICAL':
            cwe_id = finding.get('cwe_id')
            if cwe_id in CWE_MAPPINGS:
                output.append(f"   - CWE-{cwe_id}: {CWE_MAPPINGS[cwe_id]['name']}\n")

    output.append('\n2. **High CWEs** (Fix This Sprint)\n')
    for finding in findings:
        if finding.get('severity') == 'HIGH':
            cwe_id = finding.get('cwe_id')
            if cwe_id in CWE_MAPPINGS:
                output.append(f"   - CWE-{cwe_id}: {CWE_MAPPINGS[cwe_id]['name']}\n")

    output.append('\n3. **Medium CWEs** (Plan Next Sprint)\n')
    for finding in findings:
        if finding.get('severity') == 'MEDIUM':
            cwe_id = finding.get('cwe_id')
            if cwe_id in CWE_MAPPINGS:
                output.append(f"   - CWE-{cwe_id}: {CWE_MAPPINGS[cwe_id]['name']}\n")

    return ''.join(output)

def main():
    """Main entry point."""
    try:
        findings = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        print('Error: Invalid JSON input')
        return

    if not isinstance(findings, list):
        print('Error: Input must be a JSON array')
        return

    matrix = generate_matrix(findings)
    print(matrix)

if __name__ == '__main__':
    main()
