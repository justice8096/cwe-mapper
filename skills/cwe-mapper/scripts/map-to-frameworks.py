#!/usr/bin/env python3
"""
CWE to Framework Mapping Tool
Maps CWE IDs to regulatory frameworks (OWASP, NIST, EU AI Act, ISO 27001, SOC 2).

Usage:
    echo '[89, 502, 798]' | python map-to-frameworks.py
    python map-to-frameworks.py < cwe_list.json

Output: JSON mapping of CWEs to all applicable frameworks
"""

import sys
import json

# CWE Framework Mappings
CWE_MAPPINGS = {
    20: {
        'name': 'Improper Input Validation',
        'severity': 'HIGH',
        'owasp_2021': ['A03'],
        'owasp_llm': ['LLM01', 'LLM05'],
        'nist': ['SI-10', 'CM-6'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC2', 'CC6'],
        'mitre_attack': ['T1548', 'T1140'],
        'mitre_atlas': ['AML.T0031'],
    },
    22: {
        'name': 'Path Traversal',
        'severity': 'HIGH',
        'owasp_2021': ['A01'],
        'owasp_llm': [],
        'nist': ['AC-3'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC2', 'CC5'],
        'mitre_attack': ['T1190', 'T1185'],
        'mitre_atlas': [],
    },
    78: {
        'name': 'OS Command Injection',
        'severity': 'CRITICAL',
        'owasp_2021': ['A03'],
        'owasp_llm': ['LLM02'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1059'],
        'mitre_atlas': ['AML.T0029'],
    },
    79: {
        'name': 'Cross-site Scripting (XSS)',
        'severity': 'HIGH',
        'owasp_2021': ['A03'],
        'owasp_llm': ['LLM02', 'LLM07'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1189', 'T1059'],
        'mitre_atlas': ['AML.T0018'],
    },
    89: {
        'name': 'SQL Injection',
        'severity': 'CRITICAL',
        'owasp_2021': ['A03'],
        'owasp_llm': ['LLM02'],
        'nist': ['SI-10', 'CM-6'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1059', 'T1040'],
        'mitre_atlas': ['AML.T0029'],
    },
    94: {
        'name': 'Code Injection',
        'severity': 'CRITICAL',
        'owasp_2021': ['A03'],
        'owasp_llm': ['LLM01', 'LLM02'],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1059'],
        'mitre_atlas': ['AML.T0029'],
    },
    125: {
        'name': 'Out-of-Bounds Read',
        'severity': 'HIGH',
        'owasp_2021': ['A02'],
        'owasp_llm': [],
        'nist': ['SI-4'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': ['T1185'],
        'mitre_atlas': [],
    },
    190: {
        'name': 'Integer Overflow',
        'severity': 'MEDIUM',
        'owasp_2021': ['A02'],
        'owasp_llm': [],
        'nist': ['SI-4'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    200: {
        'name': 'Information Exposure',
        'severity': 'HIGH',
        'owasp_2021': ['A01', 'A02'],
        'owasp_llm': ['LLM08'],
        'nist': ['AC-4', 'SI-4'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC7'],
        'mitre_attack': ['T1087', 'T1526'],
        'mitre_atlas': ['AML.T0025'],
    },
    250: {
        'name': 'Execution with Unnecessary Privileges',
        'severity': 'HIGH',
        'owasp_2021': ['A05'],
        'owasp_llm': [],
        'nist': ['AC-6'],
        'eu_ai_act': [],
        'iso_27001': ['A8.2'],
        'soc2': ['CC6'],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    269: {
        'name': 'Improper Privilege Management',
        'severity': 'HIGH',
        'owasp_2021': ['A01'],
        'owasp_llm': [],
        'nist': ['AC-6'],
        'eu_ai_act': [],
        'iso_27001': ['A8.2'],
        'soc2': ['CC2'],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    276: {
        'name': 'Incorrect Default Permissions',
        'severity': 'MEDIUM',
        'owasp_2021': ['A05'],
        'owasp_llm': [],
        'nist': ['CM-2', 'CM-6'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    287: {
        'name': 'Improper Authentication',
        'severity': 'CRITICAL',
        'owasp_2021': ['A07'],
        'owasp_llm': ['LLM03'],
        'nist': ['IA-2', 'IA-5'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': ['A9.2'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1110'],
        'mitre_atlas': [],
    },
    306: {
        'name': 'Missing Authentication for Critical Function',
        'severity': 'CRITICAL',
        'owasp_2021': ['A01'],
        'owasp_llm': [],
        'nist': ['AC-2'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1190'],
        'mitre_atlas': [],
    },
    327: {
        'name': 'Use of Broken or Risky Cryptographic Algorithm',
        'severity': 'HIGH',
        'owasp_2021': ['A02', 'A05'],
        'owasp_llm': [],
        'nist': ['SC-13'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.13'],
        'soc2': ['CC9'],
        'mitre_attack': ['T1110', 'T1041'],
        'mitre_atlas': [],
    },
    330: {
        'name': 'Use of Insufficiently Random Values',
        'severity': 'MEDIUM',
        'owasp_2021': ['A02', 'A05'],
        'owasp_llm': [],
        'nist': ['CM-2', 'CM-6'],
        'eu_ai_act': [],
        'iso_27001': ['A8.13'],
        'soc2': [],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    352: {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'severity': 'MEDIUM',
        'owasp_2021': ['A01'],
        'owasp_llm': [],
        'nist': ['SI-10'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': ['T1189'],
        'mitre_atlas': [],
    },
    362: {
        'name': 'Race Condition',
        'severity': 'MEDIUM',
        'owasp_2021': ['A01'],
        'owasp_llm': [],
        'nist': [],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': ['T1134'],
        'mitre_atlas': [],
    },
    416: {
        'name': 'Use After Free',
        'severity': 'CRITICAL',
        'owasp_2021': ['A02'],
        'owasp_llm': [],
        'nist': ['SI-4'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': ['T1055'],
        'mitre_atlas': [],
    },
    434: {
        'name': 'Unrestricted Upload of File with Dangerous Type',
        'severity': 'HIGH',
        'owasp_2021': ['A04'],
        'owasp_llm': [],
        'nist': ['CM-3', 'SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.5'],
        'soc2': ['CC5'],
        'mitre_attack': ['T1189', 'T1547'],
        'mitre_atlas': ['AML.T0018'],
    },
    502: {
        'name': 'Deserialization of Untrusted Data',
        'severity': 'HIGH',
        'owasp_2021': ['A08'],
        'owasp_llm': ['LLM08'],
        'nist': ['SI-7', 'SI-10'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['PI1', 'CC6'],
        'mitre_attack': ['T1059', 'T1550'],
        'mitre_atlas': ['AML.T0020', 'AML.T0029'],
    },
    611: {
        'name': 'Improper Restriction of XML External Entity Reference',
        'severity': 'HIGH',
        'owasp_2021': ['A05', 'A08'],
        'owasp_llm': [],
        'nist': ['SI-10'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    640: {
        'name': 'Weak Password Recovery Mechanism for Forgotten Password',
        'severity': 'MEDIUM',
        'owasp_2021': ['A07'],
        'owasp_llm': [],
        'nist': ['AC-2', 'IA-5'],
        'eu_ai_act': [],
        'iso_27001': [],
        'soc2': [],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
    798: {
        'name': 'Use of Hard-coded Credentials',
        'severity': 'HIGH',
        'owasp_2021': ['A05'],
        'owasp_llm': [],
        'nist': ['IA-5'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.4'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1098', 'T1555'],
        'mitre_atlas': [],
    },
    862: {
        'name': 'Missing Authorization',
        'severity': 'CRITICAL',
        'owasp_2021': ['A01'],
        'owasp_llm': ['LLM03'],
        'nist': ['AC-6', 'AC-2'],
        'eu_ai_act': ['Article 35'],
        'iso_27001': ['A8.3'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1531', 'T1485'],
        'mitre_atlas': [],
    },
    918: {
        'name': 'Server-Side Request Forgery (SSRF)',
        'severity': 'HIGH',
        'owasp_2021': ['A10'],
        'owasp_llm': [],
        'nist': ['SC-7'],
        'eu_ai_act': ['Article 15'],
        'iso_27001': ['A8.1'],
        'soc2': ['CC6'],
        'mitre_attack': ['T1570', 'T1021', 'T1008'],
        'mitre_atlas': [],
    },
    1104: {
        'name': 'Use of Unmaintained Third Party Components',
        'severity': 'HIGH',
        'owasp_2021': ['A06'],
        'owasp_llm': [],
        'nist': ['SI-2'],
        'eu_ai_act': [],
        'iso_27001': ['A8.6'],
        'soc2': ['CC3'],
        'mitre_attack': [],
        'mitre_atlas': [],
    },
}

def map_cwe(cwe_id: int) -> dict:
    """Get framework mappings for a CWE ID."""
    if cwe_id not in CWE_MAPPINGS:
        return {
            'cwe_id': cwe_id,
            'name': 'Unknown CWE',
            'severity': 'UNKNOWN',
            'owasp_2021': [],
            'owasp_llm': [],
            'nist': [],
            'eu_ai_act': [],
            'iso_27001': [],
            'soc2': [],
            'mitre_attack': [],
            'mitre_atlas': [],
        }

    return CWE_MAPPINGS[cwe_id]

def main():
    """Main entry point."""
    MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MB
    try:
        raw_input = sys.stdin.read(MAX_INPUT_BYTES)
        if len(raw_input) == MAX_INPUT_BYTES:
            print("Error: Input exceeds 10 MB maximum", file=sys.stderr)
            sys.exit(1)
        cwe_list = json.loads(raw_input)
    except json.JSONDecodeError as e:
        # CWE-209: Generic error message without exposing internal structure
        print(json.dumps({'error': 'Invalid JSON input'}, indent=2), file=sys.stderr)
        sys.exit(1)

    if not isinstance(cwe_list, list):
        print(json.dumps({'error': 'Invalid request format'}, indent=2), file=sys.stderr)
        sys.exit(1)

    # CWE-20: Validate CWE IDs - must be positive integers within valid range
    # CWE-681: Explicit type validation before conversion
    validated_cwes = []
    for cwe in cwe_list:
        try:
            cwe_id = int(cwe)
        except (TypeError, ValueError):
            print(json.dumps({'error': f'Invalid CWE ID type: expected integer'}, indent=2), file=sys.stderr)
            sys.exit(1)
        if cwe_id < 1 or cwe_id > 99999:
            print(json.dumps({'error': f'CWE ID out of valid range (1-99999)'}, indent=2), file=sys.stderr)
            sys.exit(1)
        validated_cwes.append(cwe_id)

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
            for framework in ['owasp_2021', 'owasp_llm', 'nist', 'eu_ai_act', 'iso_27001', 'soc2', 'mitre_attack', 'mitre_atlas']
        },
    }

    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
