#!/usr/bin/env python3
"""
CWE Identification Tool
Analyzes source code and identifies potential CWE vulnerabilities.

Usage:
    cat vulnerable.py | python identify-cwes.py
    python identify-cwes.py < code.java

Output: JSON array of {cwe_id, name, severity, line, evidence, confidence}
"""

import sys
import re
import json
from collections import defaultdict

# CWE Detection Patterns
CWE_PATTERNS = {
    787: {
        'name': 'Out-of-Bounds Write',
        'severity': 'CRITICAL',
        'patterns': [
            r'\b(memcpy|strcpy|strcat|memmove)\s*\([^)]*\)',
            r'\[[^\]]*\]\s*=\s*[^;]*;',  # Array write without bounds
        ],
        'languages': ['c', 'cpp', 'java', 'javascript'],
    },
    79: {
        'name': 'Cross-site Scripting (XSS)',
        'severity': 'HIGH',
        'patterns': [
            r'innerHTML\s*=',
            r'dangerouslySetInnerHTML',
            r'\beval\s*\(',
            r'\bFunction\s*\(',
            r'template\s*\$\{',
            # CWE-1333: Bounded quantifiers to prevent ReDoS
            r'f["\'][^"\']{0,200}\$\{[^}]{0,100}user[^}]{0,100}\}',
        ],
        'languages': ['javascript', 'typescript', 'html', 'python'],
    },
    89: {
        'name': 'SQL Injection',
        'severity': 'CRITICAL',
        'patterns': [
            # CWE-1333: Use bounded quantifiers instead of unbounded .*
            r'"SELECT[^"]{0,200}"\s*\+\s*[a-zA-Z_]',
            r"'SELECT[^']{0,200}'\s*\+\s*[a-zA-Z_]",
            r'f"SELECT[^"]{0,200}\{',
            r"f'SELECT[^']{0,200}\{",
            r'query\s*=\s*f["\']SELECT[^"\']{0,200}\{',
            r'string\.format\s*\(\s*["\']SELECT[^"\']{0,200}["\']',
        ],
        'languages': ['java', 'python', 'php', 'javascript', 'ruby'],
    },
    416: {
        'name': 'Use After Free',
        'severity': 'CRITICAL',
        'patterns': [
            r'free\s*\(\s*\w+\s*\).*\w+->',
            r'delete\s+\w+\s*;.*\w+->',
            r'drop\s*\(.*\).*use of .* after move',
        ],
        'languages': ['c', 'cpp', 'rust'],
    },
    78: {
        'name': 'OS Command Injection',
        'severity': 'CRITICAL',
        'patterns': [
            # CWE-1333: Bounded quantifiers
            r'os\.system\s*\(["\'][^"\']{0,200}\{',
            r'exec\s*\(["\'][^"\']{0,200}\{',
            r'`[^`]{0,200}\$\{[^}]{0,200}\}`',
            r'subprocess\.call\s*\([^,]+\s*\+',
            r'system\s*\(["\'][^"\']{0,200}\{',
        ],
        'languages': ['python', 'javascript', 'php', 'ruby', 'java'],
    },
    20: {
        'name': 'Improper Input Validation',
        'severity': 'HIGH',
        'patterns': [
            r'request\.(args|form|json)\[',
            r'req\.(params|query|body)\.',
            r'argv\[',
            r'sys\.argv\[',
            r'process\.argv\[',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    125: {
        'name': 'Out-of-Bounds Read',
        'severity': 'HIGH',
        'patterns': [
            r'\[[^\]]*\]\s*without bounds check',
            r'for\s*\(\s*[^;]+<=[^;]+\.length',
            r'memcpy.*\w+.*\w+_len',
        ],
        'languages': ['c', 'cpp', 'javascript'],
    },
    22: {
        'name': 'Path Traversal',
        'severity': 'HIGH',
        'patterns': [
            r'\.\./|\.\.\\\\',
            r"request\.(args|form|json)\['(file|path|dir|filename)'\]",
            r'open\s*\(\s*["\']["\'].*\{',
            r'Path\s*\(\s*[a-zA-Z_]+',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    352: {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'severity': 'MEDIUM',
        'patterns': [
            r'POST|PUT|DELETE.*without.*token|csrf',
            r'form\s+method=["\']post["\'].*(?!csrf)',
            r"fetch\s*\(\s*[^,]+\s*,\s*\{\s*method\s*:\s*[\"'](POST|PUT|DELETE)",
        ],
        'languages': ['javascript', 'html', 'python'],
    },
    434: {
        'name': 'Unrestricted Upload of File with Dangerous Type',
        'severity': 'HIGH',
        'patterns': [
            r'request\.files\[',
            r'\.filename',
            r'\.save\s*\(',
            r'upload.*\.(exe|php|jsp|asp)',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    502: {
        'name': 'Deserialization of Untrusted Data',
        'severity': 'HIGH',
        'patterns': [
            r'pickle\.loads\s*\(',
            r'ObjectInputStream\.readObject\s*\(',
            r'JSON\.parse.*eval',
            r'fromJSON\s*\(',
            r'XMLDecoder',
        ],
        'languages': ['python', 'java', 'javascript'],
    },
    862: {
        'name': 'Missing Authorization',
        'severity': 'CRITICAL',
        'patterns': [
            r'@(app|api|router)\.route.*(?!@require_role|@require_permission)',
            r'def\s+(edit|delete|update|admin|destroy)\s*\([^)]*\):\s*(?!.*authz|.*permission)',
            r'if\s+is_authenticated.*(?!.*is_admin|.*permission)',
        ],
        'languages': ['python', 'javascript', 'java'],
    },
    798: {
        'name': 'Use of Hard-coded Credentials',
        'severity': 'HIGH',
        'patterns': [
            r'password\s*=\s*["\'][^"\']*["\']',
            r'api_?key\s*=\s*["\'][sk_|pk_|secret_]',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\']sk_',
        ],
        'languages': ['python', 'javascript', 'java', 'go', 'rust'],
    },
    918: {
        'name': 'Server-Side Request Forgery (SSRF)',
        'severity': 'HIGH',
        'patterns': [
            r'requests\.get\s*\(\s*[a-zA-Z_]+',
            r'urllib\.open\s*\(\s*[a-zA-Z_]+',
            r'fetch\s*\(\s*[a-zA-Z_]+',
            r'file://|gopher://',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    306: {
        'name': 'Missing Authentication for Critical Function',
        'severity': 'CRITICAL',
        'patterns': [
            r'@(app|api)\.route\s*\(["\'].*["\'].*\)(?!@login_required|@auth)',
            r'def\s+(admin|delete|process_payment)\s*\([^)]*\):\s*(?!@login_required)',
        ],
        'languages': ['python', 'javascript', 'java'],
    },
    287: {
        'name': 'Improper Authentication',
        'severity': 'CRITICAL',
        'patterns': [
            r'if\s+(username|user)\s*==\s*["\']',
            r'password\s*==\s*user_password',
            r'hardcoded.*password|api.?key',
            r'if\s+(username|user)\s*==\s*["\'][^"\']*["\']',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    94: {
        'name': 'Code Injection',
        'severity': 'CRITICAL',
        'patterns': [
            # CWE-1333: Bounded quantifiers
            r'\beval\s*\(["\'][^"\']{0,200}\{',
            r'\bexec\s*\(["\'][^"\']{0,200}\{',
            r'compile\s*\(["\'][^"\']{0,200}\{',
            r'Function\s*\(["\'][^"\']{0,200}["\']\s*,\s*["\'][^"\']{0,200}\{',
        ],
        'languages': ['python', 'javascript', 'java', 'php'],
    },
    611: {
        'name': 'Improper Restriction of XML External Entity Reference',
        'severity': 'HIGH',
        'patterns': [
            r'XMLParser|SAXParser|DocumentBuilder',
            r'DTD|ENTITY|SYSTEM',
            r'XXE|xml.*entity',
        ],
        'languages': ['java', 'python', 'php', 'ruby'],
    },
}

def detect_language(code: str) -> str:
    """Detect programming language from code patterns."""
    if 'import java' in code or 'public class' in code:
        return 'java'
    elif 'import ' in code or 'def ' in code or 'from ' in code:
        return 'python'
    elif 'require(' in code or 'const ' in code or 'function ' in code:
        return 'javascript'
    elif '<?php' in code:
        return 'php'
    elif '<html' in code or '<!DOCTYPE' in code:
        return 'html'
    else:
        return 'unknown'

def find_cwe_matches(code: str, language: str) -> list:
    """Find CWE matches in code."""
    matches = []
    lines = code.split('\n')

    for cwe_id, cwe_info in CWE_PATTERNS.items():
        # Skip if language not supported
        if language not in cwe_info.get('languages', []) and language != 'unknown':
            continue

        for pattern in cwe_info.get('patterns', []):
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for line_num, line in enumerate(lines, 1):
                    match = regex.search(line)
                    if match:
                        matches.append({
                            'cwe_id': cwe_id,
                            'name': cwe_info['name'],
                            'severity': cwe_info['severity'],
                            'line': line_num,
                            'evidence': match.group(0).strip(),
                            'confidence': 'MEDIUM' if len(match.group(0)) > 20 else 'HIGH',
                        })
            except re.error:
                continue

    return matches

def main():
    """Main entry point."""
    code = sys.stdin.read()

    if not code.strip():
        print(json.dumps([], indent=2))
        return

    language = detect_language(code)
    matches = find_cwe_matches(code, language)

    # Deduplicate and sort by line number
    seen = set()
    unique_matches = []
    for match in sorted(matches, key=lambda x: x['line']):
        key = (match['cwe_id'], match['line'])
        if key not in seen:
            seen.add(key)
            unique_matches.append(match)

    print(json.dumps(unique_matches, indent=2))

if __name__ == '__main__':
    main()
