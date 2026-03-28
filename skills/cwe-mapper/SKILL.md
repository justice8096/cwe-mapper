# CWE Mapper: Vulnerability Classification & Regulatory Mapping

**Author**: Justice
**Version**: 1.0.0
**License**: MIT

## Overview

CWE Mapper is a security vulnerability classification skill that helps developers and security teams:
- Identify vulnerabilities in code using pattern matching
- Classify findings to CWE (Common Weakness Enumeration) IDs with confidence scores
- Map vulnerabilities to OWASP, NIST, EU AI Act, ISO 27001, SOC 2, and MITRE frameworks
- Generate compliance impact matrices showing which regulations are affected

## Skill Triggers

This skill activates on:
- "CWE", "weakness", "vulnerability classification"
- "Map this vulnerability", "What CWE is this?"
- "Compliance matrix", "Which regulations does this affect?"
- "Security finding", "Vulnerability report"
- "Classify this bug", "MITRE mapping"
- Code analysis requests with security focus
- Regulatory compliance questions

## Quick Reference: CWE Top 25 (2024)

The 25 most dangerous software weaknesses to watch for:

| # | CWE | Name | Severity | Detection Pattern | OWASP |
|---|-----|------|----------|------------------|-------|
| 1 | 787 | Out-of-bounds Write | Critical | `memcpy`, `strcpy`, array access `[i]` | A02 |
| 2 | 79 | Cross-site Scripting | High | `innerHTML=`, `eval()`, template injection | A03 |
| 3 | 89 | SQL Injection | Critical | String concat queries, unsanitized params | A03 |
| 4 | 416 | Use After Free | Critical | Pointer/reference after deallocation | A02 |
| 5 | 78 | OS Command Injection | Critical | `exec()`, `system()`, backticks with user input | A03 |
| 6 | 20 | Improper Input Validation | High | Missing input sanitization, no bounds check | Multiple |
| 7 | 125 | Out-of-bounds Read | High | Array/buffer read beyond size | A02 |
| 8 | 22 | Path Traversal | High | `../`, absolute path construction | A01 |
| 9 | 352 | CSRF | Medium | State-changing ops without tokens | A01 |
| 10 | 434 | Unrestricted Upload | High | File upload without type/size checks | A04 |
| 11 | 862 | Missing Authorization | Critical | No authz checks on sensitive operations | A01 |
| 12 | 476 | NULL Pointer Dereference | Medium | Null check missing before access | A02 |
| 13 | 287 | Improper Authentication | Critical | Weak/missing auth mechanisms | A07 |
| 14 | 190 | Integer Overflow | Medium | Integer arithmetic without bounds | A02 |
| 15 | 502 | Deserialization of Untrusted Data | High | `pickle.loads()`, `ObjectInputStream.readObject()` | A08 |
| 16 | 77 | Command Injection | Critical | Unsanitized command construction | A03 |
| 17 | 119 | Buffer Overflow | Critical | Fixed buffers with unbounded input | A02 |
| 18 | 798 | Hard-coded Credentials | High | API keys, passwords in source code | A05 |
| 19 | 918 | Server-Side Request Forgery | High | Unsanitized URL fetching, file:// protocol | A10 |
| 20 | 306 | Missing Authentication | Critical | Public access to critical functions | A01 |
| 21 | 362 | Race Condition | Medium | Concurrent access without synchronization | A02 |
| 22 | 269 | Improper Privilege Management | High | Privilege escalation paths | A01 |
| 23 | 94 | Code Injection | Critical | `eval()`, `exec()`, dynamic compilation | A03 |
| 24 | 863 | Incorrect Authorization | Critical | Authorization logic flaw | A01 |
| 25 | 276 | Incorrect Default Permissions | Medium | Overly permissive default settings | A01 |

## Core Capabilities

### 1. Vulnerability Identification

When you provide code, I analyze it for:
- **Pattern matching**: Regex/AST patterns that indicate weakness
- **Language-specific context**: JavaScript, Python, Java, Go, Rust semantics
- **Evidence collection**: Exact lines and surrounding context
- **Confidence scoring**: High/Medium/Low based on pattern specificity

Example detection:
```python
# Input
import pickle
data = pickle.loads(request.get_json()['obj'])

# Output
{
  "cwe_id": 502,
  "name": "Deserialization of Untrusted Data",
  "severity": "HIGH",
  "confidence": "HIGH",
  "line": 2,
  "evidence": "pickle.loads(request.get_json()...)",
  "remediation": "Use json.loads() or validate/sign serialized data"
}
```

### 2. Framework Mapping

Each CWE maps to multiple regulatory frameworks:

**OWASP Top 10 2021** (A01-A10)
- A01: Broken Access Control
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging/Monitoring Failures
- A10: SSRF

**NIST SP 800-53** (Access Control, System & Comms Protection)
- AC-2: Account Management
- AC-6: Least Privilege
- SI-10: Information System Monitoring
- SC-4: Information Flow Enforcement

**EU AI Act** (Risk Articles)
- Article 15: Risk Assessment & Management
- Article 35: Documentation Requirements
- Article 37: Transparency & Disclosure

**ISO 27001** (Information Security Controls)
- A5.1: Organizational Controls
- A6.1: Access Controls
- A8.1: Cryptography

**SOC 2** (Trust Service Criteria)
- CC6.1: Logical & Physical Access Controls
- CC7.1: System Monitoring

### 3. Compliance Matrix Generation

Given CWEs, I produce a matrix like:

```
Security Findings Impact Matrix
===============================

CWE-89 (SQL Injection)
├─ OWASP: A03 Injection
├─ NIST: SI-10 (Information System Monitoring)
├─ EU AI Act: Article 15 (Risk Management)
├─ ISO 27001: A8.1 (Cryptography/Input Validation)
└─ SOC 2: CC7.1 (System Monitoring)

CWE-502 (Unsafe Deserialization)
├─ OWASP: A08 Data Integrity Failures
├─ NIST: SI-10
├─ EU AI Act: Article 15
├─ ISO 27001: A8.1
└─ SOC 2: CC6.1 (Access Controls)
```

## Language-Specific Detection

### JavaScript/TypeScript
- **DOM XSS**: `innerHTML=`, `eval()`, `Function()` constructor
- **Prototype Pollution**: Object spread with user input, `Object.assign()`
- **npm Vulnerabilities**: Serialization gadgets, dependency injection

### Python
- **Pickle Deserialization**: `pickle.loads()` with untrusted input
- **Subprocess Injection**: Unshelled subprocess calls with user input
- **Template SSTI**: Template rendering with user variables (Jinja2, Mako)
- **Django/Flask**: Unsafe query construction, CORS misconfig

### Java
- **XML XXE**: SAXParser, DocumentBuilder without DTD disabling
- **JNDI Injection**: `InitialContext.lookup()` with user input
- **Unsafe Reflection**: `Class.forName()`, `Method.invoke()`
- **Serialization Gadgets**: Commons-BeanUtils, Commons-Collections chains

### Go
- **Race Conditions**: Concurrent map access, shared channel state
- **Unsafe Pointers**: Direct memory access without synchronization
- **Type Assertion**: Unchecked interface conversions

### Rust
- **Unsafe Blocks**: Memory safety violations in FFI
- **Lifetime Issues**: Use-after-free in unsafe code
- **Type Confusion**: Memory reinterpretation errors

## How I Work

**Step 1: Analysis**
- Parse code or review vulnerability report
- Run pattern matching for each CWE in Top 25
- Collect evidence with line numbers and context

**Step 2: Classification**
- Assign CWE IDs with confidence scores
- Determine severity (Critical/High/Medium/Low)
- Provide remediation guidance

**Step 3: Mapping**
- Correlate each CWE to OWASP categories
- Identify applicable NIST controls
- Check EU AI Act articles
- Map to ISO 27001 and SOC 2 criteria
- Link to MITRE ATT&CK/ATLAS techniques

**Step 4: Reporting**
- Generate compliance matrix
- Show regulatory impact
- Prioritize findings by severity and framework coverage

## Reference Files

See detailed mappings in:
- **`references/cwe-top25-2024.md`**: Full CWE Top 25 with code patterns and remediations
- **`references/cwe-owasp-mapping.md`**: CWE → OWASP 2021 & LLM Top 10 cross-reference
- **`references/cwe-mitre-mapping.md`**: CWE → MITRE ATT&CK / ATLAS technique mappings
- **`references/cwe-regulatory-mapping.md`**: CWE → NIST, EU AI Act, ISO 27001, SOC 2 detailed mappings

## Scripts

Helper scripts for automation:

**`scripts/identify-cwes.py`**
```bash
cat vulnerable.py | python identify-cwes.py
# Outputs: JSON array of {cwe_id, name, severity, line, evidence, confidence}
```

**`scripts/map-to-frameworks.py`**
```bash
echo '[89, 502, 798]' | python map-to-frameworks.py
# Outputs: Mapping to OWASP, NIST, EU AI Act, ISO 27001, SOC 2
```

**`scripts/generate-matrix.py`**
```bash
cat findings.json | python generate-matrix.py > compliance-matrix.md
# Outputs: Markdown compliance impact matrix
```

## Examples

### Example 1: SQL Injection Detection
```java
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```
**Identified**: CWE-89 (SQL Injection) → OWASP A03, NIST SI-10, EU AI Act Article 15

### Example 2: Unsafe Deserialization
```python
import pickle
user_obj = pickle.loads(request.get_json()['data'])
```
**Identified**: CWE-502 → OWASP A08, NIST SI-10, SOC 2 CC6.1

### Example 3: Missing Authentication
```javascript
app.get('/admin/delete', (req, res) => {
  db.delete(req.params.id);
  res.send('Deleted');
});
```
**Identified**: CWE-306, CWE-862 → OWASP A01, A07, NIST AC-2/AC-6

## Next Steps

1. **Analyze your code**: Paste code for automatic CWE detection
2. **Ask about mappings**: "Map CWE-89 to NIST controls"
3. **Generate matrix**: "Create a compliance matrix for these CWEs"
4. **Get remediation**: "How do I fix CWE-502?"
5. **Check frameworks**: "Which EU AI Act articles does this affect?"

## Support & Feedback

For issues, questions, or suggestions about CWE mappings, please refer to:
- MITRE CWE Database: https://cwe.mitre.org/
- OWASP: https://owasp.org/
- NIST: https://csrc.nist.gov/

---

**Last Updated**: 2024
**Framework Versions**: OWASP 2021, NIST SP 800-53 Rev. 5, EU AI Act 2024, ISO 27001:2022, SOC 2 2022
