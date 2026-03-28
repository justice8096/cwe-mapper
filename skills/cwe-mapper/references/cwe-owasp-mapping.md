# CWE to OWASP Mapping Reference

Cross-reference between MITRE CWE IDs and OWASP Top 10 2021 / OWASP LLM Top 10 2025.

## OWASP Top 10 2021 (A01-A10)

### A01: Broken Access Control

**Definition**: Failures related to access control, authentication, and authorization.

**Mapped CWEs**:
- **CWE-22** (Path Traversal): Direct file access bypass
- **CWE-285** (Improper Authorization): Authorization logic errors
- **CWE-287** (Improper Authentication): Weak authentication
- **CWE-306** (Missing Authentication for Critical Function): Public access to sensitive operations
- **CWE-352** (Cross-Site Request Forgery): State-changing requests without validation
- **CWE-362** (Race Condition): Concurrent access leading to privilege escalation
- **CWE-476** (NULL Pointer Dereference): Crashes enabling access bypass
- **CWE-639** (Authorization Bypass): IDOR, privilege escalation
- **CWE-862** (Missing Authorization): No permission checks
- **CWE-863** (Incorrect Authorization): Authorization logic flaws
- **CWE-1275** (Sensitive Cookie with Improper SameSite Attribute): CSRF enablement

**Remediation Focus**:
- Implement role-based access control (RBAC)
- Validate user permissions on every protected operation
- Use anti-CSRF tokens
- Implement proper authentication (MFA where possible)
- Log and monitor authorization failures

---

### A02: Cryptographic Failures

**Definition**: Exposure of sensitive data due to failures in cryptography.

**Mapped CWEs**:
- **CWE-125** (Out-of-bounds Read): Information disclosure
- **CWE-190** (Integer Overflow): Data corruption
- **CWE-327** (Use of a Broken or Risky Cryptographic Algorithm): Weak crypto
- **CWE-331** (Insufficient Entropy): Predictable random values
- **CWE-338** (Use of Cryptographically Weak Pseudo-Random Number Generator): PRNG failures
- **CWE-347** (Improper Verification of Cryptographic Signature): Signature validation bypass
- **CWE-416** (Use After Free): Memory corruption
- **CWE-502** (Deserialization of Untrusted Data): Object gadget chains
- **CWE-613** (Insufficient Session Expiration): Session hijacking
- **CWE-787** (Out-of-bounds Write): Memory corruption
- **CWE-798** (Use of Hard-coded Credentials): Exposed secrets
- **CWE-1025** (Comparison Using Wrong Factors): Auth bypass

**Remediation Focus**:
- Use strong encryption (AES-256, ChaCha20)
- Implement proper key management
- Use secure random number generators
- Hash passwords with bcrypt/Argon2
- Protect sensitive data in transit and at rest
- Implement session timeouts

---

### A03: Injection

**Definition**: Untrusted data passed to interpreters (SQL, OS, LDAP, template engines).

**Mapped CWEs**:
- **CWE-20** (Improper Input Validation): Foundation for injection
- **CWE-74** (Improper Neutralization of Special Elements): Input sanitization
- **CWE-77** (Command Injection): OS command execution
- **CWE-78** (OS Command Injection): system(), exec() bypass
- **CWE-79** (Cross-site Scripting): HTML/JS injection
- **CWE-88** (Improper Neutralization of Argument Delimiters): Command injection
- **CWE-89** (SQL Injection): SQL query manipulation
- **CWE-90** (Improper Neutralization of Special Elements used in an LDAP Query): LDAP injection
- **CWE-91** (XML Injection): XML query manipulation
- **CWE-94** (Code Injection): Dynamic code execution
- **CWE-95** (Improper Neutralization of Directives in Dynamically Evaluated Code): Template/eval injection
- **CWE-113** (Improper Neutralization of CRLF Sequences in HTTP Headers): HTTP injection
- **CWE-117** (Improper Output Neutralization for Logs): Log injection
- **CWE-643** (Improper Neutralization in Data Serialization): Serialization injection

**Remediation Focus**:
- Use parameterized queries (prepared statements)
- Escape output for context (HTML, URL, JS, CSS, SQL)
- Input validation whitelist, not blacklist
- Use template engines with auto-escaping
- Avoid eval(), exec(), system() with user input
- Use security-focused libraries (ORM, template engines)

---

### A04: Insecure Design

**Definition**: Missing or ineffective control design preventing known attacks.

**Mapped CWEs**:
- **CWE-434** (Unrestricted Upload of File with Dangerous Type): File upload vulnerabilities
- **CWE-444** (Inconsistent Interpretation of HTTP Requests): Request smuggling
- **CWE-656** (Reliance on Security Through Obscurity): No real security mechanisms
- **CWE-862** (Missing Authorization): No design for access control
- **CWE-1021** (Improper Restriction of Rendered UI Layers or Frames): Clickjacking
- **CWE-1104** (Use of Unmaintained Third Party Components): Dependency risks

**Remediation Focus**:
- Threat modeling during design phase
- Security requirements documentation
- Attack surface analysis
- Secure SDLC practices
- Regular architectural reviews
- Defense in depth

---

### A05: Security Misconfiguration

**Definition**: Missing or incorrect security-related configuration.

**Mapped CWEs**:
- **CWE-16** (Configuration): Broad misconfiguration
- **CWE-250** (Execution with Unnecessary Privileges): Running as admin/root
- **CWE-276** (Incorrect Default Permissions): Overly permissive defaults
- **CWE-327** (Use of a Broken or Risky Cryptographic Algorithm): Weak algorithms enabled
- **CWE-330** (Use of Insufficiently Random Values): Default weak PRNG
- **CWE-434** (Unrestricted Upload): Missing file type checks
- **CWE-1104** (Use of Unmaintained Third Party Components): Outdated libraries

**Remediation Focus**:
- Minimal viable configuration
- Security headers (CSP, HSTS, etc.)
- Disable unnecessary services/features
- Strong default settings
- Regular security audits
- Automated config scanning

---

### A06: Vulnerable and Outdated Components

**Definition**: Using libraries, frameworks with known vulnerabilities.

**Mapped CWEs**:
- **CWE-1035** (Invocation of Unintended Interpreter): Component version issues
- **CWE-1104** (Use of Unmaintained Third Party Components): Outdated dependencies

**Remediation Focus**:
- Keep all dependencies updated
- Use software composition analysis (SCA)
- Monitor CVE feeds
- Regular vulnerability scanning
- Have update policies
- Use minimal dependencies

---

### A07: Authentication Failures

**Definition**: Weak or missing authentication mechanisms.

**Mapped CWEs**:
- **CWE-287** (Improper Authentication): Weak auth schemes
- **CWE-297** (Improper Validation of Certificate with Host Mismatch): TLS/SSL bypass
- **CWE-640** (Weak Password Recovery Mechanism for Forgotten Password): Account recovery issues
- **CWE-798** (Use of Hard-coded Credentials): Exposed authentication data
- **CWE-940** (Improper Verification of Source of a Communication Channel): Channel validation

**Remediation Focus**:
- Implement strong authentication (MFA, passwordless)
- Use industry-standard protocols (OAuth 2.0, OpenID Connect)
- Enforce strong password policies
- Implement account lockout mechanisms
- Secure password reset flows
- Use secure session management

---

### A08: Data Integrity Failures

**Definition**: Failures in maintaining data integrity during processing.

**Mapped CWEs**:
- **CWE-347** (Improper Verification of Cryptographic Signature): Signature bypass
- **CWE-502** (Deserialization of Untrusted Data): Object injection
- **CWE-611** (Improper Restriction of XML External Entity Reference): XXE attacks

**Remediation Focus**:
- Use HMAC/signatures for sensitive data
- Validate all inputs before deserialization
- Disable XML external entities
- Use secure serialization (JSON > Pickle > XML)
- Implement integrity checks
- Sign critical data

---

### A09: Logging and Monitoring Failures

**Definition**: Insufficient logging, monitoring, and incident response.

**Mapped CWEs**:
- **CWE-117** (Improper Output Neutralization for Logs): Log injection
- **CWE-778** (Insufficient Logging): Missing audit trails
- **CWE-1021** (Improper Restriction of Rendered UI Layers): Undetectable attacks

**Remediation Focus**:
- Log all security-relevant events
- Use centralized logging
- Implement alerting for suspicious activity
- Secure log storage
- Regular log review
- Incident response procedures

---

### A10: Server-Side Request Forgery (SSRF)

**Definition**: Unvalidated URL fetching allowing attacker to access internal resources.

**Mapped CWEs**:
- **CWE-20** (Improper Input Validation): URL validation missing
- **CWE-22** (Path Traversal): File protocol access
- **CWE-918** (Server-Side Request Forgery): Direct SSRF

**Remediation Focus**:
- Whitelist allowed URLs/hosts
- Block internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
- Disable dangerous protocols (file://, gopher://)
- Use security libraries for URL parsing
- Network segmentation
- Implement egress filtering

---

## OWASP LLM Top 10 2025 (LLM01-LLM10)

### LLM01: Prompt Injection

**Definition**: Direct/indirect injection of prompts causing unintended behavior.

**Mapped CWEs**:
- **CWE-20** (Improper Input Validation)
- **CWE-94** (Code Injection)
- **CWE-1336** (Improper Neutralization of Special Elements Used in a Template Engine)

---

### LLM02: Unsafe Plugin Execution

**Definition**: LLM plugins accepting unvalidated input causing execution of unintended code.

**Mapped CWEs**:
- **CWE-94** (Code Injection)
- **CWE-78** (OS Command Injection)
- **CWE-89** (SQL Injection)

---

### LLM03: Inadequate Authorization in Plugins

**Definition**: Plugins with insufficient authorization checks.

**Mapped CWEs**:
- **CWE-862** (Missing Authorization)
- **CWE-863** (Incorrect Authorization)

---

### LLM04: QUAD (Quantization-induced Accuracy Degradation)

**Definition**: Model quantization reducing safety properties.

**Mapped CWEs**:
- **CWE-485** (Insufficient Encapsulation)
- **CWE-693** (Protection Mechanism Failure)

---

### LLM05: Overreliance on LLM Output

**Definition**: Using LLM output without validation in security-critical contexts.

**Mapped CWEs**:
- **CWE-20** (Improper Input Validation)
- **CWE-358** (Improperly Restricted Operations on Dynamically Identified Objects)

---

### LLM06: Inadequate AI Alignment

**Definition**: LLM behavior misaligned with intended objectives.

**Mapped CWEs**:
- **CWE-693** (Protection Mechanism Failure)
- **CWE-1021** (Improper Restriction of Rendered UI Layers)

---

### LLM07: Insecure Output Handling

**Definition**: Downstream systems processing LLM output insecurely.

**Mapped CWEs**:
- **CWE-79** (Cross-site Scripting)
- **CWE-95** (Improper Neutralization in Dynamically Evaluated Code)

---

### LLM08: Vector Database Poisoning

**Definition**: Malicious data in vector databases affecting LLM behavior.

**Mapped CWEs**:
- **CWE-502** (Deserialization of Untrusted Data)
- **CWE-943** (Improper Neutralization of Special Elements in Data Query Logic)

---

### LLM09: Improper Error Handling

**Definition**: Leaking sensitive information through error messages.

**Mapped CWEs**:
- **CWE-209** (Information Exposure Through an Error Message)
- **CWE-388** (Error Handling with Incomplete Cleanup)

---

### LLM10: Training Data Poisoning

**Definition**: Malicious/biased training data causing vulnerabilities.

**Mapped CWEs**:
- **CWE-400** (Uncontrolled Resource Consumption)
- **CWE-838** (Inappropriate Encoding or Escaping)

---

## Quick Reference Matrix

| OWASP A# | Primary CWEs | Count |
|----------|-------------|-------|
| A01 | 22, 285, 287, 306, 352, 639, 862, 863 | 8 |
| A02 | 125, 190, 327, 331, 416, 502, 613, 787, 798 | 9 |
| A03 | 20, 77, 78, 79, 88, 89, 90, 91, 94 | 9 |
| A04 | 434, 444, 656, 1021, 1104 | 5 |
| A05 | 16, 250, 276, 327, 330 | 5 |
| A06 | 1035, 1104 | 2 |
| A07 | 287, 297, 640, 798 | 4 |
| A08 | 347, 502, 611 | 3 |
| A09 | 117, 778 | 2 |
| A10 | 20, 22, 918 | 3 |

---

**Last Updated**: 2024
**Framework Versions**: OWASP 2021, OWASP LLM 2025
