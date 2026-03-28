# CWE to Regulatory Framework Mapping Reference

Comprehensive cross-reference between CWE IDs and regulatory/compliance frameworks including NIST SP 800-53, EU AI Act, ISO 27001, and SOC 2.

## NIST SP 800-53 Revision 5 Mapping

NIST SP 800-53 defines security controls across 14 families. Below are CWE mappings by control family.

### AC: Access Control (AC-1 through AC-8)

**AC-2: Account Management**
- Prevents unauthorized account creation/modification
- Related CWEs: 287 (Auth), 306 (Missing Auth), 640 (Weak Password Recovery)

**AC-3: Access Enforcement**
- Enforces policy to control access to resources
- Related CWEs: 22 (Path Traversal), 285 (Improper AuthZ), 639 (AuthZ Bypass), 862 (Missing AuthZ), 863 (Incorrect AuthZ)

**AC-4: Information Flow Enforcement**
- Prevents unauthorized information flow between security domains
- Related CWEs: 200 (Info Exposure), 639 (AuthZ Bypass)

**AC-5: Separation of Duties**
- Separates duties among individuals to prevent abuse of power
- Related CWEs: 862 (Missing AuthZ), 863 (Incorrect AuthZ)

**AC-6: Least Privilege**
- Restricts privileges to minimum necessary for role
- Related CWEs: 250 (Unnecessary Privileges), 269 (Improper Privilege Management), 862 (Missing AuthZ)

**AC-7: Unsuccessful Login Attempts**
- Enforces account lockout after failed login attempts
- Related CWEs: 287 (Improper Auth), 640 (Weak Password Recovery)

---

### AT: Awareness and Training

**AT-1: Awareness and Training Policy**
- Establishes security awareness program
- Related CWEs: 434 (Unrestricted Upload), 656 (Security Through Obscurity)

---

### AU: Audit and Accountability

**AU-2: Audit Events**
- Determines auditable events and logging requirements
- Related CWEs: 117 (Log Injection), 778 (Insufficient Logging)

**AU-3: Content of Audit Records**
- Ensures audit records contain sufficient information
- Related CWEs: 209 (Error Message Info Exposure), 778 (Insufficient Logging)

**AU-4: Audit Storage Capacity**
- Allocates sufficient audit log storage
- Related CWEs: 770 (Allocation Without Limits)

**AU-12: Audit Generation**
- Ensures events are logged for use in accountability
- Related CWEs: 778 (Insufficient Logging)

---

### CA: Security Assessment and Authorization

**CA-8: Penetration Testing**
- Conducts penetration tests to assess vulnerabilities
- Related CWEs: All CWEs in scope (validation mechanism)

---

### CM: Configuration Management

**CM-2: Baseline Configuration**
- Establishes secure baseline configuration
- Related CWEs: 16 (Configuration), 276 (Incorrect Default Permissions), 330 (Insufficient Randomness)

**CM-3: Configuration Change Control**
- Controls changes to baseline configuration
- Related CWEs: 434 (Unrestricted Upload), 656 (Security Through Obscurity)

**CM-5: Access Restrictions for Change**
- Restricts changes to authorized personnel
- Related CWEs: 862 (Missing AuthZ), 863 (Incorrect AuthZ)

**CM-6: Security Configuration Settings**
- Establishes secure configuration standards
- Related CWEs: 16 (Configuration), 250 (Unnecessary Privileges), 327 (Broken Crypto)

---

### IA: Identification and Authentication

**IA-2: Authentication**
- Authenticates users/devices before granting access
- Related CWEs: 287 (Improper Auth), 297 (Certificate Validation), 640 (Weak Password Recovery), 798 (Hard-coded Credentials)

**IA-3: Device Identification and Authentication**
- Authenticates devices before network connection
- Related CWEs: 287 (Improper Auth), 297 (Certificate Validation)

**IA-4: Identifier Management**
- Manages user identifiers to prevent unauthorized usage
- Related CWEs: 287 (Improper Auth), 306 (Missing Auth)

**IA-5: Authenticator Management**
- Manages authentication credentials securely
- Related CWEs: 327 (Broken Crypto), 330 (Insufficient Randomness), 640 (Weak Password Recovery), 798 (Hard-coded Credentials)

---

### SA: System and Services Acquisition

**SA-3: System Development Life Cycle**
- Ensures secure SDLC practices
- Related CWEs: 434 (Unrestricted Upload), 656 (Security Through Obscurity)

**SA-11: Developer Security Testing**
- Requires developers to conduct security testing
- Related CWEs: All CWEs (validation mechanism)

---

### SC: System and Communications Protection

**SC-4: Information Flow Enforcement**
- Enforces information flow policies (duplicate of AC-4)
- Related CWEs: 200 (Info Exposure)

**SC-7: Boundary Protection**
- Manages information flows at system boundaries
- Related CWEs: 918 (SSRF), 1021 (Clickjacking)

**SC-13: Cryptographic Protection**
- Protects information in transit and at rest
- Related CWEs: 327 (Broken Crypto), 331 (Insufficient Entropy), 338 (Weak PRNG)

---

### SI: System and Information Integrity

**SI-2: Flaw Remediation**
- Identifies, reports, and corrects security flaws
- Related CWEs: 1104 (Outdated Components)

**SI-3: Malicious Code Protection**
- Protects against malicious code
- Related CWEs: 434 (Unrestricted Upload), 502 (Deserialization), 656 (Security Through Obscurity)

**SI-4: Information System Monitoring**
- Monitors for attacks/intrusions
- Related CWEs: 117 (Log Injection), 778 (Insufficient Logging)

**SI-7: Software, Firmware, and Information Integrity**
- Monitors/maintains integrity of software and data
- Related CWEs: 347 (Signature Validation), 502 (Deserialization), 611 (XXE)

**SI-10: Information System Monitoring (Duplicate)**
- Monitors unusual activity
- Related CWEs: 20 (Input Validation), 77 (Command Injection), 78 (OS Command Injection), 79 (XSS), 89 (SQL Injection), 94 (Code Injection), 125 (OOB Read), 200 (Info Exposure)

---

## EU AI Act Mapping

The EU AI Act (2024) introduces risk-based regulation for AI systems. Key articles relevant to CWE mappings:

### Article 15: Risk Assessment and Management

**Requirement**: High-risk AI systems must conduct risk assessments.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Incomplete risk assessment
- **CWE-200** (Information Exposure): Risk identification gap
- **CWE-434** (Unrestricted Upload): Training data risk
- **CWE-502** (Deserialization): Model integrity risk
- **CWE-79** (XSS): Model output safety
- **CWE-89** (SQL Injection): Training data access
- **CWE-94** (Code Injection): Model behavior injection

**Compliance Implication**: Must document identified risks for AI system development.

---

### Article 28: Documentation

**Requirement**: Maintain documentation of design, development, and training processes.

**Related CWEs**:
- **CWE-16** (Configuration): Configuration documentation missing
- **CWE-656** (Security Through Obscurity): Insufficient documentation
- **CWE-1104** (Outdated Components): Dependency documentation

**Compliance Implication**: CWEs indicate documentation gaps that violate Article 28.

---

### Article 35: Testing, Validation, and Verification

**Requirement**: High-risk systems require testing/validation before deployment.

**Related CWEs**:
- **CWE-20** (Input Validation): Testing inadequacy
- **CWE-434** (File Upload): Validation failure
- **CWE-502** (Deserialization): Data integrity validation
- **CWE-611** (XXE): Input format validation

**Compliance Implication**: CWE findings indicate failed testing/validation requirements.

---

### Article 37: Compliance and Remediation

**Requirement**: Monitor and remediate non-compliance.

**Related CWEs**:
- All CWEs: Indicate compliance gaps
- **CWE-1104** (Outdated Components): Remediation failure
- **CWE-778** (Insufficient Logging): Monitoring failure

**Compliance Implication**: CWE findings must be tracked and remediated.

---

## ISO 27001:2022 Mapping

ISO 27001 defines information security management system requirements organized by annexes.

### Annex A.5: Organizational Controls

**A.5.1: Policies for Information Security**
- Establishes information security policies
- Related CWEs: 16 (Configuration), 656 (Security Through Obscurity)

---

### Annex A.6: People Controls

**A.6.2: Information Security Responsibilities and Access Management**
- Assigns security responsibilities
- Related CWEs: 269 (Privilege Management), 862 (Missing AuthZ)

---

### Annex A.7: Physical Controls

**A.7.3: Securing Physical Assets**
- Protects physical assets
- Related CWEs: 200 (Info Exposure), 434 (File Upload)

---

### Annex A.8: Technological Controls

**A.8.1: User Endpoint Devices**
- Controls user device security
- Related CWEs: 200 (Info Exposure), 327 (Broken Crypto)

**A.8.2: Privileged Access Rights**
- Manages privileged access
- Related CWEs: 269 (Privilege Management), 798 (Hard-coded Credentials), 862 (Missing AuthZ)

**A.8.3: Information Access Restriction**
- Restricts information access by role
- Related CWEs: 22 (Path Traversal), 639 (AuthZ Bypass), 862 (Missing AuthZ), 863 (Incorrect AuthZ)

**A.8.4: Access to Cryptographic Keys**
- Manages cryptographic key access
- Related CWEs: 327 (Broken Crypto), 330 (Insufficient Randomness), 798 (Hard-coded Credentials)

**A.8.5: Information Security in Development and Support Processes**
- Secures development/maintenance environments
- Related CWEs: 434 (Unrestricted Upload), 656 (Security Through Obscurity)

**A.8.6: Management of Technical Vulnerabilities**
- Identifies and manages vulnerabilities
- Related CWEs: 1104 (Outdated Components)

**A.8.7: Information Systems Audit Considerations**
- Enables auditing of systems
- Related CWEs: 117 (Log Injection), 778 (Insufficient Logging)

**A.8.8: Management of Removable Media**
- Controls removable media usage
- Related CWEs: 200 (Info Exposure), 434 (Unrestricted Upload)

**A.8.9: Disposal of Information Assets**
- Securely removes/destroys information
- Related CWEs: 200 (Info Exposure), 327 (Broken Crypto)

**A.8.10: Data Transfer**
- Protects data during transfer
- Related CWEs: 297 (Certificate Validation), 327 (Broken Crypto)

**A.8.11: Monitoring**
- Monitors system activity
- Related CWEs: 117 (Log Injection), 778 (Insufficient Logging)

**A.8.12: Management of Functions Accessible via Channels**
- Controls access via remote channels
- Related CWEs: 200 (Info Exposure), 287 (Improper Auth)

**A.8.13: Use of Cryptography**
- Implements cryptography
- Related CWEs: 327 (Broken Crypto), 330 (Insufficient Randomness), 331 (Insufficient Entropy)

---

## SOC 2 Type II Trust Service Criteria Mapping

SOC 2 defines trust service criteria across 5 trust principles: Security (CC), Availability (A), Processing Integrity (PI), Confidentiality (C), Privacy (P).

### CC: Security Controls

**CC1: Governance**
- Governance framework for system security
- Related CWEs: 862 (Missing AuthZ), 863 (Incorrect AuthZ)

**CC2: Logical and Physical Access Controls**
- Controls system access
- Related CWEs: 22 (Path Traversal), 287 (Auth), 306 (Missing Auth), 639 (AuthZ Bypass), 862 (Missing AuthZ)

**CC3: System Monitoring and Change Management**
- Monitors and controls system changes
- Related CWEs: 117 (Log Injection), 778 (Insufficient Logging), 1104 (Outdated Components)

**CC4: Risk Management**
- Identifies and manages security risks
- Related CWEs: 434 (Unrestricted Upload), 656 (Security Through Obscurity)

**CC5: Design and Implement Logical/Physical Controls**
- Designs and implements access controls
- Related CWEs: 22 (Path Traversal), 434 (File Upload), 639 (AuthZ Bypass), 862 (Missing AuthZ)

**CC6: Logical and Physical Access Controls**
- Manages authentication and authorization
- Related CWEs: 287 (Improper Auth), 306 (Missing Auth), 352 (CSRF), 640 (Weak Password Recovery), 798 (Hard-coded Credentials), 862 (Missing AuthZ)

**CC7: System Monitoring**
- Monitors for security incidents
- Related CWEs: 117 (Log Injection), 200 (Info Exposure), 778 (Insufficient Logging)

**CC8: Vulnerability Management**
- Identifies and remediates vulnerabilities
- Related CWEs: 1104 (Outdated Components)

**CC9: Risk Mitigation**
- Implements risk mitigation controls
- Related CWEs: 327 (Broken Crypto), 330 (Insufficient Randomness), 331 (Insufficient Entropy)

### PI: Processing Integrity

**PI1: Systems Processing, Recording, and Reporting of Transactions**
- Ensures data accuracy in processing
- Related CWEs: 20 (Input Validation), 125 (OOB Read), 347 (Signature Validation), 502 (Deserialization)

### C: Confidentiality

**C1: Protection from Unauthorized Access**
- Prevents unauthorized data access
- Related CWEs: 22 (Path Traversal), 200 (Info Exposure), 327 (Broken Crypto), 639 (AuthZ Bypass), 798 (Hard-coded Credentials)

---

## Framework Interoperability Matrix

| CWE | OWASP | NIST | EU AI Act | ISO 27001 | SOC 2 | MITRE |
|-----|-------|------|-----------|-----------|-------|-------|
| 20 | A03 | SI-10 | Art 15 | A8.1 | CC2, CC6 | T1548 |
| 22 | A01 | AC-3 | Art 15 | A8.3 | CC2, CC6 | T1190 |
| 78 | A03 | SI-10 | Art 15 | A8.1 | CC6 | T1059 |
| 79 | A03 | SI-10 | Art 15 | A8.1 | CC6 | T1189 |
| 89 | A03 | SI-10 | Art 15 | A8.1 | CC6 | T1059 |
| 287 | A07 | IA-2 | Art 35 | A8.2 | CC6 | T1110 |
| 306 | A01 | AC-2 | Art 15 | A8.3 | CC6 | T1190 |
| 327 | A02 | SC-13 | Art 15 | A8.13 | CC9 | T1110 |
| 434 | A04 | CM-3 | Art 15 | A8.5 | CC5 | T1189 |
| 502 | A08 | SI-7 | Art 15 | A8.1 | PI1 | T1059 |
| 798 | A05 | IA-5 | Art 15 | A8.4 | CC6 | T1098 |
| 862 | A01 | AC-6 | Art 35 | A8.3 | CC6 | T1531 |
| 918 | A10 | SC-7 | Art 15 | A8.1 | CC6 | T1021 |

---

**Last Updated**: 2024
**Framework Versions**: NIST SP 800-53 Rev. 5, EU AI Act 2024, ISO 27001:2022, SOC 2 2022, MITRE ATT&CK v13
