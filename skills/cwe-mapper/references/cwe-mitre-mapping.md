# CWE to MITRE ATT&CK / ATLAS Mapping Reference

Cross-reference between CWE IDs and MITRE ATT&CK tactics/techniques and MITRE ATLAS (AI/ML specific).

## MITRE ATT&CK Framework Mapping

MITRE ATT&CK organizes adversary tactics and techniques based on real-world observations.

### Reconnaissance (TA0043)

**Definition**: Attacker gathers information about target prior to exploitation.

**Related CWEs**:
- **CWE-200** (Information Exposure): Reconnaissance information leaked
- **CWE-693** (Protection Mechanism Failure): Reconnaissance not prevented

**Techniques**:
- T1592: Gather Victim Identity Information
- T1589: Gather Victim Identity Information
- T1590: Gather Victim Network Information

---

### Resource Development (TA0042)

**Definition**: Attacker establishes resources to support operations.

**Related CWEs**:
- **CWE-434** (Unrestricted Upload of File): Staging malicious files
- **CWE-798** (Hard-coded Credentials): Embedded access credentials

**Techniques**:
- T1597: Search Open Websites/Domains
- T1583: Acquire Infrastructure
- T1586: Compromise Accounts

---

### Initial Access (TA0001)

**Definition**: Attacker gains initial foothold in target network.

**Related CWEs**:
- **CWE-79** (Cross-site Scripting): Phishing delivery
- **CWE-434** (Unrestricted Upload): Malicious file upload
- **CWE-918** (Server-Side Request Forgery): Internal access
- **CWE-1021** (Improper Restriction of Frames): Clickjacking to initial access

**Techniques**:
- T1189: Drive-by Compromise
- T1566: Phishing
- T1199: Trusted Relationship
- T1190: Exploit Public-Facing Application

---

### Execution (TA0002)

**Definition**: Attacker runs malicious code on target.

**Related CWEs**:
- **CWE-78** (OS Command Injection): Command execution
- **CWE-79** (XSS): Browser-based code execution
- **CWE-89** (SQL Injection): DBMS command execution
- **CWE-94** (Code Injection): Direct code injection
- **CWE-95** (Improper Neutralization in Evaluated Code): Template/eval execution
- **CWE-434** (Unrestricted Upload): Execute uploaded files
- **CWE-502** (Deserialization): Object gadget chain execution
- **CWE-1336** (Improper Neutralization in Template): Template injection

**Techniques**:
- T1059: Command and Scripting Interpreter
- T1203: Exploitation for Client Execution
- T1559: Inter-Process Communication
- T1106: Native API
- T1053: Scheduled Task/Job

---

### Persistence (TA0003)

**Definition**: Attacker maintains access to compromised system.

**Related CWEs**:
- **CWE-22** (Path Traversal): Persist files outside intended directory
- **CWE-434** (Unrestricted Upload): Upload backdoors
- **CWE-798** (Hard-coded Credentials): Persistence via embedded access
- **CWE-1021** (Clickjacking): Trick user into persistence action

**Techniques**:
- T1098: Account Manipulation
- T1547: Boot or Logon Autostart Execution
- T1037: Boot or Logon Initialization Scripts
- T1555: Credentials from Password Stores
- T1547: Startup Items

---

### Privilege Escalation (TA0004)

**Definition**: Attacker gains higher privilege level.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Bypass privilege checks
- **CWE-250** (Execution with Unnecessary Privileges): Source of escalation
- **CWE-269** (Improper Privilege Management): Privilege management flaws
- **CWE-362** (Race Condition): TOCTOU privilege bypass
- **CWE-416** (Use After Free): Memory exploitation for privilege escalation
- **CWE-434** (Unrestricted Upload): Upload escalation payloads
- **CWE-862** (Missing Authorization): Bypass authorization checks

**Techniques**:
- T1134: Access Token Manipulation
- T1547: Boot or Logon Autostart Execution
- T1547: Accessibility Features
- T1548: Abuse Elevation Control Mechanism
- T1611: Escape to Host

---

### Defense Evasion (TA0005)

**Definition**: Attacker avoids detection by security controls.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Evade input-based detection
- **CWE-79** (XSS): Evade detection via client-side execution
- **CWE-117** (Improper Output Neutralization for Logs): Evade log detection
- **CWE-434** (Unrestricted Upload): Upload obfuscated payloads
- **CWE-656** (Reliance on Security Through Obscurity): No real defense

**Techniques**:
- T1548: Abuse Elevation Control Mechanism
- T1197: BITS Jobs
- T1140: Deobfuscate/Decode Files or Information
- T1036: Masquerading
- T1562: Impair Defenses

---

### Credential Access (TA0006)

**Definition**: Attacker obtains credentials for system access.

**Related CWEs**:
- **CWE-200** (Information Exposure): Credential leakage
- **CWE-287** (Improper Authentication): Weak authentication bypass
- **CWE-297** (Improper Validation of Certificate): MITM credential capture
- **CWE-798** (Hard-coded Credentials): Hardcoded access credentials
- **CWE-327** (Use of Broken Cryptographic Algorithm): Weak credential encryption

**Techniques**:
- T1110: Brute Force
- T1187: Forced Authentication
- T1040: Network Sniffing
- T1555: Credentials from Password Stores
- T1056: Input Capture
- T1111: Multi-Factor Authentication Interception

---

### Discovery (TA0007)

**Definition**: Attacker explores compromised system to find resources.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Discovery via unvalidated input
- **CWE-200** (Information Exposure): Information discovery
- **CWE-209** (Information Exposure Through Error Message): Error-based discovery

**Techniques**:
- T1087: Account Discovery
- T1010: Application Window Discovery
- T1217: Browser Bookmark Discovery
- T1526: Enumerate External Targets
- T1538: Cloud Service Discovery

---

### Lateral Movement (TA0008)

**Definition**: Attacker moves through network to access other systems.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Inter-system auth bypass
- **CWE-287** (Improper Authentication): Weak cross-system auth
- **CWE-297** (Improper Certificate Validation): MITM on internal systems
- **CWE-798** (Hard-coded Credentials): Shared credentials for lateral movement
- **CWE-918** (SSRF): Access internal systems via SSRF

**Techniques**:
- T1570: Lateral Tool Transfer
- T1021: Remote Services
- T1550: Use Alternate Authentication Material
- T1570: Lateral Tool Transfer

---

### Collection (TA0009)

**Definition**: Attacker collects data of interest from compromised system.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Bypass data access controls
- **CWE-22** (Path Traversal): Access unintended data
- **CWE-125** (Out-of-bounds Read): Read sensitive memory
- **CWE-200** (Information Exposure): Unintended information leak
- **CWE-639** (Authorization Bypass): Access unauthorized data via IDOR

**Techniques**:
- T1557: Adversary-in-the-Middle
- T1115: Clipboard Data
- T1123: Audio Capture
- T1119: Automated Exfiltration
- T1185: Browser Session Hijacking

---

### Exfiltration (TA0010)

**Definition**: Attacker removes collected data from network.

**Related CWEs**:
- **CWE-200** (Information Exposure): Sensitive data exposure
- **CWE-327** (Use of Broken Cryptography): Unencrypted exfiltration
- **CWE-918** (SSRF): Exfil via SSRF endpoint

**Techniques**:
- T1020: Automated Exfiltration
- T1048: Exfiltration Over Alternative Protocol
- T1041: Exfiltration Over C2 Channel
- T1011: Exfiltration Over Other Network Medium

---

### Command and Control (TA0011)

**Definition**: Attacker communicates with compromised system.

**Related CWEs**:
- **CWE-327** (Broken Cryptography): Unencrypted C2 communication
- **CWE-434** (Unrestricted Upload): C2 upload channels
- **CWE-918** (SSRF): C2 via SSRF

**Techniques**:
- T1071: Application Layer Protocol
- T1092: Communication Through Removable Media
- T1001: Data Obfuscation
- T1008: Fallback Channels

---

### Impact (TA0040)

**Definition**: Attacker disrupts or destroys assets.

**Related CWEs**:
- **CWE-20** (Improper Input Validation): Enable impact
- **CWE-862** (Missing Authorization): Unauthorized destructive operations
- **CWE-94** (Code Injection): Execute impact payloads

**Techniques**:
- T1531: Account Access Removal
- T1485: Data Destruction
- T1561: Disk Wipe
- T1491: Defacement

---

## MITRE ATLAS: AI/ML Specific Mapping

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) focuses on ML/AI-specific attacks.

### Reconnaissance

**Relevant CWEs**:
- **CWE-200** (Information Exposure): Model/dataset reconnaissance
- **CWE-434** (Unrestricted Upload): Reconnaissance via file analysis

**ATLAS Techniques**:
- AML.T0001: Publish Model Artifacts
- AML.T0005: Acquire ML Artifacts
- AML.T0010: Discover ML Models and Datasets

---

### Resource Development

**Relevant CWEs**:
- **CWE-434** (Unrestricted Upload): Staging malicious models
- **CWE-798** (Hard-coded Credentials): Model API credentials

**ATLAS Techniques**:
- AML.T0003: Acquire Compute Resources
- AML.T0002: Publish Poisoned Datasets
- AML.T0007: Iterate on Model Training

---

### Initial Access

**Relevant CWEs**:
- **CWE-79** (XSS): Deliver poison via web interface
- **CWE-434** (Unrestricted Upload): Upload poisoned models/datasets
- **CWE-502** (Deserialization): Backdoored model deserialization

**ATLAS Techniques**:
- AML.T0020: Backdoor ML Models
- AML.T0018: Poison Training Data
- AML.T0019: Backdoor Training Data

---

### Execution

**Relevant CWEs**:
- **CWE-94** (Code Injection): Inject into model execution
- **CWE-502** (Deserialization): Execute via model gadget chains
- **CWE-95** (Evaluated Code): Template injection in model names/prompts

**ATLAS Techniques**:
- AML.T0029: Execute Arbitrary Code
- AML.T0030: Run Inference on Model
- AML.T0015: Transfer Learning

---

### Persistence

**Relevant CWEs**:
- **CWE-20** (Improper Input Validation): Persist via poisoned training data
- **CWE-434** (Unrestricted Upload): Persist backdoored models
- **CWE-798** (Hard-coded Credentials): Persistence credentials in model

**ATLAS Techniques**:
- AML.T0020: Backdoor ML Models
- AML.T0017: Change Model Behavior

---

### Defense Evasion

**Relevant CWEs**:
- **CWE-20** (Improper Input Validation): Evade detection via adversarial examples
- **CWE-117** (Log Injection): Hide from audit logs
- **CWE-656** (Security Through Obscurity): No real detection

**ATLAS Techniques**:
- AML.T0031: Evade ML Model
- AML.T0006: Adversarial Example Crafting
- AML.T0028: Model Obfuscation

---

### Credential Access

**Relevant CWEs**:
- **CWE-200** (Information Exposure): Model API key exposure
- **CWE-287** (Improper Authentication): Weak model authentication
- **CWE-798** (Hard-coded Credentials): API keys in model artifacts

**ATLAS Techniques**:
- AML.T0012: Obtain ML Training Data
- AML.T0005: Acquire ML Artifacts

---

### Collection

**Relevant CWEs**:
- **CWE-200** (Information Exposure): Training data leakage
- **CWE-639** (Authorization Bypass): Access unauthorized datasets via IDOR
- **CWE-125** (Out-of-bounds Read): Extract model weights

**ATLAS Techniques**:
- AML.T0025: Extract ML Model
- AML.T0012: Obtain ML Training Data
- AML.T0027: ML Model Inference

---

### Impact

**Relevant CWEs**:
- **CWE-20** (Improper Input Validation): Enable model poisoning impact
- **CWE-862** (Missing Authorization): Unauthorized model modification
- **CWE-502** (Deserialization): Model trojanization

**ATLAS Techniques**:
- AML.T0021: Trigger Model Poisoning
- AML.T0022: Misuse of Model
- AML.T0023: Induce Model Poisoning

---

## Quick Reference: CWE → MITRE ATT&CK Mapping

| CWE | Primary Tactic | Techniques |
|-----|---|---|
| 20 | Privilege Escalation, Defense Evasion | T1548, T1140, T1036 |
| 22 | Initial Access, Collection | T1190, T1185 |
| 78 | Execution | T1059 (Command Execution) |
| 79 | Initial Access, Execution | T1189 (Drive-by), T1059 |
| 89 | Execution, Credential Access | T1059, T1040 |
| 94 | Execution | T1059 (Code Injection) |
| 125 | Collection | T1185 (Memory Reading) |
| 200 | Discovery, Credential Access | T1087, T1526, T1111 |
| 287 | Credential Access | T1110 (Brute Force) |
| 297 | Credential Access, Lateral Movement | T1040 (MITM) |
| 306 | Initial Access | T1190 |
| 327 | Credential Access, Exfiltration | T1110, T1041 |
| 352 | Initial Access | T1189 |
| 362 | Privilege Escalation | T1134 |
| 416 | Privilege Escalation | T1548 |
| 434 | Initial Access, Persistence | T1189, T1547 |
| 502 | Execution, Persistence | T1059, T1550 |
| 639 | Collection | T1087 (Account Discovery) |
| 798 | Persistence, Credential Access | T1098, T1555 |
| 862 | Impact, Privilege Escalation | T1531, T1485 |
| 918 | Lateral Movement, Command & Control | T1570, T1021, T1008 |

---

**Last Updated**: 2024
**Framework Versions**: MITRE ATT&CK v13, MITRE ATLAS v1.0
