# Threat Model: Secure Policy Delivery & Enforcement

This document outlines the threat modeling security evaluation for Aegis GRC, identifying cryptographic hazards, out-of-band drift scenarios, and regulatory tampering vectors.

## 1. System Boundary Overview

| System boundary | Entry Point / Data Flow | Risk Level | Mitigation Status |
| --- | --- | --- | --- |
| S3/IAM Manifests | Inbound HCL file scanning via API | High | Secure AST sanitization. String escaping on parameters. |
| OPA Policy Store | Local `.rego` rule files | Critical | Signed policy files, restrictive write-permissions inside runtime context. |
| Client Ingress REST | JWT token authentication / OAuth | Medium | Integration with TLS endpoints & signed security certificates. |
| AI Prompting | Generation of evidence reports | Low | System context restriction preventing injection behaviors. |

## 2. Identified Threat Vectors & Mitigations

### Threat A: Out-of-Band Cloud Console Drift (Bypassing GRC)
- **Threat Scenario:** An operator modifies a secure S3 bucket configuration (e.g., turning off SSE-KMS encryption) directly via AWS Console. Since git is bypassed, standard pipeline gates do not record this change.
- **Remediation:** Aegis GRC implements a continuous scheduled polling loop (1.5s in demo simulation) that cross-checks the current live state against declared repo files, raising out-of-band alerts and providing a trigger to "Heal" state boundaries.

### Threat B: Tampering with Compliance Evidence Ledger
- **Threat Scenario:** An attacker suppresses logs relating to critical control failures to present a false compliant state during a SOC2 audit.
- **Remediation:** Compliance trails are cryptographically bundled using SHA-256 digests. Every generation is locked with an immutable state audit timestamp.

### Threat C: Rego Rule Injection
- **Threat Scenario:** Malicious script input injected inside standard Terraform strings overrides OPA rules to pass security checks.
- **Remediation:** Pre-parsing sanitization blocks nested statements. HCL schemas strictly define elements before evaluating in rule models.
