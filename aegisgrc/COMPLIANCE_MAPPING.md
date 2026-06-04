# Aegis Compliance-to-Code Mapping Matrix

Aegis GRC maps logical Rego constraints directly to specific regulatory requirements:

| Control ID | Framework | Description | Rego Rule Reference |
| --- | --- | --- | --- |
| **SOC2 CC6.1** | SOC 2 Type II TSC | Boundary Defense and Secure Network Architecture | `deny_unprotected_ingress` (No global egress port mappings) |
| **SOC2 CC6.3** | SOC 2 Type II TSC | Encryption of Data-at-Rest Protocols | `deny_unencrypted_s3` (S3 security rules require SSE-KMS) |
| **SOC2 CC6.4** | SOC 2 Type II TSC | Verification of Vulnerable SSH and Ingress Protocols | `deny_global_ssh` (Block global ingress to administrative port 22) |
| **ISO 27001 Annex A.8.20** | ISO/IEC 27001:2022 | Network Security Management and Infrastructure Segregation | `validate_isolated_subnets` (Prevent global route table associations to default gateways) |
| **NIST CSF v2.0 PR.DS-01** | NIST CSF v2.0 | Cryptographic Key Lifecycles & Configuration Validation | `deny_unencrypted_ebs` (Strict compliance over storage disk encryption keys) |

## Standard AI Translation Prompts

To bridge code blocks and executive understanding, Gemini AI models translate identified errors to the control map when creating compliance drafts.
This keeps evidence generation both strict (from policy code) and intelligible (to GRC directors).
