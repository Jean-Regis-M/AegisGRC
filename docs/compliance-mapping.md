# AegisGRC Compliance Mapping Matrix & Control Standards

This document describes how raw infrastructure configuration parameters scan results are mapped to official security frameworks.

---

## 1. Compliance Matrix Mapping

AegisGRC bridges the gap between infrastructure state, policy failures, and legal audit requirements:

### AWS S3 Public Access Block (`aws_s3_bucket_public_access_block`)
-   **Finding Description**: Public ACL or bucket policies allow global read/write blocks.
-   **SOC2 Trust Services Criteria**: **CC6.3** Logical boundaries and data leakage protection.
-   **ISO 27001 Control**: **A.5.15** Access Control.
-   **NIST CSF Control**: **PR.DS-02** Data-in-Transit Protection.
-   **Severity Scale**: CRITICAL (Risk score: 100).
-   **Remediation**: Configure high-rigidity blocks setting `block_public_acls = true`, `block_public_policy = true`.

### AWS S3 Server Side Encryption (`aws_s3_bucket`)
-   **Finding Description**: Default bucket lacks native KMS custom encryption configs.
-   **SOC2 Trust Services Criteria**: **CC6.1** Logical Access Security and Cryptography.
-   **ISO 27001 Control**: **A.8.24** Use of Cryptography.
-   **NIST CSF Control**: **PR.DS-01** Data-at-Rest Protection.
-   **Severity Scale**: HIGH (Risk score: 80).
-   **Remediation**: Integrate strict server side config blocks pointing to CMK.

### Insecure Security Group SSH Gateway (`aws_security_group`)
-   **Finding Description**: Ingress block leaves port 22 open to `0.0.0.0/0`.
-   **SOC2 Trust Services Criteria**: **CC6.4** Network Boundaries.
-   **ISO 27001 Control**: **A.8.20** Network Security.
-   **NIST CSF Control**: **PR.IR-01** Network Ingress Controls.
-   **Severity Scale**: CRITICAL (Risk score: 125).
-   **Remediation**: Retrack access rules strictly to authorized regional VPN cidrs.

---

## 2. Evidence Generation Framework

When producing evidence, the system collects the following metadata fields to ensure audit trail integrity:

1.  **Unique Scan ID**: Cryptographic hash identifying the scanner instance.
2.  **Target Artifact**: The specific Terraform resource string (e.g. `aws_s3_bucket.prod_logs`).
3.  **Active Evaluator**: The unique OPA Rego rule triggering the event (e.g. `soc2_cc6.s3_unencrypted`).
4.  **Audit Statement**: The formal AI-generated audit opinion stating whether the code conforms to specific rules.
5.  **Verified HCL Block**: Dynamic sample demonstrated to the auditor during visual checks.
