# System Architecture & Compliance Flow Diagrams

Aegis GRC leverages modular Python components to integrate Policy-as-Code execution with modern Large Language Models (LLMs). This document outlines the physical and logical architectures.

## Runtime Pipeline Flow

```
[ Developer Commit ] ────> [ GitHub Actions (Aegis Gate) ]
                                      │
                                      ▼
[ FastAPI Route ] ───────> [ AST Infrastructure Parser ]
                                      │
                                      ▼
[ Rego Rules ] ──────────> [ OPA Evaluation Engine ]
                                      │
                                      ▼
                       [ Compliance Risk Scorer ]
                                      │
                                      ▼
[ Gemini AI API ] ───────> [ AI Evidence Drafter (CC6 Matrix) ]
                                      │
                                      ▼
[ SQLite DB ] ───────────> [ Signed Compliance Ledger ]
```

## Modular Layout Detailed Responsibilities

### 1. Presentation Layer (`api/`)
Handles ingress HTTP requests, authenticates requests against custom user authorization tokens, and provides structured schemas for scans and policy results.

### 2. Analytical Engine (`engine/`)
- `parser.py`: Extracts attributes, resources, and ingress rules from Terraform configuration scripts.
- `opa.py`: Proxies parameters over to the local Open Policy Agent daemon or evaluates policies natively with compiled packages.
- `scorer.py`: Computes custom risk indicators based on control criteria failures.
- `ai_evidence.py`: Integrates with the Google GenAI SDK to synthesize natural-language summaries mapping vulnerabilities directly to SOC2 Trust Services Criteria (CC6).

### 3. Storage Layer (`db/`)
Maintains session configurations, continuous out-of-band drifts (e.g., resources manually changed on cloud providers), and chronological system logs.
