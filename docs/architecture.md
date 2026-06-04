# AegisGRC System Architecture & Integration Blueprint

This document details the modular system design, component interactions, data flows, and security mechanics behind AegisGRC — an enterprise-grade, AI-assisted Policy-as-Code Governance, Risk, and Compliance platform.

---

## 1. System Design & Component Layout

AegisGRC uses a structured, full-stack layout designed to decouple pipeline processes, scale policy execution, and integrate AI reasoning safeguards without blocking continuous deployment workflows:

```
+-----------------------------------------------------------------------------------+
|                              AEGISGRC ARCHITECTURE                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ Developer Push ] --> [ GitHub Actions Git-Push Hook ]                          |
|                                     |                                             |
|                                     v                                             |
|                     [ Aegis-IaC Terraform Scanner ]                               |
|                                     |                                             |
|              +----------------------+----------------------+                      |
|              |                                             |                      |
|              v                                             v                      |
|      [ AST Parser Module ]                         [ Rego Policy Library ]        |
|      (Extracts JSON Schemas)                       (Local SOC2 / ISO Rules)       |
|              |                                             |                      |
|              +----------------------+----------------------+                      |
|                                     |                                             |
|                                     v                                             |
|                        [ OPA Policy Evaluation Engine ]                           |
|                                     |                                             |
|                                     v                                             |
|                     [ Control & Framework Mapping Matrix ]                         |
|                       (SOC2 Criteria, ISO, NIST Controls)                         |
|                                     |                                             |
|                                     v                                             |
|                         [ GRC Risk Scoring Processor ]                             |
|               Score = Likelihood (L) x Impact (I) x Exposure (E)                  |
|                                     |                                             |
|              +----------------------+----------------------+                      |
|              |                                             |                      |
|              v                                             v                      |
|     [ AI GRC Triage Service ]                    [ AI GRC Evidence Service ]      |
|     (Gemini-3.5-Flash reasoning)                 (Signatures & Compliance Docs)   |
|              |                                             |                      |
|              +----------------------+----------------------+                      |
|                                     |                                             |
|                                     v                                             |
|                         [ Aegis GRC React Dashboard ]                             |
|                           (Real-time State Workspace)                             |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Core Architecture Components

1.  **Aegis-IaC Terraform Scanner**:
    -   Parses raw `.tf` modular configuration blocks into unified JSON structures. Evaluates arguments, values, variable expansions, and resource attributes natively.
2.  **OPA Policy Evaluation Engine**:
    -   Implements highly decoupled local policy evaluation blocks mimicking Open Policy Agent (OPA) compiler constraints. Compares raw block variables against target structural compliance boundaries.
3.  **Control & Framework Mapping Matrix**:
    -   Connects evaluated security policy failures with mapped governance catalogs (SOC2 Trust Services Principles, ISO 27001 clauses, NIST CSF sub-categories) dynamically, resolving corresponding audit identifiers.
4.  **GRC Risk Scoring Processor**:
    -   Applies an enterprise-grade three-dimensional risk formula to rank findings by urgency.
5.  **AI GRC Triage & Evidence Service**:
    -   Invokes a server-side **Gemini-3.5-Flash** pipeline to translate technical policy failures into business-oriented risk statements, remediation configs, and compliance certificates.
6.  **Aegis GRC React Dashboard**:
    -   Provides security teams with an interactive web layout visualizing overall compliance stance, drift incidents, and active pipeline animations.

---

## 2. Integrated Compliance Sequence Flow

```
+-----------+             +---------+          +------------+          +------------+          +------------+
| Developer |             | Scanner |          | OPA Engine |          | Gemini AI  |          | GRC Portal |
+-----------+             +---------+          +------------+          +------------+          +------------+
      |                        |                     |                       |                       |
      |--- 1. Git Push -------->                     |                       |                       |
      |   (Terraform Code)     |--- 2. Parse AST --->|                       |                       |
      |                        |                      |--- 3. Run Rego ---->|                       |
      |                        |                      |   (Violations)       |                       |
      |                        |                      |                      |--- 4. Triage Prompt ->|
      |                        |                      |                      |   (Evidence Draft)    |
      |                        |                      |                      |                       |
      |                        |<------------------ 5. Return Evidence Block ------------------------|
      |                        |                                                                     |
      |<-- 6. PR Annotated ----|                                                                     |
      |   (Approved / Blocked) |----------------------- 7. Sync State Logs ------------------------->|
```

1.  **Developer Push**: A developer modifies the Terraform infrastructure file (e.g. enabling public access blocks or turning off encryption) and commits code.
2.  **IaC Scan Trigger**: System imports the code, running AST extraction to trace resource attributes.
3.  **OPA Ruleset Evaluation**: Evaluates resources against standard Rego rules (e.g. `soc2_cc6.rego`).
4.  **Framework Mapping & Risk Evaluation**: Mapped schema binds the violation to a compliance clause (e.g., S3 unencrypted binds to **SOC2 CC6.1** with high risk score).
5.  **AI Evidence and Triage Drafting**: Server side sends the technical findings to Gemini 3.5. Gemini drafts human-readable explanations, suggests secure HCL remediations, and writes audit evidence files.
6.  **Review Integration**: Action updates the GitHub PR annotations, while server updates the AegisGRC database and logs in-app.

---

## 3. Dynamic Risk Scoring Model

To prevent alert fatigue, AegisGRC uses a composite Risk Score formula assessing impact and likelihood relative to environment parameters:

$$\text{Risk Score} = \text{Likelihood} \times \text{Impact} \times \text{Exposure}$$

Where:
*   **Likelihood** ($1 - 5$): Frequency of the finding's exploitability (e.g., broad ports open to public has high likelihood of 5; missing log validation has mid likelihood of 2).
*   **Impact** ($1 - 5$): Severe consequence to database data secrecy or resource integrity (e.g., bucket storage encryption missing has impact of 4; IAM administrative role leaks have impact of 5).
*   **Exposure** ($1 - 5$): Resource visibility based on environment categorization (production assets scale to 5, development assets scale to 2).

### Score Classifications
*   **CRITICAL** ($100 - 125$): High likelihood of immediate active exposure. Breaks compliance gates. Blocks PR merges automatically.
*   **HIGH** ($60 - 99$): Marked compliance deviation. Must be remediated within 7 days.
*   **MEDIUM** ($20 - 59$): Procedural discrepancy. Policy deviation requiring adjustments.
*   **LOW** ($1 - 19$): Minor audit warning. No physical boundary threat.

---

## 4. LLM AI Integration Guidelines

We leverage Gemini server-side using standard client options (`process.env.GEMINI_API_KEY`) to complete GRC synthesis. Gemini constructs two core records:

1.  **Risk Triage Profile**:
    -   *Rationale*: Explains the specific vulnerability to non-security stakeholders in plain English.
    -   *Remediation Builder*: Generates the exact corrected Terraform blocks.
    -   *Control Impact*: Predicts down-funnel impacts on auditor frameworks.
2.  **Compliance Evidence Record**:
    -   *Format*: Audit-ready text templates describing structural tests passed/failed.
    -   *Cryptographic verification metadata*: Includes scan date, SHA256 code digest, compiler state, and validation status (PASS/FAIL) signed by our compliance authority.
