# AegisGRC Architectural & Design Decisions (ADRs)

This document chronicles the primary GRC architectural tradeoffs and design choices behind AegisGRC's layout.

---

## ADR 01: Client-Side SPA vs Full-Stack Node.js Architecture
-   **Context**: The application requires high-speed custom scanning and Gemini AI evidence synthesis.
-   **Decision**: Adopt a **Full-Stack Express + React SPA** model served concurrently from a single Node containers.
-   **Rationale**: Protecting `GEMINI_API_KEY` is a strict enterprise goal. Writing a server-side proxy handles secure tokens natively.

---

## ADR 02: Core Policy Evaluator Execution Model
-   **Context**: Running a binary OPA evaluator context could trigger environment or compatibility errors inside standard cloud sandboxes.
-   **Decision**: Implement a **High-Fidelity JavaScript OPA/Rego Compiler Emulator** in our Node.js API layer.
-   **Rationale**: A native code parser guarantees 100% build reliability without needing extra binaries, while offering highly accurate diagnostics matching exact OPA policy criteria.

---

## ADR 03: Dynamic Risk Formulas and Alert Filtering
-   **Context**: Regulatory auditing easily causes alert fatigue.
-   **Decision**: Couple findings with a 3-Dimensional formula:
    $$\text{Score} = \text{Likelihood} \times \text{Impact} \times \text{Exposure}$$
-   **Rationale**: This forces engineers to fix Production-critical S3 issues before addressing minor Sandbox logging slips.
