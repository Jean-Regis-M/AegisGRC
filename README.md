# 🛡️ Aegis GRC — AI-Powered Policy-as-Code & Drift Healing Compliance Platform

```text
       _____                       _        _    _ _____   ______ 
      / ___ \                     | |      | |  | |  __ \ / _____)
     | |   | | ____  ____  ____ _ | |  _   | |  | | |__) ) /      
     | |   | |/ _  |/ _  |/ _  ) || | (_)  | |  | |  __ (| |      
     | |___| ( ( | ( ( | ( (_ | (_| |  _   | |__| | |  \ \ \_____ 
      \_____/ \_||_|\_||_|\____\____| (_)   \____/|_|  |_|\______)
                                                                  
      CONTINUOUS INFRASTRUCTURE ASSURANCE & CONTINUOUS COMPLIANCE ENGINE
```

Aegis GRC is a production-level, open-source continuous assurance and compliance platform. It bridges the gap between infrastructure deployment (IaC) and regulatory standards (**SOC2 Type II, ISO/IEC 27001:2022, and NIST CSF v2.0**). By compiling your cloud configurations to AST formats, checking them against automated Open Policy Agent (OPA) Web Decider policies, and enriching findings with server-side AI, Aegis empowers security engineering teams to detect, triage, and automatically heal security gaps before they hit production.

---

## 🚀 Key Architectural Capabilities

- 🔍 **Multi-Level IaC AST Scanner**: Evaluates Terraform manifests with an abstract syntax tree parser to find security misconfigurations (S3 unencrypted buckets, global ingress administrative ports, unencrypted EBS drives, etc.).
- 🛡️ **Open Policy Agent (OPA) Integration**: Built-in OPA engine that compiles and parses declarative `policies/soc2/cc6_1.rego` rules down to nanosecond-speed evaluation frames.
- ⚡ **Closed-Loop Drift Healing**: Continuous out-of-band state comparison that identifies drift from declared resources and features a single-click self-healing "Heal Boundary" pipeline.
- 🤖 **Server-Side AI Co-Pilot & Triage**: Uses Gemini models to construct precise, high-fidelity security explanations, risk mitigation plans, active code fixes, and cryptographic GRC certifications.
- 📑 **Dynamic PDF Report Architect**: Backend compilation route producing beautiful, audit-ready regulatory attestation documents on-the-fly containing score widgets, risk formulas, active findings, and full timeline logs.
- 💻 **DevOps Terminal & Ledger Timeline**: Fully reactive diagnostic audit ledger tracking system startups, ad-hoc scans, pipeline triggers, and self-healing events.

---

## 🏗️ Detailed Project Directory Structure

The repository represents a unified multi-environment full-stack system containing both the real-time **React/Express interactive Web Console** and the nested **Enterprise Python/FastAPI OPA microservice daemon** (`/aegisgrc/` folder):

```text
AegisGRC/
├── src/                         # 🎨 Front-End: Modern React + Vite Web Console
│   ├── App.tsx                  # Core interactive desktop dashboard & control loops
│   ├── types.ts                 # Strong TypeScript interface & compliance definitions
│   ├── repoFiles.ts             # Static code store rendering virtual HCL/Rego browser files
│   ├── index.css                # Global Tailwind CSS & typography definitions
│   └── main.tsx                 # Vite application mount point
├── aegisgrc/                    # 🐍 Backend: Enterprise Python + OPA Policy Microservice
│   ├── .github/workflows/       # Continuous Integration and compliance verification YAMLs
│   │   ├── ci.yml               # Automated Python code formatting and pytest workflow
│   │   └── compliance-scan.yml  # Daily periodic OPA cloud assurance scan schedule
│   ├── api/                     # FastAPI backend boundary layers
│   │   ├── main.py              # Microservice application entrance & router mapping
│   │   ├── dependencies.py      # Auth handlers, api-key validators, database sessions
│   │   ├── routers/             # Endpoint definitions
│   │   │   └── scans.py         # Handles HCL AST uploads, triggering parser & scoring
│   │   └── schemas/             # Typed request/response validator schemas (Pydantic)
│   │       └── scan.py          # Unified scan execution request-response structures
│   ├── core/                    # Platform constants and cross-module utilities
│   │   ├── config.py            # Environment-safe configuration parsers
│   │   ├── exceptions.py        # Centralized exception tracking classes
│   │   └── logging.py           # Configured system log formatters
│   ├── db/                      # GRC session SQL persistence managers (SQLAlchemy)
│   │   ├── base.py              # Declarative schema base mapping definitions
│   │   ├── models.py            # DB schema definitions (ScanReports, LedgerHistory)
│   │   └── session.py           # Thread-safe database connection session managers
│   ├── engine/                  # Core parsing, evaluation, and rating algorithms
│   │   ├── ai_evidence.py       # Intercepts scan logs to build Gemini attestation drafts
│   │   ├── opa.py               # Spawns sub-processes communicating directly with OPA CLI
│   │   ├── parser.py            # Converts raw HCL elements into parsed operational JSON ASTs
│   │   └── scorer.py            # Weights control risks (L x I x E) to derive ratings
│   ├── policies/soc2/           # Pre-loaded Policy-as-Code criteria definitions
│   │   ├── cc6_1.rego           # OPA Rego rules evaluating raw AWS network configurations
│   │   └── mapping.json         # Connects OPA rule codes directly to SOC2 common criteria
│   ├── terraform/               # Sample templates used in static scanners or mock pipelines
│   │   └── sample_infra.tf      # Intentional policy-violating HCL blueprint sample
│   ├── tests/                   # Service assurance tests suite (pytest)
│   │   ├── test_api.py          # Validates scan submission and health response structures
│   │   └── test_engine.py       # Runs test-assertions over parsers and score calculations
│   ├── Dockerfile               # Production multi-stage Docker container specification
│   ├── docker-compose.yml       # Quick-spin container sandbox orchestrator
│   ├── README.md                # Python backend microservice documentation
│   ├── ARCHITECTURE.md          # Architectural and threat mitigation specifications
│   ├── COMPLIANCE_MAPPING.md    # Detail maps tracing policies directly to AICPA criteria
│   ├── SECURITY.md              # Vulnerability capture procedures for backend operations
│   ├── CONTRIBUTING.md          # Guide for python & policy contributors
│   └── THREAT_MODEL.md          # Architectural threat models and boundaries
├── server.ts                    # ⚡ Middle-Tier: High-fidelity Node + Express Server
│   # (Executes AST parses, proxies secure Gemini actions, generates GRC PDF report artifacts)
├── package.json                 # Project dependencies & startup scripting configurations
├── CONTRIBUTING.md              # Global developer and code of conduct playbook
├── SECURITY.md                  # Global security vulnerability reporting guides
└── README.md                    # Primary repository landing page & roadmap guide
```

---

## 🔄 Automated Compliance Lifecycle

The platform runs a continuous control loop that orchestrates verification:

```text
  [ Dev Commit / Pull Request ]
               │
               ▼
   ┌───────────────────────┐
   │ AST Attribute Parser  │  <── Parses HCL input to structured JSON context
   └───────────────────────┘
               │
               ▼
   ┌───────────────────────┐
   │ OPA Evaluation Engine │  <── Validates against policies/soc2/cc6_1.rego
   └───────────────────────┘
               │
               ▼
   ┌───────────────────────┐
   │ Risk Scoring System   │  <── Calculates Risk = Impact x Likelihood x Exposure
   └───────────────────────┘
               │
               ▼
   ┌───────────────────────┐
   │ Gemini AI Enrichment  │  <── Generates secure code fixes & attestation stamps
   └───────────────────────┘
               │
               ▼
   ┌───────────────────────┐
   │   Audit Trail Log     │  <── Commits actions atomically to telemetry ledger
   └───────────────────────┘
               │
               ▼
 [ Beautiful Interactive Dashboard / PDF Downloadable Attestation Report ]
```

---

## ⚙️ Requirements & Quick Start

### Prerequisites
- **Node.js**: `v18.0.0` or higher
- **NPM**: `v9.0.0` or higher

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Jean-Regis-M/AegisGRC.git
cd AegisGRC
npm install
```

### 2. Configure Environment Secrets
Create a `.env` file at the root of the project:
```bash
# Define your Gemini API Credentials for AI Attestation & Interactive GRC Chat
GEMINI_API_KEY="AIzaSyYourSecretKeyHeaderGoesHere"
```
*(If the API Key is absent or rate-limited, Aegis gracefully transitions into an intelligent offline local backup mode with pre-baked high-fidelity compliance metrics!)*

### 3. Launch Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your web browser to access the Aegis GRC Terminal.

---

## 🛠️ How to Add Your Own OPA Compliance Policies

Adding security controls to Aegis GRC is fast and structured:

### Step 1: Write your Rego Rule
Add a new violation criteria in `policies/soc2/cc6_1.rego`:
```rego
violation[msg] {
    some resource
    resource.type == "aws_db_instance"
    not resource.attributes.storage_encrypted
    msg := sprintf("SOC2 CC6.3 Violation: DB Instance '%s' has storage encryption disabled.", [resource.name])
}
```

### Step 2: Map to GRC Controls
Register your new OPA rule inside code mappings to display it cleanly in dashboard summaries and mapping tables:
```json
"CC6.3": {
  "title": "Encryption of Data at Rest",
  "description": "Verifies static database instances and media buckets enforce KMS custom keys.",
  "rego_rules": ["is_unencrypted_db_instance", "is_unencrypted_s3_bucket"]
}
```

---

## 🤝 For Contributors: Making a Real Impact

Aegis GRC is built *by* security engineers, *for* security engineers. We are fiercely committed to building the finest open-source compliance shield. Here is where we need your talent:

1. **🔬 Custom OPA Policy Library**: We want to broaden our `.rego` catalog! Add rules protecting Google Cloud (GCP), Azure, Kubernetes configurations, and Dockerfiles.
2. **🛡️ Additional Compliance Standards**: Help us build coverage tables for **PCI-DSS v4.0**, **HIPAA Safeguards**, and **FedRAMP Moderate** criteria!
3. **💻 Real-Time Integrations**: Create plugins connecting our backend routes to Slack, Jira Tickets, and Webhooks.
4. **📊 Rich Data Visualizations**: We love maps, charts, and clean bento grids! Introduce additional D3/Recharts modules inside our main screen.

To start contributing, please review our detailed [CONTRIBUTING.md](./CONTRIBUTING.md)!

---

## 🔒 Security Vulnerability Handling

We take platform security with extreme seriousness. If you identify a structural vulnerability or key-leak, please do not create a public GitHub Issue. Instead, read our [SECURITY.md](./SECURITY.md) guidelines and report it directly to **security@aegisgrc.enterprise** so we can coordinate a secured private fix.

## 📄 Licensing & Open Source Spirit

Aegis GRC is proudly distributed under the **Apache License 2.0**. Let's build a safer, more transparent compliance future together! 🚀
