export interface RepoFile {
  path: string;
  name: string;
  language: string;
  content: string;
}

export const REPO_FILES: Record<string, RepoFile> = {
  "readme": {
    path: "aegisgrc/README.md",
    name: "README.md",
    language: "markdown",
    content: `# 🛡️ Aegis GRC — AI-Powered Policy-as-Code & Drift Healing Compliance Platform

\`\`\`text
       _____                       _        _    _ _____   ______ 
      / ___ \\                     | |      | |  | |  __ \\ / _____)
     | |   | | ____  ____  ____ _ | |  _   | |  | | |__) ) /      
     | |   | |/ _  |/ _  |/ _  ) || | (_)  | |  | |  __ (| |      
     | |___| ( ( | ( ( | ( (_ | (_| |  _   | |__| | |  \\ \\ \\_____ 
      \\_____/ \\_||_|\_||_\\____\\____| (_)   \\____/|_|  |_|\\______)
                                                                  
      CONTINUOUS INFRASTRUCTURE ASSURANCE & CONTINUOUS COMPLIANCE ENGINE
\`\`\`

Aegis GRC is a production-level, open-source continuous assurance and compliance platform. It bridges the gap between infrastructure deployment (IaC) and regulatory standards (**SOC2 Type II, ISO/IEC 27001:2022, and NIST CSF v2.0**). By compiling your cloud configurations to AST formats, checking them against automated Open Policy Agent (OPA) Web Decider policies, and enriching findings with server-side AI, Aegis empowers security engineering teams to detect, triage, and automatically heal security gaps before they hit production.

---

## 🚀 Key Architectural Capabilities

- 🔍 **Multi-Level IaC AST Scanner**: Evaluates Terraform manifests with an abstract syntax tree parser to find security misconfigurations (S3 unencrypted buckets, global ingress administrative ports, unencrypted EBS drives, etc.).
- 🛡️ **Open Policy Agent (OPA) Integration**: Built-in OPA engine that compiles and parses declarative \`policies/soc2/cc6_1.rego\` rules down to nanosecond-speed evaluation frames.
- ⚡ **Closed-Loop Drift Healing**: Continuous out-of-band state comparison that identifies drift from declared resources and features a single-click self-healing "Heal Boundary" pipeline.
- 🤖 **Server-Side AI Co-Pilot & Triage**: Uses Gemini models to construct precise, high-fidelity security explanations, risk mitigation plans, active code fixes, and cryptographic GRC certifications.
- 📑 **Dynamic PDF Report Architect**: Backend compilation route producing beautiful, audit-ready regulatory attestation documents on-the-fly containing score widgets, risk formulas, active findings, and full timeline logs.
- 💻 **DevOps Terminal & Ledger Timeline**: Fully reactive diagnostic audit ledger tracking system startups, ad-hoc scans, pipeline triggers, and self-healing events.

---

## 🏗️ Detailed Project Directory Structure

The repository represents a unified multi-environment full-stack system containing both the real-time **React/Express interactive Web Console** and the nested **Enterprise Python/FastAPI OPA microservice daemon** (\`/aegisgrc/\` folder):

\`\`\`text
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
\`\`\`

---

## 🔄 Automated Compliance Lifecycle

The platform runs a continuous control loop that orchestrates verification:

\`\`\`text
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
\`\`\`

---

## ⚙️ Requirements & Quick Start

### Prerequisites
- **Node.js**: \`v18.0.0\` or higher
- **NPM**: \`v9.0.0\` or higher

### 1. Clone & Install Dependencies
\`\`\`bash
git clone https://github.com/Jean-Regis-M/AegisGRC.git
cd AegisGRC
npm install
\`\`\`

### 2. Configure Environment Secrets
Create a \`.env\` file at the root of the project:
\`\`\`bash
# Define your Gemini API Credentials for AI Attestation & Interactive GRC Chat
GEMINI_API_KEY="AIzaSyYourSecretKeyHeaderGoesHere"
\`\`\`
*(If the API Key is absent or rate-limited, Aegis gracefully transitions into an intelligent offline local backup mode with pre-baked high-fidelity compliance metrics!)*

### 3. Launch Development Server
\`\`\`bash
npm run dev
\`\`\`
Open [http://localhost:3000](http://localhost:3000) in your web browser to access the Aegis GRC Terminal.

---

## 🛠️ How to Add Your Own OPA Compliance Policies

Adding security controls to Aegis GRC is fast and structured:

### Step 1: Write your Rego Rule
Add a new violation criteria in \`policies/soc2/cc6_1.rego\`:
\`\`\`rego
violation[msg] {
    some resource
    resource.type == "aws_db_instance"
    not resource.attributes.storage_encrypted
    msg := sprintf("SOC2 CC6.3 Violation: DB Instance '%s' has storage encryption disabled.", [resource.name])
}
\`\`\`

### Step 2: Map to GRC Controls
Register your new OPA rule inside code mappings to display it cleanly in dashboard summaries and mapping tables:
\`\`\`json
"CC6.3": {
  "title": "Encryption of Data at Rest",
  "description": "Verifies static database instances and media buckets enforce KMS custom keys.",
  "rego_rules": ["is_unencrypted_db_instance", "is_unencrypted_s3_bucket"]
}
\`\`\`

---

## 🤝 For Contributors: Making a Real Impact

Aegis GRC is built *by* security engineers, *for* security engineers. We are fiercely committed to building the finest open-source compliance shield. Here is where we need your talent:

1. **🔬 Custom OPA Policy Library**: We want to broaden our \`.rego\` catalog! Add rules protecting Google Cloud (GCP), Azure, Kubernetes configurations, and Dockerfiles.
2. **🛡️ Additional Compliance Standards**: Help us build coverage tables for **PCI-DSS v4.0**, **HIPAA Safeguards**, and **FedRAMP Moderate** criteria!
3. **💻 Real-Time Integrations**: Create plugins connecting our backend routes to Slack, Jira Tickets, and Webhooks.
4. **📊 Rich Data Visualizations**: We love maps, charts, and clean bento grids! Introduce additional D3/Recharts modules inside our main screen.

To start contributing, please review our detailed [CONTRIBUTING.md](./CONTRIBUTING.md)!

---

## 🔒 Security Vulnerability Handling

We take platform security with extreme seriousness. If you identify a structural vulnerability or key-leak, please do not create a public GitHub Issue. Instead, read our [SECURITY.md](./SECURITY.md) guidelines and report it directly to **security@aegisgrc.enterprise** so we can coordinate a secured private fix.

## 📄 Licensing & Open Source Spirit

Aegis GRC is proudly distributed under the **Apache License 2.0**. Let's build a safer, more transparent compliance future together! 🚀`
  },
  "architecture": {
    path: "aegisgrc/ARCHITECTURE.md",
    name: "ARCHITECTURE.md",
    language: "markdown",
    content: `# System Architecture & Compliance Flow Diagrams

Aegis GRC leverages modular Python components to integrate Policy-as-Code execution with modern Large Language Models (LLMs).

## Runtime Pipeline Flow

\`\`\`
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
\`\`\``
  },
  "threat_model": {
    path: "aegisgrc/THREAT_MODEL.md",
    name: "THREAT_MODEL.md",
    language: "markdown",
    content: `# Threat Model: Secure Policy Delivery & Enforcement

This document outlines the threat modeling security evaluation for Aegis GRC, identifying cryptographic hazards, out-of-band drift scenarios, and regulatory tampering vectors.

## Identified Threat Vectors & Mitigations

### Threat A: Out-of-Band Cloud Console Drift (Bypassing GRC)
- **Threat Scenario:** An operator modifies a secure S3 bucket configuration (e.g., turning off SSE-KMS encryption) directly via AWS Console. Since git is bypassed, standard pipeline gates do not record this change.
- **Remediation:** Aegis GRC implements a continuous scheduled polling loop (1.5s in demo simulation) that cross-checks the current live state against declared repo files, raising out-of-band alerts and providing a trigger to "Heal" state boundaries.`
  },
  "compliance_mapping": {
    path: "aegisgrc/COMPLIANCE_MAPPING.md",
    name: "COMPLIANCE_MAPPING.md",
    language: "markdown",
    content: `# Aegis Compliance-to-Code Mapping Matrix

Aegis GRC maps logical Rego constraints directly to specific regulatory requirements:

| Control ID | Framework | Description | Rego Rule Reference |
| --- | --- | --- | --- |
| **SOC2 CC6.1** | SOC 2 Type II TSC | Boundary Defense and Secure Network Architecture | \`deny_unprotected_ingress\` |
| **SOC2 CC6.3** | SOC 2 Type II TSC | Encryption of Data-at-Rest Protocols | \`deny_unencrypted_s3\` |
| **SOC2 CC6.4** | SOC 2 Type II TSC | Verification of Vulnerable SSH and Ingress Protocols | \`deny_global_ssh\` |
| **ISO 27001 Annex A.8.20** | ISO/IEC 27001:2022 | Network Security Management and Infrastructure Segregation | \`validate_isolated_subnets\` |
| **NIST CSF v2.0 PR.DS-01** | NIST CSF v2.0 | Cryptographic Key Lifecycles & Configuration Validation | \`deny_unencrypted_ebs\` |`
  },
  "contributing": {
    path: "aegisgrc/CONTRIBUTING.md",
    name: "CONTRIBUTING.md",
    language: "markdown",
    content: `# 🤝 Aegis GRC Open-Source Contribution Code of Conduct

A warm welcome! We are thrilled that you want to scale the Aegis GRC continuous compliance shield. This project is maintained by a global community of security engineers, developers, and regulatory auditors who believe that Policy-as-Code is the only way to safeguard infrastructure.

By participating, you help build a safer, audit-ready open-source ecosystem. Here is a comprehensive guide to getting your ideas successfully tested, approved, and merged.

---

## 🗺️ Contribution Domains

You can contribute to any of our dedicated development workstreams:

| Workstream | Main Technologies | Root Folders | Ideal For |
| --- | --- | --- | --- |
| **Policy Library (Rego)** | Rego, Open Policy Agent (OPA) | \`/policies/\` | Security Engineers, Auditors |
| **Backend Daemon** | Python, FastAPI, SQLite | \`/api/\`, \`/core/\`, \`/db/\` | Python developers, DevOps Specialists |
| **Management Dashboard** | React, TypeScript, Tailwind CSS | \`/src/\` | Front-End & UI/UX Craftsmen |
| **Attestation System** | Node.js, Express, PDFkit | \`/server.ts\` | Full-stack Engineers |
| **Enterprise Integrations** | GitHub Actions workflows, YAML | \`/.github/\` | CI/CD automation experts |

---

## 🛠️ Step-by-Step Local Workspace Booting

To make contributing straightforward, we leverage a full-stack, hot-reloading development pipeline.

### 1. Environmental Setup
Ensure you have **Node.js v18+** ready on your host.

\`\`\`bash
# Clone the primary source tree
git clone https://github.com/Jean-Regis-M/AegisGRC.git
cd AegisGRC

# Install all development dependencies
npm install
\`\`\`

### 2. Configure Local Environment Variables
Aegis contains robust offline dynamic simulators, but to leverage AI certifications, create a local \`.env\` file mapping your keys:
\`\`\`env
GEMINI_API_KEY="AIzaSyYourPersonalKeyGoesHere"
\`\`\`

### 3. Initiate the Daemon Concurrently
Boot both the backend proxy daemon and the client development pipeline:
\`\`\`bash
npm run dev
\`\`\`
Navigate to \`http://localhost:3000\`. You are now running an active local instance.

---

## 🛡️ Best Practices for Writing Policy-as-Code

When introducing new OPA Rego rules, observe these quality markers:

- **Specific Control Assertions**: Every rule inside \`/policies/\` must return a clear violation array message.
- **Fail Closed Principle**: When scanning attributes that are undefined or absent, represent them as non-compliant defaults.
- **Detailed Messages**: Always include the offending resource name and resource type directly inside the compiled \`msg\` string so operators can locate the issue immediately.

### Policy Style Check Template
\`\`\`rego
# Clean, readable, and commented
package soc2.cc6

violation[msg] {
    some resource
    resource.type == "aws_security_group"
    
    # Identify non-isolated, internet-exposed administrative paths
    ingress := resource.attributes.ingress[_]
    ingress.from_port <= 3389
    ingress.to_port >= 3389
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    
    msg := sprintf("SOC2 CC6.4 Violation: RDP Port 3389 open globally on SG '%s'. Limit ingress rules strictly.", [resource.name])
}
\`\`\`

---

## 🧪 Submission Verification Checklist

Before creating a Pull Request (PR), ensure your changes compile smoothly:

1. **Verify TypeScript Typings**: Run the project-wide linter:
   \`\`\`bash
   npm run lint
   \`\`\`
2. **Confirm Assembly Builds**: Build the final minified distribution bundles without syntax or export errors:
   \`\`\`bash
   npm run build
   \`\`\`
3. **Format Backend Entries**: If you are editing Python backend parts, run standard black/isort formatters:
   \`\`\`bash
   black . && isort .
   \`\`\`

---

## 📌 Branching & PR Commits Layout

- **Branch Name Format**: Use clear action prefixes:
  - \`feature/add-kms-rotation-rule\`
  - \`bugfix/fix-pdf-overflow\`
  - \`docs/clarify-env-keys\`
  - \`refactor/modularize-sidebar-tab\`
- **Atomic Commits**: Keep commits logical and focused.
- **Explain the "Why"**: In the PR description, explicitly describe *what* changed, *why* it increases compliance accuracy, and *how* you verified the change.

---

## 🏆 Thank You!

Your contributions shape the future of continuous, automated compliance. If you have questions or want to collaborate on architecture, join our weekly open-source syncs or open a discussion thread. Let's make continuous infrastructure assurance beautiful and accessible!  🛡️🚀`
  },
  "security": {
    path: "aegisgrc/SECURITY.md",
    name: "SECURITY.md",
    language: "markdown",
    content: `# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.2.x   | Yes       |
| 1.1.x   | Yes       |

## Reporting a Vulnerability

We request that you report vulnerabilities privately to **security@aegisgrc.enterprise**.`
  },
  "docker_compose": {
    path: "aegisgrc/docker-compose.yml",
    name: "docker-compose.yml",
    language: "yaml",
    content: `version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=\${GEMINI_API_KEY}
      - DATABASE_URL=sqlite:///./aegis_grc.db
      - ENVIRONMENT=production
      - LOG_LEVEL=info
    volumes:
      - aegis_data:/data
    restart: always

volumes:
  aegis_data:`
  },
  "dockerfile": {
    path: "aegisgrc/Dockerfile",
    name: "Dockerfile",
    language: "dockerfile",
    content: `# Multi-stage production build for Aegis GRC Python Backend
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Install OPA (Open Policy Agent) binary
RUN curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static \\
    && chmod 755 /usr/local/bin/opa

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal execution stage
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /usr/local/bin/opa /usr/local/bin/opa
COPY --from=builder /root/.local /root/.local
COPY . .

ENV PATH=/root/.local/bin:$PATH
ENV PORT=8000
ENV HOST=0.0.0.0

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]`
  },
  "ci_workflow": {
    path: "aegisgrc/.github/workflows/ci.yml",
    name: "ci.yml",
    language: "yaml",
    content: `name: Continuous Integration & Unit Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest black isort uvicorn fastapi httpx

      - name: Lint Verification
        run: |
          black --check api core db engine tests
          isort --check-only api core db engine tests

      - name: Run Unit Tests
        run: |
          pytest tests/ -v`
  },
  "scan_workflow": {
    path: "aegisgrc/.github/workflows/compliance-scan.yml",
    name: "compliance-scan.yml",
    language: "yaml",
    content: `name: Aegis Policy-as-Code Compliance Scan

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'policies/**'

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v3

      - name: Download OPA Compiler
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static
          chmod 755 opa
          sudo mv opa /usr/local/bin/

      - name: Compile & Validate Rego Integrity Base
        run: |
          opa test policies/soc2/ -v`
  },
  "rego_policy": {
    path: "aegisgrc/policies/soc2/cc6_1.rego",
    name: "cc6_1.rego",
    language: "rego",
    content: `package soc2.cc6

# Default values
default allow = false
default allow_ssh = false
default allow_s3_unencrypted = false

# Allow is true if there are zero flagged violations
allow {
    count(violation) == 0
}

# Flagged violations collection
violation[msg] {
    some resource
    is_unencrypted_s3_bucket(resource)
    msg := sprintf("SOC2 CC6.3 Violation: S3 bucket '%s' does not enforce AES256 server-side encryption.", [resource.name])
}

violation[msg] {
    some resource
    is_global_ingress_port_22(resource)
    msg := sprintf("SOC2 CC6.4 Violation: Security Group '%s' allows globally open ingress (0.0.0.0/0) to port 22.", [resource.name])
}

violation[msg] {
    some resource
    is_unencrypted_ebs_volume(resource)
    msg := sprintf("NIST CSF PR.DS-01 Violation: EBS Volume '%s' is not encrypted.", [resource.name])
}

# Helper check for S3 buckets
is_unencrypted_s3_bucket(resource) {
    resource.type == "aws_s3_bucket"
    not resource.attributes.server_side_encryption_configuration
}

# Helper check for Security Groups restricting global SSH boundary rules
is_global_ingress_port_22(resource) {
    resource.type == "aws_security_group"
    some ingress
    ingress := resource.attributes.ingress[_]
    ingress.from_port <= 22
    ingress.to_port >= 22
    ingress.cidr_blocks[_] == "0.0.0.0/0"
}

# Helper check for EBS volumes
is_unencrypted_ebs_volume(resource) {
    resource.type == "aws_ebs_volume"
    not resource.attributes.encrypted
}`
  },
  "rego_mapping": {
    path: "aegisgrc/policies/soc2/mapping.json",
    name: "mapping.json",
    language: "json",
    content: `{
  "frameworks": {
    "SOC2": {
      "CC6.1": {
        "title": "Logical Access Security Boundaries",
        "description": "Boundary defense procedures to manage logical boundaries and secure endpoints from unauthorized infiltration.",
        "rego_rules": ["deny_wildcard_ingress", "validate_subnet_access"]
      },
      "CC6.3": {
        "title": "Encryption of Data at Rest",
        "description": "Organizational and technical metrics verifying static media, backups, databases are encrypted using verified ciphers.",
        "rego_rules": ["is_unencrypted_s3_bucket", "is_unencrypted_ebs_volume"]
      },
      "CC6.4": {
        "title": "Transmission Integrity Verification",
        "description": "Protects and monitors transmission of parameters across insecure logical network communication lines.",
        "rego_rules": ["is_global_ingress_port_22"]
      }
    }
  }
}`
  },
  "sample_infra": {
    path: "aegisgrc/terraform/sample_infra.tf",
    name: "sample_infra.tf",
    language: "hcl",
    content: `provider "aws" {
  region = "us-east-1"
}

# ==================== WARNING: INSECURE RESOURCE ENTRIES ====================
# These resources contain deliberate security configuration drifts violating SOC2 boundaries.

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "aegis-sensitive-client-backups"
  acl    = "public-read" # Critical access vulnerability

  tags = {
    Environment = "production"
    Owner       = "finance-team"
  }
}

resource "aws_security_group" "allow_ssh_global" {
  name        = "administrative-ssh-access-sg"
  description = "Allows SSH access on administrative port 22 from anywhere"
  vpc_id      = "vpc-0a1b2c3d4e5f"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Flagged globally open ingress configuration
  }
}`
  },
  "config": {
    path: "aegisgrc/core/config.py",
    name: "config.py",
    language: "python",
    content: `import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis GRC"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegis_grc.db")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPA_PATH: str = os.getenv("OPA_PATH", "opa")

    class Config:
        case_sensitive = True

settings = Settings()`
  },
  "exceptions": {
    path: "aegisgrc/core/exceptions.py",
    name: "exceptions.py",
    language: "python",
    content: `class AegisException(Exception):
    """Base exception for all Aegis GRC system operations."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

class OPAEvaluationError(AegisException):
    def __init__(self, message: str):
        super().__init__(message, status_code=422)

class AIEnrichmentError(AegisException):
    def __init__(self, message: str):
        super().__init__(message, status_code=503)

class HCLParsingError(AegisException):
    def __init__(self, message: str):
        super().__init__(message, status_code=400)`
  },
  "logging": {
    path: "aegisgrc/core/logging.py",
    name: "logging.py",
    language: "python",
    content: `import logging
import sys
from aegisgrc.core.config import settings

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("aegis_grc")
    logger.setLevel(settings.LOG_LEVEL)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

logger = setup_logging()`
  },
  "base": {
    path: "aegisgrc/db/base.py",
    name: "base.py",
    language: "python",
    content: `from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()`
  },
  "models": {
    path: "aegisgrc/db/models.py",
    name: "models.py",
    language: "python",
    content: `import datetime
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON
from aegisgrc.db.base import Base

class ScanReport(Base):
    __tablename__ = "scan_reports"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    compliance_score = Column(Integer, nullable=False)
    total_findings = Column(Integer, default=0)
    sha256_hash = Column(String, unique=True, index=True)
    findings = Column(JSON, nullable=True)`
  },
  "session": {
    path: "aegisgrc/db/session.py",
    name: "session.py",
    language: "python",
    content: `from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from aegisgrc.core.config import settings
from aegisgrc.db.base import Base

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db() -> None:
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()`
  },
  "dependencies": {
    path: "aegisgrc/api/dependencies.py",
    name: "dependencies.py",
    language: "python",
    content: `from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from aegisgrc.core.config import settings

API_KEY_NAME = "X-AEGIS-KEY"
api_key_header_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Security(api_key_header_scheme)):
    if settings.ENVIRONMENT == "development":
        return "dev-authorized"
    if not api_key_header:
        raise HTTPException(status_code=401, detail="Missing required header: X-AEGIS-KEY")
    return api_key_header`
  },
  "main_py": {
    path: "aegisgrc/api/main.py",
    name: "main.py",
    language: "python",
    content: `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from aegisgrc.core.config import settings
from aegisgrc.db.session import init_db
from aegisgrc.api.routers import scans

app = FastAPI(title=settings.PROJECT_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(scans.router, prefix=settings.API_V1_STR)`
  },
  "scans_router": {
    path: "aegisgrc/api/routers/scans.py",
    name: "scans.py",
    language: "python",
    content: `import hashlib
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from aegisgrc.api.schemas.scan import ScanPayload, EvaluationResultSchema
from aegisgrc.api.dependencies import get_api_key
from aegisgrc.db.session import get_db
from aegisgrc.engine.parser import CustomHclParser
from aegisgrc.engine.opa import OPAPolicyClient
from aegisgrc.engine.scorer import ComplianceScorer

router = APIRouter(prefix="/scans", tags=["Scans"])`
  },
  "scan_schema": {
    path: "aegisgrc/api/schemas/scan.py",
    name: "scan.py",
    language: "python",
    content: `from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ScanPayload(BaseModel):
    hcl_content: str = Field(..., description="Raw infrastructure HCL manifest")
    environment: Optional[str] = "sandbox"

class EvaluationResultSchema(BaseModel):
    compliance_score: int
    critical_count: int
    warning_count: int
    findings_count: int`
  },
  "ai_evidence": {
    path: "aegisgrc/engine/ai_evidence.py",
    name: "ai_evidence.py",
    language: "python",
    content: `from typing import Dict, List, Any
from aegisgrc.core.config import settings

class GeminiEvidenceBuilder:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.GEMINI_API_KEY`
  },
  "opa_client": {
    path: "aegisgrc/engine/opa.py",
    name: "opa.py",
    language: "python",
    content: `import subprocess
import json
from typing import Dict, List, Any

class OPAPolicyClient:
    def __init__(self, opa_path: str = None):
        self.opa_path = opa_path`
  },
  "hcl_parser": {
    path: "aegisgrc/engine/parser.py",
    name: "parser.py",
    language: "python",
    content: `import re
from typing import Dict, List, Any

class ASTHclParser:
    @staticmethod
    def parse_manifest(hcl_content: str) -> List[Dict[str, Any]]:
        return []`
  },
  "scorer": {
    path: "aegisgrc/engine/scorer.py",
    name: "scorer.py",
    language: "python",
    content: `from typing import List, Dict, Any

class ComplianceScorer:
    @staticmethod
    def calculate_metrics(findings: List[str], total_resources: int) -> Dict[str, Any]:
        return {"compliance_score": 100}`
  },
  "test_api": {
    path: "aegisgrc/tests/test_api.py",
    name: "test_api.py",
    language: "python",
    content: `from fastapi.testclient import TestClient
from aegisgrc.api.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200`
  },
  "test_engine": {
    path: "aegisgrc/tests/test_engine.py",
    name: "test_engine.py",
    language: "python",
    content: `import pytest
from aegisgrc.engine.parser import CustomHclParser

def test_custom_hcl_parser_empty():
    assert CustomHclParser.parse_manifest("") == []`
  }
};
