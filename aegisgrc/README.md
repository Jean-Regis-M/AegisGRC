# Aegis GRC: Continuous Policy-as-Code & AI Compliance Shield

Aegis GRC is a next-generation Policy-as-Code engine and continuous compliance dashboard crafted for modern dev teams. It validates infrastructure manifests (such as Terraform configurations) against complex regulatory guidelines (SOC2, ISO/IEC 27001, and NIST CSF v2.0) using the Open Policy Agent (OPA) compiler, and enriches critical alert states with server-side AI-driven mitigation blueprints.

## Repository Tree Architecture

```
aegisgrc/
├── .github/workflows/
│   ├── ci.yml
│   └── compliance-scan.yml
├── api/
│   ├── main.py
│   ├── dependencies.py
│   ├── routers/
│   │   └── scans.py
│   └── schemas/
│       └── scan.py
├── core/
│   ├── config.py
│   ├── exceptions.py
│   └── logging.py
├── db/
│   ├── base.py
│   ├── models.py
│   └── session.py
├── engine/
│   ├── ai_evidence.py
│   ├── opa.py
│   ├── parser.py
│   └── scorer.py
├── policies/soc2/
│   ├── cc6_1.rego
│   └── mapping.json
├── terraform/
│   └── sample_infra.tf
├── tests/
│   ├── test_engine.py
│   └── test_api.py
├── docker-compose.yml
├── Dockerfile
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── COMPLIANCE_MAPPING.md
├── CONTRIBUTING.md
└── SECURITY.md
```

## Features

- **AST Parsing Engine:** Deconstructs Terraform manifests into intermediate operational parameters.
- **OPA Rego Enforcement:** Executes complex decalarative constraints (e.g. S3 server-side encryption toggles, open secure boundary ports).
- **Gemini AI Evidence Generator:** Automatically drafts a cryptographically synchronized compliance ledger mapping identified risks to specific regulatory controls.
- **Continuous GRC Timeline Database:** Traces system check-ins, manual drift events, and automatic self-healing operations securely.

## Getting Started

### Prerequisites

- Python 3.11+
- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa)
- Docker & Docker Compose

### Fast Startup

1. **Clone & Setup Environment:**
   ```bash
   cp .env.example .env
   # Add your GEMINI_API_KEY to .env
   ```

2. **Spin-up Services with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

3. **Verify Health Endpoint:**
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

### Running Scans

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"hcl_content": "resource \"aws_s3_bucket\" \"unencrypted\" {\n  bucket = \"unencrypted-data-bucket\"\n}"}' \
  http://localhost:8000/api/v1/scans/evaluate
```

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
