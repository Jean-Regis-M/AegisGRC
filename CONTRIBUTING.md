# 🤝 Aegis GRC Open-Source Contribution Code of Conduct

A warm welcome! We are thrilled that you want to scale the Aegis GRC continuous compliance shield. This project is maintained by a global community of security engineers, developers, and regulatory auditors who believe that Policy-as-Code is the only way to safeguard infrastructure.

By participating, you help build a safer, audit-ready open-source ecosystem. Here is a comprehensive guide to getting your ideas successfully tested, approved, and merged.

---

## 🗺️ Contribution Domains

You can contribute to any of our dedicated development workstreams:

| Workstream | Main Technologies | Root Folders | Ideal For |
| --- | --- | --- | --- |
| **Policy Library (Rego)** | Rego, Open Policy Agent (OPA) | `/policies/` | Security Engineers, Auditors |
| **Backend Daemon** | Python, FastAPI, SQLite | `/api/`, `/core/`, `/db/` | Python developers, DevOps Specialists |
| **Management Dashboard** | React, TypeScript, Tailwind CSS | `/src/` | Front-End & UI/UX Craftsmen |
| **Attestation System** | Node.js, Express, PDFkit | `/server.ts` | Full-stack Engineers |
| **Enterprise Integrations** | GitHub Actions workflows, YAML | `/.github/` | CI/CD automation experts |

---

## 🛠️ Step-by-Step Local Workspace Booting

To make contributing straightforward, we leverage a full-stack, hot-reloading development pipeline.

### 1. Environmental Setup
Ensure you have **Node.js v18+** ready on your host.

```bash
# Clone the primary source tree
git clone https://github.com/Jean-Regis-M/AegisGRC.git
cd AegisGRC

# Install all development dependencies
npm install
```

### 2. Configure Local Environment Variables
Aegis contains robust offline dynamic simulators, but to leverage AI certifications, create a local `.env` file mapping your keys:
```env
GEMINI_API_KEY="AIzaSyYourPersonalKeyGoesHere"
```

### 3. Initiate the Daemon Concurrently
Boot both the backend proxy daemon and the client development pipeline:
```bash
npm run dev
```
Navigate to `http://localhost:3000`. You are now running an active local instance.

---

## 🛡️ Best Practices for Writing Policy-as-Code

When introducing new OPA Rego rules, observe these quality markers:

- **Specific Control Assertions**: Every rule inside `/policies/` must return a clear violation array message.
- **Fail Closed Principle**: When scanning attributes that are undefined or absent, represent them as non-compliant defaults.
- **Detailed Messages**: Always include the offending resource name and resource type directly inside the compiled `msg` string so operators can locate the issue immediately.

### Policy Style Check Template
```rego
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
```

---

## 🧪 Submission Verification Checklist

Before creating a Pull Request (PR), ensure your changes compile smoothly:

1. **Verify TypeScript Typings**: Run the project-wide linter:
   ```bash
   npm run lint
   ```
2. **Confirm Assembly Builds**: Build the final minified distribution bundles without syntax or export errors:
   ```bash
   npm run build
   ```
3. **Format Backend Entries**: If you are editing Python backend parts, run standard black/isort formatters:
   ```bash
   black . && isort .
   ```

---

## 📌 Branching & PR Commits Layout

- **Branch Name Format**: Use clear action prefixes:
  - `feature/add-kms-rotation-rule`
  - `bugfix/fix-pdf-overflow`
  - `docs/clarify-env-keys`
  - `refactor/modularize-sidebar-tab`
- **Atomic Commits**: Keep commits logical and focused.
- **Explain the "Why"**: In the PR description, explicitly describe *what* changed, *why* it increases compliance accuracy, and *how* you verified the change.

---

## 🏆 Thank You!

Your contributions shape the future of continuous, automated compliance. If you have questions or want to collaborate on architecture, join our weekly open-source syncs or open a discussion thread. Let's make continuous infrastructure assurance beautiful and accessible!  🛡️🚀
