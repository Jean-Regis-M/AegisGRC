# Contributing to Aegis GRC

We welcome contributions of all forms to Aegis GRC, including new OPA Rego policies, Python FastAPI route improvements, and UI enhancements.

## Development Workflow

### 1. Style Guides
- **Python:** Use `black` and `isort` for formatting. All core functions must be annotated with TypeScript-like static type annotations.
- **Vite/React:** Follow the corporate high-contrast terminal design guidelines using strict tailwind utilities.
- **Rego:** Keep Rego statements modularized within logical `soc2_cc6` or `nist_csf` packages.

### 2. Testing Policies
Before raising a Merge/Pull Request, satisfy the local test coverage parameters:
```bash
poetry run pytest tests/ -v
```

Ensure any added Rego rules include companion unit tests (using `opa test`) placed in corresponding folders.
