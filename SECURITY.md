# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | ✅ Active |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues to: **security@marineso.com**

We will respond within **5 business days** and provide a fix timeline.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## Disclosure Policy

- We follow **Coordinated Vulnerability Disclosure (CVD)**
- Vulnerabilities are patched before public disclosure
- Credit given to researchers who report responsibly
- No legal action against good-faith researchers

## Scope

In scope:
- `stivr4469/compliance-sandbox` repository code
- Evidence Tracker API (`http://localhost:8000`)
- All SOC 2 compliance agents

Out of scope:
- Third-party dependencies (report upstream)
- Issues in LocalStack itself

## Security Controls

This project maintains SOC 2 Type II compliance. Key controls:
- All changes require PR review (CC8.1)
- Secrets managed via environment variables, never hardcoded (CC6.7)
- Automated vulnerability scanning via Dependabot (CC6.8)
- Incident response policy: see `policies/` directory (CC7.4)
