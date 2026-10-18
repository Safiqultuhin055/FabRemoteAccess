# Security Policy

## Supported versions

Fabulous Remote is in **preview**. Only the latest code on `main` receives security fixes. The preview installer is not code-signed and is not intended for production use.

## Reporting a vulnerability

Please report vulnerabilities **privately**:

- Use GitHub's **"Report a vulnerability"** button on this repository's **Security** tab (private vulnerability reporting), or
- contact the repository owner directly through GitHub.

Please do **not** open a public issue, pull request or discussion for a suspected vulnerability.

Include as much of the following as you can:

- affected component (backend, desktop client, database scripts, installer, landing page) and version or commit;
- steps to reproduce, or a proof of concept;
- the impact you expect (for example authentication bypass, consent bypass, data exposure);
- any suggested fix.

Please do not access other people's data or computers, and do not run denial-of-service tests.

## Scope highlights

Reports are especially welcome for:

- anything that allows a remote session, or device registration, **without** the required approval or proof of key possession;
- authentication, token, session or CSRF weaknesses;
- Remote ID reuse, enumeration or misuse as a credential;
- secrets appearing in logs, audit records, responses or the installer;
- privilege escalation through the database roles.

## Design documentation

The security requirements, threat model, verified controls and known limitations are documented in [docs/SECURITY.md](docs/SECURITY.md).
