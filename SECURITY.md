# Security Policy

## Supported versions

Security fixes are applied to the latest release line.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that crosses a trust boundary, exposes private memory, permits path escape, or enables code execution.

Use GitHub's private vulnerability reporting for this repository. Include:

- affected version and platform;
- reproduction steps;
- expected and observed behavior;
- whether a malicious record, filesystem object, tool argument or environment variable is required;
- minimal logs with credentials and private memory removed.

Prompt injection preserved only as inert historical data, without a separate authority-boundary escape, may be reported as a regular hardening issue. When unsure, report privately.

## Scope

High-priority areas include:

- recall gaining instruction authority;
- session or workspace scope bypass;
- database/WAL/SHM/lock path substitution;
- symlink, junction or hardlink attacks;
- secret leakage through recall, exports, errors or logs;
- malformed or oversized data crossing the Python/Rust boundary;
- command injection or unsafe subprocess use;
- rollback or restore accepting an unauthenticated artifact.

Never include real API keys, OAuth tokens, passwords, client data or unredacted vault contents in a report.
