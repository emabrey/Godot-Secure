# Security Policy

## Supported versions

Only the latest release of Godot Secure is actively maintained. Security fixes
are applied to the current release and released as a new version — older
releases do not receive back-ported patches.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Public issues are visible to everyone, including potential attackers, before a
fix is available.

Instead, use **GitHub's Private Vulnerability Reporting**:

1. Go to the [Security tab](https://github.com/emabrey/Godot-Secure/security)
   of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the form with as much detail as you can provide (see below).
4. Submit — the report is visible only to repository maintainers.

GitHub's documentation on the process:
https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

## What to include in your report

A useful report includes as many of the following as apply:

- **Summary** — a brief description of the issue and its potential impact.
- **Affected component** — which part of the script or which mode (`generate`,
  `apply`, `refresh`) is involved.
- **Reproduction steps** — the minimal command line or workflow configuration
  that triggers the issue.
- **Expected vs. actual behavior** — what should happen vs. what does happen.
- **Proof of concept** — sample code, a test script, or annotated output if
  available. Limit any included encryption keys or tokens to obviously fake
  test values.
- **Suggested fix** — optional, but appreciated if you have one.
- **Your contact information** — if you would like to be credited in the
  security advisory.

You do not need to have a complete proof of concept to file a report. Partial
information is still useful and will be investigated.

## Response timeline

| Milestone | Target |
|-----------|--------|
| Initial acknowledgement | Within 5 business days |
| Triage and severity assessment | Within 10 business days |
| Fix or mitigation available | Depends on complexity; kept you informed |
| Public advisory published | After fix is released |

If you have not received an acknowledgement within 5 business days please
follow up on the same private report thread — do not open a public issue.

## Scope

Reports are in scope if they involve:

- The `godot_secure.py` script itself (any mode or subcommand).
- The security token generation or derivation logic.
- The encryption key handling — including any scenario where a key could be
  exposed in logs, environment, or process arguments.
- The GitHub Actions integration (GodotSecureAction) when the issue originates
  in code owned by this project.
- Any dependency or interaction that undermines the stated security guarantees
  in the README.

Reports are **out of scope** if they describe:

- The fundamental limitation of client-side encryption (a determined attacker
  with debugger access to the running process can always extract the key — this
  is documented and by design; see the *Security model and limitations* section
  of the README).
- Vulnerabilities in Godot Engine itself, mbedTLS, or any third-party library
  (report those to the respective upstream projects).
- Theoretical attacks with no practical path to exploitation.

## Credits

Reporters who disclose vulnerabilities responsibly will be credited by name (or
handle) in the published GitHub Security Advisory for the issue, unless they
prefer to remain anonymous.
