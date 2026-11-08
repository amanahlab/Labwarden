# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker gains. You can expect an answer within a week. Fixes are released as soon as they are ready, and the advisory credits you unless you prefer otherwise.

## Supported versions

Only the latest release and `main` get security fixes.

## Scope

LabWarden is meant for a home lab or a small trusted network. The README section "Security model" describes what each credential can do and how to deploy with TLS and a Docker socket proxy. The `testbed/` directory contains deliberately vulnerable packages and images for testing; reports about them are out of scope.
