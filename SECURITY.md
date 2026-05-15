# Security Policy

## Reporting a vulnerability

Please report security issues privately instead of opening a public issue. Include a clear description, reproduction steps, affected files or flows, and the likely impact.

## Areas to review carefully

- WebAuthn registration and login flows
- session handling
- rate limiting
- environment secrets

## Secret handling

- Never commit credentials, tokens, private keys, or populated `.env` files.
- Rotate exposed credentials immediately.
- Prefer least-privilege configuration for services and deployment targets.
