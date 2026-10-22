# Security Policy & Hardening Architecture (PhishMatrix v4.0)

## Implemented Defensive Controls
1. **Zero Hardcoded Secrets:** All API keys are loaded strictly via environment variables (`.env` locally, encrypted Vercel secrets in production).
2. **SSRF & DNS Rebinding Shield:** Blocks RFC1918 private ranges, loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), and internal hostnames before any socket connection.
3. **DOM XSS Prevention:** Enforces strict HTML entity encoding (`escapeHTML`) across all client-side rendering and sets `Content-Security-Policy`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.
4. **AI Prompt Injection Sandbox:** Strips control characters and sandboxes untrusted telemetry inside `<untrusted_telemetry>` tags with system-level instruction overrides.
5. **WAF Rate Limiting:** Enforces per-IP sliding window rate limits (30 requests/minute).
