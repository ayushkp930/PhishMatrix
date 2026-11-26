# PhishMatrix security

## Application controls

- A submitted URL is parsed and assessed as an indicator. The server does not connect to its web origin, follow its redirects or retrieve HTML, files or screenshots. The optional DNS lookup is a resolver query and rejects non-public answers. Network enrichment uses known registry or contracted provider endpoints with TLS verification, provider response limits and HTTP deadlines.
- The frontend uses `textContent` and DOM methods to display untrusted values as text. The same-origin content security policy disables inline scripts, plugins, framing and cross-origin requests from the dashboard.
- JSON request bodies have a 128 KiB limit, an intake timeout and individual field limits. Scan API calls have process-local request and concurrency limits. Use upstream quotas or authentication for shared or public installations since serverless instances have independent counters.
- Email and HTML inputs are treated as untrusted evidence. They are neither executed nor sent to an AI service. Cases remain in browser memory until exported or cleared. Paste headers are not proof of sender authentication.
- The **LOL** honeypot returns HTTP 418 on selected probes. It logs a generic category and does not reflect submitted payloads. It is a supplementary detection control.
- Keep secrets in deployment settings or a local `.env`. The example file contains placeholders. If previous committed values were active, revoke and replace them in their provider accounts and review provider logs for unauthorized use.

These controls and tests cover selected failure modes. Public production use also requires maintained dependencies, controlling outbound traffic at the hosting layer, secure reverse-proxy configuration, and review against the deployment environment.

## Reporting

Send reports privately to the repository maintainer. Describe the affected version, impact, and relevant evidence, with sensitive values removed. Use an isolated test instance and keep public production endpoints out of your validation.
