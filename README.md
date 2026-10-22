<div align="center">
  <img src="https://img.shields.io/badge/PhishMatrix-v6.0_Enterprise_Workbench-59d5e8?style=for-the-badge&logo=shield&logoColor=0a0e19" alt="Version">
  <img src="https://img.shields.io/badge/Threat_Engines-16+_Parallel_Feeds-4ed4a0?style=for-the-badge" alt="16 Feeds">
  <img src="https://img.shields.io/badge/WAF_&_Deception-HTTP_418_Honeypot-f6bf64?style=for-the-badge" alt="Honeypot">
  <img src="https://img.shields.io/badge/Python-FastAPI_Async-0284c7?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-b39aff?style=for-the-badge" alt="License">

  <h1>🛡️ PhishMatrix v6.0 — Threat Intelligence Workbench & Autonomous SOAR</h1>
  <p><b>An enterprise-grade, asynchronous phishing investigation platform orchestrating 16 Threat Intelligence Feeds, a Smart Failover AI SOC Analyst Council, a 1,000+ Domain Zero-Quota Whitelist, an Active Deception WAF Honeypot, and 12 Automated Blue-Team Detection Rules.</b></p>

  <h3>
    🚀 <a href="https://phish-matrix-71kd.vercel.app/" target="_blank">Launch Live Workbench (Vercel)</a>
    &nbsp;•&nbsp;
    📖 <a href="https://phish-matrix-71kd.vercel.app/docs" target="_blank">OpenAPI / Swagger</a>
    &nbsp;•&nbsp;
    🌐 <a href="https://ayushkp930.github.io" target="_blank">Author Portfolio</a>
  </h3>
</div>

---

## ⚡ Executive Overview

Traditional URL scanners rely exclusively on static blocklists, leaving organizations blind to **Zero-Day Phishing**, newly registered domains (NRDs), and client-side evasion techniques. **PhishMatrix v6.0** solves this by combining **16 parallel OSINT & commercial intelligence connectors** with deep **RDAP/Port-43 WHOIS**, **DOM payload de-obfuscation**, **counter-offensive C2 bot unmasking**, and an **AI SOC Analyst Failover Council**—delivering a deterministic risk score, interactive relationship graph, and prioritized remediation playbook in **under 4 seconds**.

---

## 🔥 Core Architecture & Capabilities

### 1. 🌐 16-Engine Parallel Threat Intelligence Matrix
Executes non-blocking asynchronous queries (`httpx` + `asyncio`) with **Zero-Failure Silent Self-Healing**:
* **Reputation & SafeBrowsing:** VirusTotal v3, Google Web Risk, URLScan.io Sandbox, AbuseIPDB.
* **Global Threat Pulses & Scanners:** AlienVault OTX, Pulsedive Community Intel, GreyNoise Community API, Shodan / InternetDB (Open Ports & CVEs).
* **Malware, Botnet C2 & DarkWeb:** Authenticated Abuse.ch (**URLhaus** & **ThreatFox**), **MalShare** Malware Hash DB, **Stamparm Maltrail** GitHub Feed, **HudsonRock Cavalier** (RedLine/Lumma Infostealer Logs).
* **Network, DNSBL & Email Hygiene:** **Project Honey Pot (`HTTP:BL`)** DNS Blacklist, **Mailboxlayer** MX/Disposable Domain Audit, **IP-API.com** (Proxy, VPN, Tor Exit & Datacenter Hosting Detection), **crt.sh** Certificate Transparency Logs, and Dual-Engine **RDAP + Port-43 WHOIS**.

### 2. ⚡ 1,000+ Trusted Domain Whitelist Engine (Zero API Quota Waste)
* Built-in fast-path covering **1,000+ verified global and Indian enterprise/government domains** (`github.com`, `google.com`, `microsoft.com`, `onlinesbi.sbi`, `gov.in`, `nic.in`, etc.).
* Resolves known benign baselines in **`<0.5 seconds` while consuming `0` external API credits**, preserving rate limits for genuine suspicious indicators.

### 3. 🍯 Active Deception WAF, SSRF Guard & Hidden Honeypot (`HTTP 418`)
* **Strict SSRF & DNS-Rebinding Shield:** Blocks RFC1918 private networks, loopback (`127.0.0.1`, `::1`), cloud metadata (`169.254.169.254`), and hex/octal IP encoding tricks while supporting cellular NAT64 (`64:ff9b::/96`) resolution.
* **WAF & Prompt Injection Sandbox:** Intercepts XSS (`<script>`, event handlers), SQLi (`UNION SELECT`, `' OR 1=1`), OS Command Injection, Path Traversal (`../../`), and LLM Prompt Injection attempts, trapping attackers with a custom **`HTTP 418 I'm a Teapot` Active Deception Honeypot** response.
* **Decoy Trap Routes:** Monitors unauthorized probes to `/admin`, `/.env`, `/wp-admin`, `/config.json`, and `/phpmyadmin`.

### 4. 🧠 Smart Failover AI SOC Analyst Council
* Uses a cost-optimized waterfall failover chain: **Llama-3.3-70B (Groq) ➔ Gemini-2.5-Flash ➔ Qwen-2.5-Coder-32B (OpenRouter) ➔ Autonomous Local Neural Engine**.
* Sandboxes untrusted indicator telemetry inside `<untrusted_telemetry>` tags to prevent indirect prompt injection.

### 5. 🕵️‍♂️ Counter-Offensive DOM Hunter & Zero-Day Heuristics
* **Telegram C2 Bot Unmasker:** Extracts hardcoded bot tokens from phishing kits and queries Telegram's `getMe` API to expose the attacker's bot identity.
* **Modern Attack Vector Detection:** Flags **ClickFix Clipboard PowerShell Hijacks**, Browser-in-the-Browser (BitB) OAuth popups, Web3 Crypto Drainers, Levenshtein brand typosquatting, Shannon entropy (DGA), and IDN Punycode (`xn--`) homographs.

### 6. 🛡️ 12 Automated Blue-Team Defensive Artifacts & SOC Playbook
Automatically generates copy-ready detection rules and prioritized **P1/P2/P3 Remediation Playbooks**:
* **Endpoint & File:** YARA Phishing Kit Rule, Windows Defender PowerShell Block.
* **SIEM & Log Hunting:** Sigma YAML Rule, Splunk SPL, Microsoft Sentinel KQL, CrowdStrike Falcon LogScale (CQL), Elastic Kibana KQL.
* **Network & Perimeter WAF:** Suricata / Snort 3 IDS Rules, Zeek (Bro) DNS Script, Cloudflare WAF Expression, ModSecurity OWASP CRS `SecRule`, Linux UFW / `iptables` + DNS Sinkhole, and Registrar / CERT-In Abuse Takedown Notice.

---

## 🧪 Verified Live Production Diagnostics (`8/8 PASSED`)

```text
🚀 Initiating Full System Diagnostics on: https://phish-matrix-71kd.vercel.app
================================================================================
[✓] PASS | 1. Health Endpoint & WAF Status               | Status: 200
[✓] PASS | 2. Decoy Route Honeypot (/admin)              | HTTP 418 Teapot Blocked
[✓] PASS | 3. XSS Payload WAF Interception               | Malicious script blocked!
[✓] PASS | 4. SSRF Cloud Metadata Guard                  | Internal IP scan blocked!
[✓] PASS | 5. Trusted 1000+ Domain Whitelist Fast-Path   | 0 API Credits used. Time: 0.47s
[✓] PASS | 6. Deep 16-Engine & AI Triage Validation      | 17 Engines | Time: 3.73s | SOC Rules: True
[✓] PASS | 7. Email Header & Spoofing Analyzer           | Risk Score: 100/100
[✓] PASS | 8. Bulk Triage & Parallel Batch Processor     | Successfully processed 3 varied IOCs
================================================================================
```

---

## 💻 Kali Linux Terminal CLI Mode

Query the live engine directly from your terminal for instant ANSI-colored ASCII triage:

```bash
# Scan a suspicious indicator
curl -s "https://phish-matrix-71kd.vercel.app/cli?url=verify-human-cloudflare-cdn.xyz"

# Test the Active Deception Honeypot from CLI
curl -s "https://phish-matrix-71kd.vercel.app/cli?url=http://127.0.0.1/admin"
```

---

## 📂 Project Structure

```text
PhishMatrix/
├── app/
│   ├── main.py                  # FastAPI Workbench API, WAF Middleware, Rate Limiter & Decoy Routes
│   ├── orchestrator.py          # 16-Engine Async Coordinator, SOC Playbook & Graph Builder
│   ├── security.py              # SSRF Guard, NAT64 Handler, XSS/SQLi/RCE Honeypot & Defanger
│   ├── whitelist.py             # 1,000+ Verified Global & Indian Enterprise Domain Fast-Path
│   ├── email_parser.py          # RFC-5322 Email Header Spoofing + Mailboxlayer Analyzer
│   └── engines/
│       ├── threat_intel.py      # VT, WebRisk, AbuseIPDB, URLScan, OTX, Pulsedive, GreyNoise, Shodan, MalShare, Mailboxlayer, IP-API
│       ├── darkweb.py           # Auth URLhaus, ThreatFox, Maltrail GitHub, Project Honey Pot HTTP:BL, HudsonRock, crt.sh
│       ├── dom_hunter.py        # Telegram getMe Unmasker, ClickFix, BitB, Crypto Drainer & JS De-obfuscator
│       ├── forensics.py         # Dual-Engine RDAP + Port-43 WHOIS, TLS Audit, DNS (SPF/DMARC) & Redirect Unroller
│       ├── heuristics.py        # Levenshtein Typosquatting, Shannon Entropy, Punycode & Lure Heuristics
│       ├── ai_council.py        # Failover AI Analyst (Groq Llama-3.3-70B -> Gemini-2.5 -> OpenRouter Qwen-2.5)
│       └── soc_generator.py     # 12 Blue-Team Rules (YARA, Sigma, Suricata, SPL, KQL, CQL, WAF, Zeek, UFW)
├── static/
│   └── index.html               # Threat Intelligence Workbench UI (Overview, URL, Email, Bulk, Rules, Ledger)
├── test_phishmatrix.py          # Automated Pytest Security & Orchestrator Test Suite
├── system_diagnostics.py        # End-to-End Live Production Verification Script
├── SECURITY.md                  # Defensive Controls & Vulnerability Disclosure Policy
├── LICENSE                      # MIT License
├── requirements.txt
└── vercel.json
```

---

## ⚙️ Local Setup & Testing

```bash
git clone https://github.com/ayushkp930/PhishMatrix.git
cd PhishMatrix
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run Unit & Security Test Suite
pytest -v

# Run Full Production Diagnostics
python3 system_diagnostics.py

# Start Local Workbench Server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 👨‍💻 Author & License

Engineered by **[Ayush Kumar Patel](https://github.com/ayushkp930)**  
🌐 Portfolio: [ayushkp930.github.io](https://ayushkp930.github.io) • 🔗 LinkedIn: [Ayush Kumar Patel](https://www.linkedin.com/in/ayush-kumar-patel-5a7985368/)

Licensed under the **MIT License** — see [`LICENSE`](LICENSE) and [`SECURITY.md`](SECURITY.md) for details.