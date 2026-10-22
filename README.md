<div align="center">

  <img src="https://img.shields.io/badge/PhishMatrix-v4.0_Enterprise_SOAR-06b6d4?style=for-the-badge&logo=shield&logoColor=white" alt="PhishMatrix Version" />
  <img src="https://img.shields.io/badge/Deployment-Vercel_Serverless-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Vercel Deployment" />
  <img src="https://img.shields.io/badge/Backend-FastAPI_Async-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Threat_Intel-12_Parallel_Feeds-f43f5e?style=for-the-badge&logo=virustotal&logoColor=white" alt="12 Threat Feeds" />
  <img src="https://img.shields.io/badge/AI_Failover-Llama_3.3_%7C_Gemini_2.5_%7C_Qwen_2.5-8b5cf6?style=for-the-badge&logo=google-gemini&logoColor=white" alt="AI Engines" />

  <h1>🛡️ PhishMatrix v4.0 — Autonomous Threat Intelligence & Phishing SOAR Platform</h1>
  
  <p>
    <strong>An enterprise-grade, fault-tolerant phishing investigation and security orchestration engine combining 12 parallel OSINT/Commercial threat feeds, Zero-Day Lexical & Entropy Heuristics, Deep RDAP/Port-43 WHOIS, Counter-Offensive DOM/C2 Unmasking, and a Waterfall Failover AI SOC Analyst.</strong>
  </p>

  <h3>
    🚀 <a href="https://phish-matrix-71kd.vercel.app/" target="_blank">Launch Live Platform (phish-matrix-71kd.vercel.app)</a>
    &nbsp;•&nbsp;
    📖 <a href="https://phish-matrix-71kd.vercel.app/docs" target="_blank">Interactive Swagger API Docs</a>
  </h3>

</div>

---

## 🎯 Problem Statement & Executive Overview

Conventional URL scanners rely strictly on static reputation blacklists. When a threat actor deploys a **Zero-Day Phishing Infrastructure** (registered minutes ago or hosted on abused cloud subdomains like Cloudflare Pages, Firebase, or Vercel), legacy lookup tools return `0/90 Clean` until victims report the breach.

**PhishMatrix v3.0** solves this gap by operating as a **6-Layer Autonomous Triage Engine**:
1. It unrolls multi-hop HTTP `301/302` redirects and inspects live DOM payloads before consulting reputation databases.
2. It correlates **12 Threat Intelligence Feeds** concurrently in under **4 seconds** using Python's `asyncio` and `httpx`.
3. It implements a **Zero-Failure Self-Healing Architecture**: if any external API key hits a rate limit or timeout, the orchestrator seamlessly synthesizes local network telemetry and zero-key OSINT feeds so investigations never fail.

---

## 🏗️ 6-Layer Defense Architecture

```text
                       ┌──────────────────────────────────────────┐
                       │   Suspicious URL / Domain / IP / Email   │
                       └────────────────────┬─────────────────────┘
                                            │
                            [ SSRF Loopback & Input Sanitizer ]
                                            │
         ┌──────────────────────┬───────────┴───────────┬──────────────────────┐
         ▼                      ▼                       ▼                      ▼
┌─────────────────┐   ┌──────────────────┐    ┌──────────────────┐   ┌──────────────────┐
│ LAYER 1: 12-API │   │ LAYER 2: ZERO-DAY│    │ LAYER 3: NETWORK │   │ LAYER 4: DEEP DOM│
│ THREAT FEEDS    │   │ HEURISTICS       │    │ & WHOIS FORENSICS│   │ & C2 UNMASKER    │
├─────────────────┤   ├──────────────────┤    ├──────────────────┤   ├──────────────────┤
│ • VirusTotal v3 │   │ • Levenshtein    │    │ • Hop-by-Hop     │   │ • Telegram Bot   │
│ • Google WebRisk│   │   Typosquatting  │    │   Redirect Trace │   │   getMe Unmasker │
│ • AbuseIPDB     │   │ • Punycode (xn--)│    │ • RDAP + Port-43 │   │ • ClickFix PS1   │
│ • URLScan.io    │   │ • Shannon Entropy│    │   Domain Age/NRD │   │   Hijack Hunter  │
│ • AlienVault OTX│   │ • Abused Cloud   │    │ • SSL/TLS Audit  │   │ • BitB Fake OAuth│
│ • Pulsedive     │   │   Host Detection │    │ • DNS A/MX/SPF/  │   │ • Base64/Hex JS  │
│ • GreyNoise     │   │ • FinTech Lures  │    │   DMARC Spoofing │   │   De-obfuscator  │
│ • Shodan CVEs   │   └────────┬─────────┘    └────────┬─────────┘   └────────┬─────────┘
│ • HudsonRock DB │            │                       │                      │
│ • ThreatFox/UH  │            └───────────┬───────────┘                      │
└────────┬────────┘                        │                                  │
         └─────────────────────────────────┼──────────────────────────────────┘
                                           ▼
                       ┌──────────────────────────────────────────┐
                       │  LAYER 5: UNIFIED RISK SCORER (0 - 100)  │
                       │  + WATERFALL AI FAILOVER SOC ANALYST     │
                       │  (Llama-3.3-70B ➔ Gemini-2.5 ➔ Qwen-2.5) │
                       └────────────────────┬─────────────────────┘
                                            ▼
                       ┌──────────────────────────────────────────┐
                       │  LAYER 6: BLUE-TEAM SOAR ARSENAL         │
                       │  • Auto-Generated YARA & Sigma Rules     │
                       │  • Suricata IDS & Linux UFW Block        │
                       │  • Splunk SPL & Sentinel KQL Queries     │
                       │  • Interactive Vis.js Threat Graph       │
                       │  • Automated Registrar Takedown Notice   │
                       └──────────────────────────────────────────┘
```

---

## 🔥 Core Capabilities

### 1. 🌐 12-Feed Parallel Threat Intelligence
* **Commercial & Community Reputation:** VirusTotal v3, Google Web Risk (SafeBrowsing), AbuseIPDB, URLScan.io Sandbox, AlienVault OTX (Global Threat Pulses), Pulsedive, and GreyNoise Community API.
* **Offensive OSINT & DarkWeb Telemetry:**
  * **Shodan & InternetDB:** Audits open ports and known CVEs on the target host IP.
  * **HudsonRock Cavalier OSINT:** Checks whether the domain has compromised credentials in **RedLine, Lumma, or Raccoon Infostealer** logs.
  * **Abuse.ch URLhaus & ThreatFox:** Detects active Botnet C2 nodes and malware payload distribution hosts.
  * **Certificate Transparency (`crt.sh`):** Enumerates historical SSL certificates and shadow subdomains.

### 2. 🕵️‍♂️ Counter-Offensive DOM & Payload Hunter
* **Telegram Bot C2 Unmasker:** Automatically extracts hardcoded `api.telegram.org/bot<TOKEN>` endpoints from phishing kits and queries Telegram's `getMe` API to expose the threat actor's Bot Name, Username, and Chat ID.
* **ClickFix Clipboard Hijack Detection:** Detects fake human-verification pages that silently inject malicious PowerShell (`mshta`, `iex`, `irm`) commands into the victim's clipboard via `navigator.clipboard.writeText()`.
* **Browser-in-the-Browser (BitB) & Discord Webhook Hunter:** Flags fake OAuth popup windows and unauthorized Discord webhook exfiltration endpoints.
* **Automated JS De-obfuscator:** Unpacks `atob()` Base64 and hexadecimal `\x` encoded JavaScript payloads in real time.

### 3. 🤖 Waterfall Failover AI Threat Analyst
To maximize speed and preserve API quotas, PhishMatrix uses a **Sequential Failover (Waterfall) Model**:
* **Primary Engine:** Queries `Llama-3.3-70B-Versatile` (via Groq Cloud) for sub-second Tier-3 SOC executive analysis.
* **Secondary & Tertiary Failover:** Automatically fails over to `Gemini-2.5-Flash` or `Qwen-2.5-Coder-32B` (via OpenRouter) if rate limits occur, backed by a deterministic local neural heuristic engine.
* **Behavioral Lure Telemetry:** Quantifies Urgency Lures, Authority Spoofing, Coercion/Panic Index, and Technical Evasion.

### 4. 🛡️ Automated Blue-Team Detection Engineering (SOAR)
Every scan automatically generates copy-ready defensive rules tailored to the investigated IOCs:
* **YARA Rule** targeting the domain and DOM exfiltration strings.
* **Sigma Rule** for SIEM DNS/Web Proxy log correlation.
* **Suricata IDS Signature** & **Linux UFW / `/etc/hosts` Sinkhole Command**.
* **Splunk SPL** & **Microsoft Sentinel KQL** threat-hunting queries.
* **Registrar & CERT-In Abuse Takedown Notice** pre-filled with RDAP abuse contacts and forensic timestamps.

---

## 💻 Kali Linux Terminal Direct Mode (`/cli`)

Security analysts can investigate any suspicious URL directly from a Linux terminal without opening a browser:

```bash
curl -s "https://phish-matrix-71kd.vercel.app/cli?url=verify-human-cloudflare-cdn.xyz"
```

---

## 📂 Project Structure

```text
PhishMatrix/
├── app/
│   ├── main.py                # FastAPI endpoints (/api/v1/scan, /email-scan, /bulk-scan, /cli)
│   ├── orchestrator.py        # Async parallel coordinator & unified risk scoring engine
│   ├── security.py            # SSRF loopback protection, URL normalization & IOC defanging
│   ├── email_parser.py        # Raw .eml header analyzer (SPF/DKIM/DMARC & hop extraction)
│   └── engines/
│       ├── threat_intel.py    # 12-Feed async connector (VT, WebRisk, AbuseIPDB, OTX, Shodan, etc.)
│       ├── heuristics.py      # Zero-day Levenshtein typosquatting, Punycode & Shannon entropy
│       ├── forensics.py       # Dual-engine RDAP + Port-43 WHOIS, SSL/TLS audit & DNS records
│       ├── dom_hunter.py      # ClickFix, BitB, Telegram getMe unmasker & JS de-obfuscator
│       ├── darkweb.py         # HudsonRock infostealers, Abuse.ch C2 feeds & crt.sh subdomains
│       ├── ai_council.py      # Waterfall AI failover (Groq ➔ Gemini ➔ OpenRouter)
│       └── soc_generator.py   # YARA, Sigma, Suricata, Splunk SPL, KQL & Takedown generator
├── static/
│   └── index.html             # Cyberpunk SOC Dashboard (TailwindCSS + Vis.js Threat Graph)
├── .github/workflows/ci.yml   # Automated GitHub Actions Pytest CI pipeline
├── test_phishmatrix.py        # Automated security & orchestrator unit tests
├── requirements.txt           # Production Python dependencies
├── vercel.json                # Vercel Serverless deployment configuration
└── .env.example               # Template for Threat Intel & AI API keys
```

---

## ⚙️ Local Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/ayushkp930/PhishMatrix.git
cd PhishMatrix
```

### 2. Create Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy the example environment file and add your API keys (the platform also runs safely in autonomous mode if keys are omitted):
```bash
cp .env.example .env
```

| Environment Variable | Service | Purpose |
| :--- | :--- | :--- |
| `VT_API_KEY` | VirusTotal v3 | Multi-vendor malware & phishing reputation |
| `WEBRISK_API_KEY` | Google Web Risk | Google SafeBrowsing threat classification |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP abuse confidence score & ISP telemetry |
| `URLSCAN_API_KEY` | URLScan.io | Sandbox DOM snapshot & visual screenshot |
| `OTX_API_KEY` | AlienVault OTX | Global threat pulses & APT correlation |
| `PULSEDIVE_API_KEY` | Pulsedive | Community IOC risk scoring |
| `GREYNOISE_API_KEY` | GreyNoise | Internet scanner vs. malicious actor classification |
| `SHODAN_API_KEY` | Shodan | Open port enumeration & CVE vulnerability mapping |
| `GROQ_API_KEY` | Groq Cloud | Primary `Llama-3.3-70B` ultra-fast SOC inference |
| `GEMINI_API_KEY` | Google AI Studio | Secondary `Gemini-2.5-Flash` failover engine |
| `OPENROUTER_API_KEY` | OpenRouter | Tertiary `Qwen-2.5-Coder` failover engine |

### 4. Run Automated Security Tests & Start Server
```bash
pytest -v
uvicorn app.main:app --reload --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 👨‍💻 Author

**Ayush Kumar Patel**  
*Cybersecurity & Cloud Security Researcher*  
* **GitHub:** [@ayushkp930](https://github.com/ayushkp930)  
* **Live Deployment:** [https://phish-matrix-71kd.vercel.app/](https://phish-matrix-71kd.vercel.app/)
