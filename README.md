# PhishMatrix 7.8.1 · Email Investigation Console

The dashboard accepts a pasted raw message or a UTF-8/ASCII `.eml` file up to 50 KB. Run the scan to export case JSON, a static PDF summary or a SIEM event. Existing URL, HTML, bulk and hash API routes remain available. A different Reply-To domain is contextual unless the email also contains a deceptive or listed link. An attached email is reported as a separate artifact. Scan it separately to inspect its contents.

A password expiry or account suspension subject with a short deadline and pressure to act scores 20, below the alert threshold. A direct request in the message body to send a password or code scores 35. The body rule ignores common quoted-text markers and HTML blockquotes. These narrow rules currently match English wording.

PhishMatrix is a FastAPI phishing triage tool for URLs, domains, IPs, submitted email and inert HTML samples. Each verdict includes the contributing detection rules and the status of the sources queried. The browser session can export case JSON with analyst notes and disposition. Individual investigations export a timestamped SIEM event with the same case ID as the report.

## Run locally

Requires Python 3.11 or later.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On Linux or macOS, use `python3` and `.venv/bin/python`. Open `http://127.0.0.1:8000`. **Load training sample** runs an offline HTML scenario with a credential form and deceptive link labels.

## Investigation modes

| Mode | Evidence |
| --- | --- |
| URL / domain / IP | RDAP, optional registry WHOIS fallback, local indicators, brand lookalike rules, optional provider reputation |
| Email | Sender, Reply-To, envelope domain, link-label mismatches, defanged links and attachment names |
| HTML sample | Credential forms that post to a different domain, messaging webhook form destinations, link-label mismatches and ClickFix patterns |
| File hash | Exact MD5, SHA-1 or SHA-256 metadata lookup, whole-file YARA and Windows process image hash hunts |
| Bulk | Up to eight indicators, with a separate outcome for each |

The URL scanner does not request the submitted page. Default outbound traffic for URL investigations goes to registration authorities and configured intelligence providers. Submitted queries stay local. Web Risk defaults to origin-only lookups, with an explicit deployment setting for public paths. Query values are also removed from exported URLs. HTML and email are interpreted as text without executing scripts, opening attachments or fetching embedded resources.

## Detection and scoring

- A domain registered within 24 hours adds 40 points and reaches `SUSPICIOUS`. A date-only result qualifies for that band on the current UTC date. A domain aged 1–30 completed days adds 35.
- Direct RDAP lookups use Verisign for `.com` and `.net`, NIXI for `.in`, and the IANA bootstrap registry for other supported suffixes. The Public Suffix List identifies the registered domain behind URLs such as `login.example.co.in`.
- Current exact URL matches from a trusted provider or local feed can reach `MALICIOUS`. Registration age, IP reputation, lexical features and submitted artifact behavior are capped below that threshold.
- The rule engine counts each rule once and caps related evidence. The evidence score measures weighted findings on a 0–100 scale. Source coverage determines how to read low scores. An ordinary password field, a normal email link and pasted authentication claims contribute no risk points by themselves.
- Shared-hosting tenant creation time differs from provider-domain registration age. The results flag known shared hosting, and an exact URL match can still raise the score.

Run the offline scoring benchmark with `python -m scripts.evaluate_rules`. It reports triage precision, recall and fixture-level errors. These fixtures are synthetic and do not establish production accuracy.

## Kaggle dataset model

The included URL model uses 15 local structural features. It shows an analyst context score and leaves the deterministic verdict and risk score independent. The model is trained on historical labels and can miss current phishing or overflag legitimate URLs.

Training used 393,134 rows and threshold selection used 59,492 validation rows. Registered domains were assigned to mutually exclusive train, validation and test partitions by a stable hash. The evaluations below used the held-out partitions of three dataset samples. The two additional datasets may share providers or collection conventions and the sample mix differs from operational traffic.

| Dataset | Tested URLs | Model precision | Model recall | Benign false-positive rate |
| --- | ---: | ---: | ---: | ---: |
| [Malicious URLs](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) | 1,495 | 56.0% | 30.5% | 23.4% |
| [Phishing URL Features Dataset](https://www.kaggle.com/datasets/elifzelik/phishing-url-features-dataset) | 1,762 | 94.5% | 65.4% | 4.4% |
| [Phishing URLs with Extracted Features](https://www.kaggle.com/datasets/victusadi/phishing-urls-dataset-with-extracted-features) | 1,140 | 98.8% | 77.5% | 5.3% |

The bundled coefficients are derived from *Phishing URL Features Dataset* by Elif Özçelik, Farah ElSilk and Murat Osmanoglu. The dataset is [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), [DOI 10.34740/KAGGLE/DSV/15339081](https://doi.org/10.34740/kaggle/dsv/15339081). The changes were URL normalization, selection of local features and domain-grouped fitting. The source datasets are downloaded separately.

```bash
python -m scripts.evaluate_datasets malicious-urls-dataset.zip phishing-url-features-dataset.zip phishing-urls-dataset-with-extracted-features.zip
```

To retrain, install scikit-learn in your development environment and run `python -m scripts.train_dataset_model phishing-url-features-dataset.zip`. The application uses the resulting JSON coefficients without scikit-learn at runtime.

## Optional threat intelligence

For local setup, copy `.env.example` to `.env`. On Vercel, use **Project → Settings → Environment Variables** in the same project. Existing values keep the names below. Select Production or Preview as appropriate, then create a fresh deployment for that environment. Keep actual keys in Vercel and outside the repo. [Vercel environment variables](https://vercel.com/docs/environment-variables)

| Provider | Environment variables or route |
| --- | --- |
| VirusTotal | `VT_API_KEY` and `PHISHMATRIX_VT_SHARE=1` for public indicators |
| Google Web Risk | `WEBRISK_API_KEY`. Origin lookup by default. `PHISHMATRIX_WEBRISK_PATH_SHARE=1` includes public paths while omitting the query. |
| URLScan | `URLSCAN_API_KEY`. Searches existing reports by hostname or IP. |
| AlienVault OTX, Pulsedive | `OTX_API_KEY`, `PULSEDIVE_API_KEY` |
| AbuseIPDB, GreyNoise, Shodan | `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`. Use a public IP or enable `PHISHMATRIX_DNS_LOOKUPS=1` for hostnames. |
| ThreatFox and URLhaus | `ABUSECH_AUTH_KEY`. URLhaus exact lookup also needs `PHISHMATRIX_URLHAUS_PATH_SHARE=1`. |
| Project Honey Pot | `HTTPBL_API_KEY`. IPv4 only. The DNS protocol includes the key in queries sent to the configured resolver. |
| Mailboxlayer | `MAILBOXLAYER_API_KEY`. Uses HTTPS and a conventional postmaster address to check domain MX metadata without an SMTP probe. Raw email remains local. |
| MalShare | `MALSHARE_API_KEY`. Use **File hash** or `POST /api/v1/hash-lookup` for metadata. |
| Groq, Gemini, OpenRouter | `GROQ_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` and `PHISHMATRIX_AI_SUMMARY=1`. The first available provider supplies commentary based on the verdict and built-in rule identifiers. |
| Certificate Transparency, Hudson Rock legacy aggregate, Shodan InternetDB | `PHISHMATRIX_PUBLIC_INTEL=1`. InternetDB is the keyless alternative when Shodan has no key. The Hudson Rock legacy response is accepted only when it includes an aggregate count. |
| IP-API | `IP_API_KEY` for HTTPS Pro access. The legacy plaintext endpoint is retired in this integration. |
| Maltrail | `PHISHMATRIX_MALTRAIL_FILE` points to an authorized local or mounted snapshot. The legacy download URL returned 404. Review the [upstream license](https://github.com/stamparm/trails) before using it. |

For an integration smoke test, deploy v7.2 to Preview and scan a public test indicator. **Intelligence coverage** distinguishes authentication, quota, missing-IP and availability states. `PHISHMATRIX_INCLUDE_ALLOWLIST=1` runs provider checks for established allowlisted homepage URLs. A provider can reject an otherwise valid key because of product permissions or quota. The legacy Telegram token lookup is superseded by offline evidence inspection.

VirusTotal queries can result in indicator scanning or dataset inclusion. Only enable it for authorized public indicators. [VirusTotal API guidance](https://docs.virustotal.com/reference/domain-info)

Build a searchable local snapshot from the official OpenPhish Community feed or an authorized analyst STIX 2.1 export. Import supports simple equality patterns for URLs, domain names and IP addresses, and skips unsupported, revoked and expired indicators.

```bash
python -m scripts.refresh_intel --openphish
python -m scripts.refresh_intel --stix trusted-indicators.json
python -m scripts.refresh_intel --openphish --stix trusted-indicators.json
```

Set `PHISHMATRIX_INTEL_FILE=intel-snapshot.json`. The import script replaces the snapshot only after successful validation. Community entries expire 72 hours after a successful refresh. STIX entries without an expiry expire seven days after import. Keep the generated snapshot local. [OpenPhish feed terms](https://openphish.com/phishing_feeds.html)

## SOC exports

### Reading the verdict

- **Inconclusive** means the available sources do not cover the submitted indicator well enough to report a negative result. The console still shows the observed score, including zero. A registration date, host-level no-match, dataset model or missing key cannot clear a URL path. Client-side URL fragments are outside provider coverage.
- **Known trusted domain** (`TRUSTED_ROOT`) applies to an exact allowlisted HTTPS root with registration confirmed older than 30 days and no local findings except an optional archived benign match. Paths, queries, fragments, other hosts and offline scans are outside this shortcut. Set `PHISHMATRIX_INCLUDE_ALLOWLIST=1` to run external reputation checks for these roots too.
- **No match found** means Google Web Risk returned no listing for the precise URL sent, or a completed IP reputation lookup returned no match for a bare IP. The browser shows the completed source. The API keeps the legacy `CLEAN` enum.
- **Weak signals** (`LOW_SIGNAL`) means the scan returned 1–24 evidence points alongside a completed negative source check. Review the positive findings and the scope of the negative result.
- **Suspicious** includes an exact, uncontested historical phishing, malware or defacement match. The bundled index has 635,521 hashed URL records from the 2021 [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset), including benign entries. Matching is URL-specific, including path and query. Scheme-less rows match HTTP and HTTPS. Benign matches, conflicting labels and matches limited to the portion before a fragment are context only. A historical threat match contributes 30 points.
- A recent URLScan malicious verdict contributes 40 points for an exact final page seen in the last seven days. PhishMatrix searches by hostname and verifies the most recent exact page in the read-only Result API. Empty searches are inconclusive. [URLScan Search API reference](https://urlscan.io/docs/search/)
- **Malicious** can follow a current positive exact-URL lookup. Web Risk needs permission for the API key. URLhaus exact lookup covers malware URLs and needs `ABUSECH_AUTH_KEY` plus `PHISHMATRIX_URLHAUS_PATH_SHARE=1`. URLhaus skips URLs with queries. Enable sharing only where submitted paths can be shared with the provider.

Rebuild the bundled index from the same Kaggle archive with `python -m scripts.build_historical_index malicious-urls-dataset.zip`. The index and Kaggle evaluation scripts never open their sample URLs.

URL scans produce Sigma, Splunk SPL, Sentinel KQL, Elastic KQL, CrowdStrike LogScale, Wazuh XML, Suricata and YARA hunting templates for supported hostnames. IP scans produce Sigma, Splunk and Sentinel templates. Validate fields, rule IDs and format against your own parser before enabling any detection. The workbench does not deploy rules or send takedown requests.

## API and validation

The OpenAPI schema is available at `/openapi.json`. The investigation endpoints are `/api/v1/scan`, `/api/v1/email-scan`, `/api/v1/html-scan` and `/api/v1/bulk-scan`. Use `POST /cli` with a JSON `url` field to avoid placing an indicator in the CLI endpoint's request URL.

```bash
python -m pytest -q
python -m scripts.evaluate_rules
```

See [SECURITY.md](SECURITY.md) for the deployment controls, limits and vulnerability disclosure guidance.

Built by [Ayush Kumar Patel](https://github.com/ayushkp930). MIT license.


## Validate exported detection rules

Install the validation tools with `python -m pip install -r requirements-test.txt`, then run `python -m pytest -q`. The suite compiles YARA and runs Sigma DNS queries against synthetic telemetry. Windows DNS and process hash hunts require the matching log sources and field mappings. An indicator match identifies a file or event for investigation.

The Sigma findings template targets structured PhishMatrix triage events. The exact digest for submitted HTML or email applies to its UTF-8 text, including its line endings. The hostname YARA rule searches ASCII and UTF-16LE text. Bulk reports summarize the individual inputs.


## Offline triage and behavior hunts

Select **Analyze offline with local evidence only** for a URL or bulk investigation. API clients can send `"offline": true` to the scan or bulk-scan endpoint. This mode runs local URL checks and available indicator indexes without DNS, registration, AI or live reputation calls. HTML and email analysis examines submitted text without opening links or executing scripts. In passive mode, an unavailable enrichment source leaves the local findings available.

Download `/api/v1/rules/pack.zip` for 151 Sigma rules and 10 YARA text hunts. Sigma consumers need the exported structured boolean fields under `phishmatrix.findings`. Most hunts correlate two observed case findings. YARA targets ASCII-compatible HTML or MIME text up to 1 MiB. Raw-text matches require review because example code and quoted messages can contain the same markers. Provider statuses and model context are available in case JSON and the API. The console displays findings and score contributions.

### Precision and coverage checks

The 14 targeted regression cases in `test_offline_precision.py` contain eight benign examples and six review-worthy examples. Version 7.4 flagged seven of the benign examples and five of the review cases. Version 7.5 flagged zero of the benign examples and all six review cases. These are development fixtures.

A separate URL-only check used the 10,000 unique URLs with the lowest SHA-256 of the URL text in each class of the UCI PhiUSIIL corpus. Both versions used local URL rules and the bundled historical index. Among 10,000 labeled legitimate URLs, both versions flagged zero. Among 9,984 supported labeled phishing URLs, both flagged 41 (0.41% recall). Sixteen unsupported phishing inputs were excluded. An inconclusive result counted as a missed detection for phishing inputs. This snapshot measures URL-only coverage. Submitted page behavior and live reputation need separate evaluation. [UCI dataset](https://archive.ics.uci.edu/dataset/967)

Repeating that UCI URL-only check on 7.7 flagged 42 of 9,984 supported phishing inputs (0.42%) and zero of 10,000 legitimate inputs. A separate Kaggle index integrity check took the 2,500 distinct URLs with the lowest SHA-256 per archive class. The lookup returned 9,841 uncontested labeled matches, 96 conflicts, and 63 inputs the parser rejected. The latter check measures retrieval of indexed records.
