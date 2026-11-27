'use strict';

const byId = (id) => document.getElementById(id);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};

const templateNames = {
  sigma_rule: 'Sigma · Windows network telemetry', sigma_case: 'Sigma · PhishMatrix findings',
  sigma_process_hash: 'Sigma · Windows process image hash', yara_hash: 'YARA · exact file digest', splunk_spl: 'Splunk SPL', sentinel_kql: 'Microsoft Sentinel KQL',
  elastic_kql: 'Elastic KQL', crowdstrike_cql: 'CrowdStrike LogScale',
  wazuh_rule: 'Wazuh XML', suricata_rule: 'Suricata TLS', yara_rule: 'YARA · hostname in file text',
};
const tone = { CLEAN: 'positive', TRUSTED_ROOT: 'positive', LOW_SIGNAL: 'warning', SUSPICIOUS: 'warning', MALICIOUS: 'danger' };
const labelVerdict = {
  CLEAN: 'No match found', TRUSTED_ROOT: 'Known trusted domain', LOW_SIGNAL: 'Weak signals',
  SUSPICIOUS: 'Suspicious', INCONCLUSIVE: 'Inconclusive', MALICIOUS: 'Malicious',
  BLOCKED: 'Blocked', UNAVAILABLE: 'Unavailable',
};
let current = null;
let running = false;
let catalogueLoaded = false;
const history = [];
const caseReviews = new Map();
const scoreLabels = {
  file_reputation: 'File hash reputation', artifact: 'HTML evidence', attachment: 'Attachment metadata', registration: 'Registration',
  lexical: 'URL structure', historical: 'Historical URL evidence', url_reputation: 'Exact URL reputation', domain_reputation: 'Domain reputation',
  infrastructure: 'Infrastructure', email: 'Email evidence',
};
const emailFile = byId('email-file');
let uploadedRaw = null;
const sampleText = byId('sample-text');
const scanStatus = byId('scan-status');
const scanError = byId('scan-error');

async function getJSON(endpoint, payload) {
  const response = await fetch(endpoint, {
    ...(payload === undefined ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    }),
    signal: AbortSignal.timeout(24000),
    credentials: 'same-origin',
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status}).`);
  return body;
}

function riskPanel(result) {
  const verdict = result?.verdict;
  const score = result?.risk_score ?? null;
  byId('verdict').textContent = labelVerdict[verdict] || 'Awaiting scan';
  byId('risk-score').textContent = score === null ? '—' : String(score);
  byId('ring-fill').setAttribute('stroke-dasharray', `${score || 0} 100`);
  document.querySelector('.risk-card').dataset.tone = tone[verdict] || 'neutral';
  const topFinding = result?.evidence?.find((entry) => entry.points > 0);
  byId('risk-reason').textContent = !result ? 'Run an investigation to see the evidence.' :
    verdict === 'INCONCLUSIVE' ? (score ? 'Findings below the alert threshold. Review the evidence.' : 'The static checks returned no risk points.') :
      topFinding ? `Top finding: ${topFinding.label}.` : 'Review the evidence below.';
  byId('case-id').textContent = result?.case_id?.slice(0, 8) || '—';
  byId('link-count').textContent = result?.extracted_urls.length ?? '—';
  byId('signal-count').textContent = result?.evidence.length ?? '—';
  byId('duration').textContent = result ? `${result.scan_metadata.scan_duration_ms} ms` : '—';
  byId('scan-mode').textContent = result ? 'Static email inspection' : 'Latest investigation';
}

function renderEvidence(result) {
  const list = byId('findings');
  list.replaceChildren();
  const rows = result?.evidence || [];
  const filter = byId('filter-evidence').value;
  byId('evidence-tools').hidden = !rows.length;
  const visibleRows = rows.filter((row) => filter === 'all' || (filter === 'scored' ? row.points > 0 : row.points === 0));
  for (const evidence of visibleRows) {
    const label = node('div');
    label.append(node('strong', evidence.label), node('small', evidence.detail, 'detail'), node('small', `${evidence.rule_id} · ${evidence.source}`));
    const item = node('li');
    item.append(label, node('span', evidence.points ? `Weight ${evidence.points}` : 'Context', 'points'));
    list.append(item);
  }
  byId('evidence-total').textContent = `${rows.length} findings`;
  byId('evidence-empty').hidden = Boolean(list.children.length);
  byId('evidence-empty').textContent = rows.length ? 'No findings match this filter.' : result ?
    'The static checks returned no findings.' : 'Findings appear when the investigation returns evidence.';

  const contributions = Object.entries(result?.contributions || {});
  byId('breakdown').hidden = !contributions.length;
  const scoreRows = byId('score-rows');
  scoreRows.replaceChildren(...contributions.map(([category, score]) => {
    const row = node('li');
    row.append(node('span', scoreLabels[category] || category), node('code', `+${score}`));
    return row;
  }));
  const scoreCap = byId('score-cap');
  scoreCap.hidden = !result?.score_capped;
  if (result?.score_capped) scoreCap.textContent = `Raw findings ${result.uncapped_total} · final score ${result.risk_score} after evidence limits.`;

  const context = byId('response-context');
  context.replaceChildren();
  if (result) {
    context.append(node('p', `Subject · ${result.subject}`), node('p', `From · ${result.from || 'Unavailable'}`));
    if (result.reply_to) context.append(node('p', `Reply-To · ${result.reply_to}`));
    if (result.extracted_urls.length) context.append(node('p', 'Extracted links'), ...result.extracted_urls.map((url) => node('p', url)));
    if (result.attachments.length) context.append(node('p', `Attachment names · ${result.attachments.join(', ')}`));
  }
  context.hidden = !context.children.length;

  const actions = byId('actions');
  actions.replaceChildren();
  for (const recommendation of result?.recommendations || []) {
    const item = node('li');
    if (typeof recommendation === 'string') {
      item.textContent = recommendation;
    } else {
      item.append(node('strong', `${recommendation.priority} ${recommendation.category}`), document.createTextNode(recommendation.action));
    }
    actions.append(item);
  }
  actions.hidden = !actions.children.length;
}

function displayRule(result, key) {
  byId('rule-text').textContent = result?.soc_arsenal?.[key] || '';
  const hints = {
    sigma_case: 'Matches the listed findings in exported PhishMatrix events. Forward the structured event fields to your SIEM.',
    sigma_rule: 'Hunts for the investigated host in Windows DNS queries or the destination IP in network connection logs. A hit identifies contact for review.',
    sigma_process_hash: 'Requires Windows process creation telemetry with image hashing enabled. Matches executed images only.',
    yara_hash: result?.kind === 'hash' ? 'Matches the complete file digest supplied in this case.' : 'Matches the exact UTF-8 text submitted here. Changes to encoding or line endings produce a different digest.',
    yara_rule: 'Searches ASCII and UTF-16LE text for the exact hostname. A mention in a file is contextual evidence.',
    suricata_rule: 'Matches the exact hostname in visible TLS SNI. Assign an unused local SID before loading.',
    wazuh_rule: 'Requires JSON events with dns.question.name. Assign an unused local rule ID before loading.',
  };
  byId('rule-scope').textContent = hints[key] || 'Hunting query for the submitted indicator. Verify field mappings against your telemetry.';
}

function renderRules(result) {
  const select = byId('rule-select');
  select.replaceChildren();
  for (const key of Object.keys(result?.soc_arsenal || {})) {
    const option = node('option', templateNames[key] || key);
    option.value = key;
    select.append(option);
  }
  byId('rule-picker').hidden = !select.children.length;
  displayRule(result, select.value);
  byId('download-case').disabled = !result;
  byId('download-pdf').disabled = !result?.report_pdf;
  byId('download-siem').disabled = !result?.siem_event;
}

function show(result) {
  current = result;
  byId('filter-evidence').value = 'all';
  byId('case-notes').hidden = !result?.case_id;
  const review = caseReviews.get(result?.case_id);
  byId('disposition').value = review?.disposition || 'Unreviewed';
  byId('notes').value = review?.notes || '';
  byId('review-saved').textContent = review ? 'Review recorded' : 'Unreviewed';
  riskPanel(result);
  renderEvidence(result);
  renderRules(result);
}

function renderHistory() {
  const list = byId('session-log');
  list.replaceChildren();
  for (const result of history) {
    const item = node('li');
    const stamp = new Date(result.timestamp);
    const label = result.subject;
    const button = node('button', label);
    button.type = 'button';
    button.append(node('small', stamp.toLocaleString()));
    button.addEventListener('click', () => {
      show(result);
      byId('evidence').scrollIntoView({ block: 'start' });
    });
    item.append(button, node('span', labelVerdict[result.verdict] || 'Complete', 'pill'));
    list.append(item);
  }
  byId('session-empty').hidden = Boolean(history.length);
  byId('clear-session').disabled = !history.length;
}

async function run() {
  if (running) return;
  running = true;
  byId('run').disabled = true;
  byId('sample').disabled = true;
  scanError.hidden = true;
  scanStatus.textContent = 'Analyzing evidence…';
  byId('radar-status').textContent = 'Analyzing evidence';
  document.body.dataset.scanning = 'true';
  const started = performance.now();
  const timer = byId('live-timer');
  timer.textContent = '0.0 s';
  const ticker = setInterval(() => {
    timer.textContent = `${((performance.now() - started) / 1000).toFixed(1)} s`;
  }, 100);
  try {
    const raw = uploadedRaw ?? sampleText.value;
    if (!raw.trim()) throw new Error('Paste a raw email or upload an .eml file.');
    const result = await getJSON('/api/v1/email-scan', { raw_email: raw, include_pdf: true });
    show(result);
    history.unshift(result);
    if (history.length > 20) caseReviews.delete(history.pop().case_id);
    byId('radar-status').textContent = 'Analysis complete';
    renderHistory();
    scanStatus.textContent = 'Investigation complete.';
  } catch (error) {
    scanStatus.textContent = '';
    byId('radar-status').textContent = 'Scan stopped';
    scanError.textContent = error.name === 'TimeoutError' ? 'The investigation timed out. Try again.' : error.message;
    scanError.hidden = false;
  } finally {
    clearInterval(ticker);
    const elapsed = (performance.now() - started) / 1000;
    timer.textContent = elapsed < 0.1 ? `${Math.round(elapsed * 1000)} ms` : `${elapsed.toFixed(1)} s`;
    delete document.body.dataset.scanning;
    running = false;
    byId('run').disabled = false;
    byId('sample').disabled = false;
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = node('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function download(data, filename) {
  downloadBlob(new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' }), filename);
}

sampleText.addEventListener('input', () => {
  uploadedRaw = null;
  emailFile.value = '';
  scanError.hidden = true;
});
emailFile.addEventListener('change', async () => {
  const [file] = emailFile.files;
  if (!file) return;
  byId('run').disabled = true;
  try {
    if (!file.name.toLowerCase().endsWith('.eml') || file.size > 50000) throw new Error('Choose a .eml file up to 50 KB.');
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    if (file !== emailFile.files[0]) return;
    if (!raw.trim() || raw.includes('\0')) throw new Error('The file must contain a text email.');
    uploadedRaw = raw;
    sampleText.value = raw;
    scanError.hidden = true;
    scanStatus.textContent = 'Email loaded.';
  } catch (error) {
    if (file !== emailFile.files[0]) return;
    emailFile.value = '';
    scanError.textContent = error instanceof TypeError ? 'The .eml file must use UTF-8 or ASCII encoding.' : error.message;
    scanError.hidden = false;
  } finally {
    if (!running) byId('run').disabled = false;
  }
});
for (const link of document.querySelectorAll('.nav-link')) link.addEventListener('click', () => {
  for (const peer of document.querySelectorAll('.nav-link')) peer.classList.toggle('selected', peer === link);
});
byId('scan-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void run();
});
byId('sample').addEventListener('click', () => {
  uploadedRaw = null;
  emailFile.value = '';
  sampleText.value = `From: Northstar Training <alerts@northstar.example>
Reply-To: review@collector.example
Subject: [TEST] Account review
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<p>Synthetic training sample.</p>
<a href="https://collector.example/review">https://northstar.example/review</a>`;
  void run();
});
byId('clear-session').addEventListener('click', () => {
  history.length = 0;
  caseReviews.clear();
  show(null);
  renderHistory();
});
byId('filter-evidence').addEventListener('change', () => renderEvidence(current));
function recordReview() {
  if (!current?.case_id) return;
  const disposition = byId('disposition').value;
  const notes = byId('notes').value.trim();
  if (disposition === 'Unreviewed' && !notes) {
    caseReviews.delete(current.case_id);
    byId('review-saved').textContent = 'Unreviewed';
    return;
  }
  caseReviews.set(current.case_id, { disposition, notes });
  byId('review-saved').textContent = 'Review recorded';
}
byId('disposition').addEventListener('change', recordReview);
byId('notes').addEventListener('input', recordReview);
byId('rule-select').addEventListener('change', (event) => {
  displayRule(current, event.target.value);
});
byId('copy-rule').addEventListener('click', async () => {
  const button = byId('copy-rule');
  try {
    await navigator.clipboard.writeText(byId('rule-text').textContent);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Select text to copy';
  }
  setTimeout(() => { button.textContent = 'Copy rule'; }, 1600);
});
byId('download-case').addEventListener('click', () => {
  if (!current) return;
  const review = caseReviews.get(current.case_id);
  const { report_pdf, ...caseData } = current;
  download(review ? { ...caseData, analyst_review: review } : caseData, `phishmatrix-${current.case_id}.json`);
});
byId('download-pdf').addEventListener('click', () => {
  if (!current?.report_pdf) return;
  const bytes = Uint8Array.from(atob(current.report_pdf), (char) => char.charCodeAt(0));
  downloadBlob(new Blob([bytes], { type: 'application/pdf' }), `phishmatrix-${current.case_id}.pdf`);
});
byId('download-siem').addEventListener('click', () => {
  if (current?.siem_event) download(current.siem_event, 'phishmatrix-siem-event.json');
});
byId('toggle-rules').addEventListener('click', async () => {
  const target = byId('catalogue');
  target.hidden = !target.hidden;
  byId('toggle-rules').setAttribute('aria-expanded', String(!target.hidden));
  if (target.hidden || catalogueLoaded) return;
  target.textContent = 'Loading rules…';
  try {
    const response = await getJSON('/api/v1/rules');
    target.replaceChildren();
    for (const rule of response.rules) {
      const item = node('p');
      item.append(node('code', rule.rule_id), document.createTextNode(rule.label));
      target.append(item);
    }
    catalogueLoaded = true;
  } catch {
    target.textContent = 'The rule catalogue is unavailable.';
  }
});
getJSON('/health').then((response) => {
  byId('server-dot').classList.add('online');
  byId('server-status').textContent = 'API online';
  byId('server-version').textContent = `Version ${response.version}`;
}).catch(() => {
  byId('server-dot').classList.add('offline');
  byId('server-status').textContent = 'API unavailable';
});
