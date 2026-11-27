'use strict';

const byId = (id) => document.getElementById(id);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};

const settings = {
  url: {
    endpoint: '/api/v1/scan',
    help: 'PhishMatrix checks registration and reputation without opening the submitted page.',
  },
  email: {
    endpoint: '/api/v1/email-scan', label: 'Raw email or MIME message', max: 50000,
    placeholder: 'From: sender@example.com\nSubject: Message to investigate\n\nPaste the email body here.',
    help: 'Email is analyzed without external lookups. Pasted authentication headers are treated as unverified claims.',
  },
  html: {
    endpoint: '/api/v1/html-scan', label: 'Page source', max: 65536,
    placeholder: 'Paste HTML as text.',
    help: 'Analyzes HTML as an inert document. PhishMatrix never runs scripts or follows links.',
  },
  hash: {
    endpoint: '/api/v1/hash-lookup',
    help: 'Looks up MD5, SHA-1 or SHA-256 metadata in MalShare. No file is uploaded or downloaded.',
  },
  bulk: {
    endpoint: '/api/v1/bulk-scan', label: 'Indicators, one per line', max: 16391,
    placeholder: 'example.com\nexample.org',
    help: 'Analyze up to eight URLs, domains or IPs as one investigation.',
  },
};

const templateNames = {
  sigma_rule: 'Sigma · Windows network telemetry', sigma_case: 'Sigma · PhishMatrix findings',
  sigma_process_hash: 'Sigma · Windows process image hash', yara_hash: 'YARA · exact file digest', splunk_spl: 'Splunk SPL', sentinel_kql: 'Microsoft Sentinel KQL',
  elastic_kql: 'Elastic KQL', crowdstrike_cql: 'CrowdStrike LogScale',
  wazuh_rule: 'Wazuh XML', suricata_rule: 'Suricata TLS', yara_rule: 'YARA · hostname in file text',
};
const tone = { CLEAN: 'positive', SUSPICIOUS: 'warning', INCONCLUSIVE: 'warning', MALICIOUS: 'danger' };
const labelVerdict = { CLEAN: 'No match found', SUSPICIOUS: 'Suspicious', INCONCLUSIVE: 'Inconclusive', MALICIOUS: 'Malicious', BLOCKED: 'Blocked', UNAVAILABLE: 'Unavailable' };
let mode = 'url';
let current = null;
let running = false;
let catalogueLoaded = false;
const history = [];
const drafts = new Map();
const caseReviews = new Map();
const scoreLabels = {
  file_reputation: 'File hash reputation', artifact: 'HTML evidence', attachment: 'Attachment metadata', registration: 'Registration',
  lexical: 'URL structure', historical: 'Historical URL evidence', url_reputation: 'Exact URL reputation', domain_reputation: 'Domain reputation',
  infrastructure: 'Infrastructure', email: 'Email evidence',
};
const indicator = byId('indicator');
const sampleText = byId('sample-text');
const scanStatus = byId('scan-status');
const scanError = byId('scan-error');

function changeMode(next) {
  drafts.set(mode, [indicator.value, sampleText.value]);
  mode = next;
  const config = settings[mode];
  const hasIndicator = mode === 'url' || mode === 'html' || mode === 'hash';
  const hasText = Boolean(config.label);
  const [savedIndicator, savedSample] = drafts.get(mode) || ['', ''];
  indicator.value = savedIndicator;
  sampleText.value = savedSample;
  indicator.hidden = byId('indicator-label').hidden = !hasIndicator;
  indicator.required = mode === 'url' || mode === 'hash';
  indicator.placeholder = mode === 'hash' ? 'Enter an MD5, SHA-1 or SHA-256 digest' : mode === 'html' ? 'https://example.com (optional)' : 'https://example.com';
  byId('indicator-label').textContent = mode === 'hash' ? 'File hash' : mode === 'html' ? 'Page URL, if known' : 'URL, domain or IP address';
  sampleText.hidden = byId('sample-label').hidden = !hasText;
  sampleText.required = hasText;
  sampleText.placeholder = config.placeholder || '';
  sampleText.maxLength = config.max || 65536;
  byId('sample-label').textContent = config.label || '';
  byId('input-help').textContent = config.help;
  for (const button of document.querySelectorAll('[data-mode]')) {
    button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
  }
  scanError.hidden = true;
}

function scanPayload() {
  if (mode === 'hash') return { hash: indicator.value.trim() };
  if (mode === 'url') return { url: indicator.value.trim() };
  if (mode === 'email') return { raw_email: sampleText.value };
  if (mode === 'html') return { html: sampleText.value, url: indicator.value.trim() || null };
  return { urls: sampleText.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean) };
}

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
  const isBulk = result?.kind === 'bulk';
  const verdict = result?.verdict;
  const score = verdict !== 'INCONCLUSIVE' && Number.isFinite(result?.risk_score) ? result.risk_score : null;
  const scoreText = score === null ? '—' : String(score);
  byId('verdict').textContent = isBulk ? 'Batch complete' : labelVerdict[verdict] || 'Awaiting scan';
  byId('risk-score').textContent = scoreText;
  byId('ring-fill').setAttribute('stroke-dasharray', `${score || 0} 100`);
  document.querySelector('.risk-card').dataset.tone = tone[verdict] || 'neutral';
  const age = result?.forensics?.whois;
  const explanation = age?.is_newly_registered
    ? `${age.queried_domain} · ${result.domain_age}`
    : result?.score_capped ? 'The score counts overlapping signals once and applies evidence limits.' : result?.executive_summary || (isBulk ? `${result.count} indicators analyzed.` : '');
  byId('risk-reason').textContent = explanation || (result ? 'Review the evidence and source coverage below.' : 'Run an investigation to see the verdict and its supporting evidence.');
  byId('case-id').textContent = result?.case_id?.slice(0, 8) || '—';
  byId('domain-age').textContent = age && result.domain_age ? result.domain_age.split(' (')[0] : '—';
  byId('domain-source').textContent = age ? [age.queried_domain, age.registration_source || age.registration_status].join(' · ') : 'RDAP / WHOIS';
  byId('signal-count').textContent = isBulk ? result.count : (result?.evidence?.length ?? '—');
  byId('signal-detail').textContent = isBulk ? 'Indicators processed' : 'Scored and contextual findings';
  byId('duration').textContent = Number.isFinite(result?.scan_metadata?.scan_duration_ms) ? `${result.scan_metadata.scan_duration_ms} ms` : '—';
  byId('scan-mode').textContent = result?.kind ? { url: 'Passive URL investigation', email: 'Offline email triage', html: 'Offline HTML inspection', bulk: 'Passive bulk scan', hash: 'File hash metadata lookup' }[result.kind] : 'Latest investigation';
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
    item.append(label, node('span', evidence.points ? `+${evidence.points}` : 'Context', 'points'));
    list.append(item);
  }
  for (const row of result?.results || []) {
    const label = node('div');
    label.append(node('strong', row.indicator || `Indicator ${row.position}`), node('small', row.reputation_coverage?.detail || row.domain_age || row.detail || ''));
    const item = node('li');
    item.append(label, node('span', labelVerdict[row.verdict] || row.verdict, 'pill'));
    list.append(item);
  }
  byId('evidence-total').textContent = result?.kind === 'bulk' ? `${result.count} results` : `${rows.length} findings`;
  byId('evidence-empty').hidden = Boolean(list.children.length);
  byId('evidence-empty').textContent = rows.length ? 'No findings match this filter.' : result?.kind === 'hash' ? result.executive_summary : result?.verdict === 'INCONCLUSIVE' ? 'No positive findings. Available evidence is insufficient.' : result ? 'The completed checks returned no findings.' : 'Findings appear when the investigation returns evidence.';

  const providerList = byId('providers');
  providerList.replaceChildren();
  for (const [name, record] of Object.entries(result?.providers || {})) {
    const item = node('li');
    const state = node('span', record.status, 'pill');
    if (['Match', 'Historical match', 'Unavailable', 'Stale or empty', 'Auth rejected', 'Access denied', 'Rate limited'].includes(record.status)) state.dataset.state = 'warning';
    else if (['Confirmed', 'No match', 'No active match'].includes(record.status)) state.dataset.state = 'positive';
    item.append(node('strong', name), state);
    providerList.append(item);
  }
  byId('providers-empty').hidden = Boolean(providerList.children.length);
  byId('providers-empty').textContent = result?.kind === 'html' || result?.kind === 'email'
    ? 'This artifact was analyzed offline. No external sources were queried.'
    : 'Registration and reputation sources show here after a URL scan.';

  const advisory = result?.ai_advisory;
  byId('analyst-advisory').hidden = !advisory;
  if (advisory) {
    byId('advisory-source').textContent = advisory.source;
    byId('advisory-text').textContent = advisory.text;
  }
  const model = result?.dataset_model;
  byId('dataset-model').hidden = !model;
  if (model) {
    byId('model-score').textContent = model.flagged ? 'Elevated' : 'Below threshold';
    byId('model-detail').textContent = `Model signal ${Math.round(model.score * 100)}/100 · context only`;
  }
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
  if (result?.kind === 'email') {
    context.append(node('p', `Subject · ${result.subject}`), node('p', `From · ${result.from || 'Unavailable'}`));
    if (result.reply_to) context.append(node('p', `Reply-To · ${result.reply_to}`));
    if (result.extracted_urls.length) context.append(node('p', 'Extracted links'), ...result.extracted_urls.map((url) => node('p', url)));
    if (result.attachments.length) context.append(node('p', `Attachment names · ${result.attachments.join(', ')}`));
  } else if (result?.kind === 'html') {
    const page = result.dom_forensics;
    if (page.page_title) context.append(node('p', `Page title · ${page.page_title}`));
    context.append(node('p', `Forms inspected · ${page.forms_inspected}`));
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
    const label = result.target?.defanged_domain || result.subject || (result.kind === 'bulk' ? `${result.count} indicators` : result.kind === 'hash' ? result.target.hash.slice(0, 16) + '…' : 'HTML sample');
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
    const result = await getJSON(settings[mode].endpoint, scanPayload());
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

function download(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' }));
  const anchor = node('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

for (const button of document.querySelectorAll('[data-mode]')) button.addEventListener('click', () => changeMode(button.dataset.mode));
for (const link of document.querySelectorAll('.nav-link')) link.addEventListener('click', () => {
  for (const peer of document.querySelectorAll('.nav-link')) peer.classList.toggle('selected', peer === link);
});
byId('scan-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void run();
});
byId('sample').addEventListener('click', () => {
  changeMode('html');
  indicator.value = 'https://northstar-training.example/login';
  sampleText.value = '<title>Northstar verification sample</title>\n<form action="https://collector.example/session">\n  <input type="password" name="password">\n</form>\n<a href="https://collector.example/help">https://northstar-training.example/help</a>';
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
  download(review ? { ...current, analyst_review: review } : current, 'phishmatrix-case.json');
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
