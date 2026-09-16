/* ==========================================================================
   IronLedger — frontend client
   This talks to the real FastAPI backend (see /backend): every ledger block,
   hash, anomaly, MITRE hit, and attribution score shown here comes from a
   live API call, not a local simulation. The four-act stepper just tells the
   backend which act to run next; everything after that is a fetch + render.
   ========================================================================== */

const THRESHOLDS = { pressure: 9.5, temp: 95, vibration: 5.5 };

let API_BASE = 'http://localhost:8000';

function short(hash) { return hash ? hash.slice(0, 8) + '…' + hash.slice(-6) : ''; }
function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(API_BASE + path, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${method} ${path} → ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.status === 204 ? null : res.json();
}

/* ============ State ============ */
let state = {
  connected: false,
  chainInfo: null,
  act: 0,
  ledger: [],
  anomalies: [],
  mitreMatrix: null,
  telemetryEval: null,
  plant: { pressure: 6.1, temp: 71, vibration: 2.3, valveOpen: true, sisArmed: true },
  telemetryHistory: [],
  forensicSteps: [],
  attribution: null,
  reportBlockId: null,
  selectedBlock: null,
  verify: { chain_verified: true, mismatches: [] },
};

/* ============ Connectivity ============ */
async function checkConnection() {
  try {
    const root = await api('/');
    state.connected = true;
    state.chainInfo = root.chain;
    setApiStatus(true, root.chain.configured ? 'Sepolia configured' : 'local mode (no chain)');
    hideBanner();
  } catch (e) {
    state.connected = false;
    setApiStatus(false, 'unreachable');
    showBanner();
  }
  renderChainStatus();
  return state.connected;
}

function setApiStatus(ok, text) {
  const el = document.getElementById('api-config-status');
  el.textContent = text;
  el.className = 'api-config-status ' + (ok ? 'ok' : 'err');
}
function showBanner() {
  document.getElementById('conn-banner').classList.remove('hidden');
  document.getElementById('conn-banner-text').textContent =
    `Can't reach the IronLedger API at ${API_BASE} — is the backend running? (uvicorn app.main:app --reload)`;
}
function hideBanner() { document.getElementById('conn-banner').classList.add('hidden'); }

/* ============ Data refresh ============ */
async function refreshAll() {
  if (!state.connected) return;
  const [ledger, anomalies, mitreMatrix, verify] = await Promise.all([
    api('/ledger/blocks'),
    api('/anomalies'),
    api('/mitre/matrix'),
    api('/ledger/verify'),
  ]);
  state.ledger = ledger;
  state.anomalies = anomalies;
  state.mitreMatrix = mitreMatrix;
  state.verify = verify;

  derivePlantState();

  if (state.act >= 4 && ledger.length) {
    const startBlock = ledger[ledger.length - 1];
    const recon = await api('/forensics/reconstruct', { method: 'POST', body: { start_block_id: startBlock.id } });
    state.forensicSteps = recon.steps;
    state.attribution = recon.attribution;
    state.reportBlockId = startBlock.id;
  } else {
    state.forensicSteps = [];
    state.attribution = null;
    state.reportBlockId = ledger.length ? ledger[ledger.length - 1].id : null;
  }

  const latestTelemetryBlock = [...ledger].reverse().find(b => b.command === 'TELEMETRY_REPORT');
  if (latestTelemetryBlock) {
    state.telemetryEval = await api('/telemetry/evaluate', {
      method: 'POST',
      body: {
        source: latestTelemetryBlock.source, entity: latestTelemetryBlock.entity,
        pressure: latestTelemetryBlock.params.pressure,
        temp: latestTelemetryBlock.params.temp,
        vibration: latestTelemetryBlock.params.vibration,
      },
    });
  }
}

function derivePlantState() {
  const p = { pressure: 6.1, temp: 71, vibration: 2.3, valveOpen: true, sisArmed: true };
  const history = [];
  for (const b of state.ledger) {
    if (b.command === 'TELEMETRY_REPORT') {
      p.pressure = b.params.pressure; p.temp = b.params.temp; p.vibration = b.params.vibration;
      history.push({ pressure: p.pressure, temp: p.temp });
    } else if (b.command === 'DISABLE_INTERLOCK') {
      p.sisArmed = false;
    } else if (b.command === 'SET_VALVE') {
      p.valveOpen = b.params.position !== 'CLOSED';
    }
  }
  state.plant = p;
  state.telemetryHistory = history.slice(-24);
}

/* ============ Act stepper ============ */
async function runToAct(target) {
  for (let n = state.act + 1; n <= target; n++) {
    await api(`/simulate/act/${n}`, { method: 'POST' });
    state.act = n;
    await refreshAll();
    render();
  }
}

async function resetAll() {
  await api('/simulate/reset', { method: 'POST' });
  state.act = 0;
  state.selectedBlock = null;
  await refreshAll();
  render();
}

/* ============ Rendering ============ */
function render() {
  renderTopbarStepper();
  renderChainStatus();
  renderDashboard();
  renderLedger();
  renderAnomaly();
  renderForensics();
  renderMitre();
}

function renderTopbarStepper() {
  document.querySelectorAll('.act-btn').forEach(btn => {
    const n = +btn.dataset.act;
    btn.classList.toggle('done', n <= state.act);
    btn.classList.toggle('current', n === state.act);
  });
}

function renderChainStatus() {
  const dot = document.querySelector('#chain-status .dot');
  const val = document.getElementById('chain-status-value');
  if (!state.connected) {
    dot.className = 'dot dot-offline'; val.textContent = 'Offline'; return;
  }
  if (!state.verify.chain_verified) {
    dot.className = 'dot dot-critical'; val.textContent = 'Tamper Detected'; return;
  }
  dot.className = 'dot dot-safe';
  val.textContent = state.ledger.length ? 'Verified' : 'Idle';
}

function pct(value, max) { return Math.min(100, Math.max(4, (value / max) * 100)); }

function renderDashboard() {
  const p = state.plant;
  document.getElementById('stat-pressure').innerHTML = `${p.pressure} <small>bar</small>`;
  document.getElementById('stat-temp').innerHTML = `${p.temp} <small>°C</small>`;
  document.getElementById('stat-vibe').innerHTML = `${p.vibration} <small>mm/s</small>`;
  const mlScore = state.telemetryEval ? state.telemetryEval.ml_score : 0.06;
  document.getElementById('stat-ml').textContent = mlScore.toFixed(2);

  setBar('stat-pressure-bar', pct(p.pressure, THRESHOLDS.pressure), p.pressure > THRESHOLDS.pressure);
  setBar('stat-temp-bar', pct(p.temp, THRESHOLDS.temp), p.temp > THRESHOLDS.temp);
  setBar('stat-vibe-bar', pct(p.vibration, THRESHOLDS.vibration), p.vibration > THRESHOLDS.vibration);
  setBar('stat-ml-bar', mlScore * 100, mlScore > 0.6);

  drawTelemetryChart();

  const list = document.getElementById('recent-events');
  const recent = state.ledger.slice(-6).reverse();
  list.innerHTML = recent.length ? recent.map(b => `
    <li>
      <div>
        <div>${b.command} <span class="event-meta">· ${b.entity}</span></div>
        <div class="event-hash">${short(b.onchain_hash)}${b.tx_hash ? ' · on-chain' : ''}</div>
      </div>
      <span class="event-meta">${fmtTime(b.ts)}</span>
    </li>`).join('') : '<li class="alert-empty">No ledger entries yet — run the simulation.</li>';

  document.getElementById('sis-interlock').textContent = p.sisArmed ? 'Armed' : 'Bypassed';
  document.getElementById('sis-interlock').className = 'badge' + (p.sisArmed ? '' : ' badge-critical');
  document.getElementById('sis-valve').textContent = p.valveOpen ? 'Open' : 'Forced Closed';
  document.getElementById('sis-valve').className = 'badge' + (p.valveOpen ? '' : ' badge-critical');
  document.getElementById('sis-blocks').textContent = state.ledger.length;

  const alertList = document.getElementById('alert-list');
  const latest = state.anomalies.slice(-4).reverse();
  alertList.innerHTML = latest.length ? latest.map(a => `
    <li class="alert-item ${a.severity === 'warning' ? 'warning' : ''}">
      <span class="dotmark"></span>
      <div>
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.description}</div>
        <div class="alert-tag">${fmtTime(a.ts)}${a.technique ? ' · ' + a.technique : ''}</div>
      </div>
    </li>`).join('') : '<li class="alert-empty">No anomalies flagged. Baseline nominal.</li>';
}

function setBar(id, widthPct, danger) {
  const el = document.getElementById(id);
  el.style.width = Math.min(100, widthPct) + '%';
  el.style.background = danger ? 'var(--critical)' : (widthPct > 65 ? 'var(--warning)' : 'var(--navy)');
}

function drawTelemetryChart() {
  const svg = document.getElementById('telemetry-chart');
  const hist = state.telemetryHistory;
  if (!hist.length) { svg.innerHTML = ''; return; }
  const W = 560, H = 200, PAD = 20;
  const n = hist.length;
  const xStep = (W - PAD * 2) / Math.max(1, n - 1);
  const pMax = 12, tMax = 110;
  const toY = (v, max) => H - PAD - (v / max) * (H - PAD * 2);

  const pPts = hist.map((h, i) => `${PAD + i * xStep},${toY(h.pressure, pMax)}`).join(' ');
  const tPts = hist.map((h, i) => `${PAD + i * xStep},${toY(h.temp, tMax)}`).join(' ');
  const threshY = toY(THRESHOLDS.pressure, pMax);

  svg.innerHTML = `
    <line x1="${PAD}" y1="${threshY}" x2="${W - PAD}" y2="${threshY}" stroke="var(--critical)" stroke-width="1" stroke-dasharray="4 4" opacity="0.55"/>
    <polyline points="${tPts}" fill="none" stroke="#C98F8A" stroke-width="2"/>
    <polyline points="${pPts}" fill="none" stroke="var(--navy)" stroke-width="2.2"/>
  `;
}

function renderLedger() {
  const body = document.getElementById('ledger-body');
  body.innerHTML = state.ledger.map(b => `
    <tr data-index="${b.id}" class="${state.selectedBlock === b.id ? 'selected' : ''}">
      <td>${b.id}</td>
      <td>${fmtTime(b.ts)}</td>
      <td>${b.source}</td>
      <td>${b.command} <span class="mono">/ ${b.entity}</span></td>
      <td class="mono">${short(b.prev_hash)}</td>
      <td class="mono">${short(b.onchain_hash)}</td>
      <td>${b.tampered ? '<span class="badge badge-critical">Tampered</span>' : '<span class="badge">Verified</span>'}</td>
    </tr>`).join('') || '';
  if (!state.ledger.length) {
    body.innerHTML = `<tr><td colspan="7" class="alert-empty">No blocks anchored yet — run the simulation stepper.</td></tr>`;
  }
  renderBlockDetail(state.selectedBlock);
}

function renderBlockDetail(id) {
  const empty = document.getElementById('block-detail-empty');
  const body = document.getElementById('block-detail-body');
  const b = state.ledger.find(x => x.id === id);
  if (!b) { empty.classList.remove('hidden'); body.classList.add('hidden'); return; }
  empty.classList.add('hidden'); body.classList.remove('hidden');

  let html = `
    <dl>
      <dt>Block Index</dt><dd>#${b.id}</dd>
      <dt>Timestamp</dt><dd>${fmtTime(b.ts)}</dd>
      <dt>Source</dt><dd>${b.source}</dd>
      <dt>Command / Entity</dt><dd>${b.command} → ${b.entity}</dd>
      <dt>Params (on-chain)</dt><dd>${JSON.stringify(b.params)}</dd>
      <dt>Prev Hash</dt><dd>${b.prev_hash}</dd>
      <dt>Preimage</dt><dd>${b.preimage}</dd>
      <dt>On-chain Hash</dt><dd>${b.onchain_hash}</dd>
      <dt>Sepolia Tx</dt><dd>${b.tx_hash ? b.tx_hash : (b.anchor_error || 'not anchored (local mode)')}</dd>
    </dl>`;
  if (b.tampered) {
    html += `
      <div class="tamper-diff">
        <strong>Tamper detected.</strong> Off-chain historian claims command <code>${b.offchain_command}</code>
        with params <code>${JSON.stringify(b.offchain_params)}</code>. Recomputing the hash from that claimed
        record yields <span class="mono">${short(b.offchain_hash)}</span>, which does not match the anchored
        on-chain hash <span class="mono">${short(b.onchain_hash)}</span> — proof the local log was altered
        after the fact.
      </div>`;
  }
  body.innerHTML = html;
}

function renderAnomaly() {
  drawGauge();
  const p = state.plant;
  const rows = [
    ['Reactor Pressure', `≤ ${THRESHOLDS.pressure} bar`, `${p.pressure} bar`, p.pressure > THRESHOLDS.pressure],
    ['Process Temperature', `≤ ${THRESHOLDS.temp} °C`, `${p.temp} °C`, p.temp > THRESHOLDS.temp],
    ['Rotor Vibration', `≤ ${THRESHOLDS.vibration} mm/s`, `${p.vibration} mm/s`, p.vibration > THRESHOLDS.vibration],
    ['SIS / Valve Logic', 'Interlock armed while valve forced', p.sisArmed ? 'Consistent' : 'Contradictory', !p.sisArmed],
  ];
  document.getElementById('threshold-body').innerHTML = rows.map(([label, safe, cur, breach]) => `
    <tr>
      <td>${label}</td><td class="mono">${safe}</td><td class="mono">${cur}</td>
      <td>${breach ? '<span class="badge badge-critical">Breach</span>' : '<span class="badge">Normal</span>'}</td>
    </tr>`).join('');

  const list = document.getElementById('anomaly-list');
  list.innerHTML = state.anomalies.length ? state.anomalies.slice().reverse().map(a => `
    <li class="anomaly-item ${a.severity === 'warning' ? 'warning' : ''}">
      <span class="dotmark"></span>
      <div>
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.description}</div>
        <div class="alert-tag">${fmtTime(a.ts)}${a.technique ? ' · ' + a.technique : ''}${a.block_id !== null && a.block_id !== undefined ? ' · block #' + a.block_id : ''}</div>
      </div>
    </li>`).join('') : '<li class="alert-empty">No anomalies flagged yet — run the simulation stepper above.</li>';
}

function drawGauge() {
  const svg = document.getElementById('ml-gauge');
  const score = state.telemetryEval ? state.telemetryEval.ml_score : 0.06;
  const color = score > 0.6 ? 'var(--critical)' : score > 0.3 ? 'var(--warning)' : 'var(--safe)';
  const caption = score > 0.6 ? 'Critical — multivariate outlier confirmed (Isolation Forest)'
    : score > 0.3 ? 'Elevated — monitor closely' : 'Nominal — trained on baseline telemetry';
  document.getElementById('ml-gauge-caption').textContent = caption;

  const circumference = Math.PI * 80;
  const offset = circumference * (1 - score);
  svg.innerHTML = `
    <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--stone)" stroke-width="14" stroke-linecap="round"/>
    <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="${color}" stroke-width="14" stroke-linecap="round"
      stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
    <text x="100" y="92" text-anchor="middle" font-family="var(--serif)" font-size="30" fill="var(--navy-deep)">${score.toFixed(2)}</text>
    <text x="100" y="110" text-anchor="middle" font-family="var(--sans)" font-size="10" fill="var(--muted)">anomaly score</text>
  `;
}

function renderForensics() {
  const tl = document.getElementById('forensic-timeline');
  tl.innerHTML = state.forensicSteps.length ? state.forensicSteps.map(s => `
    <li class="${s.flag === 'tamper' ? 'node-tamper' : s.flag === 'root' ? 'node-root' : ''}">
      <div class="timeline-time">${fmtTime(s.ts)} · block #${s.block_id}</div>
      <div class="timeline-title">${s.title}</div>
      <div class="timeline-desc">${s.description}</div>
      ${s.flag === 'tamper' ? '<span class="timeline-flag">Hash mismatch</span>' : s.flag === 'root' ? '<span class="timeline-flag" style="background:var(--safe-bg);color:var(--safe)">Root cause</span>' : ''}
    </li>`).join('') : '<li class="alert-empty">Run Act 4 to reconstruct the incident timeline.</li>';

  const attrEl = document.getElementById('attribution-list');
  const reportBtn = document.getElementById('report-btn');
  if (state.attribution) {
    const tiedSet = new Set([state.attribution.leader, ...(state.attribution.tied_with || [])]);
    attrEl.innerHTML = Object.entries(state.attribution.scores).sort((a, b) => b[1] - a[1]).map(([actor, score]) => `
      <div class="attr-row">
        <div class="attr-row-top"><span class="attr-actor">${actor}</span><span class="attr-score">${score}%</span></div>
        <div class="attr-bar-track"><div class="attr-bar-fill ${tiedSet.has(actor) && score > 0 ? 'leading' : ''}" style="width:${score}%"></div></div>
      </div>`).join('');
    if (state.attribution.tied_with && state.attribution.tied_with.length) {
      attrEl.innerHTML += `<p class="hint" style="margin-top:10px;">
        ${state.attribution.leader} and ${state.attribution.tied_with.join(', ')} are tied on technique-overlap
        alone — disambiguating further needs evidence beyond what this model considers (malware artifacts,
        C2 infrastructure, targeted asset type).
      </p>`;
    }
    reportBtn.disabled = !state.connected;
  } else {
    attrEl.innerHTML = '<p class="hint">Attribution scoring runs after the timeline is reconstructed in Act 4.</p>';
    reportBtn.disabled = true;
  }
}

function renderMitre() {
  const container = document.getElementById('mitre-matrix');
  const hint = document.getElementById('mitre-coverage-hint');
  if (!state.mitreMatrix) { container.innerHTML = ''; return; }

  hint.textContent = `${state.mitreMatrix.hit_count} of ${state.mitreMatrix.total_techniques} techniques ` +
    `observed in this incident — full framework shown for context`;

  container.innerHTML = state.mitreMatrix.tactics.map(tactic => `
    <div class="mitre-column">
      <div class="mitre-column-head">
        <div class="mitre-tactic-name">${tactic.name}</div>
        <div class="mitre-tactic-count">${tactic.techniques.length} techniques</div>
      </div>
      <div class="mitre-column-body">
        ${tactic.techniques.map(t => `
          <div class="mitre-row ${t.hit ? 'hit' : ''}">
            <span class="mitre-id">${t.id}</span>
            <span class="mitre-name">${t.name}</span>
          </div>`).join('')}
      </div>
    </div>`).join('');
}

/* ============ Report download ============ */
async function downloadReport() {
  if (!state.reportBlockId) return;
  const res = await fetch(`${API_BASE}/reports/${state.reportBlockId}.pdf`);
  if (!res.ok) { alert('Report generation failed — is the backend running and has Act 4 completed?'); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'ironledger-report.pdf';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* ============ Wiring ============ */
document.addEventListener('DOMContentLoaded', () => {
  const apiInput = document.getElementById('api-base-input');
  if (apiInput.value) API_BASE = apiInput.value.trim().replace(/\/$/, '');

  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const view = btn.dataset.view;
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.getElementById('view-' + view).classList.add('active');
      const titles = {
        dashboard: ['Home', 'Live posture of the operational technology network'],
        ledger: ['Ledger Explorer', 'On-chain evidence, block by block'],
        anomaly: ['Anomaly Detection', 'Physics envelopes and the Isolation Forest model'],
        forensics: ['Forensic Timeline', 'Backward-walk reconstruction and attribution'],
        mitre: ['ATT&CK Matrix', 'MITRE ATT&CK for ICS technique correlation'],
      };
      document.getElementById('page-title').textContent = titles[view][0];
      document.getElementById('page-sub').textContent = titles[view][1];
    });
  });

  document.querySelectorAll('.act-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!state.connected) { showBanner(); return; }
      await runToAct(+btn.dataset.act);
    });
  });
  document.getElementById('act-reset').addEventListener('click', async () => {
    if (!state.connected) { showBanner(); return; }
    await resetAll();
  });

  document.getElementById('ledger-body').addEventListener('click', (e) => {
    const row = e.target.closest('tr[data-index]');
    if (!row) return;
    state.selectedBlock = +row.dataset.index;
    renderLedger();
  });

  document.getElementById('report-btn').addEventListener('click', downloadReport);

  document.getElementById('api-connect-btn').addEventListener('click', async () => {
    API_BASE = document.getElementById('api-base-input').value.trim().replace(/\/$/, '');
    await bootstrap();
  });
  document.getElementById('conn-banner-retry').addEventListener('click', bootstrap);

  bootstrap();
});

async function bootstrap() {
  const ok = await checkConnection();
  if (!ok) { render(); return; }
  try {
    const simState = await api('/simulate/state');
    state.act = simState.act || 0;
  } catch { state.act = 0; }
  await refreshAll();
  render();
}

// Debug hook for devtools/tests.
window.__ironledger = { getState: () => state, runToAct, resetAll, checkConnection, refreshAll, setApiBase: (u) => { API_BASE = u; } };
