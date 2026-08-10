const $ = (s) => document.querySelector(s);
const state = { actions: new Set(), charts: {}, tab: 'waf', httpLimits: {}, wafLimits: {}, rangeSel: { waf: '24', http: '24' } };
let loadSeq = 0;
let zonesSeq = 0;
let rangeSeq = 0;

const PALETTE = ['#e74c3c','#f1c40f','#3498db','#2ecc71','#9b59b6','#1abc9c','#e67e22','#34495e','#ff7675','#74b9ff'];
const ACTION_COLOR = { block:'#e74c3c', managed_challenge:'#f1c40f', jschallenge:'#f39c12', challenge:'#e67e22', allow:'#2ecc71', log:'#3498db', skip:'#9b59b6' };

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error((await r.json().catch(()=>({error:r.statusText}))).error || r.statusText);
  return r.json();
}

function buildQuery() {
  const p = new URLSearchParams();
  p.set('account', $('#account').value);
  p.set('zone', $('#zone').value);
  const hours = Number($('#range').value);
  const until = new Date();
  const since = new Date(until.getTime() - hours*3600*1000);
  p.set('since', since.toISOString());
  p.set('until', until.toISOString());
  if (state.actions.size) p.set('action', [...state.actions].join(','));
  const appendFilter = (param, inputId, transform) => {
    for (const value of parseFilterSet(inputId, transform)) p.append(param, value);
  };
  appendFilter('host', 'hostFilter');
  appendFilter('path', 'pathFilter');
  appendFilter('rule', 'ruleFilter');
  appendFilter('country', 'countryFilter', value => value.toUpperCase());
  appendFilter('asn', 'asnFilter', value => value.replace(/^AS/i, ''));
  appendFilter('ua', 'uaFilter');
  return p.toString();
}

// Shared account/zone/time-range params, without the WAF-only facet filters (used by the HTTP tab).
function buildBaseQuery() {
  const p = new URLSearchParams();
  p.set('account', $('#account').value);
  p.set('zone', $('#zone').value);
  const hours = Number($('#range').value);
  const until = new Date();
  const since = new Date(until.getTime() - hours*3600*1000);
  p.set('since', since.toISOString());
  p.set('until', until.toISOString());
  return p.toString();
}

function showError(msg) { const e = $('#error'); if (msg) { e.textContent = msg; e.style.display = 'block'; } else e.style.display = 'none'; }
function showWarn(msg) { const e = $('#warn'); if (msg) { e.textContent = msg; e.style.display = 'block'; } else e.style.display = 'none'; }

// ── Facet (multi-select) helpers ────────────────────────────────────────────
// Path and User-Agent use one exact value per line because commas are valid data;
// the shorter facets accept comma- or newline-separated values.
function parseFilterSet(inputId, transform) {
  const exactLines = inputId === 'pathFilter' || inputId === 'uaFilter';
  const separator = exactLines ? /\r?\n/ : /[,\r\n]+/;
  const raw = ($('#'+inputId).value || '').split(separator).map(s => s.trim()).filter(Boolean);
  return new Set(transform ? raw.map(transform) : raw);
}
function writeFilterSet(inputId, set) {
  const exactLines = inputId === 'pathFilter' || inputId === 'uaFilter';
  $('#'+inputId).value = [...set].join(exactLines ? '\n' : ',');
}
function toggleFilter(inputId, value, transform) {
  if (value === undefined || value === null || value === '' || value === '?' || value === '(unknown)') return;
  const v = transform ? transform(value) : String(value);
  const set = parseFilterSet(inputId, transform);
  if (set.has(v)) set.delete(v); else set.add(v);
  writeFilterSet(inputId, set);
  // Open the filter bar so the user can see / edit active filters
  const d = $('#filtersDetails'); if (d && !d.open) d.open = true;
  load();
}
function updateFiltersBadge() {
  const ids = ['hostFilter','pathFilter','ruleFilter','countryFilter','asnFilter','uaFilter'];
  let n = 0;
  for (const id of ids) {
    n += parseFilterSet(id).size;
  }
  const b = $('#filtersActiveCount');
  if (n > 0) { b.textContent = n; b.style.display = 'inline-block'; }
  else { b.style.display = 'none'; }
}
const ACTIVE_BAR = '#f6821f';
const INACTIVE_BAR = '#3a414e';
function barColors(keys, active, fallback) {
  if (!active.size) return keys.map(() => fallback);
  return keys.map(k => active.has(k) ? ACTIVE_BAR : INACTIVE_BAR);
}

function destroyChart(key) { if (state.charts[key]) { state.charts[key].destroy(); delete state.charts[key]; } }

function describeChart(canvasId, title, labels, values, formatter = fmtNum) {
  const details = labels.slice(0, 20).map((label, index) => `${label}: ${formatter(values[index])}`);
  $('#'+canvasId).setAttribute('aria-label', details.length ? `${title}. ${details.join('; ')}` : `${title}. No data.`);
}

function renderChartControls(canvasId, labels, values, onPick, active) {
  const container = $('#'+canvasId+'Controls');
  if (!container) return;
  container.replaceChildren();
  if (!onPick) return;
  labels.forEach((label, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'chip';
    button.textContent = `${label} (${fmtNum(values[index])})`;
    button.setAttribute('aria-pressed', String(active?.has(label) || false));
    button.addEventListener('click', () => onPick(label));
    container.appendChild(button);
  });
}

function barChart(canvasId, labels, values, colors, onPick, active) {
  destroyChart(canvasId);
  describeChart(canvasId, 'Bar chart', labels, values);
  renderChartControls(canvasId, labels, values, onPick, active);
  const chart = new Chart($('#'+canvasId), {
    type: 'bar',
    data: { labels, datasets: [{ data: values, backgroundColor: colors || PALETTE, borderWidth: 0 }] },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8a93a6' } }, y: { ticks: { color: '#e6e8ee' } } },
      maintainAspectRatio: false,
      onClick: onPick ? (_evt, els) => {
        if (els.length) onPick(chart.data.labels[els[0].index]);
      } : undefined,
      onHover: onPick ? (evt, els) => {
        const native = evt.native; if (!native) return;
        const canvas = native.target;
        let cursor = els.length ? 'pointer' : '';
        if (!els.length) {
          const area = chart.chartArea;
          const rect = canvas.getBoundingClientRect();
          const x = native.clientX - rect.left;
          const y = native.clientY - rect.top;
          if (x < area.left && y >= area.top && y <= area.bottom) cursor = 'pointer';
        }
        canvas.style.cursor = cursor;
      } : undefined,
    }
  });
  state.charts[canvasId] = chart;
  if (onPick) {
    // Native click listener for the tick label area (Chart.js onClick is unreliable here)
    const canvas = chart.canvas;
    // Remove any previous listener attached by an earlier render — otherwise
    // each redraw stacks another handler that still closes over a stale chart
    // (with stale labels from a previous zone/filter), causing flicker and
    // unrelated values being toggled.
    if (canvas._tickClickHandler) {
      canvas.removeEventListener('click', canvas._tickClickHandler);
    }
    const handler = (e) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const area = chart.chartArea;
      const lbls = chart.data.labels;
      if (!lbls || !lbls.length) return;
      if (x >= area.left) return; // clicks inside chart area are handled by Chart.js onClick
      if (y < area.top || y > area.bottom) return;
      const slot = (area.bottom - area.top) / lbls.length;
      const idx = Math.floor((y - area.top) / slot);
      if (idx >= 0 && idx < lbls.length) onPick(lbls[idx]);
    };
    canvas._tickClickHandler = handler;
    canvas.addEventListener('click', handler);
  }
}

function doughnut(canvasId, labels, values, colors) {
  destroyChart(canvasId);
  describeChart(canvasId, 'Doughnut chart', labels, values);
  state.charts[canvasId] = new Chart($('#'+canvasId), {
    type: 'doughnut',
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: '#171a21', borderWidth: 2 }] },
    options: { plugins: { legend: { position: 'bottom', labels: { color: '#e6e8ee' } } }, maintainAspectRatio: false }
  });
}

function timeSeries(canvasId, series) {
  destroyChart(canvasId);
  // pivot to per-action
  const hours = [...new Set(series.map(s => s.hour))].sort();
  const actions = [...new Set(series.map(s => s.action))];
  describeChart(canvasId, 'Sampled WAF rows by action over time', actions,
    actions.map(action => series.filter(point => point.action === action).reduce((sum, point) => sum + point.count, 0)));
  const datasets = actions.map(a => ({
    label: a,
    data: hours.map(h => {
      const m = series.find(x => x.hour === h && x.action === a);
      return m ? m.count : 0;
    }),
    backgroundColor: ACTION_COLOR[a] || '#888',
    borderColor: ACTION_COLOR[a] || '#888',
    stack: 's',
  }));
  state.charts[canvasId] = new Chart($('#'+canvasId), {
    type: 'bar',
    data: { labels: hours.map(h => h.replace('T',' ').slice(5,16)), datasets },
    options: { plugins: { legend: { labels: { color: '#e6e8ee' } } }, scales: { x: { stacked: true, ticks: { color: '#8a93a6' } }, y: { stacked: true, ticks: { color: '#8a93a6' } } }, maintainAspectRatio: false }
  });
}

function bindToggleRows(tbody, onActivate) {
  tbody.querySelectorAll('tr').forEach(tr => {
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-pressed', String(tr.classList.contains('active')));
    const activate = () => onActivate(tr);
    tr.addEventListener('click', activate);
    tr.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activate();
      }
    });
  });
}

function renderRulesTable(rows) {
  const active = parseFilterSet('ruleFilter');
  const any = active.size > 0;
  const tbody = $('#tblRules tbody');
  tbody.innerHTML = rows.slice(0, 30).map(r => {
    const isActive = active.has(r.key);
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-rule="${escapeHtml(r.key)}"><td>${escapeHtml(r.key)}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  bindToggleRows(tbody, tr => toggleFilter('ruleFilter', tr.dataset.rule));
}

function renderPathsTable(rows) {
  const active = parseFilterSet('pathFilter');
  const any = active.size > 0;
  const tbody = $('#tblPaths tbody');
  tbody.innerHTML = rows.slice(0, 50).map(r => {
    const isActive = active.has(r.key);
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-path="${escapeHtml(r.key)}"><td title="${escapeHtml(r.key)}">${escapeHtml(r.key.length > 100 ? r.key.slice(0,100)+'…' : r.key)}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  bindToggleRows(tbody, tr => toggleFilter('pathFilter', tr.dataset.path));
}

function renderAsnTable(rows) {
  const active = parseFilterSet('asnFilter');
  const any = active.size > 0;
  const tbody = $('#tblAsn tbody');
  tbody.innerHTML = rows.slice(0, 50).map(r => {
    const isActive = active.has(r.key);
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-asn="${escapeHtml(r.key)}"><td>AS${escapeHtml(r.key)}</td><td title="${escapeHtml(r.label||'')}">${escapeHtml((r.label||'').slice(0,60))}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  bindToggleRows(tbody, tr => toggleFilter('asnFilter', tr.dataset.asn));
}

function renderUaTable(rows) {
  const active = parseFilterSet('uaFilter');
  const any = active.size > 0;
  const tbody = $('#tblUa tbody');
  tbody.innerHTML = rows.slice(0, 50).map(r => {
    const isActive = active.has(r.key);
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-ua="${escapeHtml(r.key)}"><td title="${escapeHtml(r.key)}">${escapeHtml(r.key.length > 120 ? r.key.slice(0,120)+'…' : r.key)}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  bindToggleRows(tbody, tr => toggleFilter('uaFilter', tr.dataset.ua));
}

function renderEvents(events) {
  $('#eventsCount').textContent = `(${events.length})`;
  const tbody = $('#tblEvents tbody');
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${escapeHtml((e.datetime||'').replace('T',' ').slice(0,19))}</td>
      <td><span class="badge b-${escapeHtml(e.action||'')}">${escapeHtml(e.action||'')}</span></td>
      <td>${escapeHtml(e.source||'')}</td>
      <td>${escapeHtml(e.clientCountryName||'')}</td>
      <td>${escapeHtml(e.clientIP||'')}</td>
      <td title="${escapeHtml(e.clientASNDescription||'')}">${e.clientAsn ? 'AS'+e.clientAsn : ''}</td>
      <td>${escapeHtml(e.clientRequestHTTPHost||'')}</td>
      <td title="${escapeHtml(e.clientRequestPath||'')}">${escapeHtml((e.clientRequestPath||'').slice(0,60))}</td>
      <td>${escapeHtml(e.clientRequestHTTPMethodName||'')}</td>
      <td>${escapeHtml(e.ruleId||'')}</td>
      <td>${escapeHtml(e.rayName||'')}</td>
    </tr>
  `).join('');
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function loadZones() {
  const seq = ++zonesSeq;
  ++rangeSeq;
  ++loadSeq;
  const acc = $('#account').value;
  if (!acc) return;
  showError(''); $('#refresh').disabled = true;
  try {
    const { zones } = await api('/api/zones?account=' + encodeURIComponent(acc));
    if (seq !== zonesSeq || $('#account').value !== acc) return;
    if (!zones.length) { $('#zone').innerHTML = ''; showError('Account has no zones, or the token is missing Zone: Read.'); return; }
    $('#zone').innerHTML = zones.map(z => `<option value="${escapeHtml(z.id)}">${escapeHtml(z.name)} (${escapeHtml(z.plan||'?')})</option>`).join('');
    await applyTabRangeAndLoad();
  } catch (e) { if (seq === zonesSeq) showError(e.message); }
  finally { if (seq === zonesSeq) $('#refresh').disabled = false; }
}

async function load() {
  if (!$('#zone').value) return;
  const seq = ++loadSeq;
  showError(''); showWarn(''); $('#refresh').disabled = true;
  const t0 = performance.now();
  try {
    const q = buildQuery();
    const summary = await api('/api/stats?'+q);
    if (seq !== loadSeq) return; // superseded by a newer load()
    const dur = Math.round(performance.now() - t0);
    const cache = summary.cache || '—';
    const tag = cache === 'HIT' ? '⚡ cache HIT' : (cache === 'MISS' ? '☁ cache MISS' : '');
    $('#perf').textContent = `${dur} ms  ·  ${tag}`;
    const events = { events: summary.events || [] };
    if (summary.range && summary.range.maxRangeSeconds) {
      const key = $('#account').value + '|' + $('#zone').value;
      const maxH = Math.max(1, Math.floor(summary.range.maxRangeSeconds / 3600));
      if (summary.range.limitSource === 'cloudflare') state.wafLimits[key] = maxH;
      setRangeOptions(maxH, $('#range').value);
    }

    // KPIs
    const total = summary.byAction.reduce((s, r) => s + r.count, 0);
    const get = (k) => summary.byAction.find(r => r.key === k)?.count || 0;
    $('#kpiTotal').textContent = total.toLocaleString('en-US');
    $('#kpiBlock').textContent = get('block').toLocaleString('en-US');
    $('#kpiChallenge').textContent = (get('managed_challenge')+get('jschallenge')+get('challenge')).toLocaleString('en-US');
    $('#kpiAllow').textContent = (get('allow')+get('log')).toLocaleString('en-US');

    timeSeries('chartSeries', summary.series);
    doughnut('chartAction', summary.byAction.map(r=>r.key), summary.byAction.map(r=>r.count),
      summary.byAction.map(r => ACTION_COLOR[r.key] || '#888'));
    const countryKeys = summary.byCountry.slice(0,15).map(r=>r.key||'?');
    const activeCountry = parseFilterSet('countryFilter');
    barChart('chartCountry', countryKeys, summary.byCountry.slice(0,15).map(r=>r.count),
      barColors(countryKeys, activeCountry, '#3498db'), (label) => toggleFilter('countryFilter', label), activeCountry);
    const hostKeys = summary.byHost.slice(0,15).map(r=>r.key||'?');
    const activeHost = parseFilterSet('hostFilter');
    barChart('chartHost', hostKeys, summary.byHost.slice(0,15).map(r=>r.count),
      barColors(hostKeys, activeHost, '#3498db'), (label) => toggleFilter('hostFilter', label), activeHost);
    doughnut('chartSource', summary.bySource.map(r=>r.key), summary.bySource.map(r=>r.count), PALETTE);
    renderRulesTable(summary.byRule);
    renderPathsTable(summary.byPath || []);
    renderAsnTable(summary.byAsn || []);
    renderUaTable(summary.byUserAgent || []);
    renderEvents(events.events);
    updateFiltersBadge();
    const notes = ['Cloudflare may adaptively sample WAF event logs. Counts show returned log rows, not estimated event totals.'];
    if (summary.sampling?.rowLimitReached || summary.truncated) {
      const n = (summary.sampledRows ?? summary.totalSampled ?? 0).toLocaleString('en-US');
      notes.push(`The response also reached its ${n}-row limit, so older sampled rows are omitted.`);
    }
    if (summary.range?.clamped) {
      notes.push(`Range limited to the most recent ${fmtDuration(summary.range.effectiveSeconds)} for this zone.`);
    }
    if (summary.range?.limitSource === 'fallback') {
      notes.push('The zone limit lookup was unavailable; the requested range was sent unchanged.');
    }
    showWarn(notes.join('  '));
  } catch (e) {
    if (seq === loadSeq) showError(e.message);
  } finally { if (seq === loadSeq) $('#refresh').disabled = false; }
}

// ── HTTP Traffic tab ────────────────────────────────────────────────────────
const STATUS_COLOR = { '2xx':'#2ecc71', '3xx':'#3498db', '4xx':'#f1c40f', '5xx':'#e74c3c', 'other':'#9b59b6' };

function fmtNum(n) { return Math.round(n || 0).toLocaleString('en-US'); }
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B','KB','MB','GB','TB','PB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n >= 10 ? 0 : 1)) + ' ' + u[i];
}
function fmtDuration(secs) {
  secs = Number(secs) || 0;
  if (secs >= 48 * 3600) return Math.round(secs / 86400) + ' days';
  const h = Math.max(1, Math.round(secs / 3600));
  return h + (h === 1 ? ' hour' : ' hours');
}
function fmtTimeLabel(t, dim) {
  const s = String(t || '');
  return dim === 'datetimeMinute' ? s.slice(11, 16) : s.replace('T', ' ').slice(5, 16);
}
function statusClass(code) {
  const n = Number(code);
  if (n >= 200 && n < 300) return '2xx';
  if (n >= 300 && n < 400) return '3xx';
  if (n >= 400 && n < 500) return '4xx';
  if (n >= 500 && n < 600) return '5xx';
  return 'other';
}
function togglePanel(id, show) { const el = $('#'+id); if (el) el.style.display = show ? '' : 'none'; }

// Re-flow the HTTP breakdown panels by view. Short (adaptive) view packs cache / content / version /
// by-status-class into one row of quarters. Long (roll-up) view — where hostnames, paths and
// performance are hidden — arranges the remaining breakdowns into two rows of thirds, reordering via
// CSS `order` so "status codes" sits next to top countries + cache (col classes keep it responsive).
function layoutHttpPanels(long) {
  const set = (id, cols, order) => {
    const el = $('#' + id); if (!el) return;
    el.classList.remove('col-3', 'col-4', 'col-6', 'col-8', 'col-12');
    el.classList.add('col-' + cols);
    el.style.order = order == null ? '' : String(order);
  };
  if (long) {
    set('panelHttpCountry', 4, 1);
    set('panelHttpCache', 4, 2);
    set('panelHttpStatusCodes', 4, 3);
    set('panelHttpContentType', 4, 4);
    set('panelHttpVersion', 4, 5);
    set('panelHttpStatusClass', 4, 6);
  } else {
    set('panelHttpCountry', 4, null);
    set('panelHttpHost', 4, null);
    set('panelHttpContentType', 4, null);
    set('panelHttpCache', 4, null);
    set('panelHttpVersion', 4, null);
    set('panelHttpStatusClass', 4, null);
    set('panelHttpPath', 6, null);
    set('panelHttpStatusCodes', 6, null);
  }
}

function comboChart(canvasId, labels, bars, line, barLabel, lineLabel) {
  destroyChart(canvasId);
  const barTotal = bars.reduce((sum, value) => sum + (Number(value) || 0), 0);
  const lineTotal = line.reduce((sum, value) => sum + (Number(value) || 0), 0);
  $('#'+canvasId).setAttribute('aria-label', `${barLabel}: ${fmtNum(barTotal)}. ${lineLabel}: ${fmtBytes(lineTotal)}.`);
  state.charts[canvasId] = new Chart($('#'+canvasId), {
    data: { labels, datasets: [
      { type:'bar', label:barLabel, data:bars, backgroundColor:'#3498db', borderWidth:0, yAxisID:'y', order:2 },
      { type:'line', label:lineLabel, data:line, borderColor:'#f6821f', backgroundColor:'#f6821f', tension:.3, pointRadius:0, borderWidth:2, yAxisID:'y1', order:1 },
    ]},
    options: {
      maintainAspectRatio:false,
      interaction:{ mode:'index', intersect:false },
      plugins:{ legend:{ labels:{ color:'#e6e8ee' } },
        tooltip:{ callbacks:{ label:(c)=> c.dataset.yAxisID==='y1' ? `${c.dataset.label}: ${fmtBytes(c.parsed.y)}` : `${c.dataset.label}: ${fmtNum(c.parsed.y)}` } } },
      scales:{
        x:{ ticks:{ color:'#8a93a6', maxRotation:0, autoSkip:true, maxTicksLimit:12 }, grid:{ color:'#262b36' } },
        y:{ position:'left', beginAtZero:true, ticks:{ color:'#8a93a6' }, grid:{ color:'#262b36' } },
        y1:{ position:'right', beginAtZero:true, ticks:{ color:'#8a93a6', callback:(v)=>fmtBytes(v) }, grid:{ display:false } },
      }
    }
  });
}

function perfChart(canvasId, series, dim) {
  destroyChart(canvasId);
  const labels = series.map(s => fmtTimeLabel(s.t, dim));
  const available = series.filter(point => point.originMs != null || point.ttfbMs != null);
  $('#'+canvasId).setAttribute('aria-label', available.length
    ? `Performance chart with ${available.length} time points.`
    : 'Performance chart. No timing data.');
  state.charts[canvasId] = new Chart($('#'+canvasId), {
    type:'line',
    data:{ labels, datasets:[
      { label:'Origin response (ms)', data:series.map(s=>s.originMs), borderColor:'#e67e22', backgroundColor:'#e67e22', tension:.3, pointRadius:0, borderWidth:2, spanGaps:true },
      { label:'Edge TTFB (ms)', data:series.map(s=>s.ttfbMs), borderColor:'#3498db', backgroundColor:'#3498db', tension:.3, pointRadius:0, borderWidth:2, spanGaps:true },
    ]},
    options:{ maintainAspectRatio:false, plugins:{ legend:{ labels:{ color:'#e6e8ee' } } },
      scales:{ x:{ ticks:{ color:'#8a93a6', maxRotation:0, autoSkip:true, maxTicksLimit:12 }, grid:{ color:'#262b36' } }, y:{ beginAtZero:true, ticks:{ color:'#8a93a6' }, grid:{ color:'#262b36' } } } }
  });
}

function renderHttpStatusDoughnut(byStatus) {
  const m = new Map();
  for (const r of byStatus) { const c = statusClass(r.key); m.set(c, (m.get(c)||0) + r.requests); }
  const order = ['2xx','3xx','4xx','5xx','other'];
  const labels = order.filter(k => m.has(k));
  doughnut('chartHttpStatus', labels, labels.map(k=>m.get(k)), labels.map(k=>STATUS_COLOR[k]));
}

function renderHttpPaths(rows) {
  $('#tblHttpPaths tbody').innerHTML = rows.slice(0, 50).map(r =>
    `<tr><td title="${escapeHtml(r.key)}">${escapeHtml(r.key.length > 100 ? r.key.slice(0,100)+'…' : r.key)}</td><td class="num">${fmtNum(r.requests)}</td><td class="num">${fmtBytes(r.bytes)}</td></tr>`
  ).join('');
}

function renderHttpStatusTable(rows) {
  const sorted = [...rows].sort((a,b) => b.requests - a.requests);
  $('#tblHttpStatus tbody').innerHTML = sorted.slice(0, 30).map(r =>
    `<tr><td><span class="badge b-status-${statusClass(r.key)}">${escapeHtml(String(r.key))}</span></td><td class="num">${fmtNum(r.requests)}</td></tr>`
  ).join('');
}

async function loadHttp() {
  if (!$('#zone').value) return;
  const seq = ++loadSeq;
  showError(''); showWarn(''); $('#refresh').disabled = true;
  const t0 = performance.now();
  try {
    const d = await api('/api/http-stats?' + buildBaseQuery());
    if (seq !== loadSeq) return; // superseded by a newer load

    const dur = Math.round(performance.now() - t0);
    const cache = d.cache || '—';
    const tag = cache === 'HIT' ? '⚡ cache HIT' : (cache === 'MISS' ? '☁ cache MISS' : '');
    $('#perf').textContent = `${dur} ms  ·  ${tag}`;
    if (d.range && d.range.maxRangeSeconds) {
      const key = $('#account').value + '|' + $('#zone').value;
      const maxH = Math.max(1, Math.floor(d.range.maxRangeSeconds / 3600));
      state.httpLimits[key] = maxH;
      setRangeOptions(maxH, $('#range').value);
    }
    $('#httpWindow').textContent = d.range?.calendarDays
      ? `· ${d.range.calendarDays} calendar days`
      : (d.range?.effectiveSeconds ? '· last ' + fmtDuration(d.range.effectiveSeconds) : '');
    layoutHttpPanels(d.dataset && d.dataset !== 'adaptive');

    $('#hkpiReq').textContent = fmtNum(d.totals.requests);
    $('#hkpiBytes').textContent = fmtBytes(d.totals.bytes);
    const usesUniqueIps = d.totals.visits == null;
    $('#hkpiVisitsLabel').textContent = usesUniqueIps ? 'Unique IPs' : 'Visits';
    const visitorValue = usesUniqueIps ? d.totals.uniqueIps : d.totals.visits;
    $('#hkpiVisits').textContent = visitorValue == null ? '—' : fmtNum(visitorValue);
    $('#hkpiCached').textContent = (d.totals.cachedPct == null) ? '—' : d.totals.cachedPct.toFixed(0) + '%';

    const labels = d.series.map(s => fmtTimeLabel(s.t, d.timeDim));
    comboChart('chartHttpSeries', labels, d.series.map(s=>s.requests), d.series.map(s=>s.bytes), 'Requests', 'Data transfer');

    renderHttpStatusDoughnut(d.byStatus || []);

    togglePanel('panelHttpCountry', (d.byCountry || []).length);
    if ((d.byCountry || []).length) {
      const cKeys = d.byCountry.slice(0,15).map(r => r.key || '?');
      barChart('chartHttpCountry', cKeys, d.byCountry.slice(0,15).map(r=>r.requests), cKeys.map(()=>'#3498db'));
    }
    togglePanel('panelHttpHost', (d.byHost || []).length);
    if ((d.byHost || []).length) {
      const hKeys = d.byHost.slice(0,15).map(r => r.key || '?');
      barChart('chartHttpHost', hKeys, d.byHost.slice(0,15).map(r=>r.requests), hKeys.map(()=>'#2ecc71'));
    }

    togglePanel('panelHttpCache', d.byCacheStatus && d.byCacheStatus.length);
    if (d.byCacheStatus && d.byCacheStatus.length)
      doughnut('chartHttpCache', d.byCacheStatus.map(r=>r.key), d.byCacheStatus.map(r=>r.requests), d.byCacheStatus.map((_,i)=>PALETTE[i%PALETTE.length]));
    togglePanel('panelHttpContentType', d.byContentType && d.byContentType.length);
    if (d.byContentType && d.byContentType.length)
      doughnut('chartHttpContentType', d.byContentType.slice(0,8).map(r=>r.key), d.byContentType.slice(0,8).map(r=>r.requests), PALETTE);
    togglePanel('panelHttpVersion', d.byHttpVersion && d.byHttpVersion.length);
    if (d.byHttpVersion && d.byHttpVersion.length)
      doughnut('chartHttpVersion', d.byHttpVersion.map(r=>r.key), d.byHttpVersion.map(r=>r.requests), PALETTE);

    togglePanel('panelHttpPath', (d.byPath || []).length);
    if ((d.byPath || []).length) renderHttpPaths(d.byPath);
    renderHttpStatusTable(d.byStatus || []);

    togglePanel('panelHttpPerf', !!d.perf);
    if (d.perf) {
      $('#hkpiOrigin').textContent = d.perf.originMs == null ? '—' : Math.round(d.perf.originMs) + ' ms';
      $('#hkpiTtfb').textContent = d.perf.ttfbMs == null ? '—' : Math.round(d.perf.ttfbMs) + ' ms';
      perfChart('chartHttpPerf', d.perf.series || [], d.timeDim);
    }

    const notes = [];
    if (d.range && d.range.clamped) notes.push('Range limited to the most recent ' + fmtDuration(d.range.effectiveSeconds) + ' (plan limit for this zone).');
    if (d.dataset && d.dataset !== 'adaptive') notes.push('Long-range view uses Cloudflare\u2019s ' + (d.dataset === 'daily' ? 'daily calendar-day' : 'hourly') + ' roll-up. The visitor KPI is globally aggregated Unique IPs; Top paths, Top hostnames and Edge performance aren\u2019t available at this range.');
    if (!d.series.length) notes.push('No HTTP traffic in the selected range for this zone.');
    showWarn(notes.join('  '));
  } catch (e) {
    if (seq === loadSeq) showError(e.message);
  } finally { if (seq === loadSeq) $('#refresh').disabled = false; }
}

// ── Tab routing ─────────────────────────────────────────────────────────────
function loadActive() { return state.tab === 'http' ? loadHttp() : load(); }
// The range dropdown is shared by both tabs. WAF options come from the per-zone Settings endpoint;
// HTTP starts generous and is refined from the range metadata returned with the first stats load.
const RANGE_OPTIONS = [
  { h: 1, l: '1 h' }, { h: 6, l: '6 h' }, { h: 24, l: '24 h' },
  { h: 72, l: '3 d' }, { h: 168, l: '7 d' }, { h: 336, l: '14 d' }, { h: 720, l: '30 d' },
];
const WAF_FALLBACK_MAX_H = 720;

function setRangeOptions(maxHours, preferValue) {
  const opts = RANGE_OPTIONS.filter(o => o.h <= maxHours);
  if (!opts.length) opts.push(RANGE_OPTIONS[2]); // safety net: always offer at least 24 h
  const sel = $('#range');
  const want = String(preferValue ?? sel.value ?? '24');
  sel.innerHTML = opts.map(o => `<option value="${o.h}">${o.l}</option>`).join('');
  const valid = opts.some(o => String(o.h) === want);
  sel.value = valid ? want : String(opts[opts.length - 1].h);
  state.rangeSel[state.tab] = sel.value;
  sel.title = state.tab === 'http'
    ? `HTTP analytics for this zone reaches back up to ${opts[opts.length - 1].l}`
    : `WAF events for this zone reach back up to ${opts[opts.length - 1].l}`;
}

// HTTP data is retained well beyond the 24 h WAF cap, so when the Settings lookup can't pin an exact
// limit we still offer the full set (the backend clamps the actual query to what the plan allows).
const HTTP_FALLBACK_MAX_H = 720; // 30 d
async function fetchWafLimits(acc, zone) {
  if (!acc || !zone) return WAF_FALLBACK_MAX_H;
  const key = acc + '|' + zone;
  if (state.wafLimits[key] != null) return state.wafLimits[key];
  let h = WAF_FALLBACK_MAX_H;
  try {
    const s = await api('/api/waf-settings?account=' + encodeURIComponent(acc) + '&zone=' + encodeURIComponent(zone));
    const secs = Number(s.maxRangeSeconds) || 0;
    if (secs >= 3600) h = Math.max(1, Math.floor(secs / 3600));
    if (s.source === 'cloudflare') state.wafLimits[key] = h;
  } catch { /* keep the generous, non-sticky fallback */ }
  return h;
}

// Rebuild the range dropdown for the active tab (HTTP needs an async limits lookup), then load.
async function applyTabRangeAndLoad() {
  const seq = ++rangeSeq;
  ++loadSeq;
  const tab = state.tab;
  const acc = $('#account').value;
  const zone = $('#zone').value;
  if (!acc || !zone) return;
  if (tab === 'http') {
    const key = acc + '|' + zone;
    setRangeOptions(state.httpLimits[key] || HTTP_FALLBACK_MAX_H, state.rangeSel.http);
  } else {
    const maxH = await fetchWafLimits(acc, zone);
    if (seq !== rangeSeq || state.tab !== tab || $('#account').value !== acc || $('#zone').value !== zone) return;
    setRangeOptions(maxH, state.rangeSel.waf);
  }
  if (seq !== rangeSeq || state.tab !== tab || $('#account').value !== acc || $('#zone').value !== zone) return;
  return loadActive();
}
function setTab(tab) {
  if (state.tab === tab) return;
  ++loadSeq;
  state.tab = tab;
  document.querySelectorAll('#tabs .tab').forEach(b => {
    const selected = b.dataset.tab === tab;
    b.classList.toggle('active', selected);
    b.setAttribute('aria-selected', String(selected));
    b.tabIndex = selected ? 0 : -1;
  });
  const isHttp = tab === 'http';
  $('#view-waf').hidden = isHttp;
  $('#view-http').hidden = !isHttp;
  // WAF-only header controls (action chips, filters, Clear/Export) make no sense on the HTTP tab.
  ['wafActions','filtersDetails','wafControls'].forEach(id => { const el = $('#'+id); if (el) el.style.display = isHttp ? 'none' : ''; });
  showError(''); showWarn(''); $('#perf').textContent = '';
  applyTabRangeAndLoad();
}

async function init() {
  try {
    const { accounts } = await api('/api/accounts');
    if (!accounts.length) { showError('No accounts configured — set CFACC_<ID>_LABEL, _ACCOUNT, _TOKEN as Worker secrets.'); return; }
    $('#account').innerHTML = accounts.map(a => `<option value="${escapeHtml(a.id)}">${escapeHtml(a.label)}</option>`).join('');
    document.querySelectorAll('#actionChips .chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const a = chip.dataset.action;
        if (state.actions.has(a)) state.actions.delete(a); else state.actions.add(a);
        chip.classList.toggle('active');
        chip.setAttribute('aria-pressed', String(state.actions.has(a)));
      });
    });
    $('#refresh').addEventListener('click', loadActive);
    $('#exportCsv').addEventListener('click', async () => {
      if (!$('#zone').value) return;
      const btn = $('#exportCsv');
      btn.disabled = true;
      showError('');
      try {
        const r = await fetch('/api/export.csv?' + buildQuery());
        if (!r.ok) {
          const t = await r.text();
          throw new Error(t || r.statusText);
        }
        const blob = await r.blob();
        const cd = r.headers.get('content-disposition') || '';
        const m = cd.match(/filename="?([^"]+)"?/i);
        const filename = m ? m[1] : 'waf-export.csv';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (e) {
        showError('Export failed: ' + e.message);
      } finally {
        btn.disabled = false;
      }
    });
    $('#clearFilters').addEventListener('click', () => {
      state.actions.clear();
      document.querySelectorAll('#actionChips .chip').forEach(c => {
        c.classList.remove('active');
        c.setAttribute('aria-pressed', 'false');
      });
      ['hostFilter','pathFilter','ruleFilter','countryFilter','asnFilter','uaFilter'].forEach(id => $('#'+id).value = '');
      updateFiltersBadge();
      load();
    });
    $('#account').addEventListener('change', loadZones);
    $('#zone').addEventListener('change', applyTabRangeAndLoad);
    $('#range').addEventListener('change', () => { state.rangeSel[state.tab] = $('#range').value; loadActive(); });
    const tabs = [...document.querySelectorAll('#tabs .tab')];
    tabs.forEach((button, index) => {
      button.addEventListener('click', () => setTab(button.dataset.tab));
      button.addEventListener('keydown', event => {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
        event.preventDefault();
        const direction = event.key === 'ArrowRight' ? 1 : -1;
        const next = tabs[(index + direction + tabs.length) % tabs.length];
        setTab(next.dataset.tab);
        next.focus();
      });
    });
    await loadZones();
  } catch (e) { showError(e.message); }
}
init();
