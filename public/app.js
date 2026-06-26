const $ = (s) => document.querySelector(s);
const state = { actions: new Set(), charts: {}, tab: 'waf', httpLimits: {}, rangeSel: { waf: '24', http: '24' } };
let loadSeq = 0;

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
  const host = $('#hostFilter').value.trim(); if (host) p.set('host', host);
  const path = $('#pathFilter').value.trim(); if (path) p.set('path', path);
  const rule = $('#ruleFilter').value.trim(); if (rule) p.set('rule', rule);
  const country = $('#countryFilter').value.trim(); if (country) p.set('country', country.toUpperCase());
  const asn = $('#asnFilter').value.trim(); if (asn) p.set('asn', asn);
  const ua = $('#uaFilter').value.trim(); if (ua) p.set('ua', ua);
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
// Each filter input holds a comma-separated set of values. Clicking an item in
// a table/chart adds or removes the value and triggers a reload.
function parseFilterSet(inputId, transform) {
  const raw = ($('#'+inputId).value || '').split(',').map(s => s.trim()).filter(Boolean);
  return new Set(transform ? raw.map(transform) : raw);
}
function writeFilterSet(inputId, set) {
  $('#'+inputId).value = [...set].join(',');
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
    const v = ($('#'+id).value || '').split(',').map(s=>s.trim()).filter(Boolean);
    n += v.length;
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

function barChart(canvasId, labels, values, colors, onPick) {
  destroyChart(canvasId);
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

function renderRulesTable(rows) {
  const active = parseFilterSet('ruleFilter');
  const any = active.size > 0;
  const tbody = $('#tblRules tbody');
  tbody.innerHTML = rows.slice(0, 30).map(r => {
    const isActive = active.has(r.key);
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-rule="${escapeHtml(r.key)}"><td>${escapeHtml(r.key)}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  tbody.querySelectorAll('tr').forEach(tr => tr.addEventListener('click', () => {
    toggleFilter('ruleFilter', tr.dataset.rule);
  }));
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
  tbody.querySelectorAll('tr').forEach(tr => tr.addEventListener('click', () => {
    toggleFilter('pathFilter', tr.dataset.path);
  }));
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
  tbody.querySelectorAll('tr').forEach(tr => tr.addEventListener('click', () => {
    toggleFilter('asnFilter', tr.dataset.asn);
  }));
}

function renderUaTable(rows) {
  // UA strings may contain commas → use single-select for UA (clicking the same UA clears the filter).
  const current = $('#uaFilter').value.trim();
  const any = current.length > 0;
  const tbody = $('#tblUa tbody');
  tbody.innerHTML = rows.slice(0, 50).map(r => {
    const isActive = current === r.key;
    const cls = isActive ? 'active' : (any ? 'inactive' : '');
    return `<tr class="row-toggle ${cls}" data-ua="${escapeHtml(r.key)}"><td title="${escapeHtml(r.key)}">${escapeHtml(r.key.length > 120 ? r.key.slice(0,120)+'…' : r.key)}</td><td class="num">${r.count}</td></tr>`;
  }).join('');
  tbody.querySelectorAll('tr').forEach(tr => tr.addEventListener('click', () => {
    const v = tr.dataset.ua;
    $('#uaFilter').value = ($('#uaFilter').value.trim() === v) ? '' : v;
    load();
  }));
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
  const acc = $('#account').value;
  if (!acc) return;
  showError(''); $('#refresh').disabled = true;
  try {
    const { zones } = await api('/api/zones?account=' + encodeURIComponent(acc));
    if (!zones.length) { $('#zone').innerHTML = ''; showError('Account has no zones, or the token is missing Zone: Read.'); return; }
    $('#zone').innerHTML = zones.map(z => `<option value="${z.id}">${escapeHtml(z.name)} (${z.plan||'?'})</option>`).join('');
    await applyTabRangeAndLoad();
  } catch (e) { showError(e.message); }
  finally { $('#refresh').disabled = false; }
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
      barColors(countryKeys, activeCountry, '#3498db'), (label) => toggleFilter('countryFilter', label));
    const hostKeys = summary.byHost.slice(0,15).map(r=>r.key||'?');
    const activeHost = parseFilterSet('hostFilter');
    barChart('chartHost', hostKeys, summary.byHost.slice(0,15).map(r=>r.count),
      barColors(hostKeys, activeHost, '#3498db'), (label) => toggleFilter('hostFilter', label));
    doughnut('chartSource', summary.bySource.map(r=>r.key), summary.bySource.map(r=>r.count), PALETTE);
    renderRulesTable(summary.byRule);
    renderPathsTable(summary.byPath || []);
    renderAsnTable(summary.byAsn || []);
    renderUaTable(summary.byUserAgent || []);
    renderEvents(events.events);
    updateFiltersBadge();
    if (summary.truncated) {
      const n = (summary.totalSampled || 0).toLocaleString('en-US');
      showWarn(`\u26A0 Showing a sample — this zone exceeds ${n} events in the selected range, so the statistics are based on the most recent ${n} events.`);
    } else {
      showWarn('');
    }
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
    $('#httpWindow').textContent = (d.range && d.range.effectiveSeconds) ? '· last ' + fmtDuration(d.range.effectiveSeconds) : '';
    layoutHttpPanels(d.dataset && d.dataset !== 'adaptive');

    $('#hkpiReq').textContent = fmtNum(d.totals.requests);
    $('#hkpiBytes').textContent = fmtBytes(d.totals.bytes);
    $('#hkpiVisits').textContent = fmtNum(d.totals.visits);
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
    if (d.dataset && d.dataset !== 'adaptive') notes.push('Long-range view uses Cloudflare\u2019s ' + (d.dataset === 'daily' ? 'daily' : 'hourly') + ' roll-up \u2014 Top paths, Top hostnames and Edge performance aren\u2019t available at this range.');
    if (!d.series.length) notes.push('No HTTP traffic in the selected range for this zone.');
    showWarn(notes.join('  '));
  } catch (e) {
    if (seq === loadSeq) showError(e.message);
  } finally { if (seq === loadSeq) $('#refresh').disabled = false; }
}

// ── Tab routing ─────────────────────────────────────────────────────────────
function loadActive() { return state.tab === 'http' ? loadHttp() : load(); }
// The range dropdown is shared by both tabs but its options differ: WAF events are only retained
// 24 h on Free, while HTTP analytics (httpRequestsAdaptiveGroups) reaches back much further — exactly
// how far is reported per-zone by /api/http-settings, so the HTTP options are built from that.
const RANGE_OPTIONS = [
  { h: 1, l: '1 h' }, { h: 6, l: '6 h' }, { h: 24, l: '24 h' },
  { h: 72, l: '3 d' }, { h: 168, l: '7 d' }, { h: 336, l: '14 d' }, { h: 720, l: '30 d' },
];
const WAF_MAX_H = 24;

function setRangeOptions(maxHours, preferValue) {
  const opts = RANGE_OPTIONS.filter(o => o.h <= maxHours);
  if (!opts.length) opts.push(RANGE_OPTIONS[2]); // safety net: always offer at least 24 h
  const sel = $('#range');
  const want = String(preferValue ?? sel.value ?? '24');
  sel.innerHTML = opts.map(o => `<option value="${o.h}">${o.l}</option>`).join('');
  const valid = opts.some(o => String(o.h) === want);
  sel.value = valid ? want : (opts.some(o => o.h === 24) ? '24' : String(opts[opts.length - 1].h));
  state.rangeSel[state.tab] = sel.value;
  sel.title = state.tab === 'http'
    ? `HTTP analytics for this zone reaches back up to ${opts[opts.length - 1].l}`
    : 'WAF events are retained 24 h on the Free plan';
}

// HTTP data is retained well beyond the 24 h WAF cap, so when the Settings lookup can't pin an exact
// limit we still offer the full set (the backend clamps the actual query to what the plan allows).
const HTTP_FALLBACK_MAX_H = 720; // 30 d
async function fetchHttpLimits() {
  const acc = $('#account').value, zone = $('#zone').value;
  if (!acc || !zone) return HTTP_FALLBACK_MAX_H;
  const key = acc + '|' + zone;
  if (state.httpLimits[key] != null) return state.httpLimits[key];
  let h = HTTP_FALLBACK_MAX_H;
  try {
    const s = await api('/api/http-settings?account=' + encodeURIComponent(acc) + '&zone=' + encodeURIComponent(zone));
    const secs = Number(s.maxRangeSeconds) || 0;
    if (secs >= 3600) h = Math.max(WAF_MAX_H, Math.floor(secs / 3600));
  } catch { /* keep the generous fallback */ }
  state.httpLimits[key] = h;
  return h;
}

// Rebuild the range dropdown for the active tab (HTTP needs an async limits lookup), then load.
async function applyTabRangeAndLoad() {
  if (state.tab === 'http') {
    const maxH = await fetchHttpLimits();
    setRangeOptions(maxH, state.rangeSel.http);
  } else {
    setRangeOptions(WAF_MAX_H, state.rangeSel.waf);
  }
  return loadActive();
}
function setTab(tab) {
  if (state.tab === tab) return;
  state.tab = tab;
  document.querySelectorAll('#tabs .tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  const isHttp = tab === 'http';
  $('#view-waf').style.display = isHttp ? 'none' : '';
  $('#view-http').style.display = isHttp ? '' : 'none';
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
      document.querySelectorAll('#actionChips .chip.active').forEach(c => c.classList.remove('active'));
      ['hostFilter','pathFilter','ruleFilter','countryFilter','asnFilter','uaFilter'].forEach(id => $('#'+id).value = '');
      updateFiltersBadge();
      load();
    });
    $('#account').addEventListener('change', loadZones);
    $('#zone').addEventListener('change', applyTabRangeAndLoad);
    $('#range').addEventListener('change', () => { state.rangeSel[state.tab] = $('#range').value; loadActive(); });
    document.querySelectorAll('#tabs .tab').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
    await loadZones();
  } catch (e) { showError(e.message); }
}
init();
