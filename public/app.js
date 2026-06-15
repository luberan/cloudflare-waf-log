const $ = (s) => document.querySelector(s);
const state = { actions: new Set(), charts: {} };
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
    await load();
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
    $('#refresh').addEventListener('click', load);
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
    $('#zone').addEventListener('change', load);
    $('#range').addEventListener('change', load);
    await loadZones();
  } catch (e) { showError(e.message); }
}
init();
