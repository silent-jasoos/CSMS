/**
 * CyberShield CSMS — dashboard.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Makes the admin dashboard come alive.
 * Fetches stats from the CSMS REST API on an interval, updates KPI counters,
 * feeds all Chart.js charts created via charts.js, and manages real-time
 * threat-event notifications.
 *
 * Depends on:  charts.js  (must be loaded first — window.CSMSCharts required)
 * ─────────────────────────────────────────────────────────────────────────────
 */

(function (global) {
  'use strict';

  // ── 0. Guard ────────────────────────────────────────────────────────────────
  if (!global.CSMSCharts) {
    console.error('[Dashboard] charts.js must be loaded before dashboard.js');
    return;
  }

  const C = global.CSMSCharts;

  // ── 1. CONFIG ───────────────────────────────────────────────────────────────
  const CFG = {
    apiBase:        '/api/v1',          // REST API base path
    refreshMs:      30_000,             // Full-refresh interval (30 s)
    liveMs:         5_000,              // Live-counter tick  ( 5 s)
    animDuration:   800,                // Counter animation ms
    maxLivePoints:  24,                 // Rolling window length for live charts
    toastDuration:  5_000               // Notification toast lifetime ms
  };

  // ── 2. CHART INSTANCE STORE ─────────────────────────────────────────────────
  const charts = {
    threats:      null,   // 24-h threat timeline  (line)
    categories:   null,   // Threat breakdown       (doughnut)
    topSources:   null,   // Top attack sources     (horizontal bar)
    severity:     null,   // Severity distribution  (bar)
    traffic:      null,   // Network traffic        (multi-line)
    geo:          null,   // Geo-origin             (polar area)
    riskGauge:    null,   // Overall risk score     (gauge)
    responseTime: null    // Avg response time      (sparkline)
  };

  // ── 3. INTERVAL HANDLES ─────────────────────────────────────────────────────
  let _refreshTimer = null;
  let _liveTimer    = null;

  // ── 4. INTERNAL HELPERS ─────────────────────────────────────────────────────

  /** Authenticated fetch wrapper — returns parsed JSON or throws. */
  async function _apiFetch(path) {
    const res = await fetch(CFG.apiBase + path, {
      headers: C.getAuthHeaders()
    });
    if (res.status === 401) {
      _handleUnauthorised();
      throw new Error('Unauthorised');
    }
    if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
    return res.json();
  }

  /** Redirect to login when the session expires. */
  function _handleUnauthorised() {
    console.warn('[Dashboard] Session expired — redirecting to login.');
    clearInterval(_refreshTimer);
    clearInterval(_liveTimer);
    setTimeout(() => { window.location.href = '/login.html'; }, 1500);
    _showToast('Session expired. Redirecting to login…', 'warning');
  }

  /**
   * Animates a numeric counter from its current displayed value to `target`.
   * @param {string} elementId
   * @param {number} target
   * @param {string} [suffix]   e.g. '%', 'ms'
   */
  function _animateCounter(elementId, target, suffix = '') {
    const el = document.getElementById(elementId);
    if (!el) return;
    const start    = parseFloat(el.textContent) || 0;
    const delta    = target - start;
    const steps    = 40;
    const stepMs   = CFG.animDuration / steps;
    let   current  = 0;

    const timer = setInterval(() => {
      current++;
      const val = start + delta * (current / steps);
      el.textContent = (Number.isInteger(target) ? Math.round(val) : val.toFixed(1)) + suffix;
      if (current >= steps) {
        el.textContent = target + suffix;
        clearInterval(timer);
      }
    }, stepMs);
  }

  /**
   * Updates a status-badge element's text and severity class.
   * @param {string} elementId
   * @param {string} text
   * @param {'critical'|'high'|'medium'|'low'|'ok'} level
   */
  function _setBadge(elementId, text, level) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = text;
    el.className   = el.className.replace(/\bbadge-\S+/g, '').trim();
    el.classList.add('badge-' + level);
  }

  /**
   * Shows a toast notification at the top-right of the viewport.
   * @param {string} message
   * @param {'info'|'warning'|'danger'|'success'} [type]
   */
  function _showToast(message, type = 'info') {
    let container = document.getElementById('csms-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'csms-toast-container';
      Object.assign(container.style, {
        position:  'fixed',
        top:       '1.25rem',
        right:     '1.25rem',
        zIndex:    '9999',
        display:   'flex',
        flexDirection: 'column',
        gap:       '0.5rem'
      });
      document.body.appendChild(container);
    }

    const colorMap = {
      info:    '#58A6FF',
      warning: '#D29922',
      danger:  '#FF4444',
      success: '#3FB950'
    };

    const toast = document.createElement('div');
    toast.className = 'csms-toast csms-toast--' + type;
    Object.assign(toast.style, {
      background:   '#161B22',
      border:       '1px solid ' + (colorMap[type] || colorMap.info),
      borderLeft:   '4px solid ' + (colorMap[type] || colorMap.info),
      color:        '#E6EDF3',
      padding:      '0.75rem 1rem',
      borderRadius: '6px',
      fontSize:     '0.85rem',
      fontFamily:   "'Segoe UI', sans-serif",
      maxWidth:     '320px',
      boxShadow:    '0 4px 12px rgba(0,0,0,0.5)',
      opacity:      '0',
      transition:   'opacity 0.3s ease, transform 0.3s ease',
      transform:    'translateX(20px)'
    });
    toast.textContent = message;
    container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.style.opacity   = '1';
      toast.style.transform = 'translateX(0)';
    });

    setTimeout(() => {
      toast.style.opacity   = '0';
      toast.style.transform = 'translateX(20px)';
      setTimeout(() => toast.remove(), 350);
    }, CFG.toastDuration);
  }

  /**
   * Appends a row to the recent-threats activity table.
   * @param {{ time:string, source:string, type:string,
   *            severity:string, status:string }} event
   */
  function _appendThreatRow(event) {
    const tbody = document.getElementById('recent-threats-body');
    if (!tbody) return;

    const severityColor = {
      critical: '#FF4444', high: '#D29922',
      medium:   '#D29922', low:  '#3FB950'
    };

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${event.time}</td>
      <td>${_escHtml(event.source)}</td>
      <td>${_escHtml(event.type)}</td>
      <td><span class="badge-severity" style="color:${severityColor[event.severity] || '#E6EDF3'}">${_escHtml(event.severity)}</span></td>
      <td><span class="badge-status badge-status--${event.status.toLowerCase()}">${_escHtml(event.status)}</span></td>
    `;
    row.style.cssText = 'opacity:0;transition:opacity 0.4s ease';
    tbody.insertBefore(row, tbody.firstChild);
    requestAnimationFrame(() => { row.style.opacity = '1'; });

    // Keep table to a maximum of 50 rows
    while (tbody.rows.length > 50) tbody.deleteRow(tbody.rows.length - 1);
  }

  /** Minimal HTML-escape to prevent XSS in table cells. */
  function _escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Maps a numeric risk score (0–100) to a human label. */
  function _riskLabel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  // ── 5. CHART INITIALISATION ─────────────────────────────────────────────────

  /** Create all chart canvases with placeholder data on first load. */
  function _initCharts() {
    const hours = C.generateHourLabels();
    const zero24 = Array(24).fill(0);

    // 5a — 24-h threat timeline
    charts.threats = C.createLineChart(
      'chart-threats',
      hours, zero24,
      'Threats Detected',
      C.COLORS.red
    );

    // 5b — Threat category doughnut
    charts.categories = C.createDoughnutChart(
      'chart-categories',
      ['Malware', 'Phishing', 'Brute Force', 'DDoS', 'Insider', 'Other'],
      [0, 0, 0, 0, 0, 0],
      [C.COLORS.red, C.COLORS.amber, C.COLORS.purple,
       C.COLORS.cyan, C.COLORS.orange, C.COLORS.muted]
    );

    // 5c — Top attack sources (horizontal bar)
    charts.topSources = C.createBarChart(
      'chart-top-sources',
      ['Loading…'], [0],
      'Events',
      C.COLORS.amber,
      true   // horizontal
    );

    // 5d — Severity distribution (vertical bar)
    charts.severity = C.createMultiBarChart(
      'chart-severity',
      C.generateDayLabels(7),
      [
        { label: 'Critical', data: Array(7).fill(0), color: C.COLORS.red    },
        { label: 'High',     data: Array(7).fill(0), color: C.COLORS.amber  },
        { label: 'Medium',   data: Array(7).fill(0), color: C.COLORS.purple },
        { label: 'Low',      data: Array(7).fill(0), color: C.COLORS.green  }
      ],
      true   // stacked
    );

    // 5e — Network traffic (multi-line)
    charts.traffic = C.createMultiLineChart(
      'chart-traffic',
      hours,
      [
        { label: 'Inbound (Gbps)',  data: zero24, color: C.COLORS.cyan  },
        { label: 'Outbound (Gbps)', data: zero24, color: C.COLORS.green }
      ]
    );

    // 5f — Geo origin (polar area)
    charts.geo = C.createPolarAreaChart(
      'chart-geo',
      ['US', 'CN', 'RU', 'DE', 'BR', 'Other'],
      [0, 0, 0, 0, 0, 0]
    );

    // 5g — Risk gauge
    charts.riskGauge = C.createGaugeChart('chart-risk-gauge', 0, 'Risk Score');

    // 5h — Response-time sparkline
    charts.responseTime = C.createSparkline('chart-response-time', zero24, C.COLORS.green);
  }

  // ── 6. DATA-FETCH & RENDER ──────────────────────────────────────────────────

  /**
   * Fetches /api/v1/dashboard/summary and updates KPI tiles.
   */
  async function _fetchSummary() {
    try {
      const d = await _apiFetch('/dashboard/summary');

      _animateCounter('kpi-total-threats',    d.totalThreats    ?? 0);
      _animateCounter('kpi-active-incidents', d.activeIncidents ?? 0);
      _animateCounter('kpi-blocked-attacks',  d.blockedAttacks  ?? 0);
      _animateCounter('kpi-risk-score',       d.riskScore       ?? 0, '%');
      _animateCounter('kpi-endpoints',        d.onlineEndpoints ?? 0);
      _animateCounter('kpi-response-time',    d.avgResponseMs   ?? 0, 'ms');
      _animateCounter('kpi-false-positives',  d.falsePositives  ?? 0, '%');

      // Status badge
      const riskLevel = (d.riskScore >= 80) ? 'critical'
                      : (d.riskScore >= 60) ? 'high'
                      : (d.riskScore >= 40) ? 'medium' : 'ok';
      _setBadge('badge-system-status', _riskLabel(d.riskScore), riskLevel);

      // Last-updated timestamp
      const el = document.getElementById('last-updated');
      if (el) el.textContent = 'Last updated: ' + new Date().toLocaleTimeString();

    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] summary fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/threats/hourly and refreshes the threat timeline
   * and response-time sparkline.
   */
  async function _fetchThreatTimeline() {
    try {
      const d = await _apiFetch('/dashboard/threats/hourly');
      const labels = C.generateHourLabels();

      C.updateChart(charts.threats, labels, d.counts ?? Array(24).fill(0));
      if (charts.responseTime && d.responseTimes)
        C.updateChart(charts.responseTime, labels, d.responseTimes, false);

    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] threat timeline fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/threats/categories and refreshes the doughnut.
   */
  async function _fetchCategories() {
    try {
      const d = await _apiFetch('/dashboard/threats/categories');
      if (!charts.categories || !d.data) return;
      charts.categories.data.datasets[0].data = d.data;
      if (d.labels) charts.categories.data.labels = d.labels;
      charts.categories.update('active');
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] categories fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/threats/sources and refreshes the top-sources bar.
   */
  async function _fetchTopSources() {
    try {
      const d = await _apiFetch('/dashboard/threats/sources');
      if (!charts.topSources || !d.sources) return;
      C.updateChart(
        charts.topSources,
        d.sources.map(s => s.ip || s.country || s.name),
        d.sources.map(s => s.count)
      );
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] top sources fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/threats/severity/daily and refreshes the
   * stacked severity bar chart.
   */
  async function _fetchSeverityTrend() {
    try {
      const d = await _apiFetch('/dashboard/threats/severity/daily');
      if (!charts.severity || !d.critical) return;
      C.updateMultiChart(
        charts.severity,
        C.generateDayLabels(7),
        [d.critical, d.high, d.medium, d.low]
      );
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] severity trend fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/network/traffic and refreshes the traffic chart.
   */
  async function _fetchTraffic() {
    try {
      const d = await _apiFetch('/dashboard/network/traffic');
      if (!charts.traffic) return;
      C.updateMultiChart(
        charts.traffic,
        C.generateHourLabels(),
        [d.inbound ?? Array(24).fill(0), d.outbound ?? Array(24).fill(0)]
      );
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] traffic fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/threats/geo and refreshes the polar-area chart.
   */
  async function _fetchGeo() {
    try {
      const d = await _apiFetch('/dashboard/threats/geo');
      if (!charts.geo || !d.data) return;
      charts.geo.data.datasets[0].data = d.data;
      if (d.labels) charts.geo.data.labels = d.labels;
      charts.geo.update('active');
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] geo fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/risk and updates the gauge chart.
   */
  async function _fetchRisk() {
    try {
      const d = await _apiFetch('/dashboard/risk');
      if (!charts.riskGauge) return;
      // Re-create gauge with new value (gauge data cannot be hot-swapped easily)
      const score = d.score ?? 0;
      charts.riskGauge = C.createGaugeChart(
        'chart-risk-gauge', score, _riskLabel(score)
      );
    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] risk fetch failed:', err);
    }
  }

  /**
   * Fetches /api/v1/dashboard/events/recent and populates the activity table.
   */
  async function _fetchRecentEvents() {
    try {
      const d = await _apiFetch('/dashboard/events/recent');
      if (!d.events || !d.events.length) return;

      // Clear table on full refresh, then populate
      const tbody = document.getElementById('recent-threats-body');
      if (tbody) tbody.innerHTML = '';
      d.events.slice(0, 25).forEach(_appendThreatRow);

    } catch (err) {
      if (err.message !== 'Unauthorised')
        console.error('[Dashboard] recent events fetch failed:', err);
    }
  }

  // ── 7. LIVE METRICS (fast ticker) ───────────────────────────────────────────

  /**
   * Fast-tick: fetches /api/v1/dashboard/live for lightweight real-time counters
   * (e.g. events-per-second, active connections) without re-drawing full charts.
   */
  async function _fetchLive() {
    try {
      const d = await _apiFetch('/dashboard/live');

      _animateCounter('kpi-events-per-sec',   d.eventsPerSec   ?? 0);
      _animateCounter('kpi-active-connections', d.activeConnections ?? 0);

      // Push one point to the rolling threat timeline (live mode)
      if (charts.threats && d.latestThreatCount !== undefined) {
        const now = new Date();
        const lbl = now.getHours().toString().padStart(2, '0') + ':' +
                    now.getMinutes().toString().padStart(2, '0');
        C.pushPoint(charts.threats, d.latestThreatCount, lbl, CFG.maxLivePoints);
      }

      // Critical alert toast
      if (d.criticalAlert) {
        _showToast('⚠ ' + d.criticalAlert, 'danger');
      }

    } catch (err) {
      // Silently ignore transient live-tick failures
    }
  }

  // ── 8. FULL REFRESH ─────────────────────────────────────────────────────────

  /** Runs all fetch functions in parallel for a complete dashboard refresh. */
  async function _refresh() {
    await Promise.allSettled([
      _fetchSummary(),
      _fetchThreatTimeline(),
      _fetchCategories(),
      _fetchTopSources(),
      _fetchSeverityTrend(),
      _fetchTraffic(),
      _fetchGeo(),
      _fetchRisk(),
      _fetchRecentEvents()
    ]);
  }

  // ── 9. FILTER / INTERACTION ─────────────────────────────────────────────────

  /** Binds the date-range selector (if present) to trigger a data refresh. */
  function _bindFilters() {
    const rangeSelect = document.getElementById('filter-time-range');
    if (rangeSelect) {
      rangeSelect.addEventListener('change', () => {
        CFG.apiBase = '/api/v1?range=' + encodeURIComponent(rangeSelect.value);
        _refresh();
      });
    }

    // Manual refresh button
    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        refreshBtn.disabled = true;
        _refresh().finally(() => { refreshBtn.disabled = false; });
      });
    }

    // Export CSV button
    const exportBtn = document.getElementById('btn-export-csv');
    if (exportBtn) {
      exportBtn.addEventListener('click', _exportCsv);
    }

    // Sidebar resize → charts need to reflow
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
      sidebar.addEventListener('transitionend', C.resizeAll);
    }
  }

  // ── 10. CSV EXPORT ──────────────────────────────────────────────────────────

  /** Exports the recent-threats table as a CSV file download. */
  function _exportCsv() {
    const table = document.getElementById('recent-threats-body');
    if (!table) return;

    const headers = ['Time', 'Source', 'Type', 'Severity', 'Status'];
    const rows    = Array.from(table.rows).map(row =>
      Array.from(row.cells).map(cell => '"' + cell.textContent.trim().replace(/"/g, '""') + '"')
    );

    const csv  = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'csms-threats-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── 11. WEBSOCKET (optional) ────────────────────────────────────────────────

  /**
   * Opens an optional WebSocket for push-based threat events.
   * Falls back gracefully if the WS endpoint is unavailable.
   */
  function _connectWebSocket() {
    const wsUrl = (window.location.protocol === 'https:' ? 'wss' : 'ws')
                + '://' + window.location.host + '/ws/threats';
    let ws;
    try {
      ws = new WebSocket(wsUrl);
    } catch (e) {
      return; // WS not available — polling handles everything
    }

    ws.addEventListener('open',  () => console.info('[Dashboard] WS connected'));
    ws.addEventListener('close', () => {
      console.info('[Dashboard] WS disconnected — relying on polling');
    });

    ws.addEventListener('message', (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'threat_event') {
          _appendThreatRow(msg.event);
          if (msg.event.severity === 'critical') {
            _showToast('Critical threat: ' + msg.event.type + ' from ' + msg.event.source, 'danger');
          }
        }
        if (msg.type === 'stats_update') {
          _animateCounter('kpi-total-threats',    msg.totalThreats    ?? 0);
          _animateCounter('kpi-active-incidents', msg.activeIncidents ?? 0);
        }
      } catch (e) {
        // Ignore malformed frames
      }
    });
  }

  // ── 12. INIT ────────────────────────────────────────────────────────────────

  /** Bootstraps the entire dashboard. Call once on DOMContentLoaded. */
  function init() {
    _initCharts();
    _bindFilters();
    _connectWebSocket();

    // Initial data load
    _refresh();

    // Full refresh on interval
    _refreshTimer = setInterval(_refresh, CFG.refreshMs);

    // Live counters on faster interval
    _liveTimer = setInterval(_fetchLive, CFG.liveMs);

    // Cleanup on unload
    window.addEventListener('beforeunload', () => {
      clearInterval(_refreshTimer);
      clearInterval(_liveTimer);
    });

    console.info('[Dashboard] Initialised. Refresh every', CFG.refreshMs / 1000, 's');
  }

  // ── 13. PUBLIC API ──────────────────────────────────────────────────────────
  global.CSMSDashboard = {
    init,
    refresh:      _refresh,
    showToast:    _showToast,
    appendThreat: _appendThreatRow,
    exportCsv:    _exportCsv,
    charts,
    config:       CFG
  };

  // Auto-init when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})(window);