/**
 * app.js
 * Frontend client for NetGuard — Real-Time Network Traffic Monitor.
 * Connects to Socket.IO and drives live UI updates + Chart.js charts.
 */

// ═══════════════════════════════════════════════════════════════
//  DOM References
// ═══════════════════════════════════════════════════════════════
const $totalPackets = document.getElementById('stat-total-packets');
const $totalBytes   = document.getElementById('stat-total-bytes');
const $pps          = document.getElementById('stat-pps');
const $protocols    = document.getElementById('stat-protocols');
const $alertCount   = document.getElementById('stat-alert-count');
const $srcTable     = document.querySelector('#src-ip-table tbody');
const $dstTable     = document.querySelector('#dst-ip-table tbody');
const $alertsList   = document.getElementById('alerts-list');
const $logList      = document.getElementById('log-list');
const $connStatus   = document.getElementById('connection-status');
const $statusText   = $connStatus.querySelector('.status-text');
const $clock        = document.getElementById('live-clock');

// ═══════════════════════════════════════════════════════════════
//  Socket.IO Connection
// ═══════════════════════════════════════════════════════════════
const socket = io();

let totalAlerts = 0;

socket.on('connect', () => {
  $connStatus.className = 'connection-status connected';
  $statusText.textContent = 'Connected';
});

socket.on('disconnect', () => {
  $connStatus.className = 'connection-status disconnected';
  $statusText.textContent = 'Disconnected';
});

// ── Initial snapshot on first connect ─────────────────────────
socket.on('initial-data', (data) => {
  updateStats(data.stats);
  renderIPTable($srcTable, data.stats.topSrcIPs);
  renderIPTable($dstTable, data.stats.topDstIPs);

  if (data.alerts && data.alerts.length > 0) {
    totalAlerts = data.alerts.length;
    $alertCount.textContent = totalAlerts;
    $alertsList.innerHTML = '';
    data.alerts.forEach((a) => appendAlert(a, false));
  }

  if (data.recentPackets) {
    data.recentPackets.slice(0, 50).reverse().forEach((p) => appendLogEntry(p, false));
  }

  // Seed timeline chart
  if (data.stats.timeline) {
    data.stats.timeline.forEach((pt) => {
      addTimelinePoint(pt.time, pt.packets);
    });
  }
});

// ── Live traffic updates every 500ms ──────────────────────────
socket.on('traffic-update', (data) => {
  updateStats(data.stats);
  renderIPTable($srcTable, data.stats.topSrcIPs);
  renderIPTable($dstTable, data.stats.topDstIPs);

  // Append new log entries
  if (data.newPackets) {
    data.newPackets.forEach((p) => appendLogEntry(p, true));
  }

  // Append new alerts
  if (data.newAlerts && data.newAlerts.length > 0) {
    totalAlerts += data.newAlerts.length;
    $alertCount.textContent = totalAlerts;
    // Clear empty-state if present
    const emptyState = $alertsList.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    data.newAlerts.forEach((a) => appendAlert(a, true));
  }

  // Update protocol chart
  updateProtocolChart(data.stats.protocols);

  // Add timeline point
  if (data.stats.timeline && data.stats.timeline.length > 0) {
    const latest = data.stats.timeline[data.stats.timeline.length - 1];
    addTimelinePoint(latest.time, latest.packets);
  }
});

// ═══════════════════════════════════════════════════════════════
//  UI Updaters
// ═══════════════════════════════════════════════════════════════

function updateStats(stats) {
  $totalPackets.textContent = stats.totalPackets.toLocaleString();
  $totalBytes.textContent = formatBytes(stats.totalBytes);
  $pps.textContent = stats.packetsThisTick;
  $protocols.textContent = Object.keys(stats.protocols).length;
}

function renderIPTable(tbody, entries) {
  if (!entries || entries.length === 0) return;
  const maxCount = entries[0].count;
  tbody.innerHTML = entries.map((e, i) => `
    <tr>
      <td style="color:var(--text-muted)">${i + 1}</td>
      <td>${e.ip}</td>
      <td>${e.count.toLocaleString()}</td>
      <td><div class="ip-bar" style="width:${Math.max(4, (e.count / maxCount) * 100)}%"></div></td>
    </tr>
  `).join('');
}

function appendAlert(alert, animate) {
  const div = document.createElement('div');
  div.className = `alert-item ${alert.severity}`;
  if (!animate) div.style.animation = 'none';

  const time = new Date(alert.timestamp).toLocaleTimeString();
  div.innerHTML = `
    <span class="alert-severity">${alert.severity}</span>
    <div class="alert-body">
      <span class="alert-rule">${alert.rule}</span>
      <span class="alert-message">${alert.message}</span>
      <span class="alert-time">${time}</span>
    </div>
  `;
  $alertsList.prepend(div);

  // Cap visible alerts at 30
  while ($alertsList.children.length > 30) {
    $alertsList.removeChild($alertsList.lastChild);
  }
}

const MAX_LOG = 60;
function appendLogEntry(pkt, animate) {
  const div = document.createElement('div');
  div.className = 'log-entry';
  if (!animate) div.style.animation = 'none';

  const time = new Date(pkt.timestamp).toLocaleTimeString();
  const proto = pkt.protocol.toLowerCase();
  div.innerHTML = `
    <span>${time}</span>
    <span>${pkt.srcIP}</span>
    <span>${pkt.dstIP}</span>
    <span><span class="protocol-badge ${proto}">${pkt.protocol}</span></span>
    <span>${formatBytes(pkt.length)}</span>
  `;
  $logList.prepend(div);

  while ($logList.children.length > MAX_LOG) {
    $logList.removeChild($logList.lastChild);
  }
}

// ═══════════════════════════════════════════════════════════════
//  Chart.js — Protocol Doughnut
// ═══════════════════════════════════════════════════════════════

const PROTOCOL_COLORS = {
  TCP:   '#00f0ff',
  UDP:   '#ff00e5',
  HTTP:  '#39ff14',
  HTTPS: '#2ecc71',
  DNS:   '#ffbe0b',
  ICMP:  '#94a3b8',
  SSH:   '#ff3b3b',
  FTP:   '#ff7800',
};

const protocolChartCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolChartCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: [],
      borderWidth: 0,
      hoverOffset: 8,
    }],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '65%',
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#94a3b8',
          font: { family: "'Inter', sans-serif", size: 12 },
          padding: 14,
          usePointStyle: true,
          pointStyleWidth: 10,
        },
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        borderColor: 'rgba(100,116,139,0.3)',
        borderWidth: 1,
        cornerRadius: 8,
        padding: 10,
      },
    },
    animation: { duration: 300 },
  },
});

function updateProtocolChart(protocols) {
  const labels = Object.keys(protocols);
  const data   = Object.values(protocols);
  const colors = labels.map((l) => PROTOCOL_COLORS[l] || '#64748b');

  protocolChart.data.labels = labels;
  protocolChart.data.datasets[0].data = data;
  protocolChart.data.datasets[0].backgroundColor = colors;
  protocolChart.update('none');
}

// ═══════════════════════════════════════════════════════════════
//  Chart.js — Traffic Timeline
// ═══════════════════════════════════════════════════════════════

const TIMELINE_MAX = 60;
const timelineChartCtx = document.getElementById('timelineChart').getContext('2d');

const timelineGradient = timelineChartCtx.createLinearGradient(0, 0, 0, 250);
timelineGradient.addColorStop(0, 'rgba(0, 240, 255, 0.25)');
timelineGradient.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

const timelineChart = new Chart(timelineChartCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Packets per tick',
      data: [],
      borderColor: '#00f0ff',
      backgroundColor: timelineGradient,
      borderWidth: 2,
      tension: 0.35,
      fill: true,
      pointRadius: 0,
      pointHoverRadius: 5,
      pointHoverBackgroundColor: '#00f0ff',
      pointHoverBorderColor: '#fff',
    }],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: {
        display: true,
        grid: { color: 'rgba(100,116,139,0.08)' },
        ticks: {
          color: '#64748b',
          font: { size: 10, family: "'JetBrains Mono', monospace" },
          maxTicksLimit: 10,
          maxRotation: 0,
        },
      },
      y: {
        display: true,
        beginAtZero: true,
        grid: { color: 'rgba(100,116,139,0.08)' },
        ticks: {
          color: '#64748b',
          font: { size: 10, family: "'JetBrains Mono', monospace" },
          stepSize: 2,
        },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        borderColor: 'rgba(100,116,139,0.3)',
        borderWidth: 1,
        cornerRadius: 8,
        padding: 10,
      },
    },
    animation: { duration: 200 },
  },
});

function addTimelinePoint(time, packets) {
  const label = new Date(time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  timelineChart.data.labels.push(label);
  timelineChart.data.datasets[0].data.push(packets);

  if (timelineChart.data.labels.length > TIMELINE_MAX) {
    timelineChart.data.labels.shift();
    timelineChart.data.datasets[0].data.shift();
  }

  timelineChart.update('none');
}

// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = bytes / Math.pow(k, i);
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
}

// ── Live Clock ────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  $clock.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
updateClock();
setInterval(updateClock, 1000);
