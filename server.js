/**
 * server.js
 * Express + Socket.IO server for the Real-Time Network Traffic Monitor.
 * All data is kept in memory — no database.
 */

const express = require('express');
const http    = require('http');
const { Server } = require('socket.io');
const path    = require('path');

const { generatePackets } = require('./trafficSimulator');
const { analyze }         = require('./securityAnalyzer');

// ── App Setup ─────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// ── In-Memory Data Stores ─────────────────────────────────────────────
const MAX_RECENT   = 100;
const MAX_ALERTS   = 50;
const TIMELINE_LEN = 60; // 60 data points for the timeline chart

let stats = {
  totalPackets:   0,
  totalBytes:     0,
  packetsThisTick: 0,
  protocols:      {},   // { TCP: count, UDP: count, ... }
  srcIPs:         {},   // { ip: count }
  dstIPs:         {},   // { ip: count }
  timeline:       [],   // [{ time, packets }] — rolling 60 entries
};

let recentPackets = [];
let alerts        = [];

// ── Traffic Processing Loop (every 500 ms) ────────────────────────────
const TICK_MS = 500;

setInterval(() => {
  const newPackets = generatePackets();
  stats.packetsThisTick = newPackets.length;

  const tickAlerts = [];

  for (const pkt of newPackets) {
    // Update global stats
    stats.totalPackets++;
    stats.totalBytes += pkt.length;
    stats.protocols[pkt.protocol] = (stats.protocols[pkt.protocol] || 0) + 1;
    stats.srcIPs[pkt.srcIP]       = (stats.srcIPs[pkt.srcIP] || 0) + 1;
    stats.dstIPs[pkt.dstIP]       = (stats.dstIPs[pkt.dstIP] || 0) + 1;

    // Security analysis
    const result = analyze(pkt, stats);
    if (result) {
      tickAlerts.push(...result);
    }

    // Keep recent packets capped
    recentPackets.unshift(pkt);
    if (recentPackets.length > MAX_RECENT) recentPackets.length = MAX_RECENT;
  }

  // Store alerts
  if (tickAlerts.length > 0) {
    alerts.unshift(...tickAlerts);
    if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  }

  // Timeline data point
  stats.timeline.push({
    time:    new Date().toISOString(),
    packets: newPackets.length,
  });
  if (stats.timeline.length > TIMELINE_LEN) {
    stats.timeline = stats.timeline.slice(-TIMELINE_LEN);
  }

  // Broadcast to all connected clients
  io.emit('traffic-update', {
    newPackets,
    stats: getPublicStats(),
    newAlerts: tickAlerts,
  });

}, TICK_MS);

// ── Socket.IO Connections ─────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`✔  Client connected  [${socket.id}]`);

  // Send snapshot on connect
  socket.emit('initial-data', {
    stats:         getPublicStats(),
    recentPackets: recentPackets.slice(0, 50),
    alerts:        alerts.slice(0, 30),
  });

  socket.on('disconnect', () => {
    console.log(`✖  Client disconnected [${socket.id}]`);
  });
});

// ── Helpers ───────────────────────────────────────────────────────────
function getPublicStats() {
  return {
    totalPackets:    stats.totalPackets,
    totalBytes:      stats.totalBytes,
    packetsThisTick: stats.packetsThisTick,
    protocols:       { ...stats.protocols },
    topSrcIPs:       topN(stats.srcIPs, 10),
    topDstIPs:       topN(stats.dstIPs, 10),
    timeline:        stats.timeline,
  };
}

function topN(map, n) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([ip, count]) => ({ ip, count }));
}

// ── Start Server ──────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n🛡️  Network Traffic Monitor running on http://localhost:${PORT}\n`);
});
