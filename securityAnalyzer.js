/**
 * securityAnalyzer.js
 * Basic cybersecurity detection rules for network traffic analysis.
 */

// Hardcoded IP watchlist — known malicious addresses
const BLACKLISTED_IPS = new Set([
  '185.220.101.1',   // Tor exit node
  '45.33.32.156',    // Scanner host
  '23.129.64.100',   // Anonymous proxy
]);

// Thresholds
const PORT_SCAN_THRESHOLD    = 30;   // packets from single IP in rolling window
const LARGE_PACKET_THRESHOLD = 9000; // bytes
const SPIKE_THRESHOLD        = 40;   // packets per tick

// Track per-source packet counts for rolling window analysis
const srcHitWindow = {};  // { ip: count }
const WINDOW_RESET_INTERVAL = 15_000; // reset every 15 seconds

// Periodically reset the rolling window
setInterval(() => {
  for (const key of Object.keys(srcHitWindow)) {
    delete srcHitWindow[key];
  }
}, WINDOW_RESET_INTERVAL);

/**
 * Severity levels: low, medium, high, critical
 */

/**
 * Analyse a single packet against all detection rules.
 * @param {Object} packet  — { timestamp, srcIP, dstIP, protocol, length }
 * @param {Object} stats   — global stats object from server
 * @returns {Object|null}  — alert object or null
 */
function analyze(packet, stats) {
  const alerts = [];

  // ── Rule 1: Blacklisted IP ────────────────────────────────────────
  if (BLACKLISTED_IPS.has(packet.srcIP)) {
    alerts.push({
      id:        generateId(),
      timestamp: packet.timestamp,
      severity:  'critical',
      rule:      'Blacklisted IP',
      message:   `Traffic from known malicious IP: ${packet.srcIP}`,
      packet,
    });
  }

  if (BLACKLISTED_IPS.has(packet.dstIP)) {
    alerts.push({
      id:        generateId(),
      timestamp: packet.timestamp,
      severity:  'high',
      rule:      'Blacklisted Destination',
      message:   `Outbound connection to known malicious IP: ${packet.dstIP}`,
      packet,
    });
  }

  // ── Rule 2: Large / jumbo packet ──────────────────────────────────
  if (packet.length > LARGE_PACKET_THRESHOLD) {
    alerts.push({
      id:        generateId(),
      timestamp: packet.timestamp,
      severity:  'medium',
      rule:      'Oversized Packet',
      message:   `Unusually large packet detected (${formatBytes(packet.length)}) from ${packet.srcIP}`,
      packet,
    });
  }

  // ── Rule 3: Suspicious protocol usage ─────────────────────────────
  if (['FTP', 'SSH'].includes(packet.protocol)) {
    // SSH/FTP from external IPs to internal network
    const isExternal = !packet.srcIP.startsWith('192.168.') && !packet.srcIP.startsWith('10.0.');
    const isInternal = packet.dstIP.startsWith('192.168.') || packet.dstIP.startsWith('10.0.');
    if (isExternal && isInternal) {
      alerts.push({
        id:        generateId(),
        timestamp: packet.timestamp,
        severity:  'high',
        rule:      'Suspicious Protocol',
        message:   `External ${packet.protocol} connection from ${packet.srcIP} → ${packet.dstIP}`,
        packet,
      });
    }
  }

  // ── Rule 4: Port scan detection (high packet rate from single IP) ─
  srcHitWindow[packet.srcIP] = (srcHitWindow[packet.srcIP] || 0) + 1;
  if (srcHitWindow[packet.srcIP] === PORT_SCAN_THRESHOLD) {
    alerts.push({
      id:        generateId(),
      timestamp: packet.timestamp,
      severity:  'high',
      rule:      'Port Scan Detected',
      message:   `High packet rate from ${packet.srcIP} (${srcHitWindow[packet.srcIP]} packets in window)`,
      packet,
    });
  }

  // ── Rule 5: Traffic spike ─────────────────────────────────────────
  if (stats.packetsThisTick > SPIKE_THRESHOLD) {
    alerts.push({
      id:        generateId(),
      timestamp: packet.timestamp,
      severity:  'medium',
      rule:      'Traffic Spike',
      message:   `Abnormal traffic volume: ${stats.packetsThisTick} packets in current tick`,
      packet,
    });
  }

  return alerts.length > 0 ? alerts : null;
}

// ── Helpers ───────────────────────────────────────────────────────────

let _idCounter = 0;
function generateId() {
  return `alert-${Date.now()}-${_idCounter++}`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

module.exports = { analyze };
