/**
 * trafficSimulator.js
 * Generates realistic-looking simulated network packet metadata.
 */

const IP_POOL = [
  // Private / internal IPs
  '192.168.1.10', '192.168.1.25', '192.168.1.50', '192.168.1.100',
  '10.0.0.5', '10.0.0.12', '10.0.0.88',
  // Public IPs (fictional services)
  '8.8.8.8', '1.1.1.1', '104.26.10.78', '172.217.14.206',
  '151.101.1.140', '13.107.42.14', '52.84.150.11',
  '93.184.216.34', '198.41.0.4', '208.67.222.222',
  // Suspicious IPs (known-bad watchlist)
  '185.220.101.1', '45.33.32.156', '23.129.64.100',
];

const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SSH', 'FTP'];

const PROTOCOL_WEIGHTS = {
  TCP:   25,
  UDP:   15,
  HTTP:  20,
  HTTPS: 25,
  DNS:   8,
  ICMP:  3,
  SSH:   2,
  FTP:   2,
};

/**
 * Pick a random element from an array.
 */
function randomFrom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Pick a weighted-random protocol.
 */
function randomProtocol() {
  const entries = Object.entries(PROTOCOL_WEIGHTS);
  const total = entries.reduce((sum, [, w]) => sum + w, 0);
  let r = Math.random() * total;
  for (const [proto, weight] of entries) {
    r -= weight;
    if (r <= 0) return proto;
  }
  return 'TCP';
}

/**
 * Generate a random packet length in bytes.
 * Most packets are small; occasional large ones.
 */
function randomLength() {
  const roll = Math.random();
  if (roll < 0.6)  return Math.floor(Math.random() * 500) + 40;        // Small
  if (roll < 0.9)  return Math.floor(Math.random() * 2000) + 500;      // Medium
  if (roll < 0.98) return Math.floor(Math.random() * 5000) + 2000;     // Large
  return Math.floor(Math.random() * 10000) + 9000;                      // Jumbo / suspicious
}

/**
 * Generate a batch of packets (1–5 per tick).
 * Occasionally injects suspicious patterns.
 */
function generatePackets() {
  const batchSize = Math.floor(Math.random() * 5) + 1;
  const packets = [];

  for (let i = 0; i < batchSize; i++) {
    packets.push({
      timestamp: new Date().toISOString(),
      srcIP:     randomFrom(IP_POOL),
      dstIP:     randomFrom(IP_POOL),
      protocol:  randomProtocol(),
      length:    randomLength(),
    });
  }

  // 8% chance: inject a "port scan burst" — many packets from one attacker IP
  if (Math.random() < 0.08) {
    const attackerIP = randomFrom(['185.220.101.1', '45.33.32.156', '23.129.64.100']);
    const burstSize = Math.floor(Math.random() * 8) + 5;
    for (let i = 0; i < burstSize; i++) {
      packets.push({
        timestamp: new Date().toISOString(),
        srcIP:     attackerIP,
        dstIP:     randomFrom(IP_POOL.slice(0, 7)), // target internal IPs
        protocol:  'TCP',
        length:    Math.floor(Math.random() * 100) + 40,
      });
    }
  }

  return packets;
}

module.exports = { generatePackets, IP_POOL };
