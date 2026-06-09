const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const http = require('http');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully'))
  .catch(err => console.log('MongoDB Error:', err));

app.use('/api/assessment', require('./routes/assessment'));

// ─── Helper: check single port ───────────────────────────────────────────────
function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => resolve(false));
    socket.connect(port, host);
  });
}

// ─── Helper: check SSL ───────────────────────────────────────────────────────
function checkSSL(domain) {
  return new Promise((resolve) => {
    const options = { host: domain, port: 443, method: 'HEAD', rejectUnauthorized: false };
    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate();
      if (!cert || !cert.valid_to) return resolve({ valid: false, error: 'No certificate found' });
      const expiry = new Date(cert.valid_to);
      const now = new Date();
      const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
      resolve({
        valid: true,
        subject: cert.subject?.CN || domain,
        issuer: cert.issuer?.O || 'Unknown',
        validTo: cert.valid_to,
        daysLeft,
        expired: daysLeft < 0,
        expiringSoon: daysLeft < 30 && daysLeft >= 0
      });
    });
    req.on('error', () => resolve({ valid: false, error: 'SSL connection failed' }));
    req.end();
  });
}

// ─── Helper: check HTTP headers ──────────────────────────────────────────────
function checkHeaders(domain) {
  return new Promise((resolve) => {
    const options = { host: domain, path: '/', method: 'HEAD', timeout: 5000 };
    const req = https.request({ ...options, port: 443 }, (res) => {
      const headers = res.headers;
      const httpsRedirect = true;
      resolve({
        statusCode: res.statusCode,
        httpsRedirect,
        headers: {
          'strict-transport-security': !!headers['strict-transport-security'],
          'x-frame-options': !!headers['x-frame-options'],
          'x-content-type-options': !!headers['x-content-type-options'],
          'content-security-policy': !!headers['content-security-policy'],
          'x-xss-protection': !!headers['x-xss-protection'],
          'referrer-policy': !!headers['referrer-policy'],
          'permissions-policy': !!headers['permissions-policy']
        }
      });
    });
    req.on('error', () => {
      http.get(`http://${domain}`, (res) => {
        resolve({ statusCode: res.statusCode, httpsRedirect: false, headers: {} });
      }).on('error', () => resolve({ statusCode: null, httpsRedirect: false, headers: {} }));
    });
    req.end();
  });
}

// ─── Helper: validate and classify input ─────────────────────────────────────
function classifyTarget(input) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

  if (ipv4Regex.test(input)) {
    const parts = input.split('.').map(Number);
    if (parts.some(n => n > 255)) return { valid: false };

    // Block private/reserved IPs (SSRF protection)
    const isPrivate =
      parts[0] === 10 ||
      parts[0] === 127 ||
      parts[0] === 0 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254);

    if (isPrivate) return { valid: false, private: true };
    return { valid: true, type: 'ip' };
  }

  if (domainRegex.test(input)) return { valid: true, type: 'domain' };

  return { valid: false };
}

// ─── Main scan endpoint ───────────────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain or IP address is required' });

  const cleanTarget = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  // Validate input
  const classification = classifyTarget(cleanTarget);
  if (!classification.valid) {
    if (classification.private) {
      return res.status(400).json({ error: 'Private or reserved IP addresses cannot be scanned' });
    }
    return res.status(400).json({ error: 'Invalid domain name or IP address' });
  }

  const isIP = classification.type === 'ip';

  try {
    // 1. DNS lookup (for domains) or reverse DNS (for IPs)
    let dnsResult = { resolved: false, ips: [], mx: [], txt: [] };
    try {
      if (isIP) {
        // For IPs: treat the IP itself as resolved, attempt reverse DNS
        dnsResult.resolved = true;
        dnsResult.ips = [cleanTarget];
        try {
          const hostnames = await dns.reverse(cleanTarget);
          dnsResult.hostname = hostnames[0] || null;
        } catch {
          dnsResult.hostname = null;
        }
      } else {
        const ips = await dns.resolve4(cleanTarget);
        dnsResult.resolved = true;
        dnsResult.ips = ips;
        try { dnsResult.mx = await dns.resolveMx(cleanTarget); } catch {}
        try { dnsResult.txt = await dns.resolveTxt(cleanTarget); } catch {}
      }
    } catch (e) {
      dnsResult.error = 'Could not resolve target';
    }

    // 2. SSL check
    const sslResult = await checkSSL(cleanTarget);

    // 3. HTTP headers
    const headerResult = await checkHeaders(cleanTarget);

    // 4. Port scan (common ports)
    const portsToCheck = [
      { port: 21, name: 'FTP', risk: 'High' },
      { port: 22, name: 'SSH', risk: 'Medium' },
      { port: 23, name: 'Telnet', risk: 'Critical' },
      { port: 25, name: 'SMTP', risk: 'Medium' },
      { port: 80, name: 'HTTP', risk: 'Low' },
      { port: 443, name: 'HTTPS', risk: 'Low' },
      { port: 3306, name: 'MySQL', risk: 'Critical' },
      { port: 5432, name: 'PostgreSQL', risk: 'Critical' },
      { port: 6379, name: 'Redis', risk: 'Critical' },
      { port: 27017, name: 'MongoDB', risk: 'Critical' },
      { port: 8080, name: 'HTTP-Alt', risk: 'Medium' },
      { port: 8443, name: 'HTTPS-Alt', risk: 'Low' }
    ];

    const portResults = await Promise.all(
      portsToCheck.map(async (p) => ({
        ...p,
        open: await checkPort(cleanTarget, p.port)
      }))
    );
    const openPorts = portResults.filter(p => p.open);

    // 5. Calculate risk score
    let score = 100;
    const findings = [];

    if (!sslResult.valid) { score -= 25; findings.push({ type: 'SSL', severity: 'Critical', detail: 'No valid SSL certificate' }); }
    else if (sslResult.expired) { score -= 25; findings.push({ type: 'SSL', severity: 'Critical', detail: 'SSL certificate has expired' }); }
    else if (sslResult.expiringSoon) { score -= 10; findings.push({ type: 'SSL', severity: 'High', detail: `SSL expires in ${sslResult.daysLeft} days` }); }

    if (!headerResult.httpsRedirect) { score -= 10; findings.push({ type: 'HTTPS', severity: 'High', detail: 'No HTTPS redirect from HTTP' }); }

    const missingHeaders = Object.entries(headerResult.headers || {}).filter(([, v]) => !v).map(([k]) => k);
    score -= missingHeaders.length * 3;
    if (missingHeaders.length > 0) findings.push({ type: 'Headers', severity: 'Medium', detail: `Missing security headers: ${missingHeaders.join(', ')}` });

    openPorts.forEach(p => {
      if (p.risk === 'Critical') { score -= 15; findings.push({ type: 'Port', severity: 'Critical', detail: `Dangerous port open: ${p.port} (${p.name})` }); }
      else if (p.risk === 'High') { score -= 8; findings.push({ type: 'Port', severity: 'High', detail: `Risky port open: ${p.port} (${p.name})` }); }
      else if (p.risk === 'Medium') { score -= 4; findings.push({ type: 'Port', severity: 'Medium', detail: `Port open: ${p.port} (${p.name})` }); }
    });

    if (!dnsResult.resolved) { score -= 20; findings.push({ type: 'DNS', severity: 'Critical', detail: 'Target could not be resolved' }); }

    score = Math.max(0, score);
    const riskLevel = score >= 80 ? 'Low' : score >= 60 ? 'Medium' : score >= 40 ? 'High' : 'Critical';

    const scanResult = {
      domain: cleanTarget,
      targetType: isIP ? 'ip' : 'domain',
      scannedAt: new Date().toISOString(),
      score,
      riskLevel,
      findings,
      ssl: sslResult,
      headers: headerResult,
      ports: { open: openPorts, all: portResults },
      dns: dnsResult
    };

    res.json(scanResult);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── AI analyze endpoint ──────────────────────────────────────────────────────
app.post('/api/ai-analyze', async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'Cyber Risk Tool API is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));