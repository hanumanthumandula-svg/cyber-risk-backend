const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dnsPromises = require('dns').promises;
const net = require('net');
const https = require('https');
const http = require('http');
const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── MongoDB ────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB Error:', err));

app.use('/api/assessment', require('./routes/assessment'));

// ── Schemas ────────────────────────────────────────────────────────────────
const scanHistorySchema = new mongoose.Schema({
  domain: String,
  targetType: String,
  score: Number,
  riskLevel: String,
  findings: Array,
  scannedAt: { type: Date, default: Date.now }
});
const ScanHistory = mongoose.model('ScanHistory', scanHistorySchema);

const blockedUrlSchema = new mongoose.Schema({
  domain: String,
  score: Number,
  riskLevel: String,
  blockedAt: { type: Date, default: Date.now }
});
const BlockedUrl = mongoose.model('BlockedUrl', blockedUrlSchema);

// ── Helper: port check ─────────────────────────────────────────────────────
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

// ── Helper: SSL check ──────────────────────────────────────────────────────
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

// ── Helper: headers check ──────────────────────────────────────────────────
function checkHeaders(domain) {
  return new Promise((resolve) => {
    const req = https.request({ host: domain, path: '/', method: 'HEAD', port: 443, timeout: 5000 }, (res) => {
      const headers = res.headers;
      resolve({
        statusCode: res.statusCode,
        httpsRedirect: true,
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

// ── Helper: classify target ────────────────────────────────────────────────
function classifyTarget(input) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  if (ipv4Regex.test(input)) {
    const parts = input.split('.').map(Number);
    if (parts.some(n => n > 255)) return { valid: false };
    const isPrivate =
      parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254);
    if (isPrivate) return { valid: false, private: true };
    return { valid: true, type: 'ip' };
  }
  if (domainRegex.test(input)) return { valid: true, type: 'domain' };
  return { valid: false };
}

// ── Helper: risk color ─────────────────────────────────────────────────────
function getRiskColor(level) {
  if (level === 'Low') return '#22c55e';
  if (level === 'Medium') return '#f59e0b';
  if (level === 'High') return '#f97316';
  return '#ef4444';
}

// ── Main scan endpoint ─────────────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain or IP is required' });

  const cleanTarget = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const classification = classifyTarget(cleanTarget);

  if (!classification.valid) {
    if (classification.private)
      return res.status(400).json({ error: 'Private/reserved IP addresses cannot be scanned' });
    return res.status(400).json({ error: 'Invalid domain name or IP address' });
  }

  const isIP = classification.type === 'ip';

  try {
    let dnsResult = { resolved: false, ips: [], mx: [], txt: [] };
    try {
      if (isIP) {
        dnsResult.resolved = true;
        dnsResult.ips = [cleanTarget];
        try { const h = await dnsPromises.reverse(cleanTarget); dnsResult.hostname = h[0]; } catch {}
      } else {
        const ips = await dnsPromises.resolve4(cleanTarget);
        dnsResult.resolved = true;
        dnsResult.ips = ips;
        try { dnsResult.mx = await dnsPromises.resolveMx(cleanTarget); } catch {}
        try { dnsResult.txt = await dnsPromises.resolveTxt(cleanTarget); } catch {}
      }
    } catch { dnsResult.error = 'Could not resolve target'; }

    const sslResult = await checkSSL(cleanTarget);
    const headerResult = await checkHeaders(cleanTarget);

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
      portsToCheck.map(async (p) => ({ ...p, open: await checkPort(cleanTarget, p.port) }))
    );
    const openPorts = portResults.filter(p => p.open);

    let score = 100;
    const findings = [];

    if (!sslResult.valid) { score -= 25; findings.push({ type: 'SSL', severity: 'Critical', detail: 'No valid SSL certificate' }); }
    else if (sslResult.expired) { score -= 25; findings.push({ type: 'SSL', severity: 'Critical', detail: 'SSL certificate expired' }); }
    else if (sslResult.expiringSoon) { score -= 10; findings.push({ type: 'SSL', severity: 'High', detail: `SSL expires in ${sslResult.daysLeft} days` }); }

    if (!headerResult.httpsRedirect) { score -= 10; findings.push({ type: 'HTTPS', severity: 'High', detail: 'No HTTPS redirect' }); }

    const missingHeaders = Object.entries(headerResult.headers || {}).filter(([, v]) => !v).map(([k]) => k);
    score -= missingHeaders.length * 3;
    if (missingHeaders.length > 0) findings.push({ type: 'Headers', severity: 'Medium', detail: `Missing: ${missingHeaders.join(', ')}` });

    openPorts.forEach(p => {
      if (p.risk === 'Critical') { score -= 15; findings.push({ type: 'Port', severity: 'Critical', detail: `Dangerous port open: ${p.port} (${p.name})` }); }
      else if (p.risk === 'High') { score -= 8; findings.push({ type: 'Port', severity: 'High', detail: `Risky port open: ${p.port} (${p.name})` }); }
      else if (p.risk === 'Medium') { score -= 4; findings.push({ type: 'Port', severity: 'Medium', detail: `Port open: ${p.port} (${p.name})` }); }
    });

    if (!dnsResult.resolved) { score -= 20; findings.push({ type: 'DNS', severity: 'Critical', detail: 'Target could not be resolved' }); }

    score = Math.max(0, score);
    const riskLevel = score >= 80 ? 'Low' : score >= 60 ? 'Medium' : score >= 40 ? 'High' : 'Critical';

    try {
      await ScanHistory.create({ domain: cleanTarget, targetType: isIP ? 'ip' : 'domain', score, riskLevel, findings });
    } catch (e) { console.error('DB save error:', e.message); }

    if (riskLevel === 'Critical' || riskLevel === 'High') {
      try {
        await BlockedUrl.findOneAndUpdate(
          { domain: cleanTarget },
          { domain: cleanTarget, score, riskLevel, blockedAt: new Date() },
          { upsert: true }
        );
      } catch (e) { console.error('Block save error:', e.message); }
    }

    res.json({
      domain: cleanTarget, targetType: isIP ? 'ip' : 'domain',
      scannedAt: new Date().toISOString(),
      score, riskLevel, findings,
      ssl: sslResult, headers: headerResult,
      ports: { open: openPorts, all: portResults },
      dns: dnsResult,
      autoBlocked: riskLevel === 'Critical' || riskLevel === 'High'
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── AI analyze endpoint ────────────────────────────────────────────────────
app.post('/api/ai-analyze', async (req, res) => {
  try {
    const { messages } = req.body;
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages,
        max_tokens: 1000,
        temperature: 0.7
      })
    });
    const data = await response.json();
    if (!response.ok) return res.status(response.status).json({ error: data.error?.message || 'Groq error' });
    res.json({ content: [{ text: data.choices[0].message.content }] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Email report endpoint ──────────────────────────────────────────────────
app.post('/api/send-report', async (req, res) => {
  try {
    const { email, domain, score, riskLevel, findings, ssl, ports } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const scoreColor = getRiskColor(riskLevel);

    const findingsRows = (findings || []).map(f => `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #334155;color:${getRiskColor(f.severity)};font-weight:600;">${f.severity}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #334155;color:#94a3b8;">${f.type}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #334155;color:#e2e8f0;">${f.detail}</td>
      </tr>`).join('');

    const openPortsList = (ports?.open || []).map(p =>
      `<li style="padding:4px 0;color:#94a3b8;">${p.port} - <strong style="color:#e2e8f0;">${p.name}</strong> <span style="color:${getRiskColor(p.risk)};">(${p.risk})</span></li>`
    ).join('');

    const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#1e293b;padding:24px;text-align:center;border-bottom:1px solid #334155;">
        <h1 style="color:#6366f1;margin:0;font-size:22px;">🛡️ CyberRisk Assessor</h1>
        <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;">Automated Security Scan Report</p>
      </div>
      <div style="padding:24px;">

        <div style="background:#1e293b;border-radius:12px;padding:20px;text-align:center;margin-bottom:20px;">
          <div style="font-size:13px;color:#94a3b8;margin-bottom:8px;">Security Score for</div>
          <div style="font-size:20px;font-weight:700;color:#e2e8f0;margin-bottom:12px;">${domain}</div>
          <div style="font-size:56px;font-weight:800;color:${scoreColor};line-height:1;">${score}</div>
          <div style="font-size:13px;color:#94a3b8;margin:4px 0 12px;">out of 100</div>
          <span style="background:${scoreColor}22;color:${scoreColor};border:1px solid ${scoreColor}44;padding:4px 16px;border-radius:99px;font-size:13px;font-weight:600;">${riskLevel} Risk</span>
        </div>

        <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;">
          <h3 style="color:#6366f1;margin:0 0 12px;font-size:15px;">SSL Certificate</h3>
          <p style="color:#94a3b8;margin:0;font-size:13px;">
            ${ssl?.valid
              ? `✅ Valid — Issued by <strong style="color:#e2e8f0;">${ssl.issuer}</strong>, expires in <strong style="color:#e2e8f0;">${ssl.daysLeft} days</strong>`
              : `❌ No valid SSL certificate found`}
          </p>
        </div>

        <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;">
          <h3 style="color:#6366f1;margin:0 0 12px;font-size:15px;">Findings (${(findings || []).length})</h3>
          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr>
                <th style="padding:8px 12px;text-align:left;color:#94a3b8;font-size:12px;border-bottom:1px solid #334155;">Severity</th>
                <th style="padding:8px 12px;text-align:left;color:#94a3b8;font-size:12px;border-bottom:1px solid #334155;">Type</th>
                <th style="padding:8px 12px;text-align:left;color:#94a3b8;font-size:12px;border-bottom:1px solid #334155;">Detail</th>
              </tr>
            </thead>
            <tbody>${findingsRows || '<tr><td colspan="3" style="padding:8px 12px;color:#94a3b8;">No findings</td></tr>'}</tbody>
          </table>
        </div>

        ${openPortsList ? `
        <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;">
          <h3 style="color:#6366f1;margin:0 0 12px;font-size:15px;">Open Ports</h3>
          <ul style="margin:0;padding-left:20px;">${openPortsList}</ul>
        </div>` : ''}

        ${riskLevel === 'High' || riskLevel === 'Critical' ? `
        <div style="background:#7f1d1d22;border:1px solid #ef444466;border-radius:12px;padding:16px;margin-bottom:20px;">
          <h3 style="color:#ef4444;margin:0 0 8px;font-size:15px;">🚨 High Risk Alert</h3>
          <p style="color:#94a3b8;margin:0;font-size:13px;">
            This domain scored <strong style="color:#ef4444;">${score}/100</strong> and has been automatically
            flagged and added to the blocked list. Accessing this domain may pose a significant
            security risk to your organization.
          </p>
        </div>` : ''}

        <div style="text-align:center;padding-top:16px;border-top:1px solid #334155;">
          <p style="color:#64748b;font-size:12px;margin:0;">Generated by CyberRisk Assessor</p>
          <p style="color:#64748b;font-size:12px;margin:4px 0 0;">
            <a href="https://cyber-risk-tool-cz2z.onrender.com" style="color:#6366f1;">cyber-risk-tool-cz2z.onrender.com</a>
          </p>
        </div>
      </div>
    </div>`;

    await resend.emails.send({
      from: 'CyberRisk Assessor <onboarding@resend.dev>',
      to: email,
      subject: `🛡️ Security Scan Report: ${domain} — Score ${score}/100 (${riskLevel} Risk)`,
      html: htmlContent
    });

    res.json({ success: true, message: `Report sent to ${email}` });

  } catch (error) {
    console.error('Email error:', error.message);
    res.status(500).json({ error: 'Failed to send email: ' + error.message });
  }
});

// ── High risk alert email ──────────────────────────────────────────────────
app.post('/api/send-alert', async (req, res) => {
  try {
    const { email, domain, score, riskLevel, findings } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const findingsList = (findings || []).map(f =>
      `<li style="padding:4px 0;color:#94a3b8;font-size:13px;">
        <span style="color:${getRiskColor(f.severity)};font-weight:600;">[${f.severity}]</span> ${f.detail}
      </li>`
    ).join('');

    const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#7f1d1d;padding:24px;text-align:center;">
        <h1 style="color:#fca5a5;margin:0;font-size:22px;">🚨 HIGH RISK ALERT</h1>
        <p style="color:#fca5a5;margin:6px 0 0;font-size:13px;opacity:0.8;">CyberRisk Assessor — Automated Security Alert</p>
      </div>
      <div style="padding:24px;">
        <div style="background:#1e293b;border-radius:12px;padding:20px;text-align:center;margin-bottom:20px;border:2px solid #ef4444;">
          <div style="font-size:16px;color:#94a3b8;margin-bottom:8px;">Dangerous domain detected</div>
          <div style="font-size:24px;font-weight:700;color:#ef4444;margin-bottom:8px;">${domain}</div>
          <div style="font-size:48px;font-weight:800;color:#ef4444;line-height:1;">${score}</div>
          <div style="font-size:13px;color:#94a3b8;margin:4px 0 12px;">out of 100</div>
          <span style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;padding:4px 16px;border-radius:99px;font-size:14px;font-weight:700;">${riskLevel} Risk</span>
        </div>

        <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;">
          <h3 style="color:#ef4444;margin:0 0 12px;font-size:15px;">Security Issues Found</h3>
          <ul style="margin:0;padding-left:20px;">${findingsList}</ul>
        </div>

        <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;">
          <h3 style="color:#6366f1;margin:0 0 8px;font-size:15px;">Action Taken</h3>
          <p style="color:#94a3b8;margin:0;font-size:13px;">
            ✅ This domain has been automatically added to your blocked list.<br/>
            ✅ Your Chrome extension will block access to this domain.<br/>
            ✅ This alert was sent automatically when the scan completed.
          </p>
        </div>

        <div style="text-align:center;padding-top:16px;border-top:1px solid #334155;">
          <p style="color:#64748b;font-size:12px;margin:0;">CyberRisk Assessor — Automated Alert System</p>
          <p style="color:#64748b;font-size:12px;margin:4px 0 0;">
            <a href="https://cyber-risk-tool-cz2z.onrender.com" style="color:#6366f1;">View Dashboard</a>
          </p>
        </div>
      </div>
    </div>`;

    await resend.emails.send({
      from: 'CyberRisk Assessor <onboarding@resend.dev>',
      to: email,
      subject: `🚨 HIGH RISK ALERT: ${domain} scored ${score}/100 — Immediate Action Required`,
      html: htmlContent
    });

    res.json({ success: true, message: `Alert sent to ${email}` });

  } catch (error) {
    console.error('Alert email error:', error.message);
    res.status(500).json({ error: 'Failed to send alert: ' + error.message });
  }
});

// ── Scan history endpoint ──────────────────────────────────────────────────
app.get('/api/scan-history', async (req, res) => {
  try {
    const history = await ScanHistory.find().sort({ scannedAt: -1 }).limit(50);
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Blocked URLs endpoint ──────────────────────────────────────────────────
app.get('/api/blocked-urls', async (req, res) => {
  try {
    const blocked = await BlockedUrl.find().sort({ blockedAt: -1 });
    res.json(blocked);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Check URL blocked ──────────────────────────────────────────────────────
app.get('/api/check-url', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    const blocked = await BlockedUrl.findOne({ domain: domain.toLowerCase() });
    res.json({ blocked: !!blocked, domain, riskLevel: blocked?.riskLevel, score: blocked?.score });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Health check ───────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ message: 'Cyber Risk Tool API is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));