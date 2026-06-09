const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully'))
  .catch(err => console.log('MongoDB Error:', err));

app.use('/api/assessment', require('./routes/assessment'));

app.post('/api/ai-analyze', async (req, res) => {
  try {
    const { companyName, industry } = req.body;
    const prompt = `You are a cybersecurity expert. Generate a complete cybersecurity risk assessment report for the following organization:

Company Name: ${companyName}
Industry: ${industry}

Generate a detailed JSON report with EXACTLY this structure and nothing else:
{
  "companyName": "${companyName}",
  "industry": "${industry}",
  "overallRiskScore": <number 0-100>,
  "riskLevel": "<Low|Medium|High|Critical>",
  "executiveSummary": "<2-3 sentence summary>",
  "threats": [
    {"name": "<threat name>", "severity": "<Low|Medium|High|Critical>", "description": "<one line>"},
    {"name": "<threat name>", "severity": "<Low|Medium|High|Critical>", "description": "<one line>"},
    {"name": "<threat name>", "severity": "<Low|Medium|High|Critical>", "description": "<one line>"},
    {"name": "<threat name>", "severity": "<Low|Medium|High|Critical>", "description": "<one line>"},
    {"name": "<threat name>", "severity": "<Low|Medium|High|Critical>", "description": "<one line>"}
  ],
  "domains": [
    {"name": "Patch Management", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "MFA & Authentication", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Monitoring & Detection", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Backup & Recovery", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Access Control", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Security Awareness", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Encryption", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"},
    {"name": "Incident Response", "score": <0-10>, "status": "<Weak|Moderate|Strong>", "recommendation": "<one line fix>"}
  ],
  "compliance": [
    {"framework": "ISO 27001", "status": "<Compliant|Partial|Non-Compliant>", "gap": "<one line>"},
    {"framework": "NIST CSF", "status": "<Compliant|Partial|Non-Compliant>", "gap": "<one line>"},
    {"framework": "PCI DSS", "status": "<Compliant|Partial|Non-Compliant>", "gap": "<one line>"},
    {"framework": "GDPR", "status": "<Compliant|Partial|Non-Compliant>", "gap": "<one line>"}
  ],
  "topRecommendations": [
    "<recommendation 1>",
    "<recommendation 2>",
    "<recommendation 3>",
    "<recommendation 4>",
    "<recommendation 5>"
  ]
}

Return ONLY the JSON. No explanation. No markdown. No extra text.`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 2000,
        temperature: 0.3
      })
    });

    const data = await response.json();
    const raw = data.choices[0].message.content;
    const clean = raw.replace(/```json|```/g, '').trim();
    const report = JSON.parse(clean);
    res.json({ success: true, report });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'Cyber Risk Tool API is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});