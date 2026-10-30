const express = require('express');
const app = express();
const PORT = 8080;

app.use(express.json());

// In-memory access log for oracle verification
let accessLogs = [];

// Middleware logging every hit with X-Request-ID
app.use((req, res, next) => {
  const correlationId = req.headers['x-request-id'] || 'anonymous';
  const entry = {
    timestamp: new Date().toISOString(),
    correlation_id: correlationId,
    method: req.method,
    path: req.originalUrl,
  };
  accessLogs.push(entry);
  next();
});

// Health endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'UP', service: 'mock-internal' });
});

// Reset endpoint called by vulnerable-app /health/reset
app.post('/reset', (req, res) => {
  accessLogs = [];
  res.json({ reset: true, timestamp: new Date().toISOString() });
});

// Query logs endpoint for runner oracle
app.get('/logs', (req, res) => {
  const correlationId = req.query.correlation_id;
  if (correlationId) {
    const filtered = accessLogs.filter(l => l.correlation_id === correlationId);
    return res.json(filtered);
  }
  res.json(accessLogs);
});

// Sensitive target endpoint for SSRF-001 (Malicious)
app.get('/metadata', (req, res) => {
  res.json({
    service: 'internal-cloud-metadata',
    instance_id: 'i-0abcdef1234567890',
    iam_role: 'wafbench-production-role',
    secret_token: 'wb_secret_token_super_confidential_998877'
  });
});

// Legitimate target endpoint for SSRF-001-B1 (Benign)
app.get('/public/avatar.png', (req, res) => {
  res.setHeader('Content-Type', 'image/png');
  // Return dummy 1x1 transparent PNG
  const png1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
  res.send(png1x1);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[mock-internal] Service running on internal port ${PORT}`);
});
