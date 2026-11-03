// mock-internal/server.js
// Javascript / Node.js 20 / Express / Private SSRF Mock Target & Oracle Logger
// Part of WAFBench Controlled Backend Stack (Author: Dat)

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

// Legitimate target endpoint for SSRF-002-B1 (Benign logo.png)
app.get('/public/logo.png', (req, res) => {
  res.setHeader('Content-Type', 'image/png');
  const png1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
  res.send(png1x1);
});

// Legitimate target endpoint for HOLD-SSRF-001-B1 (Benign favicon.ico)
app.get('/public/favicon.ico', (req, res) => {
  res.setHeader('Content-Type', 'image/x-icon');
  const dummyIco = Buffer.from('AAABAAEAAQEAAAEAIAAwAAAAFgAAACgAAAABAAAAAgAAAAEAIAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
  res.send(dummyIco);
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[mock-internal] Service running on internal port ${PORT}`);
});

// Graceful Shutdown
function gracefulShutdown(signal) {
  server.close(() => {
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
