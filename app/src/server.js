// app/src/server.js
// Javascript / Node.js 20 / Express / WAFBench Target Server

const express = require('express');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const db = require('./db');

const healthRoutes = require('./routes/health');
const sqliRoutes = require('./routes/sqli');
const xssRoutes = require('./routes/xss');
const traversalRoutes = require('./routes/traversal');
const fetchRoutes = require('./routes/fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Correlation ID & Single-Line JSON Logger Middleware (Registered first)
app.use((req, res, next) => {
  const correlationId = req.headers['x-request-id'] || uuidv4();
  req.correlationId = correlationId;
  res.setHeader('X-Request-ID', correlationId);

  const startTime = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logEntry = {
      timestamp: new Date().toISOString(),
      correlation_id: correlationId,
      tier: 'vulnerable-app',
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      duration_ms: duration,
      ip: req.ip || req.connection.remoteAddress,
    };
    // Output single-line JSON log to stdout as required by telemetry specifications
    console.log(JSON.stringify(logEntry));
  });

  next();
});

// Body Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static files (legitimate download path)
app.use('/public', express.static(path.join(__dirname, '../public')));

// Mount Routes
app.use('/', healthRoutes);
app.use('/', sqliRoutes);
app.use('/', xssRoutes);
app.use('/', traversalRoutes);
app.use('/', fetchRoutes);

// Global Error Handler
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  const statusCode = err.status || err.statusCode || 500;
  return res.status(statusCode).json({
    success: false,
    error: err.message || 'Internal Server Error',
    correlation_id: req.correlationId || 'untracked'
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'APP_STARTUP',
    port: PORT,
    status: 'READY'
  }));
});

// Graceful Shutdown Handler
function gracefulShutdown(signal) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'APP_SHUTDOWN',
    signal: signal
  }));
  server.close(async () => {
    try {
      await db.pool.end();
    } catch (err) {
      // Ignore cleanup error
    }
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
