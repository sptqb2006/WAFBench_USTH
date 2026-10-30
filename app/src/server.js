const express = require('express');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const healthRoutes = require('./routes/health');
const sqliRoutes = require('./routes/sqli');
const xssRoutes = require('./routes/xss');
const traversalRoutes = require('./routes/traversal');
const fetchRoutes = require('./routes/fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Body Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static files (legitimate download path)
app.use('/public', express.static(path.join(__dirname, '../public')));

// Correlation ID & Single-Line JSON Logger Middleware
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
    // Xuất log trên đúng 1 dòng JSON ra stdout theo yêu cầu
    console.log(JSON.stringify(logEntry));
  });

  next();
});

// Mount Routes
app.use('/', healthRoutes);
app.use('/', sqliRoutes);
app.use('/', xssRoutes);
app.use('/', traversalRoutes);
app.use('/', fetchRoutes);

app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'APP_STARTUP',
    port: PORT,
    status: 'READY'
  }));
});
