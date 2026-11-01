// app/src/routes/health.js
// Javascript / Node.js 20 / Express / WAFBench Target

const express = require('express');
const router = express.Router();
const db = require('../db');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// Pre-cache Fixture F1 seed SQL in memory to ensure fast reset (<= 5s)
const seedPath = path.join(__dirname, '../sql/seed.sql');
let cachedSeedSql = null;

function getSeedSql() {
  if (!cachedSeedSql) {
    cachedSeedSql = fs.readFileSync(seedPath, 'utf8');
  }
  return cachedSeedSql;
}

router.get('/health', async (req, res) => {
  try {
    const result = await db.query('SELECT 1 as alive');
    return res.status(200).json({
      status: 'UP',
      app: 'vulnerable-app',
      db: result.rows.length > 0 ? 'CONNECTED' : 'DOWN',
      correlation_id: req.correlationId,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    return res.status(500).json({
      status: 'ERROR',
      error: err.message,
      correlation_id: req.correlationId
    });
  }
});

router.post('/health/reset', async (req, res) => {
  const start = Date.now();
  try {
    const seedSql = getSeedSql();

    // Nạp lại Fixture F1 trong PostgreSQL
    await db.query(seedSql);

    // Kích hoạt xóa log trên mock-internal service
    const mockUrl = process.env.MOCK_SERVICE_URL || 'http://mock-internal:8080';
    try {
      await axios.post(`${mockUrl}/reset`, {}, { timeout: 2000 });
    } catch (mockErr) {
      // Mock reset warning
    }

    const duration = Date.now() - start;
    return res.status(200).json({
      success: true,
      action: 'FIXTURE_RESET',
      fixture: 'F1',
      reset_duration_ms: duration,
      correlation_id: req.correlationId
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message,
      correlation_id: req.correlationId
    });
  }
});

module.exports = router;
