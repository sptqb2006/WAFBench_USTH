// app/src/db.js
// Javascript / Node.js 20 / pg / PostgreSQL 16 Connection Pool

const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'app-db',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME || 'vulnerable_db',
  user: process.env.DB_USER || 'app_user',
  password: process.env.DB_PASSWORD || 'app_secret_pass',
  max: 10,
  idleTimeoutMillis: 5000,
  connectionTimeoutMillis: 3000,
});

// Ngăn process crash nếu idle client bị ngắt kết nối đột ngột
pool.on('error', (err) => {
  console.error('[DB_POOL_ERROR]', err.message);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
