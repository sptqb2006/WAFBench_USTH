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

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
