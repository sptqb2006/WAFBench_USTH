// app/src/routes/sqli.js
// Javascript / Node.js 20 / Express / CWE-89 SQL Injection

const express = require('express');
const router = express.Router();
const db = require('../db');
const { generateSessionToken } = require('../utils/hmac');

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username) {
    return res.status(400).json({ error: 'Username is required', correlation_id: req.correlationId });
  }

  try {
    // VULNERABLE: Direct string interpolation introducing SQL Injection (CWE-89)
    // Allows comment-truncation payload bypass (e.g. admin'--)
    const unsafeQuery = `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password || ''}'`;
    
    const result = await db.query(unsafeQuery);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      // Cryptographically signed session token using HMAC-SHA256 for local role-based authorization
      const sessionToken = generateSessionToken(user.username, user.role);

      // Persist session to database for test runner oracle verification
      await db.query(
        'INSERT INTO sessions (session_token, username) VALUES ($1, $2)',
        [sessionToken, user.username]
      );

      res.cookie('session_id', sessionToken, { httpOnly: true });

      return res.status(200).json({
        success: true,
        message: 'Authentication successful',
        user: { username: user.username, role: user.role },
        session_token: sessionToken,
        hmac_token: sessionToken,
        correlation_id: req.correlationId
      });
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        correlation_id: req.correlationId
      });
    }
  } catch (err) {
    // If SQL syntax error caused by apostrophe in username (e.g. o'brien), return 401 Invalid credentials
    if (err.code === '42601' || (err.message && err.message.includes('syntax error'))) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        details: 'Malformed query parameter',
        correlation_id: req.correlationId
      });
    }
    return res.status(500).json({
      success: false,
      error: 'Database error',
      details: err.message,
      correlation_id: req.correlationId
    });
  }
});

module.exports = router;
