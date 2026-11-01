const express = require('express');
const router = express.Router();
const db = require('../db');
const { v4: uuidv4 } = require('uuid');

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    // VULNERABLE: Direct string concatenation creates SQL Injection vulnerability (CWE-89)
    // Allows comment-truncation: admin'-- 
    const unsafeQuery = `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password || ''}'`;
    
    const result = await db.query(unsafeQuery);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const sessionToken = uuidv4();

      // Persist active session in sessions table for Backend Oracle verification
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
    return res.status(500).json({
      success: false,
      error: 'Database error',
      details: err.message,
      correlation_id: req.correlationId
    });
  }
});

module.exports = router;
