const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/search', async (req, res) => {
  const query = req.query.q || '';

  // VULNERABLE: Direct unescaped reflection of query parameter 'q' into HTML DOM (CWE-79)
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Search Results</title>
    </head>
    <body>
      <h1>Search Results for: ${query}</h1>
      <p>No matching articles found.</p>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(htmlResponse);
});

module.exports = router;
