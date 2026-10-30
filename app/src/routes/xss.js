const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/search', async (req, res) => {
  const query = req.query.q || '';

  // VULNERABLE: Phản hồi trực tiếp chuỗi q vào DOM HTML mà không encode (CWE-79)
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Search Results</title>
    </head>
    <body>
      <h1>Kết quả tìm kiếm cho: ${query}</h1>
      <p>Không tìm thấy bài viết nào phù hợp.</p>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(htmlResponse);
});

module.exports = router;
