// app/src/routes/traversal.js
// Javascript / Node.js 20 / Express / CWE-22 Path Traversal

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

router.get('/file', (req, res) => {
  const filename = req.query.filename;

  if (!filename) {
    return res.status(400).json({ error: 'Filename parameter is required' });
  }

  // VULNERABLE: path.join không kiểm tra '../' dẫn tới Path Traversal (CWE-22)
  // __dirname là /app/src/routes, nên ../../public/downloads trỏ về /app/public/downloads
  const baseDirectory = path.join(__dirname, '../../public/downloads');
  const filePath = path.join(baseDirectory, filename);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).json({
        error: 'File not found or unreadable',
        path: filePath,
        correlation_id: req.correlationId
      });
    }

    // Xác định Content-Type phù hợp theo đuôi file hoặc mặc định text/plain
    if (filename.toLowerCase().endsWith('.pdf')) {
      res.setHeader('Content-Type', 'application/pdf');
    } else {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    }
    return res.status(200).send(data);
  });
});

module.exports = router;
