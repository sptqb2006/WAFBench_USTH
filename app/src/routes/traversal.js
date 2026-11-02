// app/src/routes/traversal.js
// Javascript / Node.js 20 / Express / CWE-22 Path Traversal

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

router.get('/file', (req, res) => {
  const rawFilename = req.query.filename;

  if (!rawFilename) {
    return res.status(400).json({ error: 'Filename parameter is required', correlation_id: req.correlationId });
  }

  const filename = Array.isArray(rawFilename) ? rawFilename[0] : String(rawFilename);

  // VULNERABLE: path.join without sanitization allows directory traversal (CWE-22)
  // __dirname is /app/src/routes, so ../../public/downloads resolves to /app/public/downloads
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

    // Determine appropriate Content-Type header or fallback to text/plain
    if (filename.toLowerCase().endsWith('.pdf')) {
      res.setHeader('Content-Type', 'application/pdf');
    } else {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    }
    return res.status(200).send(data);
  });
});

module.exports = router;
