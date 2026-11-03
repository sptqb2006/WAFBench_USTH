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
  // Ensure robust path resolution regardless of working directory
  const baseDirectory = fs.existsSync(path.resolve(__dirname, '../../public/downloads'))
    ? path.resolve(__dirname, '../../public/downloads')
    : path.resolve(__dirname, '../public/downloads');

  // Normalize nested dot bypass payload (e.g. ....// -> ../)
  const targetPath = filename.includes('....//')
    ? filename.replace(/\.\.\.\.\/\//g, '../')
    : filename;
  const filePath = path.join(baseDirectory, targetPath);

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
