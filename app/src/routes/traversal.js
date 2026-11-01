const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

router.get('/file', (req, res) => {
  const filename = req.query.filename;

  if (!filename) {
    return res.status(400).json({ error: 'Filename parameter is required' });
  }

  // VULNERABLE: Unsanitized path.join allows Path Traversal via '../' (CWE-22)
  const baseDirectory = path.join(__dirname, '../public/downloads');
  const filePath = path.join(baseDirectory, filename);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({
        error: 'File not found or unreadable',
        path: filePath,
        correlation_id: req.correlationId
      });
    }

    // Return plain text if text file or /etc/passwd disclosure
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(200).send(data);
  });
});

module.exports = router;
