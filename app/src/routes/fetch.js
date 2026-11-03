// app/src/routes/fetch.js
// Javascript / Node.js 20 / Express / CWE-918 Server-Side Request Forgery

const express = require('express');
const router = express.Router();
const axios = require('axios');

router.post('/fetch', async (req, res) => {
  const { url } = req.body || {};

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required in JSON body', correlation_id: req.correlationId });
  }

  try {
    // VULNERABLE: Dispatches outbound HTTP GET request to user-supplied URL (SSRF - CWE-918)
    // In Docker container environment, loopback requests to port 8080 target the internal mock container
    const mockBase = process.env.MOCK_SERVICE_URL || 'http://mock-internal:8080';
    const dispatchUrl = url.replace(/^http:\/\/(?:127\.0\.0\.1|localhost):8080/, mockBase);

    const response = await axios.get(dispatchUrl, {
      timeout: 3000,
      headers: {
        'X-Request-ID': req.correlationId,
        'User-Agent': 'WAFBench-App-Fetcher/1.0'
      }
    });

    return res.status(200).json({
      success: true,
      target_url: url,
      response_data: response.data,
      correlation_id: req.correlationId
    });
  } catch (err) {
    return res.status(502).json({
      success: false,
      error: 'Fetch failed',
      details: err.message,
      correlation_id: req.correlationId
    });
  }
});

module.exports = router;
