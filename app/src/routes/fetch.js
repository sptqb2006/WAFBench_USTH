const express = require('express');
const router = express.Router();
const axios = require('axios');

router.post('/fetch', async (req, res) => {
  const { url } = req.body || {};

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required in JSON body' });
  }

  try {
    // VULNERABLE: Direct HTTP GET dispatch to user-supplied URL (SSRF - CWE-918)
    const response = await axios.get(url, {
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
