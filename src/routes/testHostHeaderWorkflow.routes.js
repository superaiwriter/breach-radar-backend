const express = require('express');
const router = express.Router();

// 1. GET /api/test-host-header/vulnerable -> Reads req.headers.host and constructs a password reset URL
router.get('/vulnerable', (req, res) => {
  const host = req.headers.host || 'localhost:5000';
  
  // Use host header to construct absolute URL
  const resetUrl = `https://${host}/reset/TEST_TOKEN`;

  return res.json({
    resetUrl
  });
});

// 2. GET /api/test-host-header/secure -> Always uses configured canonical application origin
router.get('/secure', (req, res) => {
  // Always use a static canonical origin
  const resetUrl = 'https://example.com/reset/TEST_TOKEN';

  return res.json({
    resetUrl
  });
});

// 3. GET /api/test-host-header/fake-200 -> Reflects Host header in harmless text only
router.get('/fake-200', (req, res) => {
  const host = req.headers.host || 'localhost:5000';

  return res.json({
    message: `Host received: ${host}`
  });
});

// 4. GET /api/test-host-header/redirect -> Redirects to the Host header if it controls the redirect destination
router.get('/redirect', (req, res) => {
  const host = req.headers.host || 'localhost:5000';

  // Perform redirect using Host header
  return res.redirect(`https://${host}/login`);
});

module.exports = router;
