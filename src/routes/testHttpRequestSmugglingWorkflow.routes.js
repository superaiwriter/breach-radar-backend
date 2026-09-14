const express = require('express');
const router = express.Router();

// GET /api/test-http-smuggling/secure
router.get('/secure', (req, res) => {
  return res.json({
    status: 'secure',
    message: 'Secure parser agreement.'
  });
});

// GET /api/test-http-smuggling/vulnerable
router.get('/vulnerable', (req, res) => {
  return res.json({
    status: 'vulnerable',
    message: 'Potential smuggling endpoint candidate.'
  });
});

// GET /api/test-http-smuggling/fake-200
router.get('/fake-200', (req, res) => {
  return res.status(200).json({
    status: 'ok',
    message: 'Harmless response.'
  });
});

module.exports = router;
