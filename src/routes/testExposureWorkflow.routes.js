const express = require('express');
const router = express.Router();

// GET /api/v1/test-exposure/secure -> safe mock profile data
router.get('/secure', (req, res) => {
  res.json({
    success: true,
    name: 'Test User',
    bio: 'Security testing'
  });
});

// GET /api/v1/test-exposure/vulnerable -> vulnerable mock endpoint returning excessive/sensitive data
router.get('/vulnerable', (req, res) => {
  res.json({
    success: true,
    id: 101,
    name: 'Test User',
    bio: 'Security testing',
    // Sensitive authentication secrets
    passwordHash: '$2a$10$eH4z5bO.cWl2sP.fXbU/1e6Q.J9lE/mU8Z3q5vA6w7z8y9x0w1v2u',
    resetToken: 'rst_3f8a9e0c1b2d3f4e5a6b',
    sessionToken: 'sess_f2e3d4c5b6a798801234',
    // Simulated JWT token
    tempJwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    // Simulated API Key
    googleApiKey: 'AIzaSyD-7e61hskad72sHhs8',
    // Simulated debug stack trace / internal details
    debugStackTrace: 'Error: Connection lost\n    at Connection.write (E:\\REACT\\backend\\node_modules\\mysql\\lib\\Connection.js:101:15)\n    at Query.run (E:\\REACT\\backend\\node_modules\\mysql\\lib\\Query.js:45:10)',
    internalDatabaseUrl: 'mongodb+srv://admin:SuperSecretPass123@cluster0.zgsfa1j.mongodb.net/production'
  });
});

module.exports = router;
