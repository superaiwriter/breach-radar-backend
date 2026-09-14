const express = require('express');
const router = express.Router();

// GET /api/v1/test-sensitive-disclosure/vulnerable/apikey -> returns fake API keys
router.get('/vulnerable/apikey', (req, res) => {
  res.status(200).json({
    status: 'active',
    google_api_key: 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P',
    aws_access_key: 'AKIAIOSFODNN7EXAMPLE',
    aws_secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  });
});

// GET /api/v1/test-sensitive-disclosure/vulnerable/dbstring -> returns fake database connection string
router.get('/vulnerable/dbstring', (req, res) => {
  res.status(200).json({
    status: 'connected',
    uri: 'mongodb+srv://admin:MySecretPassword123@cluster0.abcde.mongodb.net/prod-db'
  });
});

// GET /api/v1/test-sensitive-disclosure/secure/safe -> secure endpoint with no findings
router.get('/secure/safe', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to the secure homepage!'
  });
});

// GET /api/v1/test-sensitive-disclosure/secure/harmless -> returns harmless information (like user IDs, server headers)
router.get('/secure/harmless', (req, res) => {
  res.status(200).json({
    contact: 'support@securescan.local',
    userId: 'user_12345',
    server: 'nginx/1.18.0'
  });
});

module.exports = router;
