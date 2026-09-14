const express = require('express');
const router = express.Router();

const mockUser = {
  username: 'test-user',
  password: 'test-password'
};

// POST /api/test-nosql/secure-login -> Validates types and rejects objects
router.post('/secure-login', (req, res) => {
  const { username, password } = req.body;

  // Strict check: both must be strings to prevent operator injection
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Invalid input types. Parameters must be strings.'
    });
  }

  if (username === mockUser.username && password === mockUser.password) {
    return res.status(200).json({
      success: true,
      token: 'nosql_secure_session_token_123',
      user: username,
      message: 'Logged in successfully'
    });
  }

  return res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// POST /api/test-nosql/vulnerable-login -> Allows operator objects to bypass auth
router.post('/vulnerable-login', (req, res) => {
  const { username, password } = req.body;

  // Simulate vulnerable query: e.g. db.users.findOne({ username, password })
  // In MongoDB: { username: { $ne: 'xyz' }, password: { $ne: 'xyz' } } matches the user!
  
  let matchUsername = false;
  let matchPassword = false;

  // Check username match
  if (typeof username === 'object' && username !== null) {
    // If it's an operator query like { $ne: 'random' }, simulate match
    if (username['$ne'] !== undefined || username['$gt'] !== undefined) {
      matchUsername = true;
    }
  } else if (username === mockUser.username) {
    matchUsername = true;
  }

  // Check password match
  if (typeof password === 'object' && password !== null) {
    if (password['$ne'] !== undefined || password['$gt'] !== undefined) {
      matchPassword = true;
    }
  } else if (password === mockUser.password) {
    matchPassword = true;
  }

  if (matchUsername && matchPassword) {
    return res.status(200).json({
      success: true,
      token: 'nosql_vulnerable_session_bypass_token_abc',
      user: mockUser.username,
      message: 'Logged in successfully via query resolution'
    });
  }

  return res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// POST /api/test-nosql/fake-200-login -> Always returns HTTP 200 with success: false
router.post('/fake-200-login', (req, res) => {
  res.status(200).json({
    success: false,
    error: 'Authentication failed. Fake Operational Panel.',
    token: null
  });
});

module.exports = router;
