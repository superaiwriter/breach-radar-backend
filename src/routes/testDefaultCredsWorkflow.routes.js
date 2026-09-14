const express = require('express');
const router = express.Router();

// GET /api/v1/test-default-creds/vulnerable/login -> mock login page returning forms
router.get('/vulnerable/login', (req, res) => {
  res.send(`
    <form action="/api/v1/test-default-creds/vulnerable/login" method="POST">
      <input type="text" name="username" placeholder="Username" />
      <input type="password" name="password" placeholder="Password" />
      <button type="submit">Submit</button>
    </form>
  `);
});

// POST /api/v1/test-default-creds/vulnerable/login -> accepts admin/admin
router.post('/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin') {
    res.cookie('admin_session', 'session-123-admin', { httpOnly: true });
    return res.json({
      success: true,
      token: 'admin-authorized-token-xyz'
    });
  }

  res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// POST /api/v1/test-default-creds/secure/login -> rejects all default creds
router.post('/secure/login', (req, res) => {
  res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// POST /api/v1/test-default-creds/fake-200-login -> returns 200 but not authenticated
router.post('/fake-200-login', (req, res) => {
  res.status(200).json({
    success: false,
    error: 'Authentication failed'
  });
});

module.exports = router;
