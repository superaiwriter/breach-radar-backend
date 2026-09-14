const express = require('express');
const router = express.Router();

// Mock database state for email update tracking
let mockState = {
  email: 'usera@securescan.local'
};

// Helper to authenticate session cookie
const getAuthenticatedUser = (req) => {
  const cookie = req.headers.cookie || '';
  if (cookie.includes('csrf_session_token_usera')) return 'usera';
  return null;
};

// POST /api/test-csrf/vulnerable -> Authenticated state-changing endpoint without CSRF protection
router.post('/vulnerable', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // Mutate state without any CSRF validation
  if (req.body && req.body.email) {
    mockState.email = req.body.email;
  }

  return res.json({
    success: true,
    email: mockState.email,
    message: 'Profile updated successfully'
  });
});

// POST /api/test-csrf/secure -> Requires session cookie AND valid x-csrf-token header
router.post('/secure', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // CSRF validation
  if (req.headers['x-csrf-token'] !== 'SECURE_CSRF_TOKEN_VAL') {
    return res.status(403).json({ success: false, error: 'CSRF validation failed: Token missing or invalid' });
  }

  if (req.body && req.body.email) {
    mockState.email = req.body.email;
  }

  return res.json({
    success: true,
    email: mockState.email,
    message: 'Profile updated securely'
  });
});

// POST /api/test-csrf/token-required -> Requires session cookie AND body parameter _csrf
router.post('/token-required', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // CSRF body parameter check
  if (!req.body || req.body._csrf !== 'BODY_CSRF_TOKEN_VAL') {
    return res.status(403).json({ success: false, error: 'CSRF validation failed: Body parameter _csrf missing or invalid' });
  }

  if (req.body && req.body.email) {
    mockState.email = req.body.email;
  }

  return res.json({
    success: true,
    email: mockState.email,
    message: 'Profile updated with body token'
  });
});

// POST /api/test-csrf/fake-200 -> Always returns HTTP 200 but does NOT execute the state change
router.post('/fake-200', (req, res) => {
  return res.status(200).json({
    success: true,
    message: 'Profile settings processed successfully'
  });
});

// POST /api/test-csrf/bearer-only -> Requires Authorization Bearer token instead of ambient cookies
router.post('/bearer-only', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader !== 'Bearer bearer_token_usera') {
    return res.status(401).json({ success: false, error: 'Unauthorized: Bearer token invalid or missing' });
  }

  // Accept mutation since API token is supplied explicitly (not vulnerable to cookie CSRF)
  return res.json({
    success: true,
    email: req.body.email,
    message: 'API token validated, profile mutated'
  });
});

module.exports = router;
