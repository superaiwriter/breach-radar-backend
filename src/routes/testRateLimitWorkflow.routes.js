const express = require('express');
const router = express.Router();

// Simple in-memory request counter, keyed by session cookie + path
const requestTracker = {};

const trackRequest = (req, path) => {
  const cookie = req.cookies.bola_session || req.cookies.bfla_session || 'anon';
  const key = `${cookie}:${path}`;
  if (!requestTracker[key]) {
    requestTracker[key] = { count: 0, resetAt: Date.now() + 60 * 1000 };
  }

  // Auto reset counter after 1 minute
  if (Date.now() > requestTracker[key].resetAt) {
    requestTracker[key].count = 0;
    requestTracker[key].resetAt = Date.now() + 60 * 1000;
  }

  requestTracker[key].count += 1;
  return requestTracker[key].count;
};

// POST /api/v1/test-ratelimit/secure/login -> mock rate-limited login endpoint
router.post('/secure/login', (req, res) => {
  const attempts = trackRequest(req, '/secure/login');

  res.setHeader('X-RateLimit-Limit', '5');
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, 5 - attempts)));
  res.setHeader('X-RateLimit-Reset', '60');

  if (attempts > 5) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      success: false,
      error: 'Too many login attempts. Please try again in 60 seconds.'
    });
  }

  res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// POST /api/v1/test-ratelimit/vulnerable/login -> mock unlimited login endpoint
router.post('/vulnerable/login', (req, res) => {
  trackRequest(req, '/vulnerable/login');

  // Vulnerable: no rate limit status or headers returned; returns 401 endlessly
  res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

// GET /api/v1/test-ratelimit/low-risk/data -> mock unlimited low-risk endpoint
router.get('/low-risk/data', (req, res) => {
  trackRequest(req, '/low-risk/data');

  // Safe/Low-risk: public non-sensitive config data, rate limiting not expected
  res.json({
    success: true,
    version: '1.0.0',
    publicSetting: 'allowed'
  });
});

module.exports = router;
