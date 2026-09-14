const express = require('express');
const router = express.Router();

// In-memory user profiles database, keyed by session cookie value
const profilesDb = {};

// Helper to initialize or retrieve a profile for a session
const getProfile = (cookieVal) => {
  const key = cookieVal || 'default_anonymous_session';
  if (!profilesDb[key]) {
    profilesDb[key] = {
      name: 'Sharma Tech Developer',
      bio: 'Security researcher',
      role: 'user',
      isAdmin: false
    };
  }
  return profilesDb[key];
};

// Helper to determine session cookie
const getSessionCookie = (req) => {
  return req.cookies.bola_session || req.cookies.bfla_session || 'default_anonymous_session';
};

// =========================================================================
// SECURE ENDPOINTS (Proper Input Sanitization & Explicit Field Mapping)
// =========================================================================

// GET /api/v1/test-mass-assignment/secure/profile
router.get('/secure/profile', (req, res) => {
  const cookie = getSessionCookie(req);
  const profile = getProfile(cookie);
  res.json({
    success: true,
    ...profile
  });
});

// PATCH /api/v1/test-mass-assignment/secure/profile
router.patch('/secure/profile', (req, res) => {
  const cookie = getSessionCookie(req);
  const profile = getProfile(cookie);

  const { name, bio } = req.body;

  // Secure: explicitly maps only allowed fields
  if (name !== undefined) profile.name = name;
  if (bio !== undefined) profile.bio = bio;

  // Any other properties in req.body (e.g. role, isAdmin) are safely ignored.
  res.json({
    success: true,
    message: 'Profile updated successfully (secure)',
    profile
  });
});

// =========================================================================
// VULNERABLE ENDPOINTS (Blind Request-to-Model Mapping / Mass Assignment)
// =========================================================================

// GET /api/v1/test-mass-assignment/vulnerable/profile
router.get('/vulnerable/profile', (req, res) => {
  const cookie = getSessionCookie(req);
  const profile = getProfile(cookie);
  res.json({
    success: true,
    ...profile
  });
});

// PATCH /api/v1/test-mass-assignment/vulnerable/profile
router.patch('/vulnerable/profile', (req, res) => {
  const cookie = getSessionCookie(req);
  const profile = getProfile(cookie);

  // Vulnerable: blindly copies all properties from body directly to the profile object
  Object.assign(profile, req.body);

  res.json({
    success: true,
    message: 'Profile updated successfully (vulnerable)',
    profile
  });
});

module.exports = router;
