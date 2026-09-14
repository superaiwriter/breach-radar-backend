const express = require('express');
const router = express.Router();

// GET /api/test-open-redirect/vulnerable -> Performs an unvalidated server-side redirect to input parameter url
router.get('/vulnerable', (req, res) => {
  const targetUrl = req.query.url || '/dashboard';
  
  // Unvalidated redirect
  return res.redirect(targetUrl);
});

// GET /api/test-open-redirect/secure -> Rejects external redirects or normalizes them to /dashboard
router.get('/secure', (req, res) => {
  const targetUrl = req.query.url || '/dashboard';

  // Strict check: if it points to an external host, redirect to safe internal /dashboard
  const isExternal = targetUrl.startsWith('http://') || 
                     targetUrl.startsWith('https://') || 
                     targetUrl.startsWith('//') || 
                     targetUrl.startsWith('\\\\');

  if (isExternal) {
    return res.redirect('/dashboard');
  }

  return res.redirect(targetUrl);
});

// GET /api/test-open-redirect/internal -> Only accepts safe relative paths
router.get('/internal', (req, res) => {
  const targetUrl = req.query.url || '/dashboard';

  // Relative path validation: must start with / and not lead to protocol-relative domains
  const isSafeRelative = targetUrl.startsWith('/') && 
                        !targetUrl.startsWith('//') && 
                        !targetUrl.startsWith('/\\') &&
                        !targetUrl.startsWith('\\\\');

  if (isSafeRelative) {
    return res.redirect(targetUrl);
  }

  return res.redirect('/dashboard');
});

// GET /api/test-open-redirect/fake-200 -> Always returns HTTP 200 with normal body HTML containing target URL
router.get('/fake-200', (req, res) => {
  const targetUrl = req.query.url || '';
  res.status(200).send(`<html><body><h1>Redirection Console</h1><p>Processed destination: ${targetUrl}</p><a href="${targetUrl}">Click here to manually continue</a></body></html>`);
});

module.exports = router;
