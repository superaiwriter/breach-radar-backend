const express = require('express');
const router = express.Router();

// GET /api/test-xss/secure -> Strips tags and special characters from parameter q
router.get('/secure', (req, res) => {
  const q = req.query.q || '';
  
  // Safe logic: strip out tags, event handlers, and quotes
  const clean = q.replace(/[<>"'/]/g, '');
  res.send(`<html><body><div>Clean search query: ${clean}</div></body></html>`);
});

// GET /api/test-xss/vulnerable -> Vulnerable reflected XSS (verbatim reflection in text/html context)
router.get('/vulnerable', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body><div>Search results for: ${q}</div></body></html>`);
});

// GET /api/test-xss/reflection -> Reflects the input verbatim under text/plain content-type (safe)
router.get('/reflection', (req, res) => {
  const q = req.query.q || '';
  res.set('Content-Type', 'text/plain');
  res.send(`Search queries recorded: ${q}`);
});

// GET /api/test-xss/encoded -> HTML-encodes the input before rendering (safe)
router.get('/encoded', (req, res) => {
  const q = req.query.q || '';
  const encoded = q.replace(/&/g, '&amp;')
                   .replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;')
                   .replace(/"/g, '&quot;')
                   .replace(/'/g, '&#x27;')
                   .replace(/\//g, '&#x2F;');
  res.send(`<html><body><div>Search results: ${encoded}</div></body></html>`);
});

// GET /api/test-xss/fake-200 -> Returns HTTP 200 with a static HTML console page (safe)
router.get('/fake-200', (req, res) => {
  res.status(200).send('<html><body><h1>Search System Operational</h1><p>Status: OK</p></body></html>');
});

module.exports = router;
