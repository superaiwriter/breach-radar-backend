const express = require('express');
const router = express.Router();

// Raw body parser middleware for XML
router.use((req, res, next) => {
  let data = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => {
    data += chunk;
  });
  req.on('end', () => {
    req.rawBody = data;
    next();
  });
});

// POST /api/test-xxe/secure -> Safely parses XML without resolving external entities
router.post('/secure', (req, res) => {
  const xml = req.rawBody || '';

  // Safe parsing: rejects entity declarations or resolves them to empty string
  // Here we return the parsed XML without resolving &xxe; entity to the marker
  let result = xml.replace(/&[A-Za-z0-9_]+;/g, '');
  // Strip out DOCTYPE definition for clean output
  result = result.replace(/<!DOCTYPE[^>]*>/gi, '');

  res.set('Content-Type', 'application/xml');
  res.send(`<result>${result.trim()}</result>`);
});

// POST /api/test-xxe/vulnerable -> Simulates external entity resolution returning the marker
router.post('/vulnerable', (req, res) => {
  const xml = req.rawBody || '';

  // Vulnerable logic: check if an external entity SYSTEM declaration is present
  // and resolve it to PENTESTRADAR_XXE_MARKER
  let resolved = xml;
  if (xml.includes('<!ENTITY') && xml.includes('SYSTEM')) {
    // Replace entity reference &xxe; or any entity reference with the marker
    resolved = xml.replace(/&[A-Za-z0-9_]+;/g, 'PENTESTRADAR_XXE_MARKER');
  }

  // Strip DOCTYPE definition to simulate successful entity resolution in final render
  resolved = resolved.replace(/<!DOCTYPE[^>]*>/gi, '').replace(/<\?xml[^>]*\?>/gi, '');

  res.set('Content-Type', 'application/xml');
  res.send(`<result>${resolved.trim()}</result>`);
});

// POST /api/test-xxe/reflection -> Directly reflects XML request payload unchanged
router.post('/reflection', (req, res) => {
  const xml = req.rawBody || '';
  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

// POST /api/test-xxe/fake-200 -> Always returns HTTP 200 with normal console output
router.post('/fake-200', (req, res) => {
  res.status(200).send('<html><body><h1>XML Import Console</h1><p>Status: Operational. No document received.</p></body></html>');
});

module.exports = router;
