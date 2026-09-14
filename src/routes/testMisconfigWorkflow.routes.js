const express = require('express');
const router = express.Router();

// =========================================================================
// DIRECTORY LISTING ENDPOINTS
// =========================================================================

// GET /api/v1/test-misconfig/vulnerable/uploads -> Directory listing enabled
router.get('/vulnerable/uploads', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html>
  <head>
    <title>Index of /uploads</title>
  </head>
  <body>
    <h1>Index of /uploads</h1>
    <ul>
      <li><a href="../">Parent Directory</a></li>
      <li><a href="backup-db.sql">backup-db.sql</a></li>
      <li><a href="avatar.png">avatar.png</a></li>
    </ul>
  </body>
</html>`);
});

// GET /api/v1/test-misconfig/secure/uploads -> Directory listing disabled/restricted
router.get('/secure/uploads', (req, res) => {
  res.status(403).json({
    success: false,
    error: 'Access denied. Directory browsing is disabled on this server.'
  });
});

// =========================================================================
// VERBOSE ERROR ENDPOINTS
// =========================================================================

// GET /api/v1/test-misconfig/vulnerable/error -> Returns node stack trace
router.get('/vulnerable/error', (req, res) => {
  res.status(500).json({
    success: false,
    error: "TypeError: Cannot read properties of undefined (reading 'split')\n    at Object.run (e:\\REACT\\backend\\src\\routes\\testMisconfigWorkflow.routes.js:31:18)\n    at Layer.handle [as handle_request] (e:\\REACT\\backend\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at next (e:\\REACT\\backend\\node_modules\\express\\lib\\router\\route.js:144:13)"
  });
});

// GET /api/v1/test-misconfig/secure/error -> Returns generic safe error
router.get('/secure/error', (req, res) => {
  res.status(500).json({
    success: false,
    error: 'Internal Server Error'
  });
});

// =========================================================================
// DANGEROUS HTTP METHOD ENDPOINTS
// =========================================================================

// ALL /api/v1/test-misconfig/vulnerable/trace -> supports dangerous TRACE method
router.all('/vulnerable/trace', (req, res) => {
  if (req.method === 'TRACE') {
    res.setHeader('Content-Type', 'message/http');
    // Echo back the request headers in TRACE response body
    let echo = 'TRACE /api/v1/test-misconfig/vulnerable/trace HTTP/1.1\r\n';
    for (const [key, value] of Object.entries(req.headers)) {
      echo += `${key}: ${value}\r\n`;
    }
    echo += '\r\n';
    return res.send(echo);
  }

  res.json({
    success: true,
    message: 'Standard endpoint request accepted.'
  });
});

// ALL /api/v1/test-misconfig/secure/trace -> rejects dangerous TRACE method
router.all('/secure/trace', (req, res) => {
  if (req.method === 'TRACE') {
    return res.status(405).send('Method Not Allowed');
  }

  res.json({
    success: true,
    message: 'Standard endpoint request accepted.'
  });
});

module.exports = router;
