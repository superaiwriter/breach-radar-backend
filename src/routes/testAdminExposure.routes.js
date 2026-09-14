const express = require('express');
const router = express.Router();

// GET /api/v1/test-admin-exposure/vulnerable/dashboard -> exposed admin console without authentication
router.get('/vulnerable/dashboard', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <html>
      <head>
        <title>Sharma Tech Admin Console Dashboard</title>
      </head>
      <body>
        <h1>Administrative Console</h1>
        <div id="admin-panel">
          <h3>System Metrics</h3>
          <p>Database Status: Connected</p>
          <button onclick="alert('Shutdown triggered!')">Shutdown Server</button>
        </div>
      </body>
    </html>
  `);
});

// GET /api/v1/test-admin-exposure/vulnerable/jenkins -> exposed admin login page
router.get('/vulnerable/jenkins', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <html>
      <head>
        <title>Jenkins Console [Jenkins]</title>
      </head>
      <body>
        <h2>Jenkins Login</h2>
        <form action="/login" method="POST">
          <input type="text" name="j_username" placeholder="Username" />
          <input type="password" name="j_password" placeholder="Password" />
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
  `);
});

// GET /api/v1/test-admin-exposure/secure/dashboard -> secure restricted console returning 403
router.get('/secure/dashboard', (req, res) => {
  res.status(403).json({
    success: false,
    error: 'Access denied. Management console requires VPN IP restriction.'
  });
});

module.exports = router;
