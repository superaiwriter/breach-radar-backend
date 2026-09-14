const express = require('express');
const router = express.Router();

// Mock resources database
const resources = {
  101: { id: 101, owner: 'usera@securescan.local', data: 'Private User A Document (Sensitive Business Info)' },
  102: { id: 102, owner: 'userb@securescan.local', data: 'Private User B Document (Sensitive Business Info)' }
};

// GET /api/v1/test-bola/login-page -> serves simple HTML form for login form detection
router.get('/login-page', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <html>
      <body>
        <h2>PenTestRadar BOLA Test Login</h2>
        <form action="/api/v1/test-bola/login" method="POST">
          <div>
            <label>Username/Email:</label>
            <input type="text" name="username" id="username" />
          </div>
          <div>
            <label>Password:</label>
            <input type="password" name="password" id="password" />
          </div>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

// POST /api/v1/test-bola/login -> handles credentials and sets session cookie
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (password !== 'Password123!') {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  let cookieVal = '';
  if (username === 'usera@securescan.local') {
    cookieVal = 'bola_session_usera_secret_token';
  } else if (username === 'userb@securescan.local') {
    cookieVal = 'bola_session_userb_secret_token';
  } else {
    return res.status(401).json({ success: false, error: 'User not found' });
  }

  // Set the bola_session cookie
  res.cookie('bola_session', cookieVal, { httpOnly: true, path: '/' });
  res.json({ success: true, message: 'Logged in successfully', user: username });
});

// Helper to determine logged-in user from session cookies
const getAuthenticatedUser = (req) => {
  const cookie = req.cookies.bola_session || req.cookies.bfla_session;
  if (cookie === 'bola_session_usera_secret_token' || cookie === 'bfla_session_usera_secret_token') return 'usera@securescan.local';
  if (cookie === 'bola_session_userb_secret_token' || cookie === 'bfla_session_userb_secret_token') return 'userb@securescan.local';
  if (cookie === 'bola_session_admin_secret_token' || cookie === 'bfla_session_admin_secret_token') return 'admin@securescan.local';
  return null;
};

// =========================================================================
// VULNERABLE ENDPOINTS (Broken Object Level Authorization)
// =========================================================================

// GET /api/v1/test-bola/vulnerable/resources/:id
router.get('/vulnerable/resources/:id', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  const id = parseInt(req.params.id, 10);
  const resource = resources[id];

  if (!resource) {
    return res.status(404).json({ success: false, error: 'Resource not found' });
  }

  // Vulnerable: Returns resource details to ANY authenticated user without verifying ownership
  res.json({
    success: true,
    resourceId: resource.id,
    owner: resource.owner,
    data: resource.data,
    disclosureMsg: 'Protected Resource Data Exposed Successfully'
  });
});

// =========================================================================
// SECURE ENDPOINTS (Proper Object Level Authorization Checks)
// =========================================================================

// GET /api/v1/test-bola/secure/resources/:id
router.get('/secure/resources/:id', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  const id = parseInt(req.params.id, 10);
  const resource = resources[id];

  if (!resource) {
    return res.status(404).json({ success: false, error: 'Resource not found' });
  }

  // Secure: verifies that the authenticated user owns the resource
  if (resource.owner !== user) {
    return res.status(403).json({
      success: false,
      error: 'Access denied. You do not have permission to view this resource.'
    });
  }

  res.json({
    success: true,
    resourceId: resource.id,
    owner: resource.owner,
    data: resource.data
  });
});

module.exports = router;
