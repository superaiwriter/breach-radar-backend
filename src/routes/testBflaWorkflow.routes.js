const express = require('express');
const router = express.Router();

// Mock administrative user list
const adminUsers = [
  { id: 1, email: 'admin@securescan.local', role: 'admin' },
  { id: 2, email: 'user@pentestradar.com', role: 'user' },
  { id: 3, email: 'usera@securescan.local', role: 'user' },
  { id: 4, email: 'userb@securescan.local', role: 'user' }
];

// GET /api/v1/test-bfla/login-page -> serves HTML form for login form detection
router.get('/login-page', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <html>
      <body>
        <h2>PenTestRadar BFLA Test Login</h2>
        <form action="/api/v1/test-bfla/login" method="POST">
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

// POST /api/v1/test-bfla/login -> handles credentials and sets session cookie
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (password !== 'Password123!') {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  let cookieVal = '';
  if (username === 'admin@securescan.local') {
    cookieVal = 'bfla_session_admin_secret_token';
  } else if (username === 'usera@securescan.local') {
    cookieVal = 'bfla_session_usera_secret_token';
  } else if (username === 'userb@securescan.local') {
    cookieVal = 'bfla_session_userb_secret_token';
  } else {
    cookieVal = 'bfla_session_user_secret_token'; // default test user
  }

  // Set the bfla_session cookie
  res.cookie('bfla_session', cookieVal, { httpOnly: true, path: '/' });
  res.json({ success: true, message: 'Logged in successfully', user: username });
});

// Helper to determine logged-in user from session cookies
const getAuthenticatedUserRole = (req) => {
  const cookie = req.cookies.bfla_session || req.cookies.bola_session;
  if (cookie === 'bfla_session_admin_secret_token' || cookie === 'bola_session_admin_secret_token') return 'admin';
  if (cookie === 'bfla_session_usera_secret_token' || cookie === 'bola_session_usera_secret_token' ||
      cookie === 'bfla_session_userb_secret_token' || cookie === 'bola_session_userb_secret_token' ||
      cookie === 'bfla_session_user_secret_token' || cookie === 'bola_session_user_secret_token') {
    return 'user';
  }
  return null;
};

// =========================================================================
// VULNERABLE ENDPOINTS (Broken Function Level Authorization)
// =========================================================================

// GET /api/v1/test-bfla/vulnerable/admin/users
router.get('/vulnerable/admin/users', (req, res) => {
  const role = getAuthenticatedUserRole(req);
  if (!role) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // Vulnerable: Returns administrative users list to ANY authenticated role without checking if role === 'admin'
  res.json({
    success: true,
    users: adminUsers,
    disclosureMsg: 'Protected Admin Users List Exposed'
  });
});

// =========================================================================
// SECURE ENDPOINTS (Proper Function Level Authorization Checks)
// =========================================================================

// GET /api/v1/test-bfla/secure/admin/users
router.get('/secure/admin/users', (req, res) => {
  const role = getAuthenticatedUserRole(req);
  if (!role) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // Secure: verifies that the authenticated user has 'admin' privilege
  if (role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: 'Access denied. Administrator privileges required.'
    });
  }

  res.json({
    success: true,
    users: adminUsers
  });
});

module.exports = router;
