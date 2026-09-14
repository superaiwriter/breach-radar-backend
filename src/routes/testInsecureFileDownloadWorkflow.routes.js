const express = require('express');
const router = express.Router();

const mockFiles = {
  'TEST_FILE_A': {
    id: 'TEST_FILE_A',
    owner: 'usera@securescan.local',
    name: 'user-a-private.txt',
    content: 'USER_A_PRIVATE_FILE_MARKER',
    isPublic: false
  },
  'TEST_FILE_B': {
    id: 'TEST_FILE_B',
    owner: 'userb@securescan.local',
    name: 'user-b-private.txt',
    content: 'USER_B_PRIVATE_FILE_MARKER',
    isPublic: false
  },
  'PUBLIC_FILE': {
    id: 'PUBLIC_FILE',
    owner: 'admin@securescan.local',
    name: 'public.txt',
    content: 'PUBLIC_FILE_MARKER',
    isPublic: true
  }
};

const getAuthenticatedUser = (req) => {
  const cookie = req.cookies.bola_session || req.cookies.insecure_download_session;
  if (cookie === 'bola_session_usera_secret_token' || cookie === 'insecure_download_session_usera') return 'usera@securescan.local';
  if (cookie === 'bola_session_userb_secret_token' || cookie === 'insecure_download_session_userb') return 'userb@securescan.local';
  if (cookie === 'bola_session_admin_secret_token' || cookie === 'insecure_download_session_admin') return 'admin@securescan.local';
  return null;
};

// GET /secure/:fileId
router.get('/secure/:fileId', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  const file = mockFiles[req.params.fileId];
  if (!file) {
    return res.status(404).json({ success: false, error: 'File not found' });
  }

  // Proper Auth check
  if (!file.isPublic && file.owner !== user) {
    return res.status(403).json({ success: false, error: 'Forbidden' });
  }

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  return res.send(file.content);
});

// GET /vulnerable/:fileId
router.get('/vulnerable/:fileId', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  const file = mockFiles[req.params.fileId];
  if (!file) {
    return res.status(404).json({ success: false, error: 'File not found' });
  }

  // Vulnerable: no authorization checks!
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  return res.send(file.content);
});

// GET /fake-200/:fileId
router.get('/fake-200/:fileId', (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  const file = mockFiles[req.params.fileId];
  if (!file) {
    return res.status(404).json({ success: false, error: 'File not found' });
  }

  // Returns HTTP 200 with generic/unrelated HTML content
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send('<html><body><h1>Files Dashboard</h1><p>Status: OK</p></body></html>');
});

module.exports = router;
