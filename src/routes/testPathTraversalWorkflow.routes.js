const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Safe uploads directory in the backend root
const safeDir = path.join(__dirname, '../../uploads');

// GET /api/test-files/secure -> Sanitizes and rejects traversal
router.get('/secure', (req, res) => {
  const file = req.query.file || 'example.txt';
  
  // Resolve absolute path
  const resolvedPath = path.resolve(safeDir, file);
  
  // Verify that the resolved path is inside safeDir
  if (!resolvedPath.startsWith(safeDir)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied: Directory traversal attempt detected'
    });
  }

  if (file === 'example.txt') {
    return res.send('This is example.txt safe content');
  }

  try {
    if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
      const content = fs.readFileSync(resolvedPath, 'utf8');
      return res.send(content);
    }
    res.status(404).send('File not found');
  } catch (err) {
    res.status(500).send('Error reading file');
  }
});

// GET /api/test-files/vulnerable -> Vulnerable to traversal
router.get('/vulnerable', (req, res) => {
  const file = req.query.file || '';
  if (!file) {
    return res.status(400).send('File parameter missing');
  }

  // Vulnerable logic: joins path raw without validating the directory boundary
  const resolvedPath = path.join(safeDir, file);

  try {
    if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
      const content = fs.readFileSync(resolvedPath, 'utf8');
      return res.send(content);
    }
    res.status(404).send('File not found');
  } catch (err) {
    res.status(500).send('Error reading file');
  }
});

// GET /api/test-files/fake-200 -> Returns HTTP 200 but generic page
router.get('/fake-200', (req, res) => {
  res.status(200).send('<html><body><h1>Files Dashboard</h1><p>Operation successful. No file requested.</p></body></html>');
});

module.exports = router;
