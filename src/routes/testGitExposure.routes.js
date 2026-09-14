const express = require('express');
const router = express.Router();

router.get('/vulnerable/.git/HEAD', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send('ref: refs/heads/main\n');
});

router.get('/secure/.git/HEAD', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'File not found.'
  });
});

module.exports = router;
