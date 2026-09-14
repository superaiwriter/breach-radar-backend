const express = require('express');
const router = express.Router();

router.get('/vulnerable/backup.sql', (req, res) => {
  res.setHeader('Content-Type', 'application/sql');
  res.send(`
    -- Sharma Tech Database Dump
    -- Version 1.0.0
    CREATE TABLE users (
      id INT PRIMARY KEY,
      username VARCHAR(50),
      password VARCHAR(255)
    );
    INSERT INTO users VALUES (1, 'admin', 'super-secret-password-123');
  `);
});

router.get('/secure/backup.sql', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'File not found.'
  });
});

module.exports = router;
