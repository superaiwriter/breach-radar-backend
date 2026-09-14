const express = require('express');
const router = express.Router();

const handleVulnerable = (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <html>
      <head><title>Index of /uploads/</title></head>
      <body>
        <h1>Index of /uploads/</h1>
        <hr>
        <pre>
          <a href="../">../</a>
          <a href="backup.zip">backup.zip</a>             18-Aug-2026 12:00    1024567
          <a href="test.txt">test.txt</a>               18-Aug-2026 12:05        123
        </pre>
        <hr>
      </body>
    </html>
  `);
};

const handleSecure = (req, res) => {
  res.status(403).json({
    success: false,
    error: 'Directory browsing is disabled.'
  });
};

router.get('/vulnerable/uploads', handleVulnerable);
router.get('/vulnerable/uploads/', handleVulnerable);
router.get('/secure/uploads', handleSecure);
router.get('/secure/uploads/', handleSecure);

module.exports = router;
