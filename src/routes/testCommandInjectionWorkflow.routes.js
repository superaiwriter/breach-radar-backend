const express = require('express');
const router = express.Router();

// GET /api/test-command-injection/secure
router.get('/secure', (req, res) => {
  const host = req.query.host || '';

  // Strict input validation: must be a valid hostname or IP address
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9.\-]+$/;

  // Check for command injection characters
  if (/[;&|`$]/g.test(host) || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({
      success: false,
      error: 'Invalid host target. Only valid IP addresses or hostnames are allowed.'
    });
  }

  res.send(`PING ${host} (${host}): 56 data bytes\n64 bytes from ${host}: icmp_seq=0 ttl=64 time=0.04 ms`);
});

// GET /api/test-command-injection/vulnerable
router.get('/vulnerable', (req, res) => {
  const host = req.query.host || '';

  // Vulnerable logic: simulates shell command execution (e.g. system("ping " + host))
  // If the host target contains separators and an echo command, extract the marker and output it
  if (/[;&|`$]/g.test(host)) {
    // Extract the marker using regex
    const match = host.match(/echo\s+([A-Za-z0-9_]+)/);
    if (match && match[1]) {
      const marker = match[1];
      return res.send(`PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.03 ms\nCommand execution output:\n${marker}`);
    }
  }

  // If normal input, return regular ping output
  if (/^[a-zA-Z0-9.\-]+$/.test(host)) {
    return res.send(`PING ${host} (${host}): 56 data bytes\n64 bytes from ${host}: icmp_seq=0 ttl=64 time=0.04 ms`);
  }

  // Reflection-like fallback but it's part of ping failure error
  res.status(400).send(`ping: unknown host ${host}`);
});

// GET /api/test-command-injection/reflection
router.get('/reflection', (req, res) => {
  const host = req.query.host || '';
  // Simply reflects the input string directly
  res.send(`Target diagnostics console: host=${host}`);
});

// GET /api/test-command-injection/fake-200
router.get('/fake-200', (req, res) => {
  res.status(200).send('<html><body><h1>Network Tools Console</h1><p>Status: Active</p></body></html>');
});

module.exports = router;
