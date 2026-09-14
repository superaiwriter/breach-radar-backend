const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const net = require('net');

// Helper to perform safe fetch (no crashes on network errors/timeouts)
function performFetch(targetUrlStr, res) {
  try {
    const url = new URL(targetUrlStr);
    
    // Only support http and https
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return res.status(400).send('Invalid protocol. Only HTTP/HTTPS are supported.');
    }

    const client = url.protocol === 'https:' ? https : http;
    const reqOptions = {
      timeout: 3000
    };

    const clientReq = client.get(url, reqOptions, (clientRes) => {
      let body = '';
      clientRes.on('data', (chunk) => {
        body += chunk;
        if (body.length > 50000) { // Limit response size to prevent resource exhaustion
          clientReq.destroy();
        }
      });
      clientRes.on('end', () => {
        res.status(clientRes.statusCode).send(body);
      });
    });

    clientReq.on('timeout', () => {
      clientReq.destroy();
      res.status(504).send('Gateway Timeout');
    });

    clientReq.on('error', (err) => {
      res.status(502).send(`Bad Gateway: ${err.message}`);
    });

  } catch (err) {
    res.status(400).send(`Invalid URL format: ${err.message}`);
  }
}

// 1. GET /api/test-ssrf/vulnerable -> Accepts URL, fetches it
router.get('/vulnerable', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).send('Missing "url" parameter');
  }
  performFetch(targetUrl, res);
});

// 2. GET /api/test-ssrf/secure -> Only allows explicitly approved external domain whitelist
router.get('/secure', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).send('Missing "url" parameter');
  }

  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname.toLowerCase();
    
    // Whitelist only allows example.com or example.invalid
    const whitelist = ['example.com', 'www.example.com', 'example.invalid'];
    if (!whitelist.includes(hostname)) {
      return res.status(403).send('Forbidden: Destination domain is not in the whitelist.');
    }

    performFetch(targetUrl, res);
  } catch (err) {
    res.status(400).send(`Invalid URL: ${err.message}`);
  }
});

// 3. GET /api/test-ssrf/fake-200 -> Returns HTTP 200 immediately without outbound request
router.get('/fake-200', (req, res) => {
  res.status(200).send('Successfully verified request (No outbound request performed).');
});

// 4. GET /api/test-ssrf/internal-blocked -> Rejects localhost, loopback, private IP ranges
router.get('/internal-blocked', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).send('Missing "url" parameter');
  }

  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname.toLowerCase();

    // Check if hostname resolves or matches localhost / loopback / private IP
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return res.status(403).send('Forbidden: Internal destinations are blocked.');
    }

    if (net.isIP(hostname)) {
      const parts = hostname.split('.').map(Number);
      // 10.0.0.0/8
      if (parts[0] === 10) return res.status(403).send('Forbidden: Internal destination.');
      // 172.16.0.0/12
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return res.status(403).send('Forbidden: Internal destination.');
      // 192.168.0.0/16
      if (parts[0] === 192 && parts[1] === 168) return res.status(403).send('Forbidden: Internal destination.');
      // 127.0.0.0/8
      if (parts[0] === 127) return res.status(403).send('Forbidden: Internal destination.');
    }

    performFetch(targetUrl, res);
  } catch (err) {
    res.status(400).send(`Invalid URL: ${err.message}`);
  }
});

module.exports = router;
