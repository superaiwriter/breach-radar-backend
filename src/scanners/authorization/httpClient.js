const https = require('https');
const http = require('http');

const DEFAULT_TIMEOUT_MS = 10000;

// GET-only, non-destructive by design (Authorization checks must never POST/PUT/DELETE).
// Redirects are intentionally NOT auto-followed — a 30x to a login page is itself
// evidence that the endpoint is protected, so the caller inspects it directly
// rather than this client silently chasing it and hiding that signal.
function fetchRaw(urlString, { timeoutMs = DEFAULT_TIMEOUT_MS, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (error) {
      reject(error);
      return;
    }

    const client = url.protocol === 'https:' ? https : http;
    const request = client.get(
      url,
      {
        timeout: timeoutMs,
        headers: { 'User-Agent': 'SecureScan/1.0 (+authorization-scanner)', ...headers }
      },
      (response) => {
        let body = '';
        response.on('data', (chunk) => {
          body += chunk;
          if (body.length > 500000) response.destroy(); // cap read size
        });
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode,
            headers: response.headers,
            body
          });
        });
      }
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

module.exports = { fetchRaw };