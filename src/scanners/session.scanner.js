const https = require('https');
const http = require('http');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY } = require('../constants');

const SCANNER_NAME = 'session';
const TIMEOUT_MS = 10000;

function fetchHeaders(urlString) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return reject(e);
    }
    const client = url.protocol === 'https:' ? https : http;
    const req = client.get(
      url,
      { timeout: TIMEOUT_MS, headers: { 'User-Agent': 'SecureScan/1.0' } },
      (res) => {
        res.resume(); // discard body, headers are all we need
        resolve({ statusCode: res.statusCode, headers: res.headers });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.on('error', reject);
  });
}

function parseCookie(cookieStr) {
  const parts = cookieStr.split(';').map((p) => p.trim());
  const [nameValue, ...attrParts] = parts;
  const eqIdx = nameValue.indexOf('=');
  const name = eqIdx === -1 ? nameValue : nameValue.substring(0, eqIdx);
  const value = eqIdx === -1 ? '' : nameValue.substring(eqIdx + 1);

  const attributes = {};
  attrParts.forEach((attr) => {
    const [key, ...valParts] = attr.split('=');
    attributes[key.trim().toLowerCase()] = valParts.join('=').trim() || true;
  });

  return { name, value, attributes };
}

async function scanSession(domain, authContext = null) {
  const baseUrl = `https://${domain}`;
  const findings = [];
  const metadata = { domain, cookiesInspected: 0 };

  try {
    const cookies = [];

    // Probe base URL for set-cookies
    try {
      const res = await withTimeout(fetchHeaders(baseUrl), TIMEOUT_MS, 'Session probe request');
      const setCookies = res.headers['set-cookie'] || [];
      const cookieHeaders = Array.isArray(setCookies) ? setCookies : [setCookies];
      cookieHeaders.forEach((c) => {
        if (c) cookies.push(parseCookie(c));
      });
    } catch (err) {
      // Continue if network fails, we will still check authContext cookies
    }

    // Extract cookies from authContext
    if (authContext && authContext.cookieJar) {
      authContext.cookieJar.split(';').forEach((c) => {
        if (c.trim()) {
          cookies.push(parseCookie(c));
        }
      });
    }

    metadata.cookiesInspected = cookies.length;

    const sessionCookieNames = /session|sid|token|jwt|auth|phpsessid|jsessionid|connect\.sid/i;

    cookies.forEach((cookie) => {
      const isSession = sessionCookieNames.test(cookie.name);
      if (!isSession) return;

      const attrs = cookie.attributes;

      // 1. Missing HttpOnly flag
      if (!('httponly' in attrs)) {
        findings.push(
          createFinding({
            name: 'Session Cookie Missing HttpOnly Flag',
            desc: `The session cookie "${cookie.name}" is missing the HttpOnly attribute.`,
            severity: SEVERITY_LEVELS.HIGH,
            cwe: 'CWE-1004',
            path: '/',
            impact: 'Cross-Site Scripting (XSS) attacks can be used by an attacker to steal the session cookie.',
            fix: 'Set the HttpOnly attribute on session cookies.',
            scanner: SCANNER_NAME,
            category: AUTH_SECURITY_CATEGORY,
            subCategory: 'Session Hijacking',
            cvssScore: 7.5,
            evidence: `Cookie: ${cookie.name}`
          })
        );
      }

      // 2. Missing Secure flag
      if (!('secure' in attrs)) {
        findings.push(
          createFinding({
            name: 'Session Cookie Missing Secure Flag',
            desc: `The session cookie "${cookie.name}" is missing the Secure attribute.`,
            severity: SEVERITY_LEVELS.HIGH,
            cwe: 'CWE-614',
            path: '/',
            impact: 'The session cookie can be transmitted over unencrypted HTTP channels, exposing it to interception.',
            fix: 'Set the Secure attribute on session cookies.',
            scanner: SCANNER_NAME,
            category: AUTH_SECURITY_CATEGORY,
            subCategory: 'Session Hijacking',
            cvssScore: 7.5,
            evidence: `Cookie: ${cookie.name}`
          })
        );
      }

      // 3. SameSite check
      const samesite = attrs.samesite;
      if (!samesite || samesite.toLowerCase() === 'none') {
        findings.push(
          createFinding({
            name: 'Session Cookie Missing SameSite Protection',
            desc: `The session cookie "${cookie.name}" has SameSite attribute unset or set to None.`,
            severity: SEVERITY_LEVELS.MEDIUM,
            cwe: 'CWE-1275',
            path: '/',
            impact: 'Allows Cross-Site Request Forgery (CSRF) attacks using session credentials.',
            fix: 'Set SameSite attribute to Lax or Strict on session cookies.',
            scanner: SCANNER_NAME,
            category: AUTH_SECURITY_CATEGORY,
            subCategory: 'Session Fixation',
            cvssScore: 5.3,
            evidence: `SameSite value: ${samesite || 'unset'}`
          })
        );
      }
    });

  } catch (err) {
    return createResult(SCANNER_NAME, [], { domain, error: err.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanSession
};