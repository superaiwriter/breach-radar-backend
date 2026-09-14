const https = require('https');
const http = require('http');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS } = require('../constants');

const SCANNER_NAME = 'cookie';
const TIMEOUT_MS = 10000;
const COOKIE_CATEGORY = 'Cookie Security';

// Anything beyond this is flagged as a "long session lifetime" cookie.
const LONG_LIFETIME_DAYS = 30;
const VERY_LONG_LIFETIME_DAYS = 365;

function fetchHeaders(urlString) {
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
      { timeout: TIMEOUT_MS, headers: { 'User-Agent': 'SecureScan/1.0' } },
      (response) => {
        response.resume(); // discard body, headers are all we need
        response.on('end', () => resolve({ statusCode: response.statusCode, headers: response.headers, finalUrl: urlString }));
      }
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

// Parses a single raw "Set-Cookie" header string into name + attribute map.
function parseCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const [nameValue, ...attrParts] = parts;
  const eqIndex = nameValue.indexOf('=');
  const name = eqIndex === -1 ? nameValue : nameValue.slice(0, eqIndex);

  const attributes = {};
  attrParts.forEach((attr) => {
    const [key, ...rest] = attr.split('=');
    attributes[key.trim().toLowerCase()] = rest.join('=').trim() || true;
  });

  return { name, raw, attributes };
}

function cookieLifetimeDays(attributes) {
  if (attributes['max-age']) {
    const seconds = Number(attributes['max-age']);
    if (!Number.isNaN(seconds)) return seconds / 86400;
  }
  if (attributes.expires) {
    const expiryDate = new Date(attributes.expires);
    if (!Number.isNaN(expiryDate.getTime())) {
      return (expiryDate.getTime() - Date.now()) / (1000 * 86400);
    }
  }
  return null; // session cookie (expires when browser closes) — no persistent lifetime
}

function buildFinding({ name, desc, severity, cwe, path, impact, fix, evidence, cvssScore = null }) {
  return createFinding({
    scanner: SCANNER_NAME,
    name,
    desc,
    severity,
    cwe,
    path,
    impact,
    fix,
    category: COOKIE_CATEGORY,
    subCategory: name,
    cvssScore,
    evidence,
    references: ['https://owasp.org/www-community/controls/SecureCookieAttribute', 'https://owasp.org/www-community/HttpOnly']
  });
}

function analyzeCookie(cookie, baseUrl) {
  const findings = [];
  const { name, raw, attributes } = cookie;
  const looksSensitive = /session|token|sid|auth|jwt|login/i.test(name);

  // 1. Missing HttpOnly
  if (!('httponly' in attributes)) {
    findings.push(
      buildFinding({
        name: 'Missing HttpOnly',
        desc: `The "${name}" cookie does not set the HttpOnly flag.`,
        severity: looksSensitive ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.LOW,
        cwe: 'CWE-1004',
        path: baseUrl,
        impact: 'Cookies without HttpOnly can be read by client-side JavaScript, making them stealable via XSS.',
        fix: 'Add the HttpOnly attribute to prevent client-side script access to the cookie.',
        evidence: `Set-Cookie: ${raw}`,
        cvssScore: looksSensitive ? 7.4 : 3.1
      })
    );
  }

  // 2. Missing Secure
  if (!('secure' in attributes)) {
    findings.push(
      buildFinding({
        name: 'Missing Secure',
        desc: `The "${name}" cookie does not set the Secure flag.`,
        severity: looksSensitive ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-614',
        path: baseUrl,
        impact: 'Cookies without Secure can be transmitted over plain HTTP, exposing them to network interception.',
        fix: 'Add the Secure attribute so the cookie is only sent over HTTPS.',
        evidence: `Set-Cookie: ${raw}`,
        cvssScore: looksSensitive ? 7.5 : 5.3
      })
    );
  }

  // 3. Missing SameSite
  if (!('samesite' in attributes)) {
    findings.push(
      buildFinding({
        name: 'Missing SameSite',
        desc: `The "${name}" cookie does not set the SameSite attribute.`,
        severity: SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-352',
        path: baseUrl,
        impact: 'Without SameSite, the cookie may be sent on cross-site requests, increasing CSRF risk.',
        fix: 'Set SameSite=Strict or SameSite=Lax (use SameSite=None only with Secure, for legitimate cross-site use).',
        evidence: `Set-Cookie: ${raw}`,
        cvssScore: 5.4
      })
    );
  }

  // 4. Weak cookie flags — invalid/risky attribute combinations.
  const sameSiteValue = typeof attributes.samesite === 'string' ? attributes.samesite.toLowerCase() : null;
  if (sameSiteValue === 'none' && !('secure' in attributes)) {
    findings.push(
      buildFinding({
        name: 'Weak Cookie Flags',
        desc: `The "${name}" cookie sets SameSite=None without the Secure flag.`,
        severity: SEVERITY_LEVELS.HIGH,
        cwe: 'CWE-1275',
        path: baseUrl,
        impact: 'SameSite=None without Secure is rejected by modern browsers or, where accepted, offers no cross-site protection at all.',
        fix: 'Always pair SameSite=None with the Secure attribute, or use Strict/Lax instead.',
        evidence: `Set-Cookie: ${raw}`,
        cvssScore: 6.5
      })
    );
  }
  if (typeof attributes.domain === 'string' && attributes.domain.startsWith('.')) {
    findings.push(
      buildFinding({
        name: 'Weak Cookie Flags',
        desc: `The "${name}" cookie is scoped to all subdomains via Domain=${attributes.domain}.`,
        severity: SEVERITY_LEVELS.LOW,
        cwe: 'CWE-1275',
        path: baseUrl,
        impact: 'An overly broad Domain attribute exposes the cookie to every subdomain, widening the impact of a compromise on any one of them.',
        fix: 'Scope the cookie to the exact host that needs it rather than the whole domain, unless cross-subdomain sharing is required.',
        evidence: `Set-Cookie: ${raw}`,
        cvssScore: 3.7
      })
    );
  }

  // 5. Long session lifetime
  const lifetimeDays = cookieLifetimeDays(attributes);
  if (lifetimeDays !== null && looksSensitive && lifetimeDays > LONG_LIFETIME_DAYS) {
    findings.push(
      buildFinding({
        name: 'Long Session Lifetime',
        desc: `The "${name}" cookie persists for approximately ${Math.round(lifetimeDays)} days.`,
        severity: lifetimeDays > VERY_LONG_LIFETIME_DAYS ? SEVERITY_LEVELS.MEDIUM : SEVERITY_LEVELS.LOW,
        cwe: 'CWE-613',
        path: baseUrl,
        impact: 'Long-lived session cookies increase the window during which a stolen cookie remains usable by an attacker.',
        fix: 'Shorten session cookie lifetime (hours to a few days) and rely on refresh tokens or re-authentication for longer sessions.',
        evidence: `Set-Cookie: ${raw} (≈ ${Math.round(lifetimeDays)} days)`,
        cvssScore: lifetimeDays > VERY_LONG_LIFETIME_DAYS ? 4.3 : 2.6
      })
    );
  }

  return findings;
}

async function scanCookies(domain) {
  const findings = [];
  const baseUrl = `https://${domain}`;
  const metadata = { domain, cookiesFound: 0 };

  let response;
  try {
    response = await withTimeout(fetchHeaders(baseUrl), TIMEOUT_MS, 'Cookie scan');
  } catch (error) {
    return createResult(SCANNER_NAME, [], { domain, error: error.message }, false);
  }

  const setCookieHeaders = response.headers['set-cookie'] || [];
  metadata.cookiesFound = setCookieHeaders.length;

  if (setCookieHeaders.length === 0) {
    return createResult(SCANNER_NAME, [], metadata, true); // no cookies issued — nothing to flag
  }

  setCookieHeaders.forEach((raw) => {
    const cookie = parseCookie(raw);
    findings.push(...analyzeCookie(cookie, baseUrl));
  });

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanCookies
};