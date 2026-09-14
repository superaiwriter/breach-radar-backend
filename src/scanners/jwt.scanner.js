const https = require('https');
const http = require('http');
const jwt = require('jsonwebtoken');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY } = require('../constants');

const SCANNER_NAME = 'jwt';
const TIMEOUT_MS = 10000;
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g;

// RFC 7518 registered "alg" values. Anything outside this set (besides
// "none", handled as its own critical check) is flagged as non-standard/weak.
const RECOGNIZED_STRONG_ALGS = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512'
];

function fetchPage(urlString) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (error) {
      reject(error);
      return;
    }

    const client = url.protocol === 'https:' ? https : http;
    const request = client.get(url, { timeout: TIMEOUT_MS, headers: { 'User-Agent': 'SecureScan/1.0' } }, (response) => {
      let body = '';
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 500000) response.destroy();
      });
      response.on('end', () => resolve({ statusCode: response.statusCode, headers: response.headers, body, finalUrl: urlString }));
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

// Collects every unique JWT-shaped string across all passively observable
// sources, tagging where each one was found (for evidence).
function collectJwts(response) {
  const found = new Map(); // token -> Set of source labels

  const addFrom = (label, text) => {
    if (!text) return;
    const matches = text.match(JWT_PATTERN);
    if (!matches) return;
    matches.forEach((token) => {
      if (!found.has(token)) found.set(token, new Set());
      found.get(token).add(label);
    });
  };

  // 1. Response headers (covers any reflected Authorization / WWW-Authenticate header)
  Object.entries(response.headers || {}).forEach(([key, value]) => {
    const values = Array.isArray(value) ? value : [value];
    values.forEach((v) => addFrom(`Header: ${key}`, String(v)));
  });

  // 2. Cookies specifically (subset of headers, but labeled distinctly for clarity)
  (response.headers['set-cookie'] || []).forEach((cookie) => addFrom('Cookie', cookie));

  // 3. Response body / inline scripts (covers tokens hardcoded into shipped JS, and
  //    any client code that reads/writes localStorage/sessionStorage with a JWT literal)
  addFrom('Response Body', response.body);

  return found;
}

// Best-effort localStorage/sessionStorage inspection. Only runs if the optional
// "puppeteer" package is installed — this scanner does not require it.
async function collectJwtsFromLocalStorage(baseUrl) {
  let puppeteer;
  try {
    puppeteer = require('puppeteer');
  } catch {
    return { attempted: false, found: new Map() };
  }

  const found = new Map();
  let browser;
  try {
    browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.goto(baseUrl, { waitUntil: 'networkidle2', timeout: TIMEOUT_MS });

    const storageDump = await page.evaluate(() => {
      const dump = {};
      try {
        for (let i = 0; i < localStorage.length; i += 1) {
          const key = localStorage.key(i);
          dump[`localStorage:${key}`] = localStorage.getItem(key);
        }
        for (let i = 0; i < sessionStorage.length; i += 1) {
          const key = sessionStorage.key(i);
          dump[`sessionStorage:${key}`] = sessionStorage.getItem(key);
        }
      } catch {
        // storage may be inaccessible depending on page — ignore
      }
      return dump;
    });

    Object.entries(storageDump).forEach(([label, value]) => {
      const matches = String(value || '').match(JWT_PATTERN);
      if (matches) matches.forEach((token) => {
        if (!found.has(token)) found.set(token, new Set());
        found.get(token).add(label);
      });
    });
  } catch {
    // page failed to load / storage inaccessible — treat as attempted, nothing found
  } finally {
    if (browser) await browser.close().catch(() => {});
  }

  return { attempted: true, found };
}

function buildFinding({ name, subCategory, desc, severity, cwe, path, impact, fix, evidence, cvssScore = null }) {
  return createFinding({
    scanner: SCANNER_NAME,
    name,
    desc,
    severity,
    cwe,
    path,
    impact,
    fix,
    category: AUTH_SECURITY_CATEGORY,
    subCategory,
    cvssScore,
    evidence,
    references: [
      'https://owasp.org/www-project-cheat-sheets/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
      'https://datatracker.ietf.org/doc/html/rfc7519'
    ]
  });
}

// Runs all passive checks against one decoded token and returns any findings.
function analyzeToken(token, sources, baseUrl) {
  const findings = [];
  const sourceLabel = [...sources].join(', ');
  const shortToken = `${token.slice(0, 16)}...${token.slice(-8)}`;

  let decoded;
  try {
    decoded = jwt.decode(token, { complete: true }); // decode ONLY — never verify signature
  } catch {
    return findings;
  }
  if (!decoded || !decoded.header) return findings;

  const { header, payload } = decoded;
  const alg = header.alg;

  // 1. alg:none
  if (alg === 'none') {
    findings.push(
      buildFinding({
        name: 'JWT alg:none',
        subCategory: 'JWT alg:none',
        desc: `A JWT (${sourceLabel}) uses the "none" algorithm, meaning it is completely unsigned.`,
        severity: SEVERITY_LEVELS.CRITICAL,
        cwe: 'CWE-347',
        path: baseUrl,
        impact: 'Anyone can forge or modify a token signed with alg:none without detection — full authentication bypass.',
        fix: 'Reject tokens with alg=none on the server; always require and verify a strong signing algorithm.',
        evidence: `Token: ${shortToken} | Source: ${sourceLabel} | Header: ${JSON.stringify(header)}`,
        cvssScore: 9.8
      })
    );
  } else if (!RECOGNIZED_STRONG_ALGS.includes(alg)) {
    // 2. Weak / non-standard algorithm
    findings.push(
      buildFinding({
        name: 'JWT Weak or Non-Standard Algorithm',
        subCategory: 'JWT Weak Algorithm',
        desc: `A JWT (${sourceLabel}) uses an unrecognized or non-standard algorithm ("${alg}").`,
        severity: SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-327',
        path: baseUrl,
        impact: 'Non-standard algorithms are more likely to have implementation flaws or be exploitable via algorithm-confusion attacks.',
        fix: 'Use a well-supported algorithm from the RFC 7518 registered set (e.g. RS256, ES256, or HS256 with a strong secret).',
        evidence: `Token: ${shortToken} | Source: ${sourceLabel} | alg: ${alg}`,
        cvssScore: 5.9
      })
    );
  }

  if (payload && typeof payload === 'object') {
    // 3. Expired token
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      findings.push(
        buildFinding({
          name: 'Expired JWT Observed',
          subCategory: 'JWT Expired Token',
          desc: `A JWT (${sourceLabel}) was observed with an "exp" claim in the past.`,
          severity: SEVERITY_LEVELS.LOW,
          cwe: 'CWE-613',
          path: baseUrl,
          impact: 'An expired token being served or retained suggests improper session cleanup, though the token itself should no longer be accepted server-side.',
          fix: 'Verify the server rejects expired tokens, and ensure clients clear expired tokens from storage.',
          evidence: `Token: ${shortToken} | exp: ${new Date(payload.exp * 1000).toISOString()}`,
          cvssScore: 3.1
        })
      );
    }

    // 4. Missing exp
    if (!payload.exp) {
      findings.push(
        buildFinding({
          name: 'JWT Missing exp Claim',
          subCategory: 'JWT Missing exp',
          desc: `A JWT (${sourceLabel}) does not contain an "exp" (expiration) claim.`,
          severity: SEVERITY_LEVELS.HIGH,
          cwe: 'CWE-613',
          path: baseUrl,
          impact: 'A token without an expiration claim remains valid indefinitely if leaked or stolen.',
          fix: 'Always issue tokens with a reasonable "exp" claim and enforce refresh/rotation.',
          evidence: `Token: ${shortToken} | payload keys: ${Object.keys(payload).join(', ')}`,
          cvssScore: 7.5
        })
      );
    }

    // 5. Missing iss
    if (!payload.iss) {
      findings.push(
        buildFinding({
          name: 'JWT Missing iss Claim',
          subCategory: 'JWT Missing iss',
          desc: `A JWT (${sourceLabel}) does not contain an "iss" (issuer) claim.`,
          severity: SEVERITY_LEVELS.LOW,
          cwe: 'CWE-345',
          path: baseUrl,
          impact: 'Without an issuer claim, the token cannot be validated as coming from a trusted, expected source.',
          fix: 'Include and validate the "iss" claim against the expected issuer.',
          evidence: `Token: ${shortToken} | payload keys: ${Object.keys(payload).join(', ')}`,
          cvssScore: 2.7
        })
      );
    }

    // 6. Missing aud
    if (!payload.aud) {
      findings.push(
        buildFinding({
          name: 'JWT Missing aud Claim',
          subCategory: 'JWT Missing aud',
          desc: `A JWT (${sourceLabel}) does not contain an "aud" (audience) claim.`,
          severity: SEVERITY_LEVELS.MEDIUM,
          cwe: 'CWE-345',
          path: baseUrl,
          impact: 'Without an audience claim, a token issued for one service could potentially be replayed against another.',
          fix: 'Include and validate the "aud" claim so tokens are only accepted by their intended service.',
          evidence: `Token: ${shortToken} | payload keys: ${Object.keys(payload).join(', ')}`,
          cvssScore: 4.8
        })
      );
    }

    // 7. Missing iat
    if (!payload.iat) {
      findings.push(
        buildFinding({
          name: 'JWT Missing iat Claim',
          subCategory: 'JWT Missing iat',
          desc: `A JWT (${sourceLabel}) does not contain an "iat" (issued-at) claim.`,
          severity: SEVERITY_LEVELS.LOW,
          cwe: 'CWE-345',
          path: baseUrl,
          impact: 'Without an issued-at timestamp, it is harder to enforce token age limits or detect replay of very old tokens.',
          fix: 'Include the "iat" claim when issuing tokens.',
          evidence: `Token: ${shortToken} | payload keys: ${Object.keys(payload).join(', ')}`,
          cvssScore: 2.4
        })
      );
    }
  }

  return findings;
}

async function scanJwt(domain) {
  const baseUrl = `https://${domain}`;
  const findings = [];
  const metadata = { domain, tokensFound: 0, sources: [], localStorageChecked: false };

  let response;
  try {
    response = await withTimeout(fetchPage(baseUrl), TIMEOUT_MS, 'JWT scan');
  } catch (error) {
    return createResult(SCANNER_NAME, [], { domain, error: error.message }, false);
  }

  const tokenMap = collectJwts(response);

  // Local Storage / Session Storage — optional, only if puppeteer is available.
  const localStorageResult = await collectJwtsFromLocalStorage(baseUrl);
  metadata.localStorageChecked = localStorageResult.attempted;
  localStorageResult.found.forEach((sources, token) => {
    if (!tokenMap.has(token)) tokenMap.set(token, new Set());
    sources.forEach((s) => tokenMap.get(token).add(s));
  });

  metadata.tokensFound = tokenMap.size;

  tokenMap.forEach((sources, token) => {
    metadata.sources.push([...sources]);
    findings.push(...analyzeToken(token, sources, baseUrl));
  });

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanJwt
};