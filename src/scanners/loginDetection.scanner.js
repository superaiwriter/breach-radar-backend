const https = require('https');
const http = require('http');
const cheerio = require('cheerio');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY, AUTH_CHECK_TYPES } = require('../constants');

const SCANNER_NAME = 'loginDetection';
const TIMEOUT_MS = 10000;

// Paths to crawl, as requested. Admin-style paths are treated as higher
// severity since a publicly discoverable admin login increases attack surface.
const CANDIDATE_PATHS = ['/login', '/signin', '/auth', '/admin/login', '/account/login'];
const ADMIN_PATHS = ['/admin/login'];

function fetchHtml(urlString) {
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
        // follow a single redirect hop (common for /login -> /auth/login etc.)
        if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
          response.resume();
          const redirectUrl = new URL(response.headers.location, url).toString();
          fetchHtml(redirectUrl).then(resolve).catch(reject);
          return;
        }

        let body = '';
        response.on('data', (chunk) => {
          body += chunk;
          if (body.length > 500000) response.destroy(); // cap page size read
        });
        response.on('end', () => {
          resolve({ statusCode: response.statusCode, body, finalUrl: urlString });
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

// Inspects the HTML for a login form and classifies which fields it exposes.
function analyzeLoginForm(html) {
  const $ = cheerio.load(html);

  const passwordFields = $('input[type="password"]');
  if (passwordFields.length === 0) {
    return null; // no password field -> not a login page
  }

  const allInputs = $('input');
  const textOf = (el) =>
    [
      $(el).attr('name'),
      $(el).attr('id'),
      $(el).attr('placeholder'),
      $(el).attr('autocomplete'),
      $(el).attr('aria-label')
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

  let hasEmailField = false;
  let hasUsernameField = false;
  let hasRememberMe = false;
  let hasMfaField = false;

  allInputs.each((_, el) => {
    const type = ($(el).attr('type') || 'text').toLowerCase();
    const hint = textOf(el);

    if (type === 'email' || /email/.test(hint)) hasEmailField = true;
    if (type === 'text' && /user(name)?|login/.test(hint)) hasUsernameField = true;
    if (type === 'checkbox' && /remember/.test(hint)) hasRememberMe = true;
    if (/otp|mfa|2fa|two.?factor|authenticator|verification.?code/.test(hint)) hasMfaField = true;
  });

  // Remember-me / MFA hints can also appear as surrounding label text rather than input attributes.
  const bodyText = $('body').text().toLowerCase();
  if (!hasRememberMe && /remember me/.test(bodyText)) hasRememberMe = true;
  if (!hasMfaField && /(one-?time code|two-?factor authentication|authenticator app)/.test(bodyText)) hasMfaField = true;

  return {
    hasLoginForm: true,
    hasEmailField,
    hasUsernameField,
    hasPasswordField: true,
    hasRememberMe,
    hasMfaField,
    pageTitle: $('title').text().trim().slice(0, 120)
  };
}

async function scanLoginDetection(domain) {
  const findings = [];
  const detectedPages = [];
  const baseUrl = `https://${domain}`;

  await Promise.allSettled(
    CANDIDATE_PATHS.map(async (path) => {
      let response;
      try {
        response = await withTimeout(fetchHtml(`${baseUrl}${path}`), TIMEOUT_MS, 'Login page probe');
      } catch {
        return; // unreachable / timed out — skip
      }

      if (!response || response.statusCode >= 400 || !response.body) return;

      const analysis = analyzeLoginForm(response.body);
      if (!analysis) return; // page exists but no password field found — not a login page

      detectedPages.push({ path, ...analysis });

      const isAdminPath = ADMIN_PATHS.includes(path);
      const missing = [];
      if (!analysis.hasMfaField) missing.push('MFA');
      if (!analysis.hasRememberMe) missing.push('Remember Me');

      findings.push(
        createFinding({
          scanner: SCANNER_NAME,
          name: isAdminPath ? 'Exposed Admin Login Page' : 'Login Page Detected',
          desc: `A login form was found at ${path}${analysis.pageTitle ? ` ("${analysis.pageTitle}")` : ''}, exposing ${
            analysis.hasEmailField ? 'an email field' : analysis.hasUsernameField ? 'a username field' : 'a credential field'
          } and a password field.`,
          severity: isAdminPath ? SEVERITY_LEVELS.MEDIUM : SEVERITY_LEVELS.LOW,
          cwe: isAdminPath ? 'CWE-200' : '',
          path,
          impact: isAdminPath
            ? 'Publicly discoverable admin login pages are a common target for credential stuffing and brute-force attacks.'
            : 'Discovered authentication surface should be checked for rate limiting, CAPTCHA, and MFA enforcement.',
          fix: isAdminPath
            ? 'Restrict admin login access by IP allowlist/VPN, enforce MFA, and consider moving it off a guessable path.'
            : 'Ensure the login endpoint enforces rate limiting, account lockout, and offers MFA.',
          category: AUTH_SECURITY_CATEGORY,
          subCategory: AUTH_CHECK_TYPES.LOGIN_PAGE_DETECTED.subCategory,
          cvssScore: isAdminPath ? 5.3 : 3.1,
          evidence: JSON.stringify({
            path,
            emailField: analysis.hasEmailField,
            usernameField: analysis.hasUsernameField,
            passwordField: analysis.hasPasswordField,
            rememberMe: analysis.hasRememberMe,
            mfaField: analysis.hasMfaField,
            missing
          }),
          references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/']
        })
      );
    })
  );

  return createResult(SCANNER_NAME, findings, { domain, pagesDetected: detectedPages.length, detectedPages }, true);
}

module.exports = {
  scanLoginDetection
};