const https = require('https');
const http = require('http');
const cheerio = require('cheerio');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY } = require('../constants');

const SCANNER_NAME = 'auth';
const TIMEOUT_MS = 10000;

function fetchPage(urlString) {
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
        // Follow redirect (only one hop)
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.resume();
          try {
            const redirectUrl = new URL(res.headers.location, url).toString();
            fetchPage(redirectUrl).then(resolve).catch(reject);
          } catch (err) {
            reject(err);
          }
          return;
        }
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 500000) req.destroy();
        });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.on('error', reject);
  });
}

async function scanAuth(domain, authContext = null) {
  const baseUrl = `https://${domain}`;
  const findings = [];
  const metadata = { domain, loginPageChecked: false, clickjackingChecked: false };

  try {
    const paths = ['/login', '/signin', '/auth', '/admin/login'];
    let pageData = null;
    let foundPath = '';

    for (const path of paths) {
      try {
        const res = await withTimeout(fetchPage(`${baseUrl}${path}`), TIMEOUT_MS, `Auth scan path ${path}`);
        if (res.statusCode === 200 && res.body.includes('password')) {
          pageData = res;
          foundPath = path;
          break;
        }
      } catch (err) {
        // continue trying other paths
      }
    }

    if (pageData) {
      metadata.loginPageChecked = true;
      const $ = cheerio.load(pageData.body);
      const form = $('form');

      // Check 1: Insecure form submission
      form.each((_, el) => {
        const action = $(el).attr('action');
        if (action && action.startsWith('http://')) {
          findings.push(
            createFinding({
              name: 'Insecure Form Submission',
              desc: `The login form at ${foundPath} submits credentials over unencrypted HTTP (${action}).`,
              severity: SEVERITY_LEVELS.HIGH,
              cwe: 'CWE-319',
              path: foundPath,
              impact: 'Credentials can be intercepted in transit by an on-path attacker.',
              fix: 'Update the form action attribute to use HTTPS.',
              scanner: SCANNER_NAME,
              category: AUTH_SECURITY_CATEGORY,
              subCategory: 'Broken Authentication',
              cvssScore: 7.5,
              evidence: `Form action: ${action}`
            })
          );
        }
      });

      // Check 2: Missing Clickjacking protection on login page
      const xFrameOptions = pageData.headers['x-frame-options'];
      const csp = pageData.headers['content-security-policy'];
      const hasFrameAncestors = csp && csp.includes('frame-ancestors');

      if (!xFrameOptions && !hasFrameAncestors) {
        findings.push(
          createFinding({
            name: 'Missing Clickjacking Protection on Login Page',
            desc: `The login page at ${foundPath} does not send X-Frame-Options or Content-Security-Policy frame-ancestors headers.`,
            severity: SEVERITY_LEVELS.MEDIUM,
            cwe: 'CWE-1021',
            path: foundPath,
            impact: 'Attackers can iframe the login page to perform clickjacking attacks and steal credentials.',
            fix: "Set the 'X-Frame-Options: DENY' or 'SAMEORIGIN' header, or frame-ancestors in CSP.",
            scanner: SCANNER_NAME,
            category: AUTH_SECURITY_CATEGORY,
            subCategory: 'Broken Authentication',
            cvssScore: 4.3,
            evidence: 'No clickjacking headers found'
          })
        );
      }
      metadata.clickjackingChecked = true;

      // Check 3: Autocomplete disabled on password field.
      // Note: modern guidance (OWASP ASVS 2.x+) flags autocomplete="off" on password
      // fields as an anti-pattern — it blocks password managers and pushes users
      // toward weaker, memorized/reused passwords. This replaces the old check,
      // which only fired on the rare autocomplete="on" case.
      const passwordField = $('input[type="password"]');
      passwordField.each((_, el) => {
        const autocomplete = ($(el).attr('autocomplete') || '').toLowerCase();
        if (autocomplete === 'off' || autocomplete === 'false') {
          findings.push(
            createFinding({
              name: 'Password Manager Blocked via autocomplete="off"',
              desc: `The password field in the login form at ${foundPath} sets autocomplete="${autocomplete}", which blocks browser password managers.`,
              severity: SEVERITY_LEVELS.LOW,
              cwe: 'CWE-522',
              path: foundPath,
              impact: 'Disabling autocomplete prevents users from relying on password managers, encouraging weaker, memorized, or reused passwords — the opposite of its intended security benefit.',
              fix: 'Remove autocomplete="off" from the password field, or set it to "current-password" (login) / "new-password" (registration) so password managers work correctly.',
              scanner: SCANNER_NAME,
              category: AUTH_SECURITY_CATEGORY,
              subCategory: 'Weak Password Policy',
              cvssScore: 2.1,
              evidence: `Password input autocomplete attribute: "${autocomplete}"`
            })
          );
        }
      });
    }

    // Check 4: MFA signal check — broadened beyond simple keyword matching on the
    // login page body, and reported as a low-confidence, hedged signal rather than
    // an assertive claim, since MFA commonly lives behind a second step/page that
    // a single-page passive check cannot see.
    if (pageData) {
      const haystack = pageData.body.toLowerCase();
      const textSignals = ['otp', 'mfa', '2fa', 'two-factor', 'two factor', '2-step', 'authenticator', 'verification code', 'security code'];
      const providerScriptSignals = ['duosecurity', 'duo_web', 'authy', 'okta-signin-widget', 'auth0', 'twilio'];

      const hasTextSignal = textSignals.some((signal) => haystack.includes(signal));
      const hasProviderSignal = providerScriptSignals.some((signal) => haystack.includes(signal));

      if (!hasTextSignal && !hasProviderSignal) {
        findings.push(
          createFinding({
            name: 'No MFA Signal Found on Login Page',
            desc: `No text, form field, or known MFA-provider script referencing multi-factor authentication was found on the login page at ${foundPath}.`,
            severity: SEVERITY_LEVELS.LOW,
            cwe: 'CWE-308',
            path: foundPath || '/',
            impact: 'Absence of any MFA signal on the primary login page suggests MFA may not be offered, increasing exposure to credential-stuffing and brute-force attacks — though MFA occurring on a later step cannot be ruled out by this passive check alone.',
            fix: 'Offer Multi-Factor Authentication (TOTP authenticator, SMS, or WebAuthn) and confirm this finding manually if MFA is implemented behind a secondary login step.',
            scanner: SCANNER_NAME,
            category: AUTH_SECURITY_CATEGORY,
            subCategory: 'MFA Bypass',
            cvssScore: 3.2,
            evidence: 'No MFA-related text, field, or known provider script signal detected on the primary login page.'
          })
        );
      }
    }

  } catch (err) {
    return createResult(SCANNER_NAME, [], { domain, error: err.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanAuth
};