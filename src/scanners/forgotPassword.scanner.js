const https = require('https');
const http = require('http');
const cheerio = require('cheerio');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY } = require('../constants');

const SCANNER_NAME = 'forgotPassword';
const TIMEOUT_MS = 10000;
const RECOMMENDED_MIN_TOKEN_LENGTH = 20; // characters; ~ >=120 bits for hex/base62 tokens
const LONG_EXPIRY_THRESHOLD_MINUTES = 24 * 60; // 24 hours

// Purely passive — we only GET these pages and read their markup/inline scripts.
// We NEVER submit the forgot-password form, so no reset email is ever triggered.
const FORGOT_PASSWORD_PATHS = [
  '/forgot-password',
  '/forgot_password',
  '/forgotpassword',
  '/password/forgot',
  '/account/forgot-password',
  '/auth/forgot-password',
  '/reset-password',
  '/password/reset'
];

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
    const request = client.get(url, { timeout: TIMEOUT_MS, headers: { 'User-Agent': 'SecureScan/1.0' } }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        const redirectUrl = new URL(response.headers.location, url).toString();
        fetchHtml(redirectUrl).then(resolve).catch(reject);
        return;
      }
      let body = '';
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 500000) response.destroy();
      });
      response.on('end', () => resolve({ statusCode: response.statusCode, finalUrl: url.toString(), body }));
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

// Distinguishes a forgot/reset-password page from login/register pages:
// an email or username field, NO password field, and "forgot"/"reset password" wording nearby.
function detectForgotPasswordForm($) {
  const forms = $('form').toArray();

  for (const formEl of forms) {
    const form = $(formEl);
    const hasPasswordInput = form.find('input[type="password"]').length > 0;
    if (hasPasswordInput) continue; // that's a login/register/reset-with-new-password form, not this one

    const identifierInput = form
      .find('input')
      .toArray()
      .find((inputEl) => {
        const input = $(inputEl);
        const type = (input.attr('type') || '').toLowerCase();
        const nameIdPlaceholder = `${input.attr('name') || ''} ${input.attr('id') || ''} ${input.attr('placeholder') || ''}`.toLowerCase();
        return type === 'email' || /email|username|user_login|identifier/.test(nameIdPlaceholder);
      });

    if (!identifierInput) continue;

    const contextText = `${$('title').text()} ${$('h1').text()} ${$('h2').text()} ${form.text()}`.toLowerCase();
    if (/forgot.*password|reset.*password|password.*reset|recover.*password|password.*recovery/.test(contextText)) {
      return form;
    }
  }

  return null;
}

function detectCaptcha($) {
  const html = $.html();
  return (
    $('.g-recaptcha, [data-sitekey], .h-captcha, .cf-turnstile').length > 0 ||
    /recaptcha|hcaptcha|turnstile/i.test(html)
  );
}

// Looks inside inline <script> blocks and href/src attributes for a reset-token
// URL pattern or a client-side regex validating token format — entirely passive,
// no request is ever made with a real/guessed token.
function inspectForTokenSignals(html) {
  const signals = { exampleToken: null, regexLength: null, source: null };

  const tokenParamMatch = html.match(/[?&]token=([A-Za-z0-9\-_.]{10,128})(?=["'&\s])/);
  if (tokenParamMatch) {
    signals.exampleToken = tokenParamMatch[1];
    signals.source = 'token query parameter found in page markup';
  }

  const routeTokenMatch = html.match(/reset-password\/([A-Za-z0-9\-_.]{10,128})(?=["'\s])/i);
  if (!signals.exampleToken && routeTokenMatch) {
    signals.exampleToken = routeTokenMatch[1];
    signals.source = 'token found in reset-password route path';
  }

  // Client-side regex validators referencing "token" nearby, e.g. /^[a-f0-9]{32}$/
  // Checked in both directions since real code varies:
  //   const tokenPattern = /^[a-f0-9]{32}$/;      (token BEFORE regex)
  //   /^[a-f0-9]{32}$/.test(token)                (token AFTER regex)
  const regexLiterals = [...html.matchAll(/\/\^?\[([^\]]+)\]\{(\d+)(?:,(\d+))?\}\$?\//g)];
  const tokenNearRegex = regexLiterals.find((match) => {
    const start = Math.max(0, match.index - 80);
    const end = Math.min(html.length, match.index + match[0].length + 80);
    return /token/i.test(html.slice(start, end));
  });
  if (tokenNearRegex) {
    const [, , min, max] = tokenNearRegex;
    signals.regexLength = max ? Number(max) : Number(min);
    signals.source = signals.source || 'client-side token-format validation regex';
  }

  return signals;
}

function inspectExpiryText(text) {
  const lower = text.toLowerCase();
  const patterns = [
    /expir\w*\s*(?:in|within|after)?\s*(\d+)\s*(minute|hour|day)s?/,
    /valid\s*for\s*(\d+)\s*(minute|hour|day)s?/,
    /link\s*(?:will\s*)?expires?\s*(?:in)?\s*(\d+)\s*(minute|hour|day)s?/
  ];

  for (const pattern of patterns) {
    const match = lower.match(pattern);
    if (match) {
      const value = Number(match[1]);
      const unit = match[2];
      const minutes = unit === 'day' ? value * 24 * 60 : unit === 'hour' ? value * 60 : value;
      return { minutes, raw: match[0] };
    }
  }

  return null;
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
    category: AUTH_SECURITY_CATEGORY,
    subCategory: name,
    cvssScore,
    evidence,
    references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities']
  });
}

async function scanForgotPassword(domain) {
  const findings = [];
  const baseUrl = `https://${domain}`;
  const metadata = { domain, forgotPasswordPageFound: false, path: null };

  let form$ = null;
  let response = null;
  let foundPath = null;

  for (const path of FORGOT_PASSWORD_PATHS) {
    // eslint-disable-next-line no-await-in-loop
    let pageResponse;
    try {
      // eslint-disable-next-line no-await-in-loop
      pageResponse = await withTimeout(fetchHtml(`${baseUrl}${path}`), TIMEOUT_MS, 'Forgot-password page probe');
    } catch {
      continue;
    }
    if (!pageResponse || pageResponse.statusCode >= 400 || !pageResponse.body) continue;

    const $ = cheerio.load(pageResponse.body);
    const form = detectForgotPasswordForm($);
    if (form) {
      form$ = $;
      response = pageResponse;
      foundPath = path;
      break;
    }
  }

  if (!form$) {
    // No forgot-password page with a matching form could be passively located — not applicable.
    return createResult(SCANNER_NAME, [], metadata, true);
  }

  metadata.forgotPasswordPageFound = true;
  metadata.path = foundPath;

  const weakSignals = [];

  // Reset endpoint — read straight from the form's action attribute (no submission).
  const form = detectForgotPasswordForm(form$);
  const actionAttr = form ? form.attr('action') : null;
  let resetEndpoint = null;
  try {
    resetEndpoint = actionAttr ? new URL(actionAttr, response.finalUrl).toString() : response.finalUrl;
  } catch {
    resetEndpoint = actionAttr || response.finalUrl;
  }
  metadata.resetEndpoint = resetEndpoint;

  // HTTPS check on the page that actually handles the reset request.
  if (!resetEndpoint.startsWith('https://')) {
    weakSignals.push('served over HTTP');
    findings.push(
      buildFinding({
        name: 'Password Reset Page Not Served Over HTTPS',
        desc: `The forgot-password page/endpoint at ${foundPath} is not served exclusively over HTTPS.`,
        severity: SEVERITY_LEVELS.HIGH,
        cwe: 'CWE-319',
        path: foundPath,
        impact: 'Password reset requests (including the identifier submitted and any resulting token in transit) can be intercepted or tampered with on an insecure connection.',
        fix: 'Serve the forgot-password page and its submission endpoint exclusively over HTTPS, and redirect all HTTP requests to HTTPS.',
        evidence: `Resolved reset endpoint: ${resetEndpoint}`,
        cvssScore: 7.4
      })
    );
  }

  // CAPTCHA / anti-automation check.
  const hasCaptcha = detectCaptcha(form$);
  if (!hasCaptcha) {
    weakSignals.push('no CAPTCHA/anti-automation control');
    findings.push(
      buildFinding({
        name: 'No CAPTCHA on Password Reset Form',
        desc: `No CAPTCHA or similar anti-automation control (reCAPTCHA, hCaptcha, Turnstile) was detected on the forgot-password form at ${foundPath}.`,
        severity: SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-799',
        path: foundPath,
        impact: 'Without anti-automation controls, the reset endpoint is easier to abuse for account-enumeration or mass password-reset-request spam/DoS against users\' inboxes.',
        fix: 'Add a CAPTCHA (or equivalent bot-mitigation control) and server-side rate limiting to the password reset request endpoint.',
        evidence: 'No recognized CAPTCHA widget or script reference found in the forgot-password page markup.'
      })
    );
  }

  // Reset-token signals (entirely passive — discovered in markup/inline scripts, never requested).
  const tokenSignals = inspectForTokenSignals(response.body);
  metadata.tokenSignals = tokenSignals;

  const tokenLength = tokenSignals.exampleToken ? tokenSignals.exampleToken.length : tokenSignals.regexLength;

  if (tokenLength) {
    metadata.detectedTokenLength = tokenLength;
    if (tokenLength < RECOMMENDED_MIN_TOKEN_LENGTH) {
      weakSignals.push('short reset token');
      findings.push(
        buildFinding({
          name: 'Password Reset Token Appears Short',
          desc: `A password reset token pattern discovered at ${foundPath} is only ${tokenLength} characters long (${tokenSignals.source}).`,
          severity: SEVERITY_LEVELS.MEDIUM,
          cwe: 'CWE-330',
          path: foundPath,
          impact: 'Short reset tokens have a smaller keyspace and may be more feasible to guess or brute-force within their validity window.',
          fix: `Use a cryptographically random reset token of at least ${RECOMMENDED_MIN_TOKEN_LENGTH} characters (or 128+ bits of entropy), generated with a secure RNG.`,
          evidence: `Detected token length: ${tokenLength} characters (source: ${tokenSignals.source})`
        })
      );
    }

    // Token reuse cannot be safely confirmed without performing an interactive reset,
    // which would trigger a real email — flagged as an informational, manual-verification item.
    findings.push(
      buildFinding({
        name: 'Password Reset Token Reuse Protection Not Confirmed',
        desc: `A reset-token pattern was found at ${foundPath}, but whether the token is invalidated after first use could not be verified passively (doing so would require triggering a real password reset).`,
        severity: SEVERITY_LEVELS.LOW,
        cwe: 'CWE-640',
        path: foundPath,
        impact: 'If reset tokens can be reused, an attacker who obtains one intercepted or leaked token could reset the password multiple times or after the legitimate user has already used it.',
        fix: 'Manually verify that reset tokens are single-use: invalidate the token server-side immediately after a successful reset, and confirm a second attempt with the same token is rejected.',
        evidence: `${tokenSignals.source}. This finding is advisory only — automated passive scanning cannot confirm reuse behavior without submitting a real reset request.`
      })
    );
  }

  // Expiry disclosure text (e.g. "This link will expire in 24 hours").
  const expiry = inspectExpiryText(form$.root().text());
  if (expiry) {
    metadata.detectedExpiryMinutes = expiry.minutes;
    if (expiry.minutes > LONG_EXPIRY_THRESHOLD_MINUTES) {
      weakSignals.push('long token expiry');
      findings.push(
        buildFinding({
          name: 'Long Password Reset Token Expiry',
          desc: `The forgot-password page at ${foundPath} indicates reset links remain valid for an extended period ("${expiry.raw}").`,
          severity: SEVERITY_LEVELS.MEDIUM,
          cwe: 'CWE-613',
          path: foundPath,
          impact: 'A long-lived reset token increases the window during which an intercepted or leaked link can be used by an attacker to take over the account.',
          fix: 'Shorten password reset token validity to a short window (commonly 15–60 minutes), and invalidate the token immediately after use or once a new reset is requested.',
          evidence: `Detected expiry text: "${expiry.raw}" (~${expiry.minutes} minutes)`
        })
      );
    }
  }

  // Consolidated weak-flow finding when multiple issues stack up.
  if (weakSignals.length >= 2) {
    findings.push(
      buildFinding({
        name: 'Weak Password Reset Flow',
        desc: `The password reset flow at ${foundPath} shows multiple weaknesses: ${weakSignals.join(', ')}.`,
        severity: SEVERITY_LEVELS.HIGH,
        cwe: 'CWE-640',
        path: foundPath,
        impact: 'Combined weaknesses in the password reset flow meaningfully increase the risk of account takeover via reset-token guessing, interception, or abuse.',
        fix: 'Harden the reset flow end-to-end: HTTPS-only, CAPTCHA + rate limiting on requests, long random single-use tokens, and short expiry windows.',
        evidence: `Weak signals detected: ${weakSignals.join(', ')}`,
        cvssScore: 7.1
      })
    );
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanForgotPassword,
  detectForgotPasswordForm
};