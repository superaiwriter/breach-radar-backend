const https = require('https');
const http = require('http');
const cheerio = require('cheerio');
const { createFinding, createResult, withTimeout } = require('./utils');
const { SEVERITY_LEVELS, AUTH_SECURITY_CATEGORY } = require('../constants');

const SCANNER_NAME = 'passwordPolicy';
const TIMEOUT_MS = 10000;
const RECOMMENDED_MIN_LENGTH = 8;

// Purely passive — we only GET and read these pages, never submit a form.
const REGISTRATION_PATHS = ['/register', '/signup', '/sign-up', '/account/register', '/auth/register', '/join'];

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
      response.on('end', () => resolve({ statusCode: response.statusCode, body }));
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

// Reads a regex "pattern" attribute for common character-class hints.
// Only inspects the content *inside* [...] character classes, so regex
// syntax like lookaheads "(?=...)" doesn't get mistaken for a symbol requirement.
function inspectPatternAttribute(pattern) {
  if (!pattern) return {};

  const classContents = [...pattern.matchAll(/\[([^\]]*)\]/g)].map((m) => m[1]);
  const combined = classContents.join(' ');

  return {
    upper: /A-Z/.test(combined),
    lower: /a-z/.test(combined),
    number: /0-9/.test(combined) || /\\d/.test(pattern),
    special: classContents.some((cls) => /\^A-Za-z0-9|\^a-zA-Z0-9/.test(cls) || /[!@#$%^&*(),.?":{}|<>~`_+=-]/.test(cls.replace(/A-Za-z0-9|A-Z|a-z|0-9|\\d|\^/g, '')))
  };
}

// Scans nearby text (labels, hint text, list items) around the password field for
// natural-language requirement hints, as a fallback when there's no HTML pattern/minlength.
function inspectSurroundingText(text) {
  const lower = text.toLowerCase();
  const lengthMatch = lower.match(/(?:minimum|at least|min\.?)\s*(\d{1,2})\s*character/) || lower.match(/(\d{1,2})\+\s*character/);
  return {
    minLengthFromText: lengthMatch ? Number(lengthMatch[1]) : null,
    upper: /uppercase|capital letter/.test(lower),
    lower: /lowercase|small letter/.test(lower),
    number: /number|digit/.test(lower),
    special: /special character|symbol|punctuation/.test(lower)
  };
}

function detectStrengthMeter($) {
  const selectors = [
    '[class*="strength" i]',
    '[id*="strength" i]',
    '[data-testid*="strength" i]',
    '[aria-label*="password strength" i]',
    'meter'
  ];
  return selectors.some((selector) => $(selector).length > 0) || /zxcvbn/i.test($.html());
}

function analyzeRegistrationPage(html) {
  const $ = cheerio.load(html);
  const passwordInput = $('input[type="password"]').first();
  if (passwordInput.length === 0) return null; // no password field -> not a registration form

  const minlengthAttr = passwordInput.attr('minlength');
  const patternAttr = passwordInput.attr('pattern');
  const patternHints = inspectPatternAttribute(patternAttr);

  // Look at the enclosing form (or a reasonable ancestor) for hint text near the field.
  const container = passwordInput.closest('form').length ? passwordInput.closest('form') : passwordInput.parent();
  const textHints = inspectSurroundingText(container.text());

  const minLength = minlengthAttr ? Number(minlengthAttr) : textHints.minLengthFromText;

  return {
    minLength,
    minLengthSource: minlengthAttr ? 'minlength attribute' : textHints.minLengthFromText ? 'page text' : null,
    requiresUpper: patternHints.upper || textHints.upper,
    requiresLower: patternHints.lower || textHints.lower,
    requiresNumber: patternHints.number || textHints.number,
    requiresSpecial: patternHints.special || textHints.special,
    hasPattern: Boolean(patternAttr),
    hasStrengthMeter: detectStrengthMeter($)
  };
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
    references: ['https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity']
  });
}

async function scanPasswordPolicy(domain) {
  const findings = [];
  const baseUrl = `https://${domain}`;
  const metadata = { domain, registrationPageFound: false, path: null };

  let analysis = null;
  let foundPath = null;

  for (const path of REGISTRATION_PATHS) {
    // eslint-disable-next-line no-await-in-loop
    let response;
    try {
      // eslint-disable-next-line no-await-in-loop
      response = await withTimeout(fetchHtml(`${baseUrl}${path}`), TIMEOUT_MS, 'Registration page probe');
    } catch {
      continue;
    }
    if (!response || response.statusCode >= 400 || !response.body) continue;

    const result = analyzeRegistrationPage(response.body);
    if (result) {
      analysis = result;
      foundPath = path;
      break;
    }
  }

  if (!analysis) {
    // No registration page with a password field could be passively located — not applicable.
    return createResult(SCANNER_NAME, [], metadata, true);
  }

  metadata.registrationPageFound = true;
  metadata.path = foundPath;
  metadata.analysis = analysis;

  const missingRules = [];

  // Minimum length
  if (analysis.minLength === null || analysis.minLength === undefined) {
    missingRules.push('minimum length');
    findings.push(
      buildFinding({
        name: 'No Minimum Password Length Detected',
        desc: `No minimum length requirement could be passively detected on the registration form at ${foundPath}.`,
        severity: SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-521',
        path: foundPath,
        impact: 'Without an enforced minimum length, users may set very short, easily guessable passwords.',
        fix: `Enforce a minimum password length of at least ${RECOMMENDED_MIN_LENGTH} characters, both client- and server-side.`,
        evidence: 'No "minlength" attribute or length-related requirement text found near the password field.'
      })
    );
  } else if (analysis.minLength < RECOMMENDED_MIN_LENGTH) {
    missingRules.push('sufficient length');
    findings.push(
      buildFinding({
        name: 'Weak Minimum Password Length',
        desc: `The registration form at ${foundPath} enforces a minimum password length of only ${analysis.minLength} characters (via ${analysis.minLengthSource}).`,
        severity: SEVERITY_LEVELS.MEDIUM,
        cwe: 'CWE-521',
        path: foundPath,
        impact: 'Short minimum lengths make passwords more susceptible to brute-force and dictionary attacks.',
        fix: `Increase the minimum required password length to at least ${RECOMMENDED_MIN_LENGTH} characters.`,
        evidence: `Detected minLength = ${analysis.minLength} (source: ${analysis.minLengthSource})`
      })
    );
  }

  // Character-class requirements
  const classChecks = [
    { key: 'requiresUpper', label: 'Uppercase Letter', name: 'Uppercase Character Not Required' },
    { key: 'requiresLower', label: 'Lowercase Letter', name: 'Lowercase Character Not Required' },
    { key: 'requiresNumber', label: 'Number', name: 'Numeric Character Not Required' },
    { key: 'requiresSpecial', label: 'Special Character', name: 'Special Character Not Required' }
  ];

  classChecks.forEach(({ key, label, name }) => {
    if (!analysis[key]) {
      missingRules.push(label.toLowerCase());
      findings.push(
        buildFinding({
          name,
          desc: `The registration form at ${foundPath} does not appear to require a ${label.toLowerCase()} in the password.`,
          severity: SEVERITY_LEVELS.LOW,
          cwe: 'CWE-521',
          path: foundPath,
          impact: `Passwords without a required ${label.toLowerCase()} have a smaller character space, reducing brute-force resistance.`,
          fix: `Require at least one ${label.toLowerCase()} in the password policy.`,
          evidence: analysis.hasPattern ? 'No matching character class found in the field\'s "pattern" attribute or nearby hint text.' : 'No "pattern" attribute present, and no matching requirement text found near the password field.'
        })
      );
    }
  });

  // Consolidated weak-policy finding when multiple requirements are absent.
  if (missingRules.length >= 3) {
    findings.push(
      buildFinding({
        name: 'Weak Password Policy',
        desc: `The registration form at ${foundPath} appears to enforce few or no password complexity requirements (missing: ${missingRules.join(', ')}).`,
        severity: SEVERITY_LEVELS.HIGH,
        cwe: 'CWE-521',
        path: foundPath,
        impact: 'A weak password policy makes user accounts significantly easier to compromise via brute-force, dictionary, or credential-stuffing attacks.',
        fix: 'Adopt a password policy requiring at least 8 characters with a mix of uppercase, lowercase, numbers, and special characters — or adopt NIST 800-63B guidance (long passphrases + breached-password screening).',
        evidence: `Missing requirements detected: ${missingRules.join(', ')}`,
        cvssScore: 6.5
      })
    );
  }

  // Password strength meter (UX/defense-in-depth signal, not a hard requirement).
  if (!analysis.hasStrengthMeter) {
    findings.push(
      buildFinding({
        name: 'No Password Strength Meter Detected',
        desc: `No visual password strength indicator was detected on the registration form at ${foundPath}.`,
        severity: SEVERITY_LEVELS.LOW,
        cwe: '',
        path: foundPath,
        impact: 'Without real-time feedback, users are less likely to choose stronger passwords voluntarily.',
        fix: 'Add a password strength meter (e.g. zxcvbn) to guide users toward stronger passwords at registration.',
        evidence: 'No element matching common strength-meter patterns (class/id containing "strength", a <meter> element, or zxcvbn) was found.'
      })
    );
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanPasswordPolicy,
  analyzeRegistrationPage
};