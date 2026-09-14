const { createFinding, withTimeout } = require('../utils');
const { SEVERITY_LEVELS } = require('../../constants');
const { fetchRaw } = require('./httpClient');

const SCANNER_NAME = 'authorization';
const TIMEOUT_MS = 10000;
const SUB_CATEGORY = 'Missing Access Control';

// Category for this whole module — kept distinct from AUTH_SECURITY_CATEGORY
// (Authentication & Account Security) per the spec: Authorization is its own category.
const AUTHORIZATION_CATEGORY = 'Authorization';

// "tier" drives default severity when no stronger PII signal is found.
const CANDIDATE_ENDPOINTS = [
  { path: '/admin', tier: 'admin' },
  { path: '/admin/users', tier: 'admin' },
  { path: '/admin/settings', tier: 'admin' },
  { path: '/api/admin', tier: 'admin' },
  { path: '/api/admin/users', tier: 'admin' },
  { path: '/api/admin/settings', tier: 'admin' },
  { path: '/api/users', tier: 'account' },
  { path: '/api/users/me', tier: 'account' },
  { path: '/api/account', tier: 'account' },
  { path: '/api/account/profile', tier: 'account' },
  { path: '/api/settings', tier: 'account' },
  { path: '/api/profile', tier: 'account' }
];

// A random, near-certainly-nonexistent path. Used as a baseline: many apps
// (SPAs especially) serve the identical index.html "catch-all" for every
// unmatched frontend route. Without this baseline, every /admin-style page
// would look "exposed" even though it's just the same public shell that
// redirects/blocks client-side after JS loads — a major false-positive source.
function buildBaselinePath() {
  return `/__pentestradar-baseline-check-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

function normalizeBody(body) {
  return (body || '').replace(/\s+/g, ' ').trim();
}

// Redirect Location headers pointing at an auth wall are themselves strong
// evidence the endpoint IS protected — must not be flagged.
function looksLikeAuthRedirect(locationHeader = '') {
  return /login|signin|sign-in|auth|sso|unauthoriz/i.test(locationHeader);
}

const ERROR_BODY_PATTERN = /unauthorized|forbidden|not authenticated|access denied|please\s*log\s*in|invalid session|permission denied/i;
const PII_KEY_PATTERN = /"email"|"password"|"ssn"|"token"|"secret"|"phone"|"address"|"apikey"|"api_key"/i;

/**
 * Pure classification function — takes already-fetched responses and decides
 * whether there's reasonable evidence of a missing access control issue.
 * Exported separately so it can be unit-tested with synthetic responses
 * without needing a live HTTP round trip (see scanner test suite / manual checks).
 *
 * Returns null when there is NOT enough evidence to flag (the conservative,
 * false-positive-avoiding default), or a classification object when there is.
 */
function classifyEndpoint({ tier }, response, baseline) {
  if (!response) return null; // request failed/timed out — inconclusive, never flag on absence of data

  const { statusCode, headers, body } = response;

  // Confirmed protected — this is the "correctly enforced" case (Test Case A) and must NOT be flagged.
  if (statusCode === 401 || statusCode === 403) return null;

  if (statusCode === 404) return null; // endpoint doesn't exist here

  if ([301, 302, 303, 307, 308].includes(statusCode)) {
    const location = headers.location || '';
    if (looksLikeAuthRedirect(location)) return null; // protected via redirect-to-login
    return null; // any other redirect target: inconclusive by design, avoid guessing
  }

  if (statusCode !== 200) return null; // 5xx / anything else: inconclusive, not evidence of exposure

  const contentType = (headers['content-type'] || '').toLowerCase();
  const isJson = contentType.includes('application/json');

  if (isJson) {
    let json;
    try {
      json = JSON.parse(body);
    } catch {
      return null; // claimed JSON but didn't parse — inconclusive
    }

    if (ERROR_BODY_PATTERN.test(body)) return null; // a 200 that is actually an auth-error payload — not exposure

    const isEmptyish =
      (Array.isArray(json) && json.length === 0) ||
      (json && typeof json === 'object' && !Array.isArray(json) && Object.keys(json).length === 0);
    if (isEmptyish) return null; // empty response body is weak/no evidence — skip rather than guess

    const hasPii = PII_KEY_PATTERN.test(body);
    const severity = tier === 'admin' ? SEVERITY_LEVELS.HIGH : hasPii ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM;
    const itemSummary = Array.isArray(json) ? `an array of ${json.length} item(s)` : `an object with keys: ${Object.keys(json).slice(0, 8).join(', ')}`;

    return {
      severity,
      evidence: `HTTP 200 with Content-Type: ${contentType}. Response body contains ${itemSummary}.`,
      reason: 'json-data-exposed-without-auth'
    };
  }

  // HTML-ish response — guard against SPA catch-all fallback false positives.
  if (baseline && baseline.body) {
    if (normalizeBody(body) === normalizeBody(baseline.body)) {
      return null; // identical to the nonexistent-path baseline — this is just the app shell, not real exposure
    }
  }

  return {
    severity: tier === 'admin' ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM,
    evidence: `HTTP 200 (Content-Type: ${contentType || 'text/html'}) returned content distinct from a nonexistent-path baseline, with no authentication challenge (no 401/403, no redirect to a login page).`,
    reason: 'html-distinct-from-baseline'
  };
}

function buildFinding({ path, classification }) {
  return createFinding({
    scanner: SCANNER_NAME,
    name: 'Missing Access Control',
    desc: `The endpoint "${path}" appears to be sensitive/administrative but was reachable without authentication.`,
    severity: classification.severity,
    cwe: 'CWE-284',
    path,
    impact:
      classification.severity === SEVERITY_LEVELS.HIGH
        ? 'Unauthenticated access to this endpoint may expose administrative functionality or sensitive user data, enabling data theft, account takeover, or further compromise.'
        : 'Unauthenticated access to this endpoint may expose functionality or data that should require a logged-in session.',
    fix: 'Require authentication (and appropriate authorization/role checks) on this endpoint server-side. Do not rely on the frontend hiding a link/route as the only protection.',
    category: AUTHORIZATION_CATEGORY,
    subCategory: SUB_CATEGORY,
    cvssScore: classification.severity === SEVERITY_LEVELS.HIGH ? 8.1 : 5.4,
    evidence: `GET ${path} → ${classification.evidence}`,
    references: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/284.html'
    ]
  });
}

async function scanMissingAccessControl(domain) {
  const baseUrl = `https://${domain}`;
  const findings = [];
  const seen = new Set(); // dedup guard: domain+path+finding-name, per spec section 7
  const metadata = { domain, endpointsChecked: 0, endpointsFlagged: 0, baselineFetched: false };

  // Fetch the baseline ONCE per scan (not per candidate) — both for efficiency
  // and so every candidate is compared against the exact same reference response.
  let baseline = null;
  try {
    baseline = await withTimeout(fetchRaw(`${baseUrl}${buildBaselinePath()}`, { timeoutMs: TIMEOUT_MS }), TIMEOUT_MS, 'Authorization baseline probe');
    metadata.baselineFetched = true;
  } catch {
    baseline = null; // proceed without a baseline — HTML classification will simply be more conservative (see classifyEndpoint)
  }

  for (const endpoint of CANDIDATE_ENDPOINTS) {
    metadata.endpointsChecked += 1;
    // eslint-disable-next-line no-await-in-loop
    let response;
    try {
      // eslint-disable-next-line no-await-in-loop
      response = await withTimeout(fetchRaw(`${baseUrl}${endpoint.path}`, { timeoutMs: TIMEOUT_MS }), TIMEOUT_MS, `Authorization probe ${endpoint.path}`);
    } catch {
      continue; // unreachable/timed out — inconclusive, skip (never flag on a failed request)
    }

    const classification = classifyEndpoint(endpoint, response, baseline);
    if (!classification) continue;

    const dedupeKey = `${domain}|${endpoint.path}|Missing Access Control`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    metadata.endpointsFlagged += 1;
    findings.push(buildFinding({ path: endpoint.path, classification }));
  }

  return { findings, metadata };
}

module.exports = {
  scanMissingAccessControl,
  classifyEndpoint, // exported for direct unit testing against synthetic responses
  CANDIDATE_ENDPOINTS
};