const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, INJECTION_CATEGORY, NOSQL_INJECTION_SUB } = require('../constants');

const SCANNER_NAME = 'noSqlInjection';

// Helper to construct baseUrl based on local vs public domain
function getBaseUrl(domain) {
  const isLocal = domain.includes('localhost') || domain.includes('127.0.0.1');
  return isLocal ? `http://${domain}` : `https://${domain}`;
}

// Robust check for local targets (localhost, 127.0.0.1, ::1)
function isLocalTarget(domain) {
  if (!domain) return false;
  let host = domain.trim().toLowerCase();
  if (!host.startsWith('http://') && !host.startsWith('https://')) {
    host = 'http://' + host;
  }
  try {
    const parsed = new URL(host);
    const hostname = parsed.hostname;
    const cleanHostname = hostname.replace(/^\[|\]$/g, '');
    return cleanHostname === 'localhost' || cleanHostname === '127.0.0.1' || cleanHostname === '::1';
  } catch (e) {
    let parts = domain.split(':');
    let hostname = parts[0].trim().toLowerCase();
    hostname = hostname.replace(/^\[|\]$/g, '');
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  }
}

// Helper to make HTTP/HTTPS requests
function makeRequest(urlString, method = 'GET', data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return reject(e);
    }

    const client = url.protocol === 'https:' ? https : http;
    const reqHeaders = {
      'User-Agent': 'SecureScan/1.0 (+nosql-injection-scanner)',
      ...headers
    };

    let postData = '';
    if (data) {
      if (typeof data === 'object') {
        postData = JSON.stringify(data);
        reqHeaders['Content-Type'] = 'application/json';
      } else {
        postData = String(data);
        reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
      }
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const options = {
      method,
      headers: reqHeaders,
      timeout: 5000
    };

    const req = client.request(url, options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1048576) req.destroy(); // 1MB maximum limit
      });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    req.on('error', req.destroy ? req.destroy : reject);

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

/**
 * Injection Scanner - NoSQL Injection Checks
 */
async function scanNoSqlInjection(domain, authContext = null, scanContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set(); // Deduplication guard

  const headersPrimary = {};
  if (authContext) {
    if (authContext.headers) Object.assign(headersPrimary, authContext.headers);
    if (authContext.cookieJar) headersPrimary['Cookie'] = authContext.cookieJar;
  }

  try {
    const isLocal = isLocalTarget(domain);
    let activeCandidates = [];

    if (isLocal) {
      // Local target routes
      activeCandidates = [
        { path: '/api/test-nosql/secure-login', method: 'POST' },
        { path: '/api/test-nosql/vulnerable-login', method: 'POST' },
        { path: '/api/test-nosql/fake-200-login', method: 'POST' }
      ];
    } else {
      // Production targets: Only run active NoSQL Injection tests if explicitly enabled
      const enabledActiveTest = process.env.NOSQL_INJECTION_TEST === 'true';
      if (!enabledActiveTest) {
        // Skip active NoSQL injection testing on external domains for safety
        return createResult(SCANNER_NAME, [], { ...metadata, skippedRemote: true }, true);
      }

      // Discover login/authentication and search endpoints on production target
      const commonProbes = [
        { path: '/login', method: 'POST' },
        { path: '/api/login', method: 'POST' },
        { path: '/api/authenticate', method: 'POST' },
        { path: '/api/users/search', method: 'POST' }
      ];

      for (const probe of commonProbes) {
        try {
          const url = `${baseUrl}${probe.path}`;
          metadata.checksPerformed.push(`NoSqlProbe:${probe.method}:${probe.path}`);
          const res = await makeRequest(url, probe.method, {}, headersPrimary);
          
          if (res.statusCode !== 404 && res.statusCode !== 502 && res.statusCode !== 503) {
            activeCandidates.push(probe);
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Probes: Max 10 test payloads per parameter/field
    const payloads = [
      // Standard MongoDB operator bypass payload
      { username: { "$ne": "wrong-username" }, password: { "$ne": "wrong-password" } },
      // Submitting object operators as string replacements
      { username: { "$gt": "" }, password: { "$gt": "" } }
    ];

    for (const candidate of activeCandidates) {
      const { path, method } = candidate;
      let bypassConfirmed = false;
      let evidenceContent = '';
      let successfulPayload = null;

      try {
        // 1. Send normal baseline (known incorrect credentials)
        const baselinePayload = { username: 'test-user-nonexistent', password: 'wrong-password-val' };
        const url = `${baseUrl}${path}`;
        
        metadata.checksPerformed.push(`NoSqlBaseline:${method}:${path}`);
        const resBaseline = await makeRequest(url, method, baselinePayload, headersPrimary);
        
        // Analyze baseline response (fails authentication)
        const baselineSuccess = resBaseline.statusCode === 200 && 
                                (resBaseline.body.includes('"success":true') || 
                                 resBaseline.body.includes('"token"') ||
                                 resBaseline.headers['set-cookie']);

        // Only test operators if the baseline request fails login (not already bypassed by default)
        if (!baselineSuccess) {
          for (const payload of payloads) {
            metadata.checksPerformed.push(`NoSqlPayload:${method}:${path}:${JSON.stringify(payload)}`);
            const resPayload = await makeRequest(url, method, payload, headersPrimary);

            // Authentication bypass criteria:
            // 1. HTTP 200 status code
            // 2. Success flag is true, or session token is returned in JSON, or cookies are set
            // 3. Fake-200 endpoint fails because it returns success: false
            const bodyParsed = resPayload.body.toLowerCase();
            const hasSuccess = bodyParsed.includes('"success":true') || bodyParsed.includes('"token"') || resPayload.headers['set-cookie'];
            const isBypassed = resPayload.statusCode === 200 && hasSuccess;

            if (isBypassed) {
              bypassConfirmed = true;
              evidenceContent = `Authentication bypassed using operator payload. Baseline request returned HTTP ${resBaseline.statusCode}, operator request returned HTTP 200 with success indicator: "${resPayload.body.trim().slice(0, 150)}"`;
              successfulPayload = payload;
              break;
            }
          }
        }
      } catch (err) {
        // ignore
      }

      if (bypassConfirmed) {
        const dedupeKey = `${domain}|${path}|NoSqlInjection`;

        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);

          // Deduplicate against MongoDB database
          const existingFinding = await Vulnerability.findOne({
            domainId: scanContext?.domainId,
            path,
            status: { $ne: 'Resolved' },
            category: INJECTION_CATEGORY,
            subCategory: NOSQL_INJECTION_SUB
          });

          if (existingFinding) {
            metadata.correlations = (metadata.correlations || 0) + 1;
          } else {
            // Redact credentials in the stored evidence/finding
            const redactedPayload = { username: '***[REDACTED_NOSQL_OPERATOR]***', password: '***[REDACTED_NOSQL_OPERATOR]***' };

            findings.push(
              createFinding({
                name: 'NoSQL Injection',
                desc: `The endpoint at "${path}" allows NoSQL Injection. An attacker can supply MongoDB operators (e.g. "$ne", "$gt") to bypass authentication checks or modify backend query context.`,
                severity: SEVERITY_LEVELS.HIGH,
                cwe: 'CWE-943',
                path,
                impact: 'NoSQL Injection allows attackers to bypass authentication schemas, extract database records, retrieve user roles/credentials, or access unauthorized operational context without permissions.',
                fix: 'Validate all inputs against strict expected schemas on the server side. Ensure query parameters are cast explicitly to strings before query execution. Use parameterized query libraries or validation layers (like Express Validator) to strip operator structures.',
                scanner: SCANNER_NAME,
                category: INJECTION_CATEGORY,
                subCategory: NOSQL_INJECTION_SUB,
                cvssScore: 8.5,
                evidence: `Injected NoSQL payload ${JSON.stringify(redactedPayload)} on path "${path}". Evidence: ${evidenceContent}`,
                references: [
                  'https://owasp.org/www-pdf-archive/OWASP_IL_NoSQL_Injection.pdf',
                  'https://cwe.mitre.org/data/definitions/943.html'
                ]
              })
            );
          }
        }
      }
    }
  } catch (globalErr) {
    return createResult(SCANNER_NAME, [], { error: globalErr.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanNoSqlInjection
};
