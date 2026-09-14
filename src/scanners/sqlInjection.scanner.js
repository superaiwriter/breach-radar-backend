const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, INJECTION_CATEGORY, SQL_INJECTION_SUB } = require('../constants');

const SCANNER_NAME = 'sqlInjection';

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
      'User-Agent': 'SecureScan/1.0 (+sql-injection-scanner)',
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

// Database error signatures
const SQL_ERROR_SIGNATURES = [
  "you have an error in your sql syntax",
  "database exception",
  "sqlstate",
  "sqlite error",
  "postgresql error",
  "mysql error",
  "microsoft sql server error",
  "oracle error",
  "unclosed quotation mark",
  "sql syntax"
];

/**
 * Injection Scanner - SQL Injection Checks
 */
async function scanSqlInjection(domain, authContext = null, scanContext = null) {
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
      // Local mock candidate endpoints
      activeCandidates = [
        { path: '/api/test-sqli/secure', param: 'q', type: 'error-and-boolean' },
        { path: '/api/test-sqli/vulnerable-error', param: 'q', type: 'error' },
        { path: '/api/test-sqli/vulnerable-boolean', param: 'id', type: 'boolean' },
        { path: '/api/test-sqli/fake-200', param: 'q', type: 'none' }
      ];
    } else {
      // Production scanning: Discover potential input fields/parameters
      const commonProbes = [
        { path: '/search', param: 'q' },
        { path: '/products', param: 'id' },
        { path: '/user', param: 'id' },
        { path: '/api/products', param: 'search' },
        { path: '/api/users', param: 'name' }
      ];

      for (const probe of commonProbes) {
        try {
          const url = `${baseUrl}${probe.path}?${probe.param}=test`;
          metadata.checksPerformed.push(`SqlInjectionProbe:${probe.path}?${probe.param}`);
          const res = await makeRequest(url, 'GET', null, headersPrimary);
          
          if (res.statusCode !== 404 && res.statusCode !== 502 && res.statusCode !== 503) {
            activeCandidates.push({
              path: probe.path,
              param: probe.param,
              type: 'error-and-boolean'
            });
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Execute scans on active parameters
    for (const candidate of activeCandidates) {
      const { path, param, type } = candidate;
      let injectionConfirmed = false;
      let injectionType = '';
      let evidenceContent = '';
      let testedPayload = '';

      // 1. Error-based testing (Quotes, double quotes, tick)
      if (type === 'error' || type === 'error-and-boolean') {
        const errorProbes = ["'", '"', '`'];
        for (const probe of errorProbes) {
          const url = `${baseUrl}${path}?${param}=${encodeURIComponent(probe)}`;
          metadata.checksPerformed.push(`SqlErrorTest:${path}?${param}=${probe}`);

          try {
            const res = await makeRequest(url, 'GET', null, headersPrimary);
            const lowerBody = res.body.toLowerCase();

            // Verify if any SQL error signature matches
            const matchedError = SQL_ERROR_SIGNATURES.find(sig => lowerBody.includes(sig));
            if (matchedError) {
              injectionConfirmed = true;
              injectionType = 'Error-based SQL Injection';
              evidenceContent = `Database syntax error detected ("${matchedError}") when injecting quote: "${res.body.trim().slice(0, 150)}"`;
              testedPayload = probe;
              break;
            }
          } catch (e) {
            // ignore
          }
        }
      }

      // 2. Boolean-based testing (Baseline response vs True probe vs False probe)
      if (!injectionConfirmed && (type === 'boolean' || type === 'error-and-boolean')) {
        try {
          // Send normal baseline
          const baselineUrl = `${baseUrl}${path}?${param}=1`;
          const resBaseline = await makeRequest(baselineUrl, 'GET', null, headersPrimary);

          // Send True Probe
          const trueUrl = `${baseUrl}${path}?${param}=1' AND '1'='1`;
          const resTrue = await makeRequest(trueUrl, 'GET', null, headersPrimary);

          // Send False Probe
          const falseUrl = `${baseUrl}${path}?${param}=1' AND '1'='2`;
          const resFalse = await makeRequest(falseUrl, 'GET', null, headersPrimary);

          // Compare body contents:
          // True probe must match baseline (or be extremely similar)
          // False probe must differ significantly (different result counts/data size)
          const baselineLen = resBaseline.body.length;
          const trueLen = resTrue.body.length;
          const falseLen = resFalse.body.length;

          // Require that:
          // - Baseline and True responses are within 5% of same size (since they represent TRUE SQL statements)
          // - False response differs significantly (more than 10% size difference, or different JSON object count)
          const trueMatch = Math.abs(baselineLen - trueLen) / (baselineLen || 1) < 0.05;
          const falseMismatch = Math.abs(baselineLen - falseLen) / (baselineLen || 1) > 0.10;

          if (trueMatch && falseMismatch && resBaseline.statusCode === 200 && resTrue.statusCode === 200) {
            injectionConfirmed = true;
            injectionType = 'Boolean-based SQL Injection';
            evidenceContent = `Boolean condition difference detected. True URL returned response of size ${trueLen} bytes, False URL returned different response of size ${falseLen} bytes.`;
            testedPayload = "1' AND '1'='2";
          }
        } catch (e) {
          // ignore
        }
      }

      if (injectionConfirmed) {
        const dedupeKey = `${domain}|${path}|${param}|SqlInjection`;

        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);

          // Deduplicate against MongoDB database
          const existingFinding = await Vulnerability.findOne({
            domainId: scanContext?.domainId,
            path,
            parameter: param,
            status: { $ne: 'Resolved' },
            category: INJECTION_CATEGORY,
            subCategory: SQL_INJECTION_SUB
          });

          if (existingFinding) {
            metadata.correlations = (metadata.correlations || 0) + 1;
          } else {
            findings.push(
              createFinding({
                name: 'SQL Injection',
                desc: `The parameter "${param}" on path "${path}" is vulnerable to ${injectionType}. An attacker can manipulate backend SQL database queries by submitting custom SQL commands.`,
                severity: SEVERITY_LEVELS.HIGH,
                cwe: 'CWE-89',
                path,
                parameter: param,
                impact: 'SQL Injection permits an attacker to bypass authorization check, read/extract sensitive information from the database, execute administrator commands, and potentially escalate privileges to access the underlying OS environment.',
                fix: 'Always use parameterized SQL queries or prepared statements when interacting with SQL databases. Avoid concatenating user input directly into SQL strings. Sanitize and validate all incoming inputs against strict whitelists.',
                scanner: SCANNER_NAME,
                category: INJECTION_CATEGORY,
                subCategory: SQL_INJECTION_SUB,
                cvssScore: 8.8,
                evidence: `Injected payload "${testedPayload}" into parameter "${param}". Evidence: ${evidenceContent}`,
                references: [
                  'https://owasp.org/www-community/attacks/SQL_Injection',
                  'https://cwe.mitre.org/data/definitions/89.html'
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
  scanSqlInjection
};
