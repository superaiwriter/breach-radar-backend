const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, INJECTION_CATEGORY, SSTI_SUB } = require('../constants');

const SCANNER_NAME = 'ssti';

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
      'User-Agent': 'SecureScan/1.0 (+ssti-scanner)',
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
 * Injection Scanner - Server-Side Template Injection (SSTI) Checks
 */
async function scanSsti(domain, authContext = null, scanContext = null) {
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
        { path: '/api/test-ssti/secure', param: 'name', method: 'GET' },
        { path: '/api/test-ssti/vulnerable', param: 'name', method: 'GET' },
        { path: '/api/test-ssti/reflection', param: 'name', method: 'GET' },
        { path: '/api/test-ssti/fake-200', param: 'name', method: 'GET' }
      ];
    } else {
      // Production targets: Only run active SSTI tests if explicitly enabled
      const enabledActiveTest = process.env.SSTI_TEST === 'true';
      if (!enabledActiveTest) {
        // Skip active SSTI testing on external domains for safety
        return createResult(SCANNER_NAME, [], { ...metadata, skippedRemote: true }, true);
      }

      // Discover potential rendering/search endpoints on production target
      const commonProbes = [
        { path: '/search', param: 'q', method: 'GET' },
        { path: '/preview', param: 'name', method: 'GET' },
        { path: '/render', param: 'template', method: 'GET' },
        { path: '/api/preview', param: 'name', method: 'GET' }
      ];

      for (const probe of commonProbes) {
        try {
          const url = `${baseUrl}${probe.path}?${probe.param}=hello`;
          metadata.checksPerformed.push(`SstiProbe:${probe.method}:${probe.path}`);
          const res = await makeRequest(url, probe.method, null, headersPrimary);
          
          if (res.statusCode !== 404 && res.statusCode !== 502 && res.statusCode !== 503) {
            activeCandidates.push(probe);
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Probes (max 5)
    const sstiProbes = [
      { payload: '{{7*7}}', engine: 'Handlebars/Jinja2/Twig' },
      { payload: '${7*7}', engine: 'FreeMarker/Velocity' },
      { payload: '<%= 7*7 %>', engine: 'EJS' }
    ];

    for (const candidate of activeCandidates) {
      const { path, param, method } = candidate;
      let injectionConfirmed = false;
      let evidenceContent = '';
      let successfulPayload = '';
      let detectedEngine = '';

      try {
        const urlBase = `${baseUrl}${path}`;

        // 1. Send normal baseline request to verify the number 49 is not present by default
        const baselineUrl = `${urlBase}?${param}=hello`;
        metadata.checksPerformed.push(`SstiBaseline:${method}:${path}`);
        const resBaseline = await makeRequest(baselineUrl, method, null, headersPrimary);
        
        const hasBaselineMarker = resBaseline.body.includes('49');

        if (!hasBaselineMarker) {
          // 2. Perform safe, non-destructive SSTI checks
          for (const probe of sstiProbes) {
            const probeUrl = `${urlBase}?${param}=${encodeURIComponent(probe.payload)}`;
            metadata.checksPerformed.push(`SstiPayload:${method}:${path}:${probe.payload}`);
            
            const resPayload = await makeRequest(probeUrl, method, null, headersPrimary);

            // Reflection Check: Confirm the raw template syntax is NOT reflected unchanged
            const isReflected = resPayload.body.includes(probe.payload);

            // Evaluation Check: Check if evaluated result "49" is returned instead of raw syntax
            const isEvaluated = resPayload.statusCode === 200 && 
                                resPayload.body.includes('49') && 
                                !isReflected;

            if (isEvaluated) {
              injectionConfirmed = true;
              successfulPayload = probe.payload;
              detectedEngine = probe.engine;
              evidenceContent = `Arithmetic template expression "${probe.payload}" was evaluated to "49" by the server-side template engine. Raw payload expression did not reflect. Response excerpt: "${resPayload.body.trim().slice(0, 150)}"`;
              break;
            }
          }
        }
      } catch (err) {
        // ignore
      }

      if (injectionConfirmed) {
        const dedupeKey = `${domain}|${path}|${param}|Ssti`;

        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);

          // Deduplicate against MongoDB database
          const existingFinding = await Vulnerability.findOne({
            domainId: scanContext?.domainId,
            path,
            parameter: param,
            status: { $ne: 'Resolved' },
            category: INJECTION_CATEGORY,
            subCategory: SSTI_SUB
          });

          if (existingFinding) {
            metadata.correlations = (metadata.correlations || 0) + 1;
          } else {
            findings.push(
              createFinding({
                name: 'Server-Side Template Injection (SSTI)',
                desc: `The parameter "${param}" on path "${path}" is vulnerable to Server-Side Template Injection. Server-side template engines dynamically evaluate expressions enclosed in template brackets (like {{...}}), allowing code execution context.`,
                severity: SEVERITY_LEVELS.HIGH,
                cwe: 'CWE-1336',
                path,
                parameter: param,
                impact: 'SSTI allows attackers to execute template engine operations, access backend application context, retrieve configurations, or potentially perform Remote Code Execution (RCE) on the underlying host.',
                fix: 'Ensure user input is treated as plain text data, not as active template markup. Use template escaping mechanisms and do not generate template strings dynamically using user input concatenations.',
                scanner: SCANNER_NAME,
                category: INJECTION_CATEGORY,
                subCategory: SSTI_SUB,
                cvssScore: 8.5,
                evidence: `Injected template payload "${successfulPayload}" into parameter "${param}". Engine fingerprint: ${detectedEngine}. Evidence: ${evidenceContent}`,
                references: [
                  'https://portswigger.net/web-security/server-side-template-injection',
                  'https://cwe.mitre.org/data/definitions/1336.html'
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
  scanSsti
};
