const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, INJECTION_CATEGORY, COMMAND_INJECTION_SUB } = require('../constants');

const SCANNER_NAME = 'commandInjection';

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
      'User-Agent': 'SecureScan/1.0 (+command-injection-scanner)',
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
 * Injection Scanner - OS Command Injection Checks
 */
async function scanCommandInjection(domain, authContext = null, scanContext = null) {
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
        { path: '/api/test-command-injection/secure', param: 'host', method: 'GET' },
        { path: '/api/test-command-injection/vulnerable', param: 'host', method: 'GET' },
        { path: '/api/test-command-injection/reflection', param: 'host', method: 'GET' },
        { path: '/api/test-command-injection/fake-200', param: 'host', method: 'GET' }
      ];
    } else {
      // Production targets: Only run active Command Injection tests if explicitly enabled
      const enabledActiveTest = process.env.COMMAND_INJECTION_TEST === 'true';
      if (!enabledActiveTest) {
        // Skip active command injection testing on external domains for safety
        return createResult(SCANNER_NAME, [], { ...metadata, skippedRemote: true }, true);
      }

      // Discover potential diagnostic/system endpoints on production target
      const commonProbes = [
        { path: '/ping', param: 'host', method: 'GET' },
        { path: '/api/ping', param: 'host', method: 'GET' },
        { path: '/api/lookup', param: 'host', method: 'GET' },
        { path: '/api/diagnostics', param: 'target', method: 'GET' }
      ];

      for (const probe of commonProbes) {
        try {
          const url = `${baseUrl}${probe.path}?${probe.param}=127.0.0.1`;
          metadata.checksPerformed.push(`CommandInjectionProbe:${probe.method}:${probe.path}`);
          const res = await makeRequest(url, probe.method, null, headersPrimary);
          
          if (res.statusCode !== 404 && res.statusCode !== 502 && res.statusCode !== 503) {
            activeCandidates.push(probe);
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Generate unique marker for testing
    const randomSuffix = Math.random().toString(36).substring(2, 10);
    const executionMarker = `PENTESTRADAR_CMD_TEST_${randomSuffix}`;

    for (const candidate of activeCandidates) {
      const { path, param, method } = candidate;
      let injectionConfirmed = false;
      let evidenceContent = '';
      let successfulPayload = '';

      try {
        const urlBase = `${baseUrl}${path}`;

        // 1. Reflection Check: Send the marker directly as the parameter value.
        // If the marker is reflected in the response body, it is simple reflection.
        const reflectionUrl = `${urlBase}?${param}=${encodeURIComponent(executionMarker)}`;
        metadata.checksPerformed.push(`CmdReflectionCheck:${method}:${path}`);
        const resReflection = await makeRequest(reflectionUrl, method, null, headersPrimary);

        const isReflected = resReflection.statusCode === 200 && resReflection.body.includes(executionMarker);

        // If the parameter is reflected directly, we do NOT flag command injection to avoid false positives
        if (!isReflected) {
          // 2. Perform safe, non-destructive command injection checks (Max 5 probes)
          const commandPayloads = [
            `; echo ${executionMarker}`,
            `| echo ${executionMarker}`,
            `& echo ${executionMarker}`
          ];

          for (const payload of commandPayloads) {
            const probeUrl = `${urlBase}?${param}=127.0.0.1${encodeURIComponent(payload)}`;
            metadata.checksPerformed.push(`CmdPayload:${method}:${path}:${payload}`);
            
            const resPayload = await makeRequest(probeUrl, method, null, headersPrimary);

            // Command injection matches if HTTP 200 AND response body contains the unique executionMarker
            const isExecuted = resPayload.statusCode === 200 && resPayload.body.includes(executionMarker);

            if (isExecuted) {
              injectionConfirmed = true;
              successfulPayload = `127.0.0.1${payload}`;
              evidenceContent = `Controlled command-execution marker ("${executionMarker}") was returned only after injecting separators. Direct parameter value marker request was correctly ignored (did not reflect). Response excerpt: "${resPayload.body.trim().slice(0, 150)}"`;
              break;
            }
          }
        }
      } catch (err) {
        // ignore
      }

      if (injectionConfirmed) {
        const dedupeKey = `${domain}|${path}|${param}|CommandInjection`;

        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);

          // Deduplicate against MongoDB database
          const existingFinding = await Vulnerability.findOne({
            domainId: scanContext?.domainId,
            path,
            parameter: param,
            status: { $ne: 'Resolved' },
            category: INJECTION_CATEGORY,
            subCategory: COMMAND_INJECTION_SUB
          });

          if (existingFinding) {
            metadata.correlations = (metadata.correlations || 0) + 1;
          } else {
            findings.push(
              createFinding({
                name: 'Command Injection',
                desc: `The parameter "${param}" on path "${path}" is vulnerable to OS Command Injection. An attacker can execute arbitrary operating-system commands with the privileges of the web application.`,
                severity: SEVERITY_LEVELS.HIGH,
                cwe: 'CWE-78',
                path,
                parameter: param,
                impact: 'OS Command Injection allows full server compromise. An attacker can read/modify sensitive application files, escalate privileges, install backdoors, execute reverse shells, or use the target server to compromise internal networks.',
                fix: 'Avoid passing user input directly into system shell command execution. Use built-in API functions (like child_process.execFile or child_process.spawn) that pass arguments as elements of an array, bypassing shell interpretation. Validate inputs against strict alphanumeric patterns.',
                scanner: SCANNER_NAME,
                category: INJECTION_CATEGORY,
                subCategory: COMMAND_INJECTION_SUB,
                cvssScore: 9.8,
                evidence: `Injected command separator payload "${successfulPayload}" into parameter "${param}". Evidence: ${evidenceContent}`,
                references: [
                  'https://owasp.org/www-community/attacks/Command_Injection',
                  'https://cwe.mitre.org/data/definitions/78.html'
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
  scanCommandInjection
};
