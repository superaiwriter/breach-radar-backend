const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, CLOUD_INFRASTRUCTURE_CATEGORY, DEBUG_MODE_SUB } = require('../constants');

const SCANNER_NAME = 'debugMode';

function getBaseUrl(domain) {
  const isLocal = domain.includes('localhost') || domain.includes('127.0.0.1');
  return isLocal ? `http://${domain}` : `https://${domain}`;
}

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

function makeRequest(urlString, method = 'GET', headers = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return reject(e);
    }

    const client = url.protocol === 'https:' ? https : http;
    const reqHeaders = {
      'User-Agent': 'SecureScan/1.0 (+debug-mode-scanner)',
      ...headers
    };

    const options = {
      method,
      headers: reqHeaders,
      timeout: 4000
    };

    const req = client.request(url, options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 200000) req.destroy(); // 200KB limit for verification
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

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });
}

function detectDebugBehavior(res) {
  const headers = Object.keys(res.headers).reduce((acc, k) => {
    acc[k.toLowerCase()] = String(res.headers[k]);
    return acc;
  }, {});

  const body = res.body || '';

  const debugHeaders = [
    'x-debug-token',
    'x-symfony-debug-toolbar',
    'x-laravel-debugbar',
    'x-debug-enabled',
    'x-debug-mode'
  ];
  for (const header of debugHeaders) {
    if (headers[header]) {
      return {
        detected: true,
        evidence: `Detected debug header: "${header}: ${headers[header]}"`
      };
    }
  }

  if (body.includes('phpinfo()') && (body.includes('PHP Version') || body.includes('PHP License'))) {
    return {
      detected: true,
      evidence: `Detected phpinfo() output containing system and runtime configurations.`
    };
  }

  if (body.includes('DEBUG = True') && body.includes('Django') && body.includes('settings.py')) {
    return {
      detected: true,
      evidence: `Detected Django Debug Mode page containing settings and local environment details.`
    };
  }

  if (body.includes('Symfony Exception') || body.includes('class="exception-message-wrapper"')) {
    return {
      detected: true,
      evidence: `Detected Symfony Debug Exception page.`
    };
  }

  // Look for stack trace structures
  if (/at\s+.*\(.*:[0-9]+:[0-9]+\)/.test(body) && (body.includes('node_modules') || body.includes('processTicksAndRejections') || body.includes('Stack Trace'))) {
    let cleanedTrace = body.replace(/\/Users\/[a-zA-Z0-9_\-]+\//g, '/Users/[REDACTED]/').slice(0, 300).trim();
    return {
      detected: true,
      evidence: `Exposed verbose stack trace: "${cleanedTrace}"`
    };
  }

  return { detected: false };
}

async function scanDebugMode(domain, authContext = null, scanContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set();

  const reqHeaders = {};
  if (authContext) {
    if (authContext.headers) Object.assign(reqHeaders, authContext.headers);
    if (authContext.cookieJar) reqHeaders['Cookie'] = authContext.cookieJar;
  }

  try {
    const isLocal = isLocalTarget(domain);
    let pathsToTest = [
      '/',
      '/debug',
      '/phpinfo.php',
      '/info.php'
    ];

    if (isLocal) {
      pathsToTest.push('/api/test-debug-mode/vulnerable/trace');
      pathsToTest.push('/api/test-debug-mode/secure/trace');
    }

    for (const testPath of pathsToTest) {
      const targetUrl = `${baseUrl}${testPath}`;
      metadata.checksPerformed.push(`DebugMode:${testPath}`);

      try {
        const res = await makeRequest(targetUrl, 'GET', reqHeaders);

        const debugResult = detectDebugBehavior(res);
        if (debugResult.detected) {
          const dedupeKey = `${domain}|${testPath}|DebugMode`;

          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against MongoDB database
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path: testPath,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: DEBUG_MODE_SUB
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              findings.push(
                createFinding({
                  name: 'Debug Mode Enabled',
                  desc: `The application or framework has debugging or verbose error mode enabled. This exposes internal stack traces, configurations, system directories, or debug headers.`,
                  severity: SEVERITY_LEVELS.MEDIUM,
                  cwe: 'CWE-489',
                  path: testPath,
                  parameter: '',
                  impact: 'Enabling debug mode helps attackers map internal code structures, find system usernames, and identify vulnerable software versions or libraries.',
                  fix: 'Disable debug mode, verbose error display, or framework profiling features in production settings (e.g. set "DEBUG = False" in Django, "app.debug = false" in Flask, or environment variables like "NODE_ENV=production").',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: DEBUG_MODE_SUB,
                  cvssScore: 5.3,
                  evidence: debugResult.evidence,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration',
                    'https://cwe.mitre.org/data/definitions/489.html'
                  ]
                })
              );
            }
          }
        }
      } catch (err) {
        // ignore individual request failures
      }
    }
  } catch (globalErr) {
    return createResult(SCANNER_NAME, [], { error: globalErr.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanDebugMode
};
