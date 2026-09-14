const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, SSRF_AND_NETWORK_CATEGORY, HOST_HEADER_INJECTION_SUB } = require('../constants');

const SCANNER_NAME = 'hostHeaderInjection';

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

// Helper to make HTTP/HTTPS request overriding the Host header without following redirects
function makeRequestWithHostHeader(urlString, customHost, method = 'GET', data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return reject(e);
    }

    const client = url.protocol === 'https:' ? https : http;
    
    // Inject the custom Host header
    const reqHeaders = {
      ...headers,
      'User-Agent': 'SecureScan/1.0 (+host-header-injection-scanner)',
      'Host': customHost
    };

    const options = {
      method,
      headers: reqHeaders,
      timeout: 5000
    };

    const req = client.request(url, options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 524288) req.destroy(); // 512KB maximum limit
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

/**
 * Host Header Injection Scanner
 */
async function scanHostHeaderInjection(domain, authContext = null, scanContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set();

  const headersPrimary = {};
  if (authContext) {
    if (authContext.headers) Object.assign(headersPrimary, authContext.headers);
    if (authContext.cookieJar) headersPrimary['Cookie'] = authContext.cookieJar;
  }

  try {
    // Safe Mode check
    const activeEnabled = process.env.HOST_HEADER_TEST === 'true';
    if (!activeEnabled) {
      metadata.skippedActive = true;
      return createResult(SCANNER_NAME, [], metadata, true);
    }

    const isLocal = isLocalTarget(domain);
    let activeCandidates = [];

    if (isLocal) {
      // Local target routes
      activeCandidates = [
        { path: '/api/test-host-header/vulnerable', method: 'GET' },
        { path: '/api/test-host-header/secure', method: 'GET' },
        { path: '/api/test-host-header/fake-200', method: 'GET' },
        { path: '/api/test-host-header/redirect', method: 'GET' }
      ];
    } else {
      // Production targets: Discover potential absolute URL generation endpoints
      const commonProbes = [
        { path: '/reset', method: 'GET' },
        { path: '/password-reset', method: 'GET' },
        { path: '/forgot-password', method: 'GET' },
        { path: '/verify', method: 'GET' },
        { path: '/activation', method: 'GET' },
        { path: '/invite', method: 'GET' },
        { path: '/email', method: 'GET' },
        { path: '/account', method: 'GET' },
        { path: '/profile', method: 'GET' },
        { path: '/auth', method: 'GET' },
        { path: '/login', method: 'GET' }
      ];

      for (const probe of commonProbes) {
        if (activeCandidates.length >= 10) break;
        try {
          const testUrl = `${baseUrl}${probe.path}`;
          metadata.checksPerformed.push(`HostHeaderProbe:${probe.method}:${probe.path}`);
          const res = await makeRequestWithHostHeader(testUrl, domain, probe.method, null, headersPrimary);

          // If the page exists (returns standard response rather than error/not found)
          if (res.statusCode !== 404 && res.statusCode !== 502 && res.statusCode !== 503) {
            activeCandidates.push(probe);
          }
        } catch (e) {
          // ignore
        }
      }
    }

    const payloadHost = 'attacker.example.test';

    for (const candidate of activeCandidates) {
      const { path: endpointPath, method } = candidate;
      let injectionConfirmed = false;
      let evidenceContent = '';
      let severityLevel = SEVERITY_LEVELS.MEDIUM;
      let cvssScore = 5.3;

      // Max 2 probes per endpoint
      let probeCount = 0;
      while (probeCount < 2 && !injectionConfirmed) {
        probeCount++;
        const targetUrl = `${baseUrl}${endpointPath}`;
        metadata.checksPerformed.push(`HostHeaderScanProbe:${method}:${endpointPath}:${probeCount}`);

        try {
          const res = await makeRequestWithHostHeader(targetUrl, payloadHost, method, null, headersPrimary);

          const locationHeader = res.headers['location'] || '';
          const body = res.body || '';

          // 1. Check for security-sensitive absolute URL generation in JSON/HTML
          // Redact secrets/tokens from the evidence.
          const resetPattern = /https?:\/\/attacker\.example\.test\/reset\/[a-zA-Z0-9_\-]+/i;
          const verifyPattern = /https?:\/\/attacker\.example\.test\/verify\/[a-zA-Z0-9_\-]+/i;
          const invitePattern = /https?:\/\/attacker\.example\.test\/invite\/[a-zA-Z0-9_\-]+/i;
          const generalSensitivePattern = /https?:\/\/attacker\.example\.test\/(password|auth|login|account|token)/i;

          const isRedirectStatus = res.statusCode >= 300 && res.statusCode < 400;

          if (isRedirectStatus) {
            if (locationHeader && locationHeader.includes(payloadHost)) {
              // Deduplicate against Open Redirect to prevent duplicate findings
              const isAlreadyOpenRedirect = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path: endpointPath,
                status: { $ne: 'Resolved' },
                category: 'Client Side',
                subCategory: 'Open Redirect'
              });

              if (!isAlreadyOpenRedirect) {
                evidenceContent = `Application trusted the Host header to construct a redirect Location header: ${locationHeader}`;
                severityLevel = SEVERITY_LEVELS.MEDIUM;
                cvssScore = 5.3;
                injectionConfirmed = true;
                break;
              }
            }
          } else {
            // Only evaluate body contents on non-redirect responses
            let matchedUrl = '';
            if (resetPattern.test(body)) {
              matchedUrl = body.match(resetPattern)[0];
              severityLevel = SEVERITY_LEVELS.HIGH;
              cvssScore = 7.3;
            } else if (verifyPattern.test(body)) {
              matchedUrl = body.match(verifyPattern)[0];
              severityLevel = SEVERITY_LEVELS.HIGH;
              cvssScore = 7.3;
            } else if (invitePattern.test(body)) {
              matchedUrl = body.match(invitePattern)[0];
              severityLevel = SEVERITY_LEVELS.HIGH;
              cvssScore = 7.3;
            } else if (generalSensitivePattern.test(body)) {
              matchedUrl = body.match(generalSensitivePattern)[0];
              severityLevel = SEVERITY_LEVELS.MEDIUM;
              cvssScore = 5.3;
            }

            if (matchedUrl) {
              // Sanitize / Redact token/secrets in evidence
              const sanitizedUrl = matchedUrl.replace(/(\/reset\/|\/verify\/|\/invite\/)([a-zA-Z0-9_\-]+)/i, '$1[REDACTED]');
              evidenceContent = `Application generated a security-sensitive absolute URL using the attacker-controlled Host header. Observed URL: ${sanitizedUrl}`;
              injectionConfirmed = true;
              break;
            }
          }
        } catch (err) {
          // ignore
        }
      }

      if (injectionConfirmed) {
        const dedupeKey = `${domain}|${endpointPath}|HostHeaderInjection`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);

          // Deduplicate against MongoDB database
          const existingFinding = await Vulnerability.findOne({
            domainId: scanContext?.domainId,
            path: endpointPath,
            status: { $ne: 'Resolved' },
            category: SSRF_AND_NETWORK_CATEGORY,
            subCategory: HOST_HEADER_INJECTION_SUB
          });

          if (existingFinding) {
            metadata.correlations = (metadata.correlations || 0) + 1;
          } else {
            findings.push(
              createFinding({
                name: 'Host Header Injection',
                desc: `The application implicitly trusts the HTTP Host header value and uses it to construct absolute security-sensitive URLs (such as password reset links, verification links, or redirect locations) or to perform critical security operations.`,
                severity: severityLevel,
                cwe: 'CWE-74',
                path: endpointPath,
                parameter: 'Host Header',
                impact: 'If an attacker can manipulate the Host header, they can cause the application to generate password-reset or email verification links pointing to an attacker-controlled server. When victims click the link, their reset token or session secret is sent directly to the attacker, leading to complete account takeover.',
                fix: 'Always use a statically configured canonical origin (e.g. read from an environment configuration file) when constructing absolute URLs in security-sensitive operations. Avoid constructing URLs using req.headers.host. Ensure your web server or reverse proxy validates Host headers against an allowed whitelist.',
                scanner: SCANNER_NAME,
                category: SSRF_AND_NETWORK_CATEGORY,
                subCategory: HOST_HEADER_INJECTION_SUB,
                cvssScore,
                evidence: evidenceContent,
                references: [
                  'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection',
                  'https://portswigger.net/web-security/host-header'
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
  scanHostHeaderInjection
};
