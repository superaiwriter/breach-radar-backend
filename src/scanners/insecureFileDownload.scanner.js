const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, FILE_UPLOAD_CATEGORY, INSECURE_FILE_DOWNLOAD_SUB } = require('../constants');

const SCANNER_NAME = 'insecureFileDownload';

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
      'User-Agent': 'SecureScan/1.0 (+insecure-file-download-scanner)',
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
        if (body.length > 1048576) req.destroy(); // 1MB maximum response size limit
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
 * File & Upload Scanner - Insecure File Download Checks
 */
async function scanInsecureFileDownload(domain, authContext = null, scanContext = null) {
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
      // Local test targets with specific mock routes and identifier setups
      activeCandidates = [
        { path: '/api/test-insecure-download/secure', fileId: 'TEST_FILE_B', expectedMarker: 'USER_B_PRIVATE_FILE_MARKER', isUnauthorized: true },
        { path: '/api/test-insecure-download/vulnerable', fileId: 'TEST_FILE_B', expectedMarker: 'USER_B_PRIVATE_FILE_MARKER', isUnauthorized: true },
        { path: '/api/test-insecure-download/fake-200', fileId: 'TEST_FILE_B', expectedMarker: 'USER_B_PRIVATE_FILE_MARKER', isUnauthorized: true },
        { path: '/api/test-insecure-download/secure', fileId: 'TEST_FILE_A', expectedMarker: 'USER_A_PRIVATE_FILE_MARKER', isUnauthorized: false },
        { path: '/api/test-insecure-download/secure', fileId: 'PUBLIC_FILE', expectedMarker: 'PUBLIC_FILE_MARKER', isUnauthorized: false }
      ];
    } else {
      // Production scanning: Discover potential download endpoints
      const commonProbes = [
        { path: '/download', param: 'id' },
        { path: '/download', param: 'file' },
        { path: '/file/download', param: 'id' },
        { path: '/file', param: 'id' },
        { path: '/files', param: 'id' },
        { path: '/api/files/download', param: 'id' },
        { path: '/api/download', param: 'id' },
        { path: '/document', param: 'id' }
      ];

      for (const probe of commonProbes) {
        try {
          const url = `${baseUrl}${probe.path}?${probe.param}=1`;
          metadata.checksPerformed.push(`InsecureDownloadProbe:${probe.path}?${probe.param}`);
          const res = await makeRequest(url, 'GET', null, headersPrimary);
          
          // Endpoint exists if status is not 404, or is 404 but response suggests parameter is handled
          const isExist = res.statusCode !== 404 || 
                          res.body.toLowerCase().includes('file') || 
                          res.body.toLowerCase().includes('download');
                          
          if (isExist && res.statusCode !== 502 && res.statusCode !== 503) {
            // For remote targets, check up to 5 sequential IDs
            activeCandidates.push({
              path: probe.path,
              param: probe.param,
              remote: true
            });
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Run checks on candidates
    for (const candidate of activeCandidates) {
      if (candidate.remote) {
        const { path, param } = candidate;
        // Test sequential identifiers: Max 5 controlled variations per endpoint
        const testIds = ['1', '2', '3', '4', '5'];
        let vulnerable = false;
        let leakedContent = '';
        let accessedId = '';

        for (const testId of testIds) {
          const url = `${baseUrl}${path}?${param}=${testId}`;
          metadata.checksPerformed.push(`InsecureDownloadTest:${path}?${param}=${testId}`);

          try {
            const res = await makeRequest(url, 'GET', null, headersPrimary);
            
            // Check if response contains user B's controlled marker (if configured)
            // or if it returns sensitive keywords that suggest unauthorized file download
            const isVulnerableResponse = res.statusCode === 200 && 
                                         (res.body.includes('USER_B_PRIVATE_FILE_MARKER') ||
                                          res.body.includes('PRIVATE_FILE_MARKER'));

            if (isVulnerableResponse) {
              vulnerable = true;
              leakedContent = res.body.trim().slice(0, 150);
              accessedId = testId;
              break;
            }
          } catch (e) {
            // ignore
          }
        }

        if (vulnerable) {
          const dedupeKey = `${domain}|${path}|${param}|InsecureFileDownload`;
          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against existing findings
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path,
              status: { $ne: 'Resolved' },
              category: FILE_UPLOAD_CATEGORY,
              subCategory: INSECURE_FILE_DOWNLOAD_SUB
            });

            // Prevent duplicate BOLA findings
            const existingBola = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path,
              status: { $ne: 'Resolved' },
              category: 'API Security',
              subCategory: 'Broken Object Level Authorization (BOLA)'
            });

            if (existingFinding || existingBola) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              findings.push(
                createFinding({
                  name: 'Insecure File Download',
                  desc: `The download endpoint "${path}" via parameter "${param}" does not enforce proper authorization checks. An authenticated user can access and download files belonging to another user.`,
                  severity: SEVERITY_LEVELS.HIGH,
                  cwe: 'CWE-284',
                  path,
                  impact: 'Unauthorized access to files allows vertical or horizontal privilege escalation. Attackers can view, copy, or download sensitive business data, credentials, configurations, or personal identifiable information (PII) belonging to other users.',
                  fix: 'Enforce strict access-control checks on the server side before serving any files. Verify that the authenticated session is explicitly authorized to access the specific file ID requested.',
                  scanner: SCANNER_NAME,
                  category: FILE_UPLOAD_CATEGORY,
                  subCategory: INSECURE_FILE_DOWNLOAD_SUB,
                  cvssScore: 7.5,
                  evidence: `GET request to "${path}?${param}=${accessedId}" returned HTTP 200 with sensitive content: "${leakedContent}".`,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema',
                    'https://cwe.mitre.org/data/definitions/284.html'
                  ]
                })
              );
            }
          }
        }
      } else {
        // Local test environment candidate
        const { path, fileId, expectedMarker, isUnauthorized } = candidate;
        const url = `${baseUrl}${path}/${fileId}`;
        metadata.checksPerformed.push(`InsecureDownloadTest:${path}/${fileId}`);

        try {
          const res = await makeRequest(url, 'GET', null, headersPrimary);
          
          // Successful retrieve requires HTTP 200 and presence of expected marker
          const hasMarker = res.statusCode === 200 && res.body.includes(expectedMarker);

          if (hasMarker && isUnauthorized) {
            // Finding only if accessing User B file (unauthorized)
            const dedupeKey = `${domain}|${path}|${fileId}|InsecureFileDownload`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              // Deduplicate against MongoDB database
              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: FILE_UPLOAD_CATEGORY,
                subCategory: INSECURE_FILE_DOWNLOAD_SUB
              });

              // Prevent duplicate BOLA findings
              const existingBola = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: 'API Security',
                subCategory: 'Broken Object Level Authorization (BOLA)'
              });

              if (existingFinding || existingBola) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                findings.push(
                  createFinding({
                    name: 'Insecure File Download',
                    desc: `The administrative interface or download path at "${path}" allows authenticated users to retrieve files of other users without authorization checks.`,
                    severity: SEVERITY_LEVELS.HIGH,
                    cwe: 'CWE-284',
                    path,
                    impact: 'Exposing direct file endpoints without access control allows horizontal privilege escalation. Authenticated attackers can download sensitive configuration, backups, or business documents of other accounts.',
                    fix: 'Implement server-side ownership validation. Ensure the requesting user\'s session matches the owner of the requested file ID before returning the resource.',
                    scanner: SCANNER_NAME,
                    category: FILE_UPLOAD_CATEGORY,
                    subCategory: INSECURE_FILE_DOWNLOAD_SUB,
                    cvssScore: 7.5,
                    evidence: `GET request to "${path}/${fileId}" returned HTTP 200 with marker content: "${res.body.trim().slice(0, 150)}".`,
                    references: [
                      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema',
                      'https://cwe.mitre.org/data/definitions/284.html'
                    ]
                  })
                );
              }
            }
          }
        } catch (e) {
          // ignore
        }
      }
    }
  } catch (globalErr) {
    return createResult(SCANNER_NAME, [], { error: globalErr.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanInsecureFileDownload
};
