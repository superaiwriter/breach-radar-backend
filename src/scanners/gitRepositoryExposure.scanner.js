const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, CLOUD_INFRASTRUCTURE_CATEGORY, GIT_REPOSITORY_EXPOSURE_SUB } = require('../constants');

const SCANNER_NAME = 'gitRepositoryExposure';

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
      'User-Agent': 'SecureScan/1.0 (+git-exposure-scanner)',
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
        if (body.length > 50000) req.destroy(); // 50KB limit for Git metadata files
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

function isGitHead(body) {
  if (!body) return false;
  const clean = body.trim();
  // Valid HEAD is either a branch ref "ref: refs/heads/..." or a 40-char SHA-1 hash
  return /^ref:\s*refs\//i.test(clean) || /^[a-fA-F0-9]{40}$/.test(clean);
}

function isGitConfig(body) {
  if (!body) return false;
  // Config contains sections like [core] or [remote ...]
  return /\[core\]|\[remote\s+"[^"]+"\]|\[branch\s+"[^"]+"\]/i.test(body);
}

function isGitIndex(body) {
  if (!body) return false;
  // Git index starts with magic bytes 'DIRC' (directory cache)
  return body.startsWith('DIRC');
}

async function scanGitRepositoryExposure(domain, authContext = null, scanContext = null) {
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
      '/.git/HEAD',
      '/.git/config',
      '/.git/index'
    ];

    if (isLocal) {
      pathsToTest.push('/api/test-git-exposure/vulnerable/.git/HEAD');
      pathsToTest.push('/api/test-git-exposure/secure/.git/HEAD');
    }

    for (const testPath of pathsToTest) {
      const targetUrl = `${baseUrl}${testPath}`;
      metadata.checksPerformed.push(`GitRepositoryExposure:${testPath}`);

      try {
        const res = await makeRequest(targetUrl, 'GET', reqHeaders);

        let isValidGitFile = false;
        if (res.statusCode === 200) {
          if (testPath.endsWith('HEAD') && isGitHead(res.body)) {
            isValidGitFile = true;
          } else if (testPath.endsWith('config') && isGitConfig(res.body)) {
            isValidGitFile = true;
          } else if (testPath.endsWith('index') && isGitIndex(res.body)) {
            isValidGitFile = true;
          }
        }

        if (isValidGitFile) {
          // Standardize finding path to the parent /.git/ directory
          const reportPath = testPath.includes('/api/test-git-exposure')
            ? '/api/test-git-exposure/vulnerable/.git/'
            : '/.git/';

          const dedupeKey = `${domain}|${reportPath}|GitRepositoryExposure`;

          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against MongoDB database
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path: reportPath,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: GIT_REPOSITORY_EXPOSURE_SUB
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              // Sanitize credentials/keys from config output in evidence
              let sanitizedBody = res.body.trim().slice(0, 250);
              sanitizedBody = sanitizedBody.replace(/(url\s*=\s*https:\/\/)[^@]+@/i, '$1[REDACTED_CREDS]@');

              const evidenceText = `GET request to "${testPath}" returned HTTP 200. Content verified as a valid Git file. Output Preview: "${sanitizedBody}"`;

              findings.push(
                createFinding({
                  name: 'Git Repository Exposure',
                  desc: `The application's Git repository (.git directory) is publicly accessible. This exposes history, source code, commit logs, and internal credentials.`,
                  severity: SEVERITY_LEVELS.HIGH,
                  cwe: 'CWE-527',
                  path: reportPath,
                  parameter: '',
                  impact: 'Attackers can download the entire git history, retrieve full source code, identify internal API paths, and extract hardcoded secrets/keys.',
                  fix: 'Configure the web server or reverse proxy to block public access to the /.git/ directory and all its files (e.g., returning 403 Forbidden or 404 Not Found).',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: GIT_REPOSITORY_EXPOSURE_SUB,
                  cvssScore: 7.5,
                  evidence: evidenceText,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Configuration_and_Deployment_Management_Testing/05-Analyze_Identity_Provider_Metadata',
                    'https://cwe.mitre.org/data/definitions/527.html'
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
  scanGitRepositoryExposure
};
