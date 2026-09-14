const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, CLOUD_INFRASTRUCTURE_CATEGORY, BACKUP_FILE_EXPOSURE_SUB } = require('../constants');

const SCANNER_NAME = 'backupFileExposure';

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
      'User-Agent': 'SecureScan/1.0 (+backup-file-exposure-scanner)',
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

function isBackupContent(testPath, res) {
  const contentType = String(res.headers['content-type'] || '').toLowerCase();
  const body = res.body || '';

  // If it's HTML, it's likely a custom error or SPA fallback
  if (contentType.includes('text/html')) {
    return false;
  }

  // SQL dump check
  if (testPath.endsWith('.sql') || testPath.endsWith('.dump')) {
    return /CREATE TABLE|INSERT INTO|DROP TABLE|\-\-.*database|\-\-.*dump/i.test(body);
  }

  // ZIP/Archive check
  if (testPath.endsWith('.zip') || testPath.endsWith('.tar') || testPath.endsWith('.gz') || testPath.endsWith('.tgz')) {
    if (body.startsWith('PK\x03\x04') || body.startsWith('PK')) {
      return true;
    }
    if (body.charCodeAt(0) === 0x1f && body.charCodeAt(1) === 0x8b) {
      return true;
    }
    if (contentType.includes('application/zip') || contentType.includes('application/x-gzip') || contentType.includes('application/octet-stream')) {
      return true;
    }
  }

  // Text/Backup files
  if (testPath.endsWith('.bak') || testPath.endsWith('.old') || testPath.endsWith('.orig') || testPath.endsWith('.save') || testPath.endsWith('~')) {
    if (contentType.includes('text/plain') || contentType.includes('application/octet-stream') || contentType.includes('javascript') || contentType.includes('json')) {
      return true;
    }
  }

  // Fallback content-types indicating active file exposure
  if (contentType.includes('application/octet-stream') || contentType.includes('application/sql') || contentType.includes('text/x-sql')) {
    return true;
  }

  return false;
}

async function scanBackupFileExposure(domain, authContext = null, scanContext = null) {
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
      '/backup.sql',
      '/backup.zip',
      '/db.sql',
      '/db.dump',
      '/archive.zip',
      '/backup.tar.gz',
      '/index.js.bak',
      '/index.js.old',
      '/.env.bak',
      '/.env.old'
    ];

    if (isLocal) {
      pathsToTest.push('/api/test-backup-file-exposure/vulnerable/backup.sql');
      pathsToTest.push('/api/test-backup-file-exposure/secure/backup.sql');
    }

    for (const testPath of pathsToTest) {
      const targetUrl = `${baseUrl}${testPath}`;
      metadata.checksPerformed.push(`BackupFileExposure:${testPath}`);

      try {
        const res = await makeRequest(targetUrl, 'GET', reqHeaders);

        if (res.statusCode === 200 && isBackupContent(testPath, res)) {
          const dedupeKey = `${domain}|${testPath}|BackupFileExposure`;

          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against MongoDB database
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path: testPath,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: BACKUP_FILE_EXPOSURE_SUB
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              // Sanitize/Redact potential secrets in evidence
              let evidenceSnippet = res.body.slice(0, 200);
              evidenceSnippet = evidenceSnippet.replace(/(password|jwt|auth|token|secret|key)\s*[:=]\s*[^\s&]+/ig, '$1=[REDACTED]');

              const evidenceText = `GET request to "${testPath}" returned HTTP 200. Content-Type: ${res.headers['content-type'] || 'unknown'}. Response preview: "${evidenceSnippet}"`;

              findings.push(
                createFinding({
                  name: 'Backup File Exposure',
                  desc: `An exposed backup, archive, or source code file was detected. These files contain system credentials, database configuration details, or source code.`,
                  severity: SEVERITY_LEVELS.HIGH,
                  cwe: 'CWE-530',
                  path: testPath,
                  parameter: '',
                  impact: 'Attackers can download database dumps, source files, or configuration backups, exposing sensitive user data, application credentials, and proprietary code.',
                  fix: 'Remove all backup files, editor temporary files (.swp, ~), and archives (.zip, .tar.gz) from public directory roots. Configure the web server to block access to common backup file extensions.',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: BACKUP_FILE_EXPOSURE_SUB,
                  cvssScore: 7.5,
                  evidence: evidenceText,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                    'https://cwe.mitre.org/data/definitions/530.html'
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
  scanBackupFileExposure
};
