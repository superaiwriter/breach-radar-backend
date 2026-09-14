const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, CLOUD_INFRASTRUCTURE_CATEGORY, DIRECTORY_LISTING_SUB } = require('../constants');

const SCANNER_NAME = 'directoryListing';

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
      'User-Agent': 'SecureScan/1.0 (+directory-listing-scanner)',
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
        if (body.length > 100000) req.destroy(); // 100KB limit for autoindex pages
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

function isDirectoryListingBody(body) {
  if (!body) return false;
  const hasIndexTitle = /<title>\s*Index of\s+/i.test(body) || /<h1>\s*Index of\s+/i.test(body);
  const hasDirectoryListingText = /Directory Listing for\s+/i.test(body);
  const hasToParentDir = /To Parent Directory/i.test(body);
  const hasListingTableOrPre = (body.includes('<pre>') && body.includes('<a href=')) || (body.includes('<table>') && body.includes('Parent Directory'));
  
  return hasIndexTitle || hasDirectoryListingText || hasToParentDir || hasListingTableOrPre;
}

async function scanDirectoryListing(domain, authContext = null, scanContext = null) {
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
    let pathsToTest = ['/uploads/', '/files/', '/backup/', '/backups/', '/assets/', '/static/', '/public/', '/logs/', '/tmp/'];
    
    if (isLocal) {
      pathsToTest.push('/api/test-directory-listing/vulnerable/uploads/');
      pathsToTest.push('/api/test-directory-listing/secure/uploads/');
    }

    for (const testPath of pathsToTest) {
      const targetUrl = `${baseUrl}${testPath}`;
      metadata.checksPerformed.push(`DirectoryListing:${testPath}`);

      try {
        const res = await makeRequest(targetUrl, 'GET', reqHeaders);

        // Directory listings return 200 OK
        if (res.statusCode === 200 && isDirectoryListingBody(res.body)) {
          const dedupeKey = `${domain}|${testPath}|DirectoryListing`;
          
          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against MongoDB database
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path: testPath,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: DIRECTORY_LISTING_SUB
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              let evidenceText = `GET request to "${testPath}" returned HTTP 200 with directory listing signatures.`;
              
              findings.push(
                createFinding({
                  name: 'Directory Listing Enabled',
                  desc: `The web server or application has directory listing (directory indexing) enabled. An attacker can browse the file structure and access files directly.`,
                  severity: SEVERITY_LEVELS.MEDIUM,
                  cwe: 'CWE-548',
                  path: testPath,
                  parameter: '',
                  impact: 'Enabling directory listing exposes sensitive files, configuration scripts, backup files, and private user uploads, facilitating target reconnaissance and attack planning.',
                  fix: 'Disable directory listing or indexing in the web server configuration (e.g. "options -Indexes" in Apache .htaccess, "autoindex off;" in Nginx, or disabling directory browsing in IIS). Ensure a default index.html or empty index page exists in public directories.',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: DIRECTORY_LISTING_SUB,
                  cvssScore: 5.3,
                  evidence: evidenceText,
                  references: [
                    'https://owasp.org/www-community/attacks/Path_Traversal',
                    'https://cwe.mitre.org/data/definitions/548.html'
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
  scanDirectoryListing
};
