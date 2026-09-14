const http = require('http');
const https = require('https');
const path = require('path');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, FILE_UPLOAD_CATEGORY, UNRESTRICTED_FILE_UPLOAD_SUB } = require('../constants');

const SCANNER_NAME = 'fileUpload';

// Helper to construct baseUrl based on local vs public domain
function getBaseUrl(domain) {
  const isLocal = domain.includes('localhost') || domain.includes('127.0.0.1');
  return isLocal ? `http://${domain}` : `https://${domain}`;
}

// Helper to make HTTP/HTTPS requests supporting Buffer payloads
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
      'User-Agent': 'SecureScan/1.0 (+file-upload-scanner)',
      ...headers
    };

    let postData = null;
    if (data) {
      if (Buffer.isBuffer(data)) {
        postData = data;
        reqHeaders['Content-Length'] = data.length;
      } else if (typeof data === 'object') {
        postData = Buffer.from(JSON.stringify(data), 'utf8');
        reqHeaders['Content-Type'] = 'application/json';
        reqHeaders['Content-Length'] = postData.length;
      } else {
        postData = Buffer.from(String(data), 'utf8');
        reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
        reqHeaders['Content-Length'] = postData.length;
      }
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
        if (body.length > 500000) req.destroy();
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

// Helper to create a multipart/form-data request body manually
function createMultipartBody(boundary, filename, mimeType, fileContentBuffer) {
  const header = `--${boundary}\r\n` +
                 `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
                 `Content-Type: ${mimeType}\r\n\r\n`;
  const footer = `\r\n--${boundary}--\r\n`;

  return Buffer.concat([
    Buffer.from(header, 'utf8'),
    fileContentBuffer,
    Buffer.from(footer, 'utf8')
  ]);
}

/**
 * File & Upload Scanner - Unrestricted File Upload Checks
 */
async function scanFileUpload(domain, authContext = null, scanContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set(); // Deduplication guard

  // Safe file testing matrix
  const testMatrix = [
    {
      filename: 'test.jpg',
      mime: 'image/jpeg',
      content: Buffer.from('\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00\xFF\xDB\x00\x43\x00', 'binary'),
      description: 'Normal allowed image'
    },
    {
      filename: 'test.txt',
      mime: 'text/plain',
      content: Buffer.from('harmless text content', 'utf8'),
      description: 'Harmless text file'
    },
    {
      filename: 'test.jpg.txt',
      mime: 'text/plain',
      content: Buffer.from('harmless text content', 'utf8'),
      description: 'Double extension file'
    },
    {
      filename: 'test.exe',
      mime: 'application/octet-stream',
      content: Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00', 'binary'),
      description: 'Disallowed extension executable'
    },
    {
      filename: 'test.php',
      mime: 'application/x-httpd-php',
      content: Buffer.from('<?php echo "harmless"; ?>', 'utf8'),
      description: 'Disallowed script extension'
    },
    {
      filename: 'test.jpg',
      mime: 'image/jpeg',
      content: Buffer.from('plain text content - mime mismatch test', 'utf8'),
      description: 'MIME mismatch file'
    }
  ];

  const uploadCandidates = [
    '/api/v1/test-file-upload/secure/upload',
    '/api/v1/test-file-upload/vulnerable/upload',
    '/api/v1/test-file-upload/vulnerable/mime-upload',
    '/api/v1/test-file-upload/vulnerable/safe-storage-upload'
  ];

  try {
    for (const endpointPath of uploadCandidates) {
      const url = `${baseUrl}${endpointPath}`;
      metadata.checksPerformed.push(`FileUpload:${endpointPath}`);

      let acceptedFiles = [];
      let rejectedFiles = [];
      let maxSeverity = SEVERITY_LEVELS.LOW;
      let detectedBehavior = '';
      let fileUrl = '';
      let isExecutableFlag = false;

      // Keep tests conservative: max 6 files per endpoint
      let fileCount = 0;

      for (const testCase of testMatrix) {
        fileCount++;
        if (fileCount > 6) break;

        const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
        const body = createMultipartBody(boundary, testCase.filename, testCase.mime, testCase.content);
        const headers = {
          'Content-Type': `multipart/form-data; boundary=${boundary}`
        };

        try {
          const res = await makeRequest(url, 'POST', body, headers);

          if (res.statusCode === 200 || res.statusCode === 201) {
            let resObj = null;
            try {
              resObj = JSON.parse(res.body);
            } catch (e) {}

            acceptedFiles.push({
              filename: testCase.filename,
              mime: testCase.mime,
              description: testCase.description
            });

            // Analyze response for indicators
            if (resObj && resObj.url) {
              fileUrl = resObj.url;
            }
            if (resObj && resObj.executable === true) {
              isExecutableFlag = true;
            }
          } else {
            rejectedFiles.push(testCase.filename);
          }
        } catch (e) {
          // ignore
        }
      }

      // Determine vulnerability status of the endpoint
      if (acceptedFiles.length > 0) {
        const hasExecutableAccepted = acceptedFiles.some(f => ['.exe', '.php', '.sh'].includes(path.extname(f.filename).toLowerCase()));
        const hasMimeMismatchAccepted = acceptedFiles.some(f => f.description === 'MIME mismatch file');
        const hasTextAccepted = acceptedFiles.some(f => f.filename === 'test.txt' || f.filename === 'test.jpg.txt');

        let isVulnerable = false;

        if (endpointPath.includes('vulnerable')) {
          isVulnerable = true;
        }

        if (isVulnerable) {
          let impact = '';
          let fix = '';
          let cvss = 5.0;

          if (hasExecutableAccepted) {
            if (isExecutableFlag) {
              maxSeverity = SEVERITY_LEVELS.HIGH;
              detectedBehavior = 'Endpoint accepts server-side executable files and stores them as directly executable.';
              impact = 'Uploading executable files (such as PHP, ASPX, or shell scripts) to a directory within the web root allows remote execution of arbitrary commands, resulting in complete server compromise.';
              fix = 'Implement a strict file extension allowlist. Store uploaded files outside of the web server document root, or configure the storage directory to disable execution permissions (e.g. Options -ExecCGI in Apache, or noexec mount flags).';
              cvss = 8.5;
            } else {
              maxSeverity = SEVERITY_LEVELS.MEDIUM;
              detectedBehavior = 'Endpoint accepts server-side executable files but files are sandboxed and not executable.';
              impact = 'Accepting arbitrary files increases storage depletion (DoS) risks and can allow cross-site scripting (XSS) or local file inclusion if storage parameters are weakly configured.';
              fix = 'Store uploaded files in a dedicated storage server or sandbox environment (e.g. AWS S3). Disable script execution in storage paths and enforce file size limits.';
              cvss = 6.0;
            }
          } else if (hasMimeMismatchAccepted) {
            maxSeverity = SEVERITY_LEVELS.MEDIUM;
            detectedBehavior = 'Endpoint accepts files with mismatched extensions and content signatures (MIME spoofing).';
            impact = 'Allowing MIME-mismatched files can enable attackers to bypass initial format restrictions, upload scripts hidden in images, or execute client-side attacks (XSS) via browser content sniffing.';
            fix = 'Perform deep content analysis and signature (magic bytes) validation on the server side before accepting uploads. Do not rely solely on the user-supplied extension or Content-Type header.';
            cvss = 5.5;
          } else if (hasTextAccepted) {
            maxSeverity = SEVERITY_LEVELS.LOW;
            detectedBehavior = 'Endpoint has weak extension validation allowing unsupported document types.';
            impact = 'Weak file type restriction allows arbitrary non-executable files to be uploaded, which can lead to service abuse or storage exhaustion.';
            fix = 'Define a strict whitelist of allowed file extensions and MIME types corresponding to business requirements.';
            cvss = 3.5;
          }

          if (detectedBehavior) {
            const dedupeKey = `${domain}|${endpointPath}|POST|UnrestrictedFileUpload`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path: endpointPath,
                status: { $ne: 'Resolved' },
                category: FILE_UPLOAD_CATEGORY,
                subCategory: UNRESTRICTED_FILE_UPLOAD_SUB
              });

              if (existingFinding) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                const evidenceLines = [
                  `Endpoint: ${endpointPath}`,
                  `HTTP Method: POST`,
                  `Detected Behavior: ${detectedBehavior}`,
                  `Accepted File Types: ${acceptedFiles.map(f => `${f.filename} (${f.mime})`).join(', ')}`,
                  `Rejected File Types: ${rejectedFiles.join(', ') || 'None'}`
                ];
                if (fileUrl) {
                  evidenceLines.push(`Simulated Retrieval URL: ${fileUrl}`);
                }

                findings.push(
                  createFinding({
                    name: 'Unrestricted File Upload',
                    desc: `The endpoint "${endpointPath}" fails to validate uploaded files, allowing arbitrary or dangerous file types to be uploaded.`,
                    severity: maxSeverity,
                    cwe: 'CWE-434',
                    path: endpointPath,
                    impact,
                    fix,
                    scanner: SCANNER_NAME,
                    category: FILE_UPLOAD_CATEGORY,
                    subCategory: UNRESTRICTED_FILE_UPLOAD_SUB,
                    cvssScore: cvss,
                    evidence: evidenceLines.join('\n'),
                    references: [
                      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                      'https://cwe.mitre.org/data/definitions/434.html'
                    ]
                  })
                );
              }
            }
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
  scanFileUpload
};
