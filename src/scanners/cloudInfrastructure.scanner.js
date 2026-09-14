const http = require('http');
const https = require('https');
const Vulnerability = require('../models/Vulnerability');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, CLOUD_INFRASTRUCTURE_CATEGORY, EXPOSED_ADMIN_PANELS_SUB, CLOUD_STORAGE_EXPOSURE_SUB, SECURITY_MISCONFIGURATION_SUB, DEFAULT_CREDENTIALS_SUB, SENSITIVE_INFO_DISCLOSURE_SUB } = require('../constants');

const SCANNER_NAME = 'cloudInfrastructure';

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
      'User-Agent': 'SecureScan/1.0 (+cloud-infra-scanner)',
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

/**
 * Cloud & Infrastructure Scanner - Exposed Admin Panels, Public Cloud Storage Exposure, Security Misconfigurations & Default Credentials Checks
 */
async function scanCloudInfrastructure(domain, authContext = null, scanContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set(); // Deduplication guard
  const discoveredLoginInterfaces = [];

  try {
    // -------------------------------------------------------------------------
    // SECTION A: Exposed Admin Panels Checks
    // -------------------------------------------------------------------------
    const adminCandidates = [
      '/api/v1/test-admin-exposure/vulnerable/dashboard',
      '/api/v1/test-admin-exposure/vulnerable/jenkins',
      '/api/v1/test-admin-exposure/secure/dashboard',
      '/admin',
      '/admin/login',
      '/dashboard',
      '/administrator',
      '/actuator',
      '/swagger-ui.html',
      '/swagger-ui/index.html'
    ];

    for (const path of adminCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`AdminExposure:${path}`);

      try {
        const res = await makeRequest(url, 'GET');

        if (res.statusCode === 200 && res.body.trim().length > 0) {
          const bodyText = res.body;
          const bodyLower = bodyText.toLowerCase();

          // Collect discovered login interfaces for dynamic credentials checking
          const hasForm = bodyLower.includes('<form');
          const hasPasswordInput = bodyLower.includes('type="password"') || bodyLower.includes('name="password"') || bodyLower.includes('placeholder="password"');
          const hasUsernameInput = bodyLower.includes('name="username"') || bodyLower.includes('name="email"') || bodyLower.includes('name="user"') ||
                                   bodyLower.includes('placeholder="username"') || bodyLower.includes('placeholder="email"') || bodyLower.includes('placeholder="user"') ||
                                   bodyLower.includes('type="text"') || bodyLower.includes('type="email"') || bodyLower.includes('j_username');

          if (hasForm && hasPasswordInput && hasUsernameInput) {
            let authPath = path;
            const actionMatch = bodyText.match(/<form[^>]+action=["']([^"']+)["']/i);
            if (actionMatch && actionMatch[1]) {
              const actionValue = actionMatch[1].trim();
              if (actionValue && actionValue !== '#') {
                if (actionValue.startsWith('http://') || actionValue.startsWith('https://')) {
                  try {
                    const parsedAction = new URL(actionValue);
                    authPath = parsedAction.pathname;
                  } catch (e) {
                    authPath = actionValue;
                  }
                } else if (actionValue.startsWith('/')) {
                  authPath = actionValue;
                } else {
                  const dir = path.substring(0, path.lastIndexOf('/') + 1);
                  authPath = dir + actionValue;
                }
              }
            }
            discoveredLoginInterfaces.push(authPath);
          }

          const titleMatch = bodyText.match(/<title>([^<]+)<\/title>/i);
          const pageTitle = titleMatch ? titleMatch[1].trim() : '';
          const titleLower = pageTitle.toLowerCase();

          const isAdminTitle = titleLower.includes('admin') || titleLower.includes('dashboard') || titleLower.includes('console') || titleLower.includes('jenkins') || titleLower.includes('swagger') || titleLower.includes('management') || titleLower.includes('kibana') || titleLower.includes('grafana');
          const isAdminBody = bodyLower.includes('admin-panel') || bodyLower.includes('shutdown') || bodyLower.includes('system metrics') || bodyLower.includes('jenkins-') || bodyLower.includes('swagger-ui');

          const isHarmlessHome = titleLower === 'home' || titleLower === 'welcome' || (bodyLower.includes('welcome to') && !isAdminTitle);

          if ((isAdminTitle || isAdminBody) && !isHarmlessHome) {
            const hasLoginInput = bodyLower.includes('type="password"') || bodyLower.includes('placeholder="password"') || bodyLower.includes('placeholder="username"') || bodyLower.includes('j_username');
            
            let severity = SEVERITY_LEVELS.HIGH;
            let authStatus = 'accessible without authentication';
            let desc = `The administrative console at "${path}" was found to be publicly accessible without requiring authentication.`;
            let cvss = 8.5;

            if (hasLoginInput) {
              severity = SEVERITY_LEVELS.MEDIUM;
              authStatus = 'exposed admin login form';
              desc = `The administrative panel login interface at "${path}" is publicly exposed. While requiring authentication, exposing management consoles increases brute-force and credential stuffing risks.`;
              cvss = 5.3;
            }

            const dedupeKey = `${domain}|${path}|GET|ExposedAdminPanel`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: CLOUD_INFRASTRUCTURE_CATEGORY,
                subCategory: EXPOSED_ADMIN_PANELS_SUB
              });

              if (existingFinding) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                findings.push(
                  createFinding({
                    name: 'Exposed Admin Panel',
                    desc,
                    severity,
                    cwe: 'CWE-284',
                    path,
                    impact: severity === SEVERITY_LEVELS.HIGH
                      ? 'Unauthenticated dashboard access allows full administrative visibility or control over system resources, metrics, configurations, or users, resulting in total server compromise.'
                      : 'Exposing administrative login interfaces allows attackers to perform targeted brute-force attacks, credentials guessing, or exploit unpatched vulnerabilities in the management console software.',
                    fix: 'Restrict access to administrative consoles at the network level. Put admin panels behind a VPN, utilize IP whitelisting, configure proper multi-factor authentication, or disable public route mapping entirely.',
                    scanner: SCANNER_NAME,
                    category: CLOUD_INFRASTRUCTURE_CATEGORY,
                    subCategory: EXPOSED_ADMIN_PANELS_SUB,
                    cvssScore: cvss,
                    evidence: `GET ${path} returned HTTP 200 with title: "${pageTitle}". Authentication status: ${authStatus}.`,
                    references: [
                      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weak_Lockout_Mechanism',
                      'https://cwe.mitre.org/data/definitions/284.html'
                    ]
                  })
                );
              }
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

    // -------------------------------------------------------------------------
    // SECTION B: Public Cloud Storage Exposure Checks
    // -------------------------------------------------------------------------
    const storageCandidates = [
      '/api/v1/test-cloud-storage/s3-private-bucket',
      '/api/v1/test-cloud-storage/s3-public-listing-sensitive',
      '/api/v1/test-cloud-storage/s3-public-static-assets'
    ];

    const sensitiveMarkers = ['.env', 'backup', 'sql', '.pem', 'key', 'credentials', 'secret', 'db_'];

    for (const path of storageCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`CloudStorage:${path}`);

      try {
        const res = await makeRequest(url, 'GET');

        if (res.statusCode === 200 && res.body.trim().length > 0) {
          const bodyText = res.body;
          const isXmlListing = bodyText.includes('<ListBucketResult') || bodyText.includes('<Contents>');

          if (isXmlListing) {
            const keys = [];
            const keyRegex = /<Key>([^<]+)<\/Key>/g;
            let match;
            while ((match = keyRegex.exec(bodyText)) !== null) {
              keys.push(match[1]);
            }

            const exposedSensitives = keys.filter(key => {
              const keyLower = key.toLowerCase();
              return sensitiveMarkers.some(marker => keyLower.includes(marker));
            });

            if (exposedSensitives.length > 0) {
              const dedupeKey = `${domain}|${path}|GET|CloudStorageExposure`;

              if (!seen.has(dedupeKey)) {
                seen.add(dedupeKey);

                const existingFinding = await Vulnerability.findOne({
                  domainId: scanContext?.domainId,
                  path,
                  status: { $ne: 'Resolved' },
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: CLOUD_STORAGE_EXPOSURE_SUB
                });

                if (existingFinding) {
                  metadata.correlations = (metadata.correlations || 0) + 1;
                } else {
                  findings.push(
                    createFinding({
                      name: 'Public Cloud Storage Exposure',
                      desc: `The cloud storage bucket at "${path}" allows public listing of contents and exposes sensitive server files: ${exposedSensitives.join(', ')}.`,
                      severity: SEVERITY_LEVELS.HIGH,
                      cwe: 'CWE-306',
                      path,
                      impact: 'Unauthenticated public access to cloud storage listings can leak critical backups, environment credentials, database schema configurations, and customer private keys, triggering complete lateral server takeover and regulatory data breach.',
                      fix: 'Modify bucket access control lists (ACLs) and bucket policies to block public read access and directory listings. Restrict container access using IAM roles or signed URLs for secure temporary distribution.',
                      scanner: SCANNER_NAME,
                      category: CLOUD_INFRASTRUCTURE_CATEGORY,
                      subCategory: CLOUD_STORAGE_EXPOSURE_SUB,
                      cvssScore: 8.2,
                      evidence: `GET ${path} returned S3-compatible XML bucket listing containing ${keys.length} keys. Exposed sensitive files detected: [${exposedSensitives.join(', ')}].`,
                      references: [
                        'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Testing_for_Cloud_Storage',
                        'https://cwe.mitre.org/data/definitions/306.html'
                      ]
                    })
                  );
                }
              }
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

    // -------------------------------------------------------------------------
    // SECTION C: Security Misconfiguration Checks
    // -------------------------------------------------------------------------
    const dirCandidates = [
      '/api/v1/test-misconfig/vulnerable/uploads',
      '/api/v1/test-misconfig/secure/uploads'
    ];

    for (const path of dirCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`DirectoryListing:${path}`);

      try {
        const res = await makeRequest(url, 'GET');
        if (res.statusCode === 200 && res.body.trim().length > 0) {
          const bodyText = res.body;
          const bodyLower = bodyText.toLowerCase();

          const isDirIndex = bodyLower.includes('<title>index of') || bodyLower.includes('<h1>index of') || bodyLower.includes('directory listing for');

          if (isDirIndex) {
            const dedupeKey = `${domain}|${path}|GET|DirectoryListing`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: CLOUD_INFRASTRUCTURE_CATEGORY,
                subCategory: SECURITY_MISCONFIGURATION_SUB,
                name: 'Directory Listing Enabled'
              });

              if (existingFinding) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                findings.push(
                  createFinding({
                    name: 'Directory Listing Enabled',
                    desc: `The directory browsing configuration at "${path}" is enabled, exposing full directory indexes to unauthenticated visitors.`,
                    severity: SEVERITY_LEVELS.MEDIUM,
                    cwe: 'CWE-548',
                    path,
                    impact: 'Exposed directory indexes allow malicious users to view, download, or index all files in target uploads or source trees, revealing proprietary source files or private credentials.',
                    fix: 'Disable directory indexes in the web server configuration (e.g., using "Options -Indexes" in Apache HTTPD or removing "autoindex on" in Nginx).',
                    scanner: SCANNER_NAME,
                    category: CLOUD_INFRASTRUCTURE_CATEGORY,
                    subCategory: SECURITY_MISCONFIGURATION_SUB,
                    cvssScore: 5.3,
                    evidence: `GET ${path} returned HTTP 200 with directory listing signature: Index of /uploads.`,
                    references: [
                      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_File_Extensions_Handling',
                      'https://cwe.mitre.org/data/definitions/548.html'
                    ]
                  })
                );
              }
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

    const errorCandidates = [
      '/api/v1/test-misconfig/vulnerable/error',
      '/api/v1/test-misconfig/secure/error'
    ];

    for (const path of errorCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`VerboseErrors:${path}`);

      try {
        const res = await makeRequest(url, 'GET');
        if (res.statusCode === 500 && res.body.trim().length > 0) {
          const bodyText = res.body;

          const isStackTrace = bodyText.includes('TypeError:') || bodyText.includes('at Object.') || bodyText.includes('node_modules') || bodyText.includes('\\routes\\testMisconfig');

          if (isStackTrace) {
            const dedupeKey = `${domain}|${path}|GET|VerboseError`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: CLOUD_INFRASTRUCTURE_CATEGORY,
                subCategory: SECURITY_MISCONFIGURATION_SUB,
                name: 'Verbose Error Configuration'
              });

              if (existingFinding) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                findings.push(
                  createFinding({
                    name: 'Verbose Error Configuration',
                    desc: `The endpoint "${path}" returned a server error containing verbose stack traces and internal file paths.`,
                    severity: SEVERITY_LEVELS.MEDIUM,
                    cwe: 'CWE-209',
                    path,
                    impact: 'Verbose error configuration exposes application frameworks, dependencies versions, and server-side absolute file directories, easing target mapping and exploit planning for malicious attackers.',
                    fix: 'Configure default error handling middleware to sanitize application crashes. Return generic client messages (e.g. "Internal Server Error") and log technical stack traces to a secure local file logger.',
                    scanner: SCANNER_NAME,
                    category: CLOUD_INFRASTRUCTURE_CATEGORY,
                    subCategory: SECURITY_MISCONFIGURATION_SUB,
                    cvssScore: 5.0,
                    evidence: `GET ${path} returned HTTP 500 containing stack trace: ${bodyText.slice(0, 200)}`,
                    references: [
                      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_File_Extensions_Handling',
                      'https://cwe.mitre.org/data/definitions/209.html'
                    ]
                  })
                );
              }
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

    const methodCandidates = [
      '/api/v1/test-misconfig/vulnerable/trace',
      '/api/v1/test-misconfig/secure/trace'
    ];

    for (const path of methodCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`DangerousMethod:${path}`);

      try {
        const resTrace = await makeRequest(url, 'TRACE');
        const isTraceEchoed = resTrace.statusCode === 200 && resTrace.body.includes('TRACE /api/v1/');

        if (isTraceEchoed) {
          const dedupeKey = `${domain}|${path}|TRACE|DangerousMethod`;

          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: SECURITY_MISCONFIGURATION_SUB,
              name: 'Dangerous HTTP Method Enabled'
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              findings.push(
                createFinding({
                  name: 'Dangerous HTTP Method Enabled',
                  desc: `The HTTP TRACE method is enabled at "${path}", which echoes request headers back to the client.`,
                  severity: SEVERITY_LEVELS.LOW,
                  cwe: 'CWE-697',
                  path,
                  impact: 'Enabling TRACE increases Cross-Site Tracing (XST) risks, potentially allowing attackers to read secure/HttpOnly cookies or authorization headers via client-side scripts.',
                  fix: 'Disable the TRACE and TRACK HTTP methods in the server configuration (e.g. using "TraceEnable off" in Apache HTTPD, or blocking TRACE requests using write rules or routing middlewares in Express/Nginx).',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: SECURITY_MISCONFIGURATION_SUB,
                  cvssScore: 3.5,
                  evidence: `TRACE request to ${path} returned HTTP 200 echoing headers: ${resTrace.body.slice(0, 150)}`,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
                    'https://cwe.mitre.org/data/definitions/697.html'
                  ]
                })
              );
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

    // -------------------------------------------------------------------------
    // SECTION D: Default Credentials Checks
    // -------------------------------------------------------------------------
    const isCredTestingEnabled = process.env.DEFAULT_CREDENTIALS_TEST === 'true';

    if (isCredTestingEnabled) {
      const isLocal = isLocalTarget(domain);
      const defaultCredsCandidates = isLocal
        ? [
            '/api/v1/test-default-creds/vulnerable/login',
            '/api/v1/test-default-creds/secure/login',
            '/api/v1/test-default-creds/fake-200-login'
          ]
        : Array.from(new Set(discoveredLoginInterfaces));

      const defaultCredPairs = [
        { username: 'admin', password: 'admin' },
        { username: 'admin', password: 'password' },
        { username: 'root', password: 'root' }
      ];

      for (const path of defaultCredsCandidates) {
        const url = path.startsWith('http://') || path.startsWith('https://')
          ? path
          : `${baseUrl}${path}`;

        // Get relative display path for findings/dedupe
        let displayPath = path;
        if (path.startsWith('http://') || path.startsWith('https://')) {
          try {
            displayPath = new URL(path).pathname;
          } catch (e) {
            displayPath = path;
          }
        } else {
          try {
            displayPath = new URL('http://temp.local' + path).pathname;
          } catch (e) {
            displayPath = path;
          }
        }

        metadata.checksPerformed.push(`DefaultCreds:${displayPath}`);

        let attempts = 0;
        let loginSucceeded = false;
        let successfulCredText = '';

        for (const cred of defaultCredPairs) {
          attempts++;
          if (attempts > 3) {
            break; // Strict request cap: max 3 attempts per service
          }

          try {
            // Attempt login using POST
            const res = await makeRequest(url, 'POST', cred);

            // Authentication verification logic:
            // Must NOT treat status code 200 alone as authenticated. Confirm if JSON contains success flag or token,
            // or if Set-Cookie header contains session variables.
            const isSuccessBody = res.statusCode === 200 && (res.body.includes('"success":true') || res.body.includes('"token":'));
            const isCookieSet = res.headers['set-cookie'] !== undefined;

            if (isSuccessBody || isCookieSet) {
              loginSucceeded = true;
              successfulCredText = `Default credentials login succeeded using username: "${cred.username}" (password was redacted).`;
              break; // Stop immediately upon successful authentication
            }
          } catch (e) {
            // ignore
          }
        }

        if (loginSucceeded) {
          const dedupeKey = `${domain}|${displayPath}|POST|DefaultCredentials`;

          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);

            // Deduplicate against MongoDB database
            const existingFinding = await Vulnerability.findOne({
              domainId: scanContext?.domainId,
              path: displayPath,
              status: { $ne: 'Resolved' },
              category: CLOUD_INFRASTRUCTURE_CATEGORY,
              subCategory: DEFAULT_CREDENTIALS_SUB
            });

            if (existingFinding) {
              metadata.correlations = (metadata.correlations || 0) + 1;
            } else {
              findings.push(
                createFinding({
                  name: 'Default Credentials',
                  desc: `The administrative interface login path at "${displayPath}" was found to accept common vendor-default credentials.`,
                  severity: SEVERITY_LEVELS.HIGH,
                  cwe: 'CWE-1392', // Use of Default Credentials
                  path: displayPath,
                  impact: 'Administrative panels accessible using vendor default logins allow complete vertical privilege escalation. Attackers can bypass authentication to configure, manipulate, or delete all server databases and application code.',
                  fix: 'Change default administrative credentials immediately. Enforce a strong password complexity policy and ensure that initial vendor passwords are changed upon first setup/installation.',
                  scanner: SCANNER_NAME,
                  category: CLOUD_INFRASTRUCTURE_CATEGORY,
                  subCategory: DEFAULT_CREDENTIALS_SUB,
                  cvssScore: 8.8,
                  evidence: `POST to ${displayPath} succeeded. Evidence: ${successfulCredText}`,
                  references: [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials',
                    'https://cwe.mitre.org/data/definitions/1392.html'
                  ]
                })
              );
            }
          }
        }
      }
    }

    // -------------------------------------------------------------------------
    // SECTION E: Sensitive Information Disclosure Checks
    // -------------------------------------------------------------------------
    const sensitiveInfoCandidates = [
      '/api/v1/test-sensitive-disclosure/vulnerable/apikey',
      '/api/v1/test-sensitive-disclosure/vulnerable/dbstring',
      '/api/v1/test-sensitive-disclosure/secure/safe',
      '/api/v1/test-sensitive-disclosure/secure/harmless'
    ];

    const sensitivePatterns = {
      Google_API_Key: /AIzaSy[a-zA-Z0-9_-]{33}/gi,
      AWS_Access_Key: /AKIA[0-9A-Z]{16}/gi,
      AWS_Secret_Key: /wJalrXUtnFEMI\/[a-zA-Z0-9\/+=]{27}/gi,
      MongoDB_Connection_String: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+/gi
    };

    function redactSecrets(text) {
      if (!text) return '';
      let result = text;
      
      // 1. Redact MongoDB connection string passwords
      result = result.replace(/mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_.-]+:([^@\s]+)@[a-zA-Z0-9_.-]+/gi, (match, password) => {
        return match.replace(password, '[REDACTED SECRET]');
      });
      
      // 2. Redact Google API Keys
      result = result.replace(/AIzaSy[a-zA-Z0-9_-]{33}/gi, '[REDACTED SECRET]');
      
      // 3. Redact AWS Access Key IDs
      result = result.replace(/AKIA[0-9A-Z]{16}/gi, '[REDACTED SECRET]');
      
      // 4. Redact wJalrXUtn AWS Secret Access Key directly
      result = result.replace(/wJalrXUtnFEMI\/[a-zA-Z0-9\/+=]{27}/gi, '[REDACTED SECRET]');
      
      // 5. General key/value assignments for secrets
      result = result.replace(/(["'])(aws_secret|client_secret|private_key|token|password|passwd|google_api_key|uri)\1\s*:\s*(["'])(.*?)\3/gi, (match, q1, key, q3, val) => {
        if (val.includes('[REDACTED SECRET]')) return match;
        if (key.toLowerCase() === 'uri') {
          return `${q1}${key}${q1}: ${q3}${val.replace(/mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_.-]+:([^@\s]+)@[a-zA-Z0-9_.-]+/gi, (m, p) => m.replace(p, '[REDACTED SECRET]'))}${q3}`;
        }
        return `${q1}${key}${q1}: ${q3}[REDACTED SECRET]${q3}`;
      });

      return result;
    }

    for (const path of sensitiveInfoCandidates) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`SensitiveDisclosure:${path}`);

      try {
        const res = await makeRequest(url, 'GET');

        if (res.statusCode === 200 && res.body.trim().length > 0) {
          const bodyText = res.body.trim();
          const exposedTypes = [];

          for (const [patternName, regex] of Object.entries(sensitivePatterns)) {
            regex.lastIndex = 0;
            if (regex.test(bodyText)) {
              exposedTypes.push(patternName.replace(/_/g, ' '));
            }
          }

          if (exposedTypes.length > 0) {
            const dedupeKey = `${domain}|${path}|GET|SensitiveDisclosure`;

            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);

              const existingFinding = await Vulnerability.findOne({
                domainId: scanContext?.domainId,
                path,
                status: { $ne: 'Resolved' },
                category: CLOUD_INFRASTRUCTURE_CATEGORY,
                subCategory: SENSITIVE_INFO_DISCLOSURE_SUB
              });

              if (existingFinding) {
                metadata.correlations = (metadata.correlations || 0) + 1;
              } else {
                const redactedBody = redactSecrets(bodyText);
                findings.push(
                  createFinding({
                    name: 'Sensitive Information Disclosure',
                    desc: `The endpoint "${path}" was found to expose sensitive credentials or key materials in the response body. Detected type(s): ${exposedTypes.join(', ')}.`,
                    severity: SEVERITY_LEVELS.HIGH,
                    cwe: 'CWE-200',
                    path,
                    impact: 'Exposing credentials, API keys, or database connection strings allows external attackers to gain unauthorized access to backend services, cloud environments, or critical databases, leading to complete system compromise or data theft.',
                    fix: 'Ensure that all application secrets and sensitive configuration values are stored securely (e.g. in environment variables) and are never exposed in client-facing API responses. Implement strict serialization or data sanitization layers.',
                    scanner: SCANNER_NAME,
                    category: CLOUD_INFRASTRUCTURE_CATEGORY,
                    subCategory: SENSITIVE_INFO_DISCLOSURE_SUB,
                    cvssScore: 7.5,
                    evidence: `GET ${path} returned HTTP 200 with body:\n${redactedBody}`,
                    references: [
                      'https://owasp.org/www-community/Source_Code_Analysis_Tools',
                      'https://cwe.mitre.org/data/definitions/200.html'
                    ]
                  })
                );
              }
            }
          }
        }
      } catch (err) {
        // continue
      }
    }

  } catch (globalErr) {
    return createResult(SCANNER_NAME, [], { error: globalErr.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanCloudInfrastructure
};
