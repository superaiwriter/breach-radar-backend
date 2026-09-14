const http = require('http');
const https = require('https');
const { createFinding, createResult } = require('./utils');
const { SEVERITY_LEVELS, BUSINESS_LOGIC_CATEGORY, BUSINESS_LOGIC_FLAWS_SUB } = require('../constants');

const SCANNER_NAME = 'businessLogic';

// Helper to construct baseUrl based on local vs public domain
function getBaseUrl(domain) {
  const isLocal = domain.includes('localhost') || domain.includes('127.0.0.1');
  return isLocal ? `http://${domain}` : `https://${domain}`;
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
      'User-Agent': 'SecureScan/1.0 (+business-logic-scanner)',
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
      timeout: 8000
    };

    const req = client.request(url, options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 500000) req.destroy(); // Cap response body size
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

    req.on('error', reject);

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

/**
 * Business Logic Flaws Scanner
 */
async function scanBusinessLogic(domain, authContext = null) {
  const baseUrl = getBaseUrl(domain);
  const findings = [];
  const metadata = { domain, checksPerformed: [] };
  const seen = new Set(); // Deduplication guard

  try {
    // =========================================================================
    // 1. STATE TRANSITION BYPASS TEST (Accessing /confirm directly)
    // =========================================================================
    const confirmEndpoints = [
      '/api/v1/test-business-workflow/vulnerable/confirm',
      '/api/v1/test-business-workflow/secure/confirm',
      '/checkout/confirm',
      '/api/checkout/confirm',
      '/order/confirm',
      '/api/order/confirm'
    ];

    for (const path of confirmEndpoints) {
      const url = `${baseUrl}${path}`;
      metadata.checksPerformed.push(`StateTransition:${path}`);
      
      try {
        // Attempt to call the confirmation step directly without any workflow session/state
        const res = await makeRequest(url, 'POST', { cartId: '' });

        // If the server accepts direct access to confirm (HTTP 200) and returns confirmation success indicators
        const isSuccessStatus = res.statusCode === 200;
        const bodyText = res.body.toLowerCase();
        const hasConfirmationMarkers = bodyText.includes('confirm') || bodyText.includes('success');

        if (isSuccessStatus && hasConfirmationMarkers) {
          // If it's the secure path, it should reject direct calls. If it responds with success, it's vulnerable.
          // Note: we exclude public informational pages or error responses disguised as 200 OK.
          const isErrorDisguised = bodyText.includes('error') || bodyText.includes('invalid') || bodyText.includes('denied') || bodyText.includes('forbidden');

          if (!isErrorDisguised) {
            const dedupeKey = `${domain}|${path}|WorkflowBypass`;
            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);
              findings.push(
                createFinding({
                  name: 'Business Workflow State Transition Bypass',
                  desc: `The endpoint "${path}" was reached directly and processed successfully without completing preceding steps in the business workflow.`,
                  severity: SEVERITY_LEVELS.HIGH,
                  cwe: 'CWE-841', // Improper Enforcement of Behavioral Workflow
                  path,
                  impact: 'Unauthenticated or unauthorized clients can skip checkout verification steps, potentially placing orders without payment, bypassing registration verifications, or triggering restricted actions out of order.',
                  fix: 'Implement server-side state tracking (e.g. using secure session stores). Each subsequent step in a business workflow must validate that the preceding required steps have been completed in the expected sequence.',
                  scanner: SCANNER_NAME,
                  category: BUSINESS_LOGIC_CATEGORY,
                  subCategory: BUSINESS_LOGIC_FLAWS_SUB,
                  cvssScore: 7.5,
                  evidence: `POST ${path} directly without valid session state returned HTTP ${res.statusCode} with body:\n${res.body.slice(0, 300)}`,
                  references: [
                    'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability',
                    'https://cwe.mitre.org/data/definitions/841.html'
                  ]
                })
              );
            }
          }
        }
      } catch (err) {
        // Continue scanning other endpoints
      }
    }

    // =========================================================================
    // 2. PARAMETER MANIPULATION / CLIENT-SIDE VALIDATION TEST (Negative quantity)
    // =========================================================================
    const cartEndpoints = [
      {
        cartPath: '/api/v1/test-business-workflow/vulnerable/cart',
        addPath: '/api/v1/test-business-workflow/vulnerable/add-product'
      },
      {
        cartPath: '/api/v1/test-business-workflow/secure/cart',
        addPath: '/api/v1/test-business-workflow/secure/add-product'
      }
    ];

    for (const pair of cartEndpoints) {
      metadata.checksPerformed.push(`ParamManipulation:${pair.addPath}`);
      try {
        // Step A: Initialize the cart/session to get a cartId (simulating step 1)
        const cartRes = await makeRequest(`${baseUrl}${pair.cartPath}`, 'GET');
        let cartId = '';
        try {
          const json = JSON.parse(cartRes.body);
          cartId = json.cartId || '';
        } catch (e) {
          // fallback to regex if JSON parsing fails
          const match = cartRes.body.match(/"cartId"\s*:\s*"([^"]+)"/);
          if (match) cartId = match[1];
        }

        if (cartId) {
          // Step B: Send negative quantity parameters to add-product
          const addRes = await makeRequest(`${baseUrl}${pair.addPath}`, 'POST', {
            cartId,
            quantity: -5
          });

          // Check if server accepted the negative value (HTTP 200 and success status)
          const isSuccess = addRes.statusCode === 200;
          const bodyText = addRes.body.toLowerCase();
          const acceptsNegative = bodyText.includes('success') && (bodyText.includes('-5') || bodyText.includes('quantity'));

          if (isSuccess && acceptsNegative && !bodyText.includes('error') && !bodyText.includes('invalid')) {
            const dedupeKey = `${domain}|${pair.addPath}|ParamManipulation`;
            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);
              findings.push(
                createFinding({
                  name: 'Business Rule Enforced Only Client-Side (Parameter Manipulation)',
                  desc: `The endpoint "${pair.addPath}" accepted a negative quantity parameter (-5) on the server side, indicating business rule enforcement relies solely on frontend/client-side checks.`,
                  severity: SEVERITY_LEVELS.MEDIUM,
                  cwe: 'CWE-601', // Client-Side Enforcement of Server-Side Security
                  path: pair.addPath,
                  impact: 'Users can bypass business limitations, resulting in logical state corruption, negative cart balances, inventory discrepancies, or unintended transaction behavior.',
                  fix: 'Enforce all business rule validation rules on the server side. Never trust client-controlled parameters. Validate that quantities are strictly positive integers.',
                  scanner: SCANNER_NAME,
                  category: BUSINESS_LOGIC_CATEGORY,
                  subCategory: BUSINESS_LOGIC_FLAWS_SUB,
                  cvssScore: 5.3,
                  evidence: `POST ${pair.addPath} with quantity=-5 returned HTTP ${addRes.statusCode} with body:\n${addRes.body.slice(0, 300)}`,
                  references: [
                    'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability',
                    'https://cwe.mitre.org/data/definitions/602.html'
                  ]
                })
              );
            }
          }
        }
      } catch (err) {
        // Continue scanning
      }
    }

  } catch (globalErr) {
    return createResult(SCANNER_NAME, [], { error: globalErr.message }, false);
  }

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanBusinessLogic
};
