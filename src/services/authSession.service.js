const https = require('https');
const http = require('http');
const querystring = require('querystring');
const cheerio = require('cheerio');
const logger = require('../config/logger');
const { withTimeout } = require('../scanners/utils');

const TIMEOUT_MS = 10000;
const USER_AGENT = 'SecureScan/1.0';
const CANDIDATE_LOGIN_PATHS = ['/login', '/signin', '/auth', '/account/login'];

// In-memory store of resolved auth contexts, keyed by scanId, so the same
// session is reused across every scanner in one scan run instead of
// re-logging-in per adapter. TTL cleanup avoids leaking sessions if a scan
// crashes without cleanup being called.
const activeContexts = new Map(); // scanId -> { context, expiresAt }
const CONTEXT_TTL_MS = 30 * 60 * 1000; // 30 minutes

function storeContext(scanId, context) {
  activeContexts.set(String(scanId), { context, expiresAt: Date.now() + CONTEXT_TTL_MS });
  return context;
}

function getStoredContext(scanId) {
  const entry = activeContexts.get(String(scanId));
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    activeContexts.delete(String(scanId));
    return null;
  }
  return entry.context;
}

function clearContext(scanId) {
  activeContexts.delete(String(scanId));
}

// Periodic sweep so crashed/abandoned scans don't hold sessions forever.
setInterval(() => {
  const now = Date.now();
  for (const [scanId, entry] of activeContexts.entries()) {
    if (now > entry.expiresAt) activeContexts.delete(scanId);
  }
}, 5 * 60 * 1000).unref();

function httpRequest(urlString, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (error) {
      reject(error);
      return;
    }

    const client = url.protocol === 'https:' ? https : http;
    const request = client.request(
      url,
      {
        method,
        timeout: TIMEOUT_MS,
        headers: { 'User-Agent': USER_AGENT, ...headers }
      },
      (response) => {
        let responseBody = '';
        response.on('data', (chunk) => {
          responseBody += chunk;
          if (responseBody.length > 500000) response.destroy();
        });
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode,
            headers: response.headers,
            body: responseBody,
            finalUrl: urlString
          });
        });
      }
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);

    if (body) request.write(body);
    request.end();
  });
}

// Parses Set-Cookie response headers into a "name=value; name2=value2" jar string.
function mergeCookies(existingJar, setCookieHeaders) {
  if (!setCookieHeaders || setCookieHeaders.length === 0) return existingJar;

  const jar = new Map();
  (existingJar || '').split(';').forEach((pair) => {
    const [name, ...rest] = pair.trim().split('=');
    if (name) jar.set(name, rest.join('='));
  });

  setCookieHeaders.forEach((cookieStr) => {
    const [pair] = cookieStr.split(';');
    const [name, ...rest] = pair.trim().split('=');
    if (name) jar.set(name, rest.join('='));
  });

  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

// Finds a login form on the page and maps its field names so we know what
// to name the username/password params in the POST body.
function detectLoginForm(html) {
  const $ = cheerio.load(html);
  const form = $('form').filter((_, el) => $(el).find('input[type="password"]').length > 0).first();
  if (form.length === 0) return null;

  const passwordField = form.find('input[type="password"]').first().attr('name') || 'password';
  const userField =
    form.find('input[type="email"]').first().attr('name') ||
    form.find('input[type="text"]').first().attr('name') ||
    form.find('input[name*="user" i]').first().attr('name') ||
    'username';

  const action = form.attr('action') || '';
  const method = (form.attr('method') || 'POST').toUpperCase();

  // Carry forward any hidden fields (CSRF tokens etc.) as-is.
  const hiddenFields = {};
  form.find('input[type="hidden"]').each((_, el) => {
    const name = $(el).attr('name');
    if (name) hiddenFields[name] = $(el).attr('value') || '';
  });

  return { userField, passwordField, action, method, hiddenFields };
}

async function performCredentialLogin(domain, { username, password, loginUrl }) {
  const isLocal = domain.includes('localhost') || domain.includes('127.0.0.1');
  const baseUrl = isLocal ? `http://${domain}` : `https://${domain}`;
  const candidatePaths = loginUrl ? [loginUrl] : CANDIDATE_LOGIN_PATHS;

  for (const path of candidatePaths) {
    const pageUrl = path.startsWith('http') ? path : `${baseUrl}${path}`;

    let pageResponse;
    try {
      pageResponse = await withTimeout(httpRequest(pageUrl), TIMEOUT_MS, 'Login page fetch');
    } catch {
      continue; // try next candidate path
    }

    if (!pageResponse || pageResponse.statusCode >= 400) continue;

    const formInfo = detectLoginForm(pageResponse.body);
    if (!formInfo) continue; // no login form here — try next path

    const submitUrl = formInfo.action
      ? new URL(formInfo.action, pageUrl).toString()
      : pageUrl;

    const initialCookies = mergeCookies(null, pageResponse.headers['set-cookie']);

    const payload = querystring.stringify({
      ...formInfo.hiddenFields,
      [formInfo.userField]: username,
      [formInfo.passwordField]: password
    });

    let loginResponse;
    try {
      loginResponse = await withTimeout(
        httpRequest(submitUrl, {
          method: formInfo.method === 'GET' ? 'GET' : 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(payload),
            ...(initialCookies ? { Cookie: initialCookies } : {})
          },
          body: formInfo.method === 'GET' ? null : payload
        }),
        TIMEOUT_MS,
        'Login submission'
      );
    } catch (error) {
      logger.warn(`Authenticated scan: login submission failed at ${submitUrl}: ${error.message}`);
      continue;
    }

    const finalCookies = mergeCookies(initialCookies, loginResponse.headers['set-cookie']);

    if (!finalCookies) {
      // No session cookie came back — this path likely wasn't the real login
      // endpoint, or credentials were rejected. Try the next candidate.
      continue;
    }

    return {
      cookieJar: finalCookies,
      headers: {},
      loginUrlUsed: submitUrl,
      loginStatusCode: loginResponse.statusCode
    };
  }

  const error = new Error('Automatic login failed: no reachable login form accepted the credentials.');
  error.statusCode = 422;
  throw error;
}

/**
 * Builds an authContext for a scan from a decrypted AuthProfile.
 * authContext shape (passed to scanner adapters as an optional 2nd arg):
 *   { cookieJar: 'name=value; name2=value2', headers: { Authorization?: 'Bearer ...' } }
 */
async function resolveAuthContext(domain, decryptedProfile) {
  if (decryptedProfile.authType === 'cookie') {
    return { cookieJar: decryptedProfile.cookies, headers: {} };
  }

  if (decryptedProfile.authType === 'jwt') {
    return { cookieJar: null, headers: { Authorization: `Bearer ${decryptedProfile.jwt}` } };
  }

  // authType === 'credentials'
  return performCredentialLogin(domain, decryptedProfile);
}

module.exports = {
  resolveAuthContext,
  storeContext,
  getStoredContext,
  clearContext
};