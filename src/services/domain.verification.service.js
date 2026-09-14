const crypto = require('crypto');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const logger = require('../config/logger');
const {
  DOMAIN_VERIFICATION_STATUS,
  DOMAIN_VERIFICATION_METHODS,
  MAX_VERIFICATION_ATTEMPTS
} = require('../constants');

const DNS_HOST_PREFIX = '_securescan-verify';
const TXT_VALUE_PREFIX = 'securescan-verification=';
const HTML_PATHS = [
  '/securescan-verification.html',
  '/.well-known/securescan-verification.txt'
];
const REQUEST_TIMEOUT_MS = 10000;

function generateVerificationToken() {
  return crypto.randomBytes(24).toString('hex');
}

function buildTxtRecordValue(token) {
  return `${TXT_VALUE_PREFIX}${token}`;
}

function buildVerificationInstructions(domainDoc) {
  const token = domainDoc.verificationToken;
  const domain = domainDoc.domain;

  return {
    domain,
    verificationStatus: domainDoc.verificationStatus,
    verificationMethod: domainDoc.verificationMethod,
    verifiedAt: domainDoc.verifiedAt,
    verificationAttempts: domainDoc.verificationAttempts,
    rejectionReason: domainDoc.rejectionReason || null,
    dns: {
      type: 'TXT',
      host: `${DNS_HOST_PREFIX}.${domain}`,
      value: buildTxtRecordValue(token),
      instructions: `Add a TXT record on ${DNS_HOST_PREFIX}.${domain} with value "${buildTxtRecordValue(token)}".`
    },
    html: {
      filename: 'securescan-verification.html',
      paths: HTML_PATHS,
      content: buildTxtRecordValue(token),
      instructions: `Upload securescan-verification.html to your domain root containing: ${buildTxtRecordValue(token)}`
    }
  };
}

function isDomainVerified(domainDoc) {
  return domainDoc?.verificationStatus === DOMAIN_VERIFICATION_STATUS.VERIFIED;
}

// DEV-ONLY BYPASS: requires BOTH NODE_ENV=development AND an explicit opt-in
// flag, so this can never silently activate in production (defense in depth —
// a stray NODE_ENV=development alone is not enough to bypass real-domain
// ownership verification). Every bypassed check is logged for auditability.
// This exists purely so scans can be tested locally without completing DNS/HTML
// verification for every throwaway test domain.
function isVerificationBypassed() {
  return process.env.NODE_ENV === 'development' && process.env.ALLOW_UNVERIFIED_DOMAIN_SCANS === 'true';
}

function assertDomainVerified(domainDoc) {
  if (!domainDoc) {
    const error = new Error('Domain not found.');
    error.statusCode = 404;
    throw error;
  }

  if (isVerificationBypassed() && !isDomainVerified(domainDoc)) {
    logger.warn(
      `[domain-verification] BYPASSED for "${domainDoc.domain}" (status: ${domainDoc.verificationStatus}) — NODE_ENV=development and ALLOW_UNVERIFIED_DOMAIN_SCANS=true. This must never be enabled in production.`
    );
    return;
  }

  if (domainDoc.verificationStatus === DOMAIN_VERIFICATION_STATUS.REJECTED) {
    const error = new Error(
      `Domain "${domainDoc.domain}" verification was rejected. ${domainDoc.rejectionReason || 'Contact your workspace admin.'}`
    );
    error.statusCode = 403;
    error.code = 'DOMAIN_VERIFICATION_REJECTED';
    throw error;
  }

  if (!isDomainVerified(domainDoc)) {
    const error = new Error(
      `Domain "${domainDoc.domain}" must be verified before scans can run. Complete DNS TXT or HTML file verification first.`
    );
    error.statusCode = 403;
    error.code = 'DOMAIN_NOT_VERIFIED';
    throw error;
  }
}

async function fetchHtmlContent(urlString) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const client = url.protocol === 'https:' ? https : http;

    const request = client.get(
      url,
      { timeout: REQUEST_TIMEOUT_MS, headers: { 'User-Agent': 'SecureScan-Verifier/1.0' } },
      (response) => {
        if (response.statusCode >= 400) {
          response.resume();
          reject(new Error(`HTTP ${response.statusCode}`));
          return;
        }

        const chunks = [];
        response.on('data', (chunk) => {
          chunks.push(chunk);
          if (chunks.reduce((sum, item) => sum + item.length, 0) > 100000) {
            request.destroy();
          }
        });
        response.on('end', () => {
          resolve(Buffer.concat(chunks).toString('utf8'));
        });
      }
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timed out'));
    });
    request.on('error', reject);
  });
}

async function resolveTxtRecords(hostname) {
  try {
    const records = await dns.resolveTxt(hostname);
    return records.flat();
  } catch (error) {
    if (['ENODATA', 'ENOTFOUND', 'ESERVFAIL'].includes(error.code)) {
      return [];
    }
    throw error;
  }
}

async function verifyDnsTxt(domainDoc) {
  const expected = buildTxtRecordValue(domainDoc.verificationToken);
  const hosts = [`${DNS_HOST_PREFIX}.${domainDoc.domain}`, domainDoc.domain];
  const checked = [];

  for (const host of hosts) {
    const records = await resolveTxtRecords(host);
    checked.push({ host, records });

    if (records.some((record) => record === expected || record.includes(expected))) {
      return { verified: true, method: DOMAIN_VERIFICATION_METHODS.DNS_TXT, checked };
    }
  }

  return {
    verified: false,
    method: DOMAIN_VERIFICATION_METHODS.DNS_TXT,
    checked,
    message: `TXT record "${expected}" was not found on ${DNS_HOST_PREFIX}.${domainDoc.domain}.`
  };
}

async function verifyHtmlFile(domainDoc) {
  const expected = buildTxtRecordValue(domainDoc.verificationToken);
  const attempts = [];

  for (const path of HTML_PATHS) {
    for (const protocol of ['https', 'http']) {
      const url = `${protocol}://${domainDoc.domain}${path}`;

      try {
        const body = await fetchHtmlContent(url);
        attempts.push({ url, found: body.includes(expected) });

        if (body.includes(expected)) {
          return {
            verified: true,
            method: DOMAIN_VERIFICATION_METHODS.HTML_FILE,
            matchedUrl: url,
            attempts
          };
        }
      } catch (error) {
        attempts.push({ url, error: error.message });
      }
    }
  }

  return {
    verified: false,
    method: DOMAIN_VERIFICATION_METHODS.HTML_FILE,
    attempts,
    message: `Verification file did not contain "${expected}" at the expected paths.`
  };
}

async function applyVerificationResult(domainDoc, result) {
  domainDoc.lastVerificationAt = new Date();
  domainDoc.verificationAttempts += 1;

  if (result.verified) {
    domainDoc.verificationStatus = DOMAIN_VERIFICATION_STATUS.VERIFIED;
    domainDoc.verificationMethod = result.method;
    domainDoc.verifiedAt = new Date();
    domainDoc.rejectionReason = '';
    domainDoc.status = 'Active';
    domainDoc.statusDetail = 'Domain verified. Ready to scan.';
    await domainDoc.save();

    return {
      verified: true,
      verificationStatus: domainDoc.verificationStatus,
      verificationMethod: domainDoc.verificationMethod,
      verifiedAt: domainDoc.verifiedAt,
      domain: domainDoc
    };
  }

  if (domainDoc.verificationAttempts >= MAX_VERIFICATION_ATTEMPTS) {
    domainDoc.verificationStatus = DOMAIN_VERIFICATION_STATUS.REJECTED;
    domainDoc.rejectionReason = result.message || 'Maximum verification attempts exceeded.';
    domainDoc.status = 'Inactive';
    domainDoc.statusDetail = 'Domain verification rejected.';
  }

  await domainDoc.save();

  const error = new Error(result.message || 'Domain verification failed.');
  error.statusCode = 422;
  error.code = 'DOMAIN_VERIFICATION_FAILED';
  error.details = {
    verificationStatus: domainDoc.verificationStatus,
    verificationAttempts: domainDoc.verificationAttempts,
    rejectionReason: domainDoc.rejectionReason || null
  };
  throw error;
}

async function verifyDomainDns(domainDoc) {
  if (domainDoc.verificationStatus === DOMAIN_VERIFICATION_STATUS.VERIFIED) {
    return {
      verified: true,
      verificationStatus: domainDoc.verificationStatus,
      verificationMethod: domainDoc.verificationMethod,
      verifiedAt: domainDoc.verifiedAt,
      domain: domainDoc
    };
  }

  if (domainDoc.verificationStatus === DOMAIN_VERIFICATION_STATUS.REJECTED) {
    const error = new Error('Domain verification was rejected. Add the domain again to retry.');
    error.statusCode = 403;
    error.code = 'DOMAIN_VERIFICATION_REJECTED';
    throw error;
  }

  const result = await verifyDnsTxt(domainDoc);
  return applyVerificationResult(domainDoc, result);
}

async function verifyDomainHtml(domainDoc) {
  if (domainDoc.verificationStatus === DOMAIN_VERIFICATION_STATUS.VERIFIED) {
    return {
      verified: true,
      verificationStatus: domainDoc.verificationStatus,
      verificationMethod: domainDoc.verificationMethod,
      verifiedAt: domainDoc.verifiedAt,
      domain: domainDoc
    };
  }

  if (domainDoc.verificationStatus === DOMAIN_VERIFICATION_STATUS.REJECTED) {
    const error = new Error('Domain verification was rejected. Add the domain again to retry.');
    error.statusCode = 403;
    error.code = 'DOMAIN_VERIFICATION_REJECTED';
    throw error;
  }

  const result = await verifyHtmlFile(domainDoc);
  return applyVerificationResult(domainDoc, result);
}

function initializeDomainVerification(domainDoc) {
  domainDoc.verificationStatus = DOMAIN_VERIFICATION_STATUS.PENDING;
  domainDoc.verificationToken = generateVerificationToken();
  domainDoc.verificationMethod = null;
  domainDoc.verifiedAt = undefined;
  domainDoc.lastVerificationAt = undefined;
  domainDoc.verificationAttempts = 0;
  domainDoc.rejectionReason = '';
  domainDoc.status = 'Inactive';
  domainDoc.statusDetail = 'Pending domain verification';
  return domainDoc;
}

module.exports = {
  generateVerificationToken,
  buildVerificationInstructions,
  isDomainVerified,
  assertDomainVerified,
  verifyDomainDns,
  verifyDomainHtml,
  initializeDomainVerification
};