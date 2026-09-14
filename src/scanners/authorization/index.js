const { createResult } = require('../utils');
const { scanMissingAccessControl } = require('./missingAccessControl');

const SCANNER_NAME = 'authorization';

// authContext (optional, passed through by scanners/index.js's runScanners) will
// carry { cookieJar, headers } for an authenticated test session once Authenticated
// Scan Mode is wired up. It is accepted here now — and threaded through to future
// sibling checks — so later phases (Horizontal/Vertical Privilege Escalation) can
// compare Unauthenticated vs Normal-User vs Admin-User responses without changing
// this file's signature or how it's registered. Missing Access Control itself is
// inherently an unauthenticated-only check, so authContext is not used by it today.
async function scanAuthorization(domain, authContext = null) {
  const findings = [];
  const metadata = { domain, authContextProvided: Boolean(authContext) };

  const missingAccessControlResult = await scanMissingAccessControl(domain);
  findings.push(...missingAccessControlResult.findings);
  metadata.missingAccessControl = missingAccessControlResult.metadata;

  // Future phases (NOT implemented yet, per spec):
  //   const horizontalResult = await scanHorizontalPrivilegeEscalation(domain, authContext);
  //   const verticalResult = await scanVerticalPrivilegeEscalation(domain, authContext);

  return createResult(SCANNER_NAME, findings, metadata, true);
}

module.exports = {
  scanAuthorization
};