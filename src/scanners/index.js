const { scanSsl } = require('./ssl.scanner');
const { scanHeaders } = require('./headers.scanner');
const { scanDns } = require('./dns.scanner');
const { scanTech } = require('./tech.scanner');
const { scanAuth } = require('./auth.scanner');
const { scanLoginDetection } = require('./loginDetection.scanner');
const { scanCookies } = require('./cookie.scanner');
const { scanJwt } = require('./jwt.scanner');
const { scanPasswordPolicy } = require('./passwordPolicy.scanner');
const { scanSession } = require('./session.scanner');
const { scanForgotPassword } = require('./forgotPassword.scanner');
const { scanAuthorization } = require('./authorization');
const { scanBusinessLogic } = require('./businessLogic.scanner');
const { scanApiSecurity } = require('./apiSecurity.scanner');
const { scanCloudInfrastructure } = require('./cloudInfrastructure.scanner');
const { scanFileUpload } = require('./fileUpload.scanner');
const { scanPathTraversal } = require('./pathTraversal.scanner');
const { scanInsecureFileDownload } = require('./insecureFileDownload.scanner');
const { scanSqlInjection } = require('./sqlInjection.scanner');
const { scanNoSqlInjection } = require('./noSqlInjection.scanner');
const { scanCommandInjection } = require('./commandInjection.scanner');
const { scanSsti } = require('./ssti.scanner');
const { scanXxe } = require('./xxe.scanner');
const { scanXss } = require('./xss.scanner');
const { scanCsrf } = require('./csrf.scanner');
const { scanOpenRedirect } = require('./openRedirect.scanner');
const { scanSsrf } = require('./ssrf.scanner');
const { scanHostHeaderInjection } = require('./hostHeaderInjection.scanner');
const { scanHttpRequestSmuggling } = require('./httpRequestSmuggling.scanner');
const { scanDirectoryListing } = require('./directoryListing.scanner');
const { scanBackupFileExposure } = require('./backupFileExposure.scanner');
const { scanGitRepositoryExposure } = require('./gitRepositoryExposure.scanner');
const { scanDebugMode } = require('./debugMode.scanner');



const ADAPTERS = {
  ssl: scanSsl,
  headers: scanHeaders,
  dns: scanDns,
  tech: scanTech,
  auth: scanAuth,
  loginDetection: scanLoginDetection,
  cookie: scanCookies,
  jwt: scanJwt,
  passwordPolicy: scanPasswordPolicy,
  session: scanSession,
  forgotPassword: scanForgotPassword,
  authorization: scanAuthorization,
  businessLogic: scanBusinessLogic,
  apiSecurity: scanApiSecurity,
  cloudInfrastructure: scanCloudInfrastructure,
  fileUpload: scanFileUpload,
  pathTraversal: scanPathTraversal,
  insecureFileDownload: scanInsecureFileDownload,
  sqlInjection: scanSqlInjection,
  noSqlInjection: scanNoSqlInjection,
  commandInjection: scanCommandInjection,
  ssti: scanSsti,
  xxe: scanXxe,
  xss: scanXss,
  csrf: scanCsrf,
  openRedirect: scanOpenRedirect,
  ssrf: scanSsrf,
  hostHeaderInjection: scanHostHeaderInjection,
  httpRequestSmuggling: scanHttpRequestSmuggling,
  directoryListing: scanDirectoryListing,
  backupFileExposure: scanBackupFileExposure,
  gitRepositoryExposure: scanGitRepositoryExposure,
  debugMode: scanDebugMode
};

function resolveEnabledScanners(checks = {}) {
  const enabled = [];

  if (checks.ssl) enabled.push('ssl');
  if (checks.headers) enabled.push('headers');
  if (checks.ports || checks.compliance) enabled.push('dns');
  if (checks.malware || checks.owasp) enabled.push('tech');
  if (checks.auth || checks.owasp) enabled.push('auth');
  if (checks.loginDetection || checks.auth || checks.owasp) enabled.push('loginDetection');
  if (checks.cookie || checks.headers || checks.owasp) enabled.push('cookie');
  if (checks.jwt || checks.auth || checks.owasp) enabled.push('jwt');
  if (checks.passwordPolicy || checks.auth || checks.owasp) enabled.push('passwordPolicy');
  if (checks.session || checks.auth || checks.owasp) enabled.push('session');
  if (checks.forgotPassword || checks.auth || checks.owasp) enabled.push('forgotPassword');
  if (checks.authorization || checks.owasp) enabled.push('authorization');
  if (checks.businessLogic || checks.owasp) enabled.push('businessLogic');
  if (checks.apiSecurity || checks.owasp) enabled.push('apiSecurity');
  if (checks.cloudInfrastructure || checks.owasp) {
    enabled.push('cloudInfrastructure');
  }
  if (checks.directoryListing || checks.cloudInfrastructure || checks.owasp) {
    enabled.push('directoryListing');
  }
  if (checks.backupFileExposure || checks.cloudInfrastructure || checks.owasp) {
    enabled.push('backupFileExposure');
  }
  if (checks.gitRepositoryExposure || checks.cloudInfrastructure || checks.owasp) {
    enabled.push('gitRepositoryExposure');
  }
  if (checks.debugMode || checks.cloudInfrastructure || checks.owasp) {
    enabled.push('debugMode');
  }
  if (checks.fileUpload || checks.owasp) {
    enabled.push('fileUpload');
    enabled.push('pathTraversal');
    enabled.push('insecureFileDownload');
  }
  if (checks.injection || checks.owasp) {
    enabled.push('sqlInjection');
    enabled.push('noSqlInjection');
    enabled.push('commandInjection');
    enabled.push('ssti');
    enabled.push('xxe');
  }

  if (checks.clientSide || checks.owasp) {
    enabled.push('xss');
    enabled.push('csrf');
    enabled.push('openRedirect');
  }
  
  if (checks.ssrf || checks.owasp) {
    enabled.push('ssrf');
    enabled.push('hostHeaderInjection');
    enabled.push('httpRequestSmuggling');
  }



  if (enabled.length === 0) {
    enabled.push('ssl', 'headers');
  }

  return [...new Set(enabled)];
}

// authContext (optional) is produced by authSession.service.js for
// Authenticated Scan Mode: { cookieJar: 'name=value; ...', headers: { Authorization?: 'Bearer ...' } }
// Existing adapters (ssl, headers, dns, auth, etc.) only declare one
// parameter, so passing this through is a no-op for all of them today.
// Future auth-aware scanners (e.g. an IDOR scanner) can read it as their 2nd arg.
async function runScanners(domain, checks = {}, authContext = null, scanContext = null) {
  const enabled = resolveEnabledScanners(checks);
  const results = [];

  for (const scannerName of enabled) {
    const adapter = ADAPTERS[scannerName];
    if (!adapter) continue;

    try {
      const result = await adapter(domain, authContext, scanContext);
      results.push(result);
    } catch (error) {
      results.push({
        scanner: scannerName,
        success: false,
        findings: [],
        metadata: { error: error.message }
      });
    }
  }

  const findings = results.flatMap((result) => result.findings || []);

  return {
    scanners: enabled,
    results,
    findings
  };
}

module.exports = {
  ADAPTERS,
  resolveEnabledScanners,
  runScanners
};