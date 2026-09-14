const USER_ROLES = {
  USER: 'user',
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin'
};

const WORKSPACE_ROLES = {
  OWNER: 'Owner',
  ADMIN: 'Admin',
  ANALYST: 'Analyst'
};

const SCAN_TYPES = {
  FULL: 'Full Scan',
  QUICK: 'Quick Scan',
  CUSTOM: 'Custom Scan'
};

const SCAN_STATUS = {
  QUEUED: 'Queued',
  IN_PROGRESS: 'In Progress',
  COMPLETED: 'Completed',
  FAILED: 'Failed',
  SCHEDULED: 'Scheduled'
};

const SEVERITY_LEVELS = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low'
};

const VULN_STATUS = {
  OPEN: 'Open',
  IN_PROGRESS: 'In Progress',
  RESOLVED: 'Resolved'
};

const REPORT_TEMPLATES = {
  EXECUTIVE: 'Executive',
  TECHNICAL: 'Technical',
  COMPLIANCE: 'Compliance'
};

const REPORT_STATUS = {
  COMPLETED: 'Completed',
  IN_PROGRESS: 'In Progress',
  FAILED: 'Failed'
};

const DOMAIN_VERIFICATION_STATUS = {
  PENDING: 'pending_verification',
  VERIFIED: 'verified',
  REJECTED: 'rejected'
};

const DOMAIN_VERIFICATION_METHODS = {
  DNS_TXT: 'dns_txt',
  HTML_FILE: 'html_file'
};

const MAX_VERIFICATION_ATTEMPTS = 5;

const ALERT_TYPES = {
  SSL_EXPIRY: 'ssl_expiry',
  DOMAIN_EXPIRY: 'domain_expiry',
  CRITICAL_FINDING: 'critical_finding',
  DAILY_SUMMARY: 'daily_summary',
  SCHEDULED_SCAN: 'scheduled_scan'
};

const ALERT_STATUS = {
  ACTIVE: 'Active',
  ACKNOWLEDGED: 'Acknowledged',
  RESOLVED: 'Resolved'
};

const MONITORING_EVENT_TYPES = {
  DAILY_SCAN: 'daily_scan',
  SSL_CHECK: 'ssl_check',
  DOMAIN_EXPIRY_CHECK: 'domain_expiry_check',
  DAILY_SUMMARY: 'daily_summary'
};

const MONITORING_EVENT_STATUS = {
  SUCCESS: 'success',
  WARNING: 'warning',
  FAILED: 'failed'
};

const EXPIRY_THRESHOLDS = {
  WARNING_DAYS: 30,
  HIGH_DAYS: 7
};

const SUPPORT_TICKET_CATEGORIES = [
  'Technical Issue',
  'Billing',
  'Sales',
  'Feature Request',
  'Bug Report',
  'General Inquiry',
  'Other'
];

const SUPPORT_TICKET_PRIORITIES = [
  'Low',
  'Medium',
  'High'
];

const SUPPORT_TICKET_STATUSES = [
  'Open',
  'In Progress',
  'Waiting for Customer',
  'Resolved',
  'Closed'
];

const SUPPORT_TICKET_SOURCES = [
  'Landing Page',
  'User Panel'
];

const AUTH_SECURITY_CATEGORY = 'Authentication & Account Security';
const BUSINESS_LOGIC_CATEGORY = 'Business Logic';
const BUSINESS_LOGIC_FLAWS_SUB = 'Business Logic Flaws';
const API_SECURITY_CATEGORY = 'API Security';
const BOLA_SUB = 'Broken Object Level Authorization (BOLA)';
const BFLA_SUB = 'Broken Function Level Authorization (BFLA)';
const EXPOSURE_SUB = 'Excessive Data Exposure';
const MASS_ASSIGNMENT_SUB = 'Mass Assignment';
const RATELIMIT_SUB = 'API Rate Limit Issues';
const CLOUD_INFRASTRUCTURE_CATEGORY = 'Cloud & Infrastructure';
const EXPOSED_ADMIN_PANELS_SUB = 'Exposed Admin Panels';
const CLOUD_STORAGE_EXPOSURE_SUB = 'Public Cloud Storage Exposure';
const SECURITY_MISCONFIGURATION_SUB = 'Security Misconfiguration';
const DEFAULT_CREDENTIALS_SUB = 'Default Credentials';
const SENSITIVE_INFO_DISCLOSURE_SUB = 'Sensitive Information Disclosure';
const DIRECTORY_LISTING_SUB = 'Directory Listing';
const BACKUP_FILE_EXPOSURE_SUB = 'Backup File Exposure';
const GIT_REPOSITORY_EXPOSURE_SUB = 'Git Repository Exposure';
const DEBUG_MODE_SUB = 'Debug Mode Enabled';
const FILE_UPLOAD_CATEGORY = 'File & Upload';
const UNRESTRICTED_FILE_UPLOAD_SUB = 'Unrestricted File Upload';
const PATH_TRAVERSAL_SUB = 'Path Traversal';
const INSECURE_FILE_DOWNLOAD_SUB = 'Insecure File Download';
const INJECTION_CATEGORY = 'Injection';
const SQL_INJECTION_SUB = 'SQL Injection';
const NOSQL_INJECTION_SUB = 'NoSQL Injection';
const COMMAND_INJECTION_SUB = 'Command Injection';
const SSTI_SUB = 'SSTI';
const XXE_SUB = 'XXE';
const CLIENT_SIDE_CATEGORY = 'Client Side';
const XSS_SUB = 'Cross-Site Scripting (XSS)';
const CSRF_SUB = 'Cross-Site Request Forgery (CSRF)';
const OPEN_REDIRECT_SUB = 'Open Redirect';
const SSRF_AND_NETWORK_CATEGORY = 'SSRF & Network';
const SSRF_SUB = 'SSRF';
const HOST_HEADER_INJECTION_SUB = 'Host Header Injection';
const HTTP_REQUEST_SMUGGLING_SUB = 'HTTP Request Smuggling';



// Feasibility tiers:
//  'external'      -> runs automatically, no credentials needed
//  'authenticated'  -> needs 1 user-supplied test account (future ScanCredential flow)
//  'dual-account'   -> needs 2 user-supplied test accounts (cross-account access tests)
//  'manual'         -> cannot be safely automated (e.g. needs live OTP receipt); reported as a checklist item only
const AUTH_CHECK_TYPES = {
  WEAK_PASSWORD_POLICY: { subCategory: 'Weak Password Policy', tier: 'external' },
  SESSION_FIXATION: { subCategory: 'Session Fixation', tier: 'external' },
  JWT_SECURITY: { subCategory: 'JWT Security Issues', tier: 'external' },
  FORGOT_PASSWORD_WEAKNESS: { subCategory: 'Forgot Password Weakness', tier: 'external' },
  PASSWORD_RESET_TOKEN: { subCategory: 'Password Reset Token Issues', tier: 'external' },
  SESSION_HIJACKING: { subCategory: 'Session Hijacking', tier: 'authenticated' },
  MFA_BYPASS: { subCategory: 'MFA Bypass', tier: 'authenticated' },
  BROKEN_AUTHENTICATION: { subCategory: 'Broken Authentication', tier: 'authenticated' },
  IDOR: { subCategory: 'IDOR (Insecure Direct Object Reference)', tier: 'dual-account' },
  OTP_BYPASS: { subCategory: 'OTP Bypass', tier: 'manual' },
  LOGIN_PAGE_DETECTED: { subCategory: 'Exposed Login/Authentication Page', tier: 'external' }
};

module.exports = {
  USER_ROLES,
  WORKSPACE_ROLES,
  SCAN_TYPES,
  SCAN_STATUS,
  SEVERITY_LEVELS,
  VULN_STATUS,
  REPORT_TEMPLATES,
  REPORT_STATUS,
  DOMAIN_VERIFICATION_STATUS,
  DOMAIN_VERIFICATION_METHODS,
  MAX_VERIFICATION_ATTEMPTS,
  ALERT_TYPES,
  ALERT_STATUS,
  MONITORING_EVENT_TYPES,
  MONITORING_EVENT_STATUS,
  EXPIRY_THRESHOLDS,
  SUPPORT_TICKET_CATEGORIES,
  SUPPORT_TICKET_PRIORITIES,
  SUPPORT_TICKET_STATUSES,
  SUPPORT_TICKET_SOURCES,
  AUTH_SECURITY_CATEGORY,
  AUTH_CHECK_TYPES,
  BUSINESS_LOGIC_CATEGORY,
  BUSINESS_LOGIC_FLAWS_SUB,
  API_SECURITY_CATEGORY,
  BOLA_SUB,
  BFLA_SUB,
  EXPOSURE_SUB,
  MASS_ASSIGNMENT_SUB,
  RATELIMIT_SUB,
  CLOUD_INFRASTRUCTURE_CATEGORY,
  EXPOSED_ADMIN_PANELS_SUB,
  CLOUD_STORAGE_EXPOSURE_SUB,
  SECURITY_MISCONFIGURATION_SUB,
  DEFAULT_CREDENTIALS_SUB,
  SENSITIVE_INFO_DISCLOSURE_SUB,
  DIRECTORY_LISTING_SUB,
  BACKUP_FILE_EXPOSURE_SUB,
  GIT_REPOSITORY_EXPOSURE_SUB,
  DEBUG_MODE_SUB,
  FILE_UPLOAD_CATEGORY,
  UNRESTRICTED_FILE_UPLOAD_SUB,
  PATH_TRAVERSAL_SUB,
  INSECURE_FILE_DOWNLOAD_SUB,
  INJECTION_CATEGORY,
  SQL_INJECTION_SUB,
  NOSQL_INJECTION_SUB,
  COMMAND_INJECTION_SUB,
  SSTI_SUB,
  XXE_SUB,
  CLIENT_SIDE_CATEGORY,
  XSS_SUB,
  CSRF_SUB,
  OPEN_REDIRECT_SUB,
  SSRF_AND_NETWORK_CATEGORY,
  SSRF_SUB,
  HOST_HEADER_INJECTION_SUB,
  HTTP_REQUEST_SMUGGLING_SUB
};