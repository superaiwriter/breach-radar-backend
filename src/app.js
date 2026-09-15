const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const path = require('path');
const mongoSanitize = require('express-mongo-sanitize'); // SECURITY FIX: MongoDB injection protection
const passportSetup = require('./config/passport');
const oauthRoutes = require('./routes/oauth.routes');

const authRoutes = require('./routes/auth.routes');
const domainRoutes = require('./routes/domain.routes');
const scanRoutes = require('./routes/scan.routes');
const authProfileRoutes = require('./routes/authProfile.routes');
const vulnRoutes = require('./routes/vuln.routes');
const reportRoutes = require('./routes/report.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const monitoringRoutes = require('./routes/monitoring.routes');
const adminRoutes = require('./routes/admin.routes');
const superAdminRoutes = require('./routes/superAdmin.routes');
const userRoutes = require('./routes/user.routes');
const teamRoutes = require('./routes/team.routes');
const invitationRoutes = require('./routes/invitation.routes');
const billingRoutes = require('./routes/billing.routes');
const paymentRoutes = require('./routes/payment.routes');
const notificationRoutes = require('./routes/notification.routes');
const settingsRoutes = require('./routes/settings.routes');
const securityRoutes = require('./routes/security.routes');
const apiAccessRoutes = require('./routes/apiAccess.routes');
const integrationRoutes = require('./routes/integration.routes');
const activityLogRoutes = require('./routes/activityLog.routes');
const supportRoutes = require('./routes/support.routes');
const statsRoutes = require('./routes/stats.routes');
const pricingRoutes = require('./routes/pricing.routes');
const testBusinessWorkflowRoutes = require('./routes/testBusinessWorkflow.routes');
const testBolaWorkflowRoutes = require('./routes/testBolaWorkflow.routes');
const testBflaWorkflowRoutes = require('./routes/testBflaWorkflow.routes');
const testExposureWorkflowRoutes = require('./routes/testExposureWorkflow.routes');
const testMassAssignmentWorkflowRoutes = require('./routes/testMassAssignmentWorkflow.routes');
const testRateLimitWorkflowRoutes = require('./routes/testRateLimitWorkflow.routes');
const testAdminExposureRoutes = require('./routes/testAdminExposure.routes');
const testCloudStorageRoutes = require('./routes/testCloudStorage.routes');
const testMisconfigWorkflowRoutes = require('./routes/testMisconfigWorkflow.routes');
const testDefaultCredsWorkflowRoutes = require('./routes/testDefaultCredsWorkflow.routes');
const testSensitiveDisclosureWorkflowRoutes = require('./routes/testSensitiveDisclosureWorkflow.routes');
const testFileUploadWorkflowRoutes = require('./routes/testFileUploadWorkflow.routes');
const testPathTraversalWorkflowRoutes = require('./routes/testPathTraversalWorkflow.routes');
const testInsecureFileDownloadWorkflowRoutes = require('./routes/testInsecureFileDownloadWorkflow.routes');
const testSqlInjectionWorkflowRoutes = require('./routes/testSqlInjectionWorkflow.routes');
const testNoSqlInjectionWorkflowRoutes = require('./routes/testNoSqlInjectionWorkflow.routes');
const testCommandInjectionWorkflowRoutes = require('./routes/testCommandInjectionWorkflow.routes');
const testSstiWorkflowRoutes = require('./routes/testSstiWorkflow.routes');
const testXxeWorkflowRoutes = require('./routes/testXxeWorkflow.routes');
const testXssWorkflowRoutes = require('./routes/testXssWorkflow.routes');
const testCsrfWorkflowRoutes = require('./routes/testCsrfWorkflow.routes');
const testOpenRedirectWorkflowRoutes = require('./routes/testOpenRedirectWorkflow.routes');
const testSsrfWorkflowRoutes = require('./routes/testSsrfWorkflow.routes');
const testHostHeaderWorkflowRoutes = require('./routes/testHostHeaderWorkflow.routes');
const testHttpRequestSmugglingWorkflowRoutes = require('./routes/testHttpRequestSmugglingWorkflow.routes');
const testDirectoryListingRoutes = require('./routes/testDirectoryListing.routes');
const testBackupFileExposureRoutes = require('./routes/testBackupFileExposure.routes');
const testGitExposureRoutes = require('./routes/testGitExposure.routes');
const testDebugModeRoutes = require('./routes/testDebugMode.routes');




const { generalLimiter } = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');
const logger = require('./config/logger');

const app = express();

const defaultCorsOrigins = process.env.NODE_ENV === 'production'
  ? [
      'https://pentestradar.com',
      'https://www.pentestradar.com',
      'https://breach-radar-frontend-539618567961.europe-west1.run.app'
    ]
  : [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:5180',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5174',
      'http://127.0.0.1:5180',
      'https://pentestradar.com',
      'https://www.pentestradar.com',
      'https://breach-radar-frontend-539618567961.europe-west1.run.app'
    ];

const corsOrigins = [
  ...defaultCorsOrigins,
  process.env.FRONTEND_URL,
  process.env.CORS_ORIGIN
]
  .filter(Boolean)
  .flatMap((origin) => origin.split(','))
  .map((origin) => origin.trim())
  .filter(Boolean)
  .filter((origin, index, origins) => origins.indexOf(origin) === index);

// Security Headers
app.use(helmet());

// SECURITY FIX: Prevent MongoDB injection attacks ($gt, $ne, etc.)
app.use(mongoSanitize());

// Google OAuth setup
passportSetup(app);

// Cross Origin Resource Sharing
app.use(cors({
  origin(origin, callback) {
    if (!origin || corsOrigins.includes(origin)) {
      return callback(null, true);
    }

    logger.warn(`[cors] Blocked request from origin: ${origin}. Allowed origins: ${corsOrigins.join(', ')}`);
    return callback(new Error(`Origin ${origin} is not allowed by CORS`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Cookie Parser Middleware
app.use(cookieParser());

// Request Limiters
app.use('/api/', generalLimiter);

// Payload Parsing
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true }));
const uploadsDir = process.env.UPLOADS_DIR || path.resolve(__dirname, '../uploads');
app.use('/uploads', express.static(uploadsDir, {
  setHeaders: (res) => {
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Access-Control-Allow-Origin', '*');
  },
}));

// HTTP Request Logger
app.use(morgan('combined', {
  stream: { write: (message) => logger.http(message.trim()) }
}));

// API Endpoint Handlers Mapping
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/auth', oauthRoutes); // Google OAuth routes
app.use('/api/v1/domains', domainRoutes);
app.use('/api/v1/scans', scanRoutes);
app.use('/api/v1/auth-profiles', authProfileRoutes);
app.use('/api/v1/vulnerabilities', vulnRoutes);
app.use('/api/v1/reports', reportRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);
app.use('/api/v1/monitoring', monitoringRoutes);
app.use('/api/v1/admin', adminRoutes);
app.use('/api/v1/super-admin', superAdminRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/team', teamRoutes);
app.use('/api/v1/invitations', invitationRoutes);
app.use('/api/v1/billing', billingRoutes);
// FIX: Removed duplicate /api/payment route. Only /api/v1/payment is used by frontend.
app.use('/api/v1/payment', paymentRoutes);
app.use('/api/v1/notifications', notificationRoutes);
app.use('/api/v1/settings', settingsRoutes);
app.use('/api/v1/security', securityRoutes);
app.use('/api/v1/api-access', apiAccessRoutes);
app.use('/api/v1/integrations', integrationRoutes);
app.use('/api/v1/activity-log', activityLogRoutes);
app.use('/api/v1/support', supportRoutes);
app.use('/api/v1/stats', statsRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/v1/pricing', pricingRoutes);
app.use('/api/pricing', pricingRoutes);
app.use('/api/v1/test-business-workflow', testBusinessWorkflowRoutes);
app.use('/api/v1/test-bola', testBolaWorkflowRoutes);
app.use('/api/v1/test-bfla', testBflaWorkflowRoutes);
app.use('/api/v1/test-exposure', testExposureWorkflowRoutes);
app.use('/api/v1/test-mass-assignment', testMassAssignmentWorkflowRoutes);
app.use('/api/v1/test-ratelimit', testRateLimitWorkflowRoutes);
app.use('/api/v1/test-admin-exposure', testAdminExposureRoutes);
app.use('/api/v1/test-cloud-storage', testCloudStorageRoutes);
app.use('/api/v1/test-misconfig', testMisconfigWorkflowRoutes);
app.use('/api/v1/test-default-creds', testDefaultCredsWorkflowRoutes);
app.use('/api/v1/test-sensitive-disclosure', testSensitiveDisclosureWorkflowRoutes);
app.use('/api/v1/test-file-upload', testFileUploadWorkflowRoutes);
app.use('/api/test-files', testPathTraversalWorkflowRoutes);
app.use('/api/test-insecure-download', testInsecureFileDownloadWorkflowRoutes);
app.use('/api/test-sqli', testSqlInjectionWorkflowRoutes);
app.use('/api/test-nosql', testNoSqlInjectionWorkflowRoutes);
app.use('/api/test-command-injection', testCommandInjectionWorkflowRoutes);
app.use('/api/test-ssti', testSstiWorkflowRoutes);
app.use('/api/test-xxe', testXxeWorkflowRoutes);
app.use('/api/test-xss', testXssWorkflowRoutes);
app.use('/api/test-csrf', testCsrfWorkflowRoutes);
app.use('/api/test-open-redirect', testOpenRedirectWorkflowRoutes);
app.use('/api/test-ssrf', testSsrfWorkflowRoutes);
app.use('/api/test-host-header', testHostHeaderWorkflowRoutes);
app.use('/api/test-http-smuggling', testHttpRequestSmugglingWorkflowRoutes);
app.use('/api/test-directory-listing', testDirectoryListingRoutes);
app.use('/api/test-backup-file-exposure', testBackupFileExposureRoutes);
app.use('/api/test-git-exposure', testGitExposureRoutes);
app.use('/api/test-debug-mode', testDebugModeRoutes);




// Base Check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date() });
});

// Capture Unknown Paths
app.use((req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
});

// Centralized Application Exception Handler
app.use(errorHandler);

module.exports = app;