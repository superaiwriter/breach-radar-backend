const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
console.log("KEY_ID loaded:", !!process.env.RAZORPAY_KEY_ID);
console.log("KEY_SECRET loaded:", !!process.env.RAZORPAY_KEY_SECRET);
console.log("WEBHOOK_SECRET loaded:", !!process.env.RAZORPAY_WEBHOOK_SECRET);
const http = require('http');
const app = require('./app');
const connectDB = require('./config/db');
const { connectRedis } = require('./config/redis');
const { initializeQueues } = require('./services/queue.service');
const { startScanWorker } = require('./workers/scan.worker');
const { startReportWorker } = require('./workers/report.worker');
const { startAlertWorker } = require('./workers/alert.worker');
const { startMonitoringWorker } = require('./workers/monitoring.worker');
const { startSslWorker } = require('./workers/ssl.worker');
const { startDomainExpiryWorker } = require('./workers/domainExpiry.worker');
const { startSubscriptionExpiryWorker } = require('./workers/subscriptionExpiry.worker');
const { startMonitoringScheduler } = require('./schedulers/monitoring.scheduler');
const logger = require('./config/logger');
const { validateRazorpayEnv } = require('./config/razorpay');

const PORT = process.env.PORT || 5000;
const server = http.createServer(app);

function validateStartupConfig() {
  validateRazorpayEnv();

  const frontendUrl = String(process.env.FRONTEND_URL || '').trim();
  const corsOrigin = String(process.env.CORS_ORIGIN || '').trim();
  const redisUrl = String(process.env.REDIS_URL || '').trim();
  const redisEnabled = String(process.env.REDIS_ENABLED || '').trim().toLowerCase();

  if (!frontendUrl) {
    logger.warn('[startup] FRONTEND_URL is not set. Falling back to default local CORS origins.');
  } else {
    logger.info(`[startup] FRONTEND_URL=${frontendUrl}`);
  }

  if (corsOrigin) {
    logger.info(`[startup] CORS_ORIGIN=${corsOrigin}`);
  }

  if (redisUrl) {
    logger.info('[startup] REDIS_URL is configured. Redis-backed queues will be attempted.');
  } else if (['true', '1', 'yes'].includes(redisEnabled)) {
    logger.warn('[startup] REDIS_ENABLED is true but REDIS_URL is not set. Falling back to REDIS_HOST/REDIS_PORT.');
  } else {
    logger.warn('[startup] REDIS_URL is not configured. Redis queues are optional; payment flow does not require Redis.');
  }
}

const startServer = async () => {
  try {
    // 1. Establish Database Connection
    validateStartupConfig();

    await connectDB();

    // 1b. Seed database with initial configs and mock records
    const dbSeeder = require('./config/dbSeeder');
    await dbSeeder();

    // 2. Establish Redis and background workers when available
    const redis = connectRedis();

    if (redis) {
      try {
        initializeQueues();
        startScanWorker();
        startReportWorker();
        startAlertWorker();
        startMonitoringWorker();
        startSslWorker();
        startDomainExpiryWorker();
      } catch (queueError) {
        logger.warn(`Queue/worker setup skipped: ${queueError.message}. Mock scans will run in-process.`);
      }
    } else {
      logger.warn('Redis unavailable. Scans will run in-process via background jobs.');
    }

    startMonitoringScheduler();
    startSubscriptionExpiryWorker();

    // 4. Start HTTP Server Listener
    server.listen(PORT, () => {
      logger.info(`Server listening on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode.`);
    });
  } catch (error) {
    logger.error(`Critical server initialization crash: ${error.message}`);
    process.exit(1);
  }
};

// Handle Uncaught Exceptions
process.on('uncaughtException', (err) => {
  logger.error(`Uncaught Exception Error: ${err.message}`);
  logger.error(err.stack);
  process.exit(1);
});

// Handle Unhandled Rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error(`Unhandled Promise Rejection: ${reason}`);
  process.exit(1);
});

startServer();

// Trigger restart to reload .env config
