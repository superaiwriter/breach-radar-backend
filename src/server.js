const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const logger = require('./config/logger');

// Run critical production validation warnings on server load
if (process.env.NODE_ENV === 'production') {
  const missing = [];

  if (!process.env.MONGODB_URI) {
    missing.push('MONGODB_URI');
  }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'super_secret_jwt_access_key_12345!') {
    missing.push('JWT_SECRET');
  }
  if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET === 'super_secret_jwt_refresh_key_67890!') {
    missing.push('JWT_REFRESH_SECRET');
  }
  if (!process.env.AUTH_PROFILE_ENCRYPTION_KEY || process.env.AUTH_PROFILE_ENCRYPTION_KEY.length !== 64) {
    missing.push('AUTH_PROFILE_ENCRYPTION_KEY');
  }

  if (process.env.GOOGLE_CLIENT_ID) {
    let callbackURL = process.env.GOOGLE_CALLBACK_URL;
    if (!callbackURL && process.env.BACKEND_URL) {
      callbackURL = `${process.env.BACKEND_URL}/api/v1/auth/google/callback`;
    }
    if (!callbackURL || callbackURL.includes('localhost') || callbackURL.includes('127.0.0.1')) {
      missing.push('GOOGLE_CALLBACK_URL (must be configured to a production domain when GOOGLE_CLIENT_ID is active)');
    }
  }

  if (missing.length > 0) {
    logger.warn(`[startup] CONFIGURATION WARNING: The following environment variables should be configured securely in production: ${missing.join(', ')}`);
  }
}

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
const { validateRazorpayEnv } = require('./config/razorpay');

const PORT = process.env.PORT || 8080;
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

const initializeBackgroundServices = async () => {
  try {
    logger.info('Initializing background services...');
    validateStartupConfig();

    // 1. Establish Database Connection
    try {
      await connectDB();

      // 1b. Seed database with initial configs and mock records
      const dbSeeder = require('./config/dbSeeder');
      await dbSeeder();

      // 1c. Clean up stuck scans from previous crashed/restarted sessions
      try {
        const Scan = require('./models/Scan');
        const Domain = require('./models/Domain');
        const { SCAN_STATUS } = require('./constants');

        const stuckScans = await Scan.find({
          status: { $in: [SCAN_STATUS.QUEUED, SCAN_STATUS.IN_PROGRESS] }
        });

        if (stuckScans.length > 0) {
          logger.info(`[startup] Found ${stuckScans.length} stuck scans in active state. Cleaning up...`);
          for (const scan of stuckScans) {
            scan.status = SCAN_STATUS.FAILED;
            scan.completedAt = new Date();
            scan.errorDetail = 'Scan interrupted due to server restart.';
            await scan.save();

            const domain = await Domain.findById(scan.domainId);
            if (domain) {
              domain.statusDetail = 'Scan failed: Interrupted by server restart.';
              if (domain.verificationStatus === 'verified') {
                domain.status = 'Active';
              }
              await domain.save();
            }
          }
          logger.info('[startup] Stuck scans cleanup completed.');
        }
      } catch (cleanupError) {
        logger.error(`Failed to clean up stuck scans: ${cleanupError.message}`);
      }
    } catch (dbError) {
      logger.error(`Database connection or seeding failed: ${dbError.message}`);
    }

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
      logger.warn('Redis unavailable or disabled. Scans will run in-process via background jobs.');
    }

    startMonitoringScheduler();
    startSubscriptionExpiryWorker();

    logger.info('All background services initialization completed.');
  } catch (error) {
    logger.error(`Background services initialization failed: ${error.message}`);
  }
};

const startServer = () => {
  try {
    // Start HTTP Server Listener immediately on 0.0.0.0 to satisfy Cloud Run startup probes
    server.listen(PORT, '0.0.0.0', () => {
      logger.info(`Server listening on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode.`);
      initializeBackgroundServices();
    });
  } catch (error) {
    logger.error(`Critical server listener startup crash: ${error.message}`);
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

// Graceful Shutdown Logic
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);

  // Set a timeout to force shutdown if graceful shutdown takes too long
  const forceShutdownTimeout = setTimeout(() => {
    logger.warn('Graceful shutdown timeout exceeded. Force shutting down.');
    process.exit(1);
  }, 10000); // 10 seconds

  server.close(async () => {
    logger.info('HTTP server closed.');

    try {
      const mongoose = require('mongoose');
      if (mongoose.connection?.readyState !== 0) {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed.');
      }

      const { getRedisClient } = require('./config/redis');
      const redis = getRedisClient();
      if (redis) {
        await redis.quit();
        logger.info('Redis connection closed.');
      }
    } catch (err) {
      logger.error(`Error during graceful shutdown: ${err.message}`);
    } finally {
      clearTimeout(forceShutdownTimeout);
      logger.info('Graceful shutdown completed.');
      process.exit(0);
    }
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();

// Trigger restart to reload .env config
