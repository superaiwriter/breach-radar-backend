const cron = require('node-cron');
const logger = require('../config/logger');
const {
  addMonitoringJob,
  addSslMonitoringJob,
  addDomainExpiryJob
} = require('../services/queue.service');

const DEFAULT_CRON = '0 2 * * *';
const SSL_CRON = process.env.SSL_MONITORING_CRON || DEFAULT_CRON;
const DOMAIN_EXPIRY_CRON = process.env.DOMAIN_EXPIRY_CRON || DEFAULT_CRON;
const DAILY_SCAN_CRON = process.env.DAILY_SCAN_CRON || DEFAULT_CRON;
const SUMMARY_CRON = process.env.DAILY_SUMMARY_CRON || '30 2 * * *';

let started = false;

function isMonitoringEnabled() {
  return process.env.MONITORING_ENABLED !== 'false';
}

function startMonitoringScheduler() {
  if (started) return;
  if (!isMonitoringEnabled()) {
    logger.info('Monitoring scheduler disabled via MONITORING_ENABLED=false');
    return;
  }

  started = true;
<<<<<<< HEAD
  logger.info('Starting PentestRadar monitoring scheduler');
=======
  logger.info('Starting Pentestradar monitoring scheduler');
>>>>>>> c6e6a65c73bbe1bac59ccd1bda686a7df18a830c

  cron.schedule(DAILY_SCAN_CRON, async () => {
    logger.info('Cron triggered: daily domain scans');
    try {
      await addMonitoringJob('daily-scans');
    } catch (error) {
      logger.error(`Failed to enqueue daily scans: ${error.message}`);
      const monitoringService = require('../services/monitoring.service');
      await monitoringService.runDailyScansForAllDomains();
    }
  });

  cron.schedule(SSL_CRON, async () => {
    logger.info('Cron triggered: SSL expiry monitoring');
    try {
      await addSslMonitoringJob('ssl-checks');
    } catch (error) {
      logger.error(`Failed to enqueue SSL monitoring: ${error.message}`);
      const monitoringService = require('../services/monitoring.service');
      await monitoringService.runSslChecksForAllDomains();
    }
  });

  cron.schedule(DOMAIN_EXPIRY_CRON, async () => {
    logger.info('Cron triggered: domain expiry monitoring');
    try {
      await addDomainExpiryJob('domain-expiry-checks');
    } catch (error) {
      logger.error(`Failed to enqueue domain expiry monitoring: ${error.message}`);
      const monitoringService = require('../services/monitoring.service');
      await monitoringService.runDomainExpiryChecksForAllDomains();
    }
  });

  cron.schedule(SUMMARY_CRON, async () => {
    logger.info('Cron triggered: daily monitoring summaries');
    try {
      await addMonitoringJob('daily-summary');
    } catch (error) {
      logger.error(`Failed to enqueue daily summary: ${error.message}`);
      const monitoringService = require('../services/monitoring.service');
      await monitoringService.sendDailySummaries();
    }
  });

  logger.info(
    `Monitoring cron schedules active — scans: ${DAILY_SCAN_CRON}, ssl: ${SSL_CRON}, domain expiry: ${DOMAIN_EXPIRY_CRON}, summary: ${SUMMARY_CRON}`
  );
}

module.exports = {
  startMonitoringScheduler
};
