const cron = require('node-cron');
const logger = require('../config/logger');
const Subscription = require('../models/Subscription');
const SubscriptionPlan = require('../models/SubscriptionPlan');
const User = require('../models/User');
const Organization = require('../models/Organization');
const Notification = require('../models/Notification');
const billingService = require('../services/billing.service');
const auditService = require('../services/audit.service');

async function checkSubscriptionExpiries() {
  logger.info('[subscription-expiry-worker] Checking for expired subscriptions...');
  try {
    const now = new Date();
    
    // Find subscriptions that are not Starter, and have nextBillingDate <= now
    // where status is active, cancelled, or suspended
    const expiredSubscriptions = await Subscription.find({
      currentPlan: { $ne: 'Starter' },
      nextBillingDate: { $lte: now },
      status: { $in: ['active', 'cancelled', 'suspended'] }
    });

    logger.info(`[subscription-expiry-worker] Found ${expiredSubscriptions.length} expired subscriptions to process.`);

    const starterPlan = await SubscriptionPlan.findOne({ name: 'Starter' });
    if (!starterPlan) {
      logger.error('[subscription-expiry-worker] Starter plan not found in database. Cannot perform downgrades.');
      return;
    }

    for (const sub of expiredSubscriptions) {
      try {
        const user = await User.findById(sub.userId);
        const org = await Organization.findById(sub.organizationId);

        if (!user || !org) {
          logger.warn(`[subscription-expiry-worker] User or Org not found for subscription ID: ${sub._id}. Skipping.`);
          continue;
        }

        const oldPlan = sub.currentPlan;

        logger.info(`[subscription-expiry-worker] Downgrading subscription ${sub._id} for Org ${org.name} from ${oldPlan} to Starter.`);

        // Revert to Starter immediately in the DB (billing cycles, maxSeats, limits)
        await billingService.changePlanImmediate(
          user,
          org,
          sub,
          starterPlan,
          'monthly',
          'free',
          `auto_expire_${Date.now()}`
        );

        // Create system notification
        await Notification.create({
          organizationId: org._id,
          userId: user._id,
          email: user.email,
          type: 'SUBSCRIPTION_EXPIRED',
          title: 'Subscription Expired',
          message: `Your ${oldPlan} subscription has expired and has been automatically downgraded to the Starter plan.`
        });

        // Audit log for Subscription Expired (since changePlanImmediate logs 'Plan Downgrade', this registers the cause)
        await auditService.logAudit({
          userId: user._id,
          action: 'Subscription Expired',
          description: `Subscription for plan ${oldPlan} has expired. Automatically downgraded to Starter plan.`,
          status: 'Success'
        });

        logger.info(`[subscription-expiry-worker] Successfully expired subscription for Org: ${org.name}`);
      } catch (subErr) {
        logger.error(`[subscription-expiry-worker] Error processing subscription expiry for sub ID ${sub._id}: ${subErr.message}`);
      }
    }
  } catch (error) {
    logger.error(`[subscription-expiry-worker] Error checking subscription expiries: ${error.message}`);
  }
}

async function retryFailedInvoiceEmails() {
  logger.info('[invoice-email-retry] Checking for failed invoice emails to retry...');
  try {
    const Invoice = require('../models/Invoice');
    const { sendInvoiceEmail } = require('../services/email/resend.service');

    const failedInvoices = await Invoice.find({
      emailDeliveryStatus: 'failed',
      emailDeliveryAttempts: { $lt: 5 } // Max 5 attempts
    });

    logger.info(`[invoice-email-retry] Found ${failedInvoices.length} failed invoice emails to retry.`);

    for (const invoice of failedInvoices) {
      try {
        const user = await User.findById(invoice.userId);
        const backendUrl = process.env.BACKEND_URL;
        if (!backendUrl && !invoice.pdfUrl) {
          logger.error('[subscription-worker] BACKEND_URL is not configured in environment variables for invoice download link.');
        }
        const safeBackendUrl = (backendUrl || '').replace(/\/+$/, '');
        const downloadLink = invoice.pdfUrl || `${safeBackendUrl}/uploads/invoices/${invoice.invoiceNumber}.pdf`;
        
        invoice.emailDeliveryAttempts += 1;
        
        await sendInvoiceEmail({
          to: user.email,
          invoiceNumber: invoice.invoiceNumber,
          planName: invoice.planName,
          amount: invoice.amount,
          date: invoice.generatedAt,
          downloadLink
        });

        invoice.emailDeliveryStatus = 'sent';
        invoice.emailDeliveryError = '';
        await invoice.save();
        logger.info(`[invoice-email-retry] Successfully retried and sent invoice email for ${invoice.invoiceNumber}`);
      } catch (retryErr) {
        invoice.emailDeliveryError = retryErr.message;
        await invoice.save();
        logger.error(`[invoice-email-retry] Retry failed for invoice ${invoice.invoiceNumber}: ${retryErr.message}`);
      }
    }
  } catch (err) {
    logger.error(`[invoice-email-retry] Error retrying invoice emails: ${err.message}`);
  }
}

// Function to schedule the worker (run daily at midnight)
const startSubscriptionExpiryWorker = () => {
  logger.info('Initializing Subscription Expiry Worker...');
  const cronExpression = process.env.SUBSCRIPTION_EXPIRY_CRON || '0 0 * * *';
  
  cron.schedule(cronExpression, async () => {
    logger.info('Cron triggered: subscription expiry check');
    await checkSubscriptionExpiries();
    await retryFailedInvoiceEmails();
  });
  
  logger.info(`Subscription Expiry cron schedule active — cron: ${cronExpression}`);
};

module.exports = {
  checkSubscriptionExpiries,
  retryFailedInvoiceEmails,
  startSubscriptionExpiryWorker
};
