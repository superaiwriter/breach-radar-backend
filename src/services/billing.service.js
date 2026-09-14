const crypto = require('crypto');
const mongoose = require('mongoose');
const SubscriptionPlan = require('../models/SubscriptionPlan');
const Subscription = require('../models/Subscription');
const PaymentTransaction = require('../models/PaymentTransaction');
const Invoice = require('../models/Invoice');
const Domain = require('../models/Domain');
const Scan = require('../models/Scan');
const TeamMember = require('../models/TeamMember');
const teamService = require('./team.service');
const invoicePdfService = require('./invoicePdf.service');
const auditService = require('./audit.service');
const logger = require('../config/logger');
const {
  getRazorpayClient,
  getRazorpayKeyInfo,
  logRazorpayError
} = require('../config/razorpay');

const PLAN_ORDER = ['Starter', 'Professional', 'Business', 'Enterprise'];

function addMonths(date, count) {
  const next = new Date(date);
  next.setMonth(next.getMonth() + count);
  return next;
}

function cycleMultiplier(cycle) {
  return cycle === 'yearly' ? 10 : 1;
}

function formatCurrency(amount, currency = 'INR') {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency,
    maximumFractionDigits: 0,
  }).format(amount || 0);
}

function generateInvoiceNumber() {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const suffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `INV-${date}-${suffix}`;
}

function mapPlan(plan) {
  const monthly = plan.price || 0;
  return {
    id: plan._id,
    name: plan.name,
    displayName: plan.displayName || plan.name,
    monthly,
    yearly: monthly * cycleMultiplier('yearly'),
    currency: plan.currency || 'INR',
    billingInterval: plan.billingInterval,
    seatLimit: plan.seatLimit,
    domainLimit: plan.domainLimit,
    scanLimit: plan.scanLimit,
    sortOrder: plan.sortOrder,
    isActive: plan.isActive,
    features: plan.features || [],
  };
}

function mapInvoice(invoice) {
  return {
    id: invoice._id,
    invoiceNumber: invoice.invoiceNumber,
    date: invoice.generatedAt || invoice.createdAt,
    amount: invoice.amount,
    tax: invoice.tax,
    currency: invoice.currency,
    amountLabel: formatCurrency(invoice.amount + invoice.tax, invoice.currency),
    planName: invoice.planName,
    status: invoice.paymentStatus,
    transactionId: invoice.transactionId,
  };
}

function mapTransaction(transaction) {
  return {
    id: transaction._id,
    transactionId: transaction.transactionId,
    provider: transaction.provider,
    amount: transaction.amount,
    currency: transaction.currency,
    amountLabel: formatCurrency(transaction.amount, transaction.currency),
    status: transaction.status,
    createdAt: transaction.createdAt,
  };
}

async function ensureSubscription(user, organization) {
  let subscription = await Subscription.findOne({ organizationId: organization._id });

  if (!subscription) {
    subscription = await Subscription.create({
      userId: organization.ownerId || user._id,
      organizationId: organization._id,
      currentPlan: organization.subscriptionPlan || 'Starter',
      billingCycle: 'monthly',
      startDate: new Date(),
      nextBillingDate: addMonths(new Date(), 1),
      paymentStatus: 'free',
      status: 'active',
    });

    await auditService.logAudit({
      userId: organization.ownerId || user._id,
      action: 'Plan Created',
      description: `Starter plan subscription created automatically.`,
      status: 'Success'
    });
  }

  return subscription;
}

async function getUsageMetrics(user, organization, subscription, plan) {
  const workspaceId = user.preferences?.activeWorkspaceId;
  const since = subscription.startDate || new Date(new Date().getFullYear(), new Date().getMonth(), 1);

  const [domainsUsed, scansUsed, seatsUsed] = await Promise.all([
    workspaceId ? Domain.countDocuments({ workspaceId }) : 0,
    workspaceId ? Scan.countDocuments({ workspaceId, createdAt: { $gte: since } }) : 0,
    TeamMember.countDocuments({ organizationId: organization._id, status: { $in: ['ACTIVE', 'PENDING', 'SUSPENDED'] } }),
  ]);

  const domainLimit = plan?.domainLimit || 1;
  const scanLimit = plan?.scanLimit || 5;
  const seatLimit = plan?.seatLimit || organization.maxSeats || 1;

  const displayLimit = (val) => (val >= 999999 ? 'Unlimited' : val);

  return [
    { key: 'domains', label: 'Domains', used: domainsUsed, limit: displayLimit(domainLimit), rawLimit: domainLimit, tone: 'green' },
    { key: 'scans', label: 'Scans', used: scansUsed, limit: displayLimit(scanLimit), rawLimit: scanLimit, tone: 'blue' },
    { key: 'seats', label: 'Seats', used: seatsUsed, limit: displayLimit(seatLimit), rawLimit: seatLimit, tone: 'orange' },
  ];
}

async function getOverview(userId) {
  const { user, organization, actorMember } = await teamService.getContext(userId);
  const [plansRaw, subscription] = await Promise.all([
    SubscriptionPlan.find({ isActive: true }).sort({ sortOrder: 1, price: 1 }),
    ensureSubscription(user, organization),
  ]);

  const plans = plansRaw.map(mapPlan);
  const currentPlan = plansRaw.find((plan) => plan.name === subscription.currentPlan)
    || plansRaw.find((plan) => plan.name === organization.subscriptionPlan)
    || plansRaw[0];

  const [invoices, transactions, usage] = await Promise.all([
    Invoice.find({ organizationId: organization._id }).sort({ generatedAt: -1, createdAt: -1 }).limit(12),
    PaymentTransaction.find({ organizationId: organization._id }).sort({ createdAt: -1 }).limit(12),
    getUsageMetrics(user, organization, subscription, currentPlan),
  ]);

  return {
    organization: {
      id: organization._id,
      name: organization.name,
      subscriptionPlan: organization.subscriptionPlan,
      maxSeats: organization.maxSeats,
    },
    role: actorMember.role,
    subscription: {
      id: subscription._id,
      currentPlan: subscription.currentPlan,
      billingCycle: subscription.billingCycle,
      startDate: subscription.startDate,
      expiryDate: subscription.expiryDate,
      nextBillingDate: subscription.nextBillingDate,
      paymentStatus: subscription.paymentStatus,
      status: subscription.status,
      autoRenew: subscription.autoRenew,
      transactionId: subscription.transactionId,
    },
    activePlan: currentPlan ? mapPlan(currentPlan) : null,
    plans,
    usage,
    invoices: invoices.map(mapInvoice),
    transactions: transactions.map(mapTransaction),
    paymentMethod: {
      provider: transactions[0]?.provider || 'manual',
      last4: transactions[0]?.metadata?.last4 || '',
      billingEmail: user.email,
    },
  };
}

/**
 * Validates whether an organization can downgrade to a target plan based on current usage.
 */
async function validatePlanDowngrade(user, organization, subscription, targetPlan) {
  const currentPlan = subscription.currentPlan;
  
  // Verify plan orders
  const currentIndex = PLAN_ORDER.indexOf(currentPlan);
  const targetIndex = PLAN_ORDER.indexOf(targetPlan.name);
  
  if (currentIndex <= targetIndex) {
    // Not a downgrade (either upgrade or same plan change)
    return { isDowngrade: false, valid: true };
  }

  const usage = await getUsageMetrics(user, organization, subscription, targetPlan);
  const violations = [];

  for (const metric of usage) {
    if (metric.rawLimit < 999999 && metric.used > metric.rawLimit) {
      violations.push(
        `Your active ${metric.label.toLowerCase()} count (${metric.used}) exceeds the target plan limit (${metric.limit}).`
      );
    }
  }

  if (violations.length > 0) {
    return {
      isDowngrade: true,
      valid: false,
      message: `Cannot downgrade subscription plan. Please address the following usage limits:`,
      violations
    };
  }

  return { isDowngrade: true, valid: true };
}

/**
 * Handle subscription upgrades (requires gateway details).
 */
async function upgradePlan(userId, { planName, planId, billingCycle, provider }) {
  const { user, organization, actorMember } = await teamService.getContext(userId);
  if (actorMember.role !== 'OWNER') {
    const error = new Error('Only the organization owner can upgrade the billing plan.');
    error.statusCode = 403;
    throw error;
  }

  const targetPlan = planName || planId;
  if (!targetPlan) {
    const error = new Error('planName or planId is required.');
    error.statusCode = 400;
    throw error;
  }

  const normalizedBillingCycle = String(billingCycle || 'monthly').trim();

  if (!['monthly', 'yearly'].includes(normalizedBillingCycle)) {
    const error = new Error('Billing cycle must be monthly or yearly.');
    error.statusCode = 400;
    throw error;
  }

  let plan;
  if (mongoose.Types.ObjectId.isValid(targetPlan)) {
    plan = await SubscriptionPlan.findById(targetPlan);
  } else {
    plan = await SubscriptionPlan.findOne({ name: targetPlan, isActive: true });
  }

  if (!plan) {
    const error = new Error('Selected plan is not available.');
    error.statusCode = 404;
    throw error;
  }

  const subscription = await ensureSubscription(user, organization);
  const amount = (plan.price || 0) * cycleMultiplier(normalizedBillingCycle);

  // If price is 0 (free tier plan upgrade, e.g. switching back from Professional to Starter)
  if (amount === 0) {
    return changePlanImmediate(user, organization, subscription, plan, normalizedBillingCycle, 'free', 'free_upgrade_txn');
  }

  const amountInPaise = Math.round(amount * 100);

  let rzpOrder;
  try {
    const keyInfo = getRazorpayKeyInfo();
    logger.info(`[billing-service] Order API called user=${user._id} plan=${plan.name} billingCycle=${normalizedBillingCycle} amountInINR=${amount} amountInPaise=${amountInPaise} keyPrefix=${keyInfo.keyPrefix} mode=${keyInfo.mode}`);
    if (keyInfo.isLiveMode) {
      logger.error('[billing-service] Live Razorpay key is active during checkout. Use rzp_test_ credentials for test payments.');
    }

    const orderPayload = {
      amount: amountInPaise,
      currency: plan.currency || 'INR',
      receipt: `rcpt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      notes: {
        userId: user._id.toString(),
        organizationId: organization._id.toString(),
        planName: plan.name,
        billingCycle: normalizedBillingCycle
      }
    };
    logger.info(`[billing-service] razorpay.orders.create request=${JSON.stringify(orderPayload)}`);
    rzpOrder = await getRazorpayClient().orders.create(orderPayload);
    logger.info(`[billing-service] razorpay.orders.create response=${JSON.stringify({
      id: rzpOrder.id,
      entity: rzpOrder.entity,
      amount: rzpOrder.amount,
      amount_paid: rzpOrder.amount_paid,
      amount_due: rzpOrder.amount_due,
      currency: rzpOrder.currency,
      receipt: rzpOrder.receipt,
      status: rzpOrder.status,
      attempts: rzpOrder.attempts,
      created_at: rzpOrder.created_at
    })}`);
  } catch (error) {
    logRazorpayError('[billing-service] Razorpay order creation failed', error);
    error.statusCode = error.statusCode || 502;
    throw error;
  }

  if (!rzpOrder?.id) {
    const error = new Error('Razorpay did not return an order id.');
    error.statusCode = 502;
    error.code = 'RAZORPAY_ORDER_ID_MISSING';
    throw error;
  }

  // Save pending transaction in our database
  const transactionId = `txn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const transaction = await PaymentTransaction.create({
    userId: user._id,
    organizationId: organization._id,
    provider: 'razorpay',
    providerOrderId: rzpOrder.id,
    transactionId,
    amount,
    currency: plan.currency || 'INR',
    status: 'pending',
    metadata: {
      planName: plan.name,
      billingCycle: normalizedBillingCycle,
      source: 'billing_upgrade'
    }
  });

  const keyInfo = getRazorpayKeyInfo();
  logger.info(`[billing-service] Order created orderId=${rzpOrder.id} amount=${rzpOrder.amount} currency=${rzpOrder.currency} keyPrefix=${keyInfo.keyPrefix} mode=${keyInfo.mode}`);

  return {
    message: `Payment initiated for ${plan.name} plan.`,
    orderId: rzpOrder.id,
    amount: rzpOrder.amount,
    currency: rzpOrder.currency,
    key: keyInfo.keyId,
    keyMode: keyInfo.mode,
    keyPrefix: keyInfo.keyPrefix,
    transaction
  };
}

/**
 * Handle subscription downgrades (checks usage limits).
 */
async function downgradePlan(userId, { planName, billingCycle }) {
  const { user, organization, actorMember } = await teamService.getContext(userId);
  if (actorMember.role !== 'OWNER') {
    const error = new Error('Only the organization owner can change subscription tiers.');
    error.statusCode = 403;
    throw error;
  }

  const normalizedPlanName = String(planName || '').trim();
  const normalizedBillingCycle = String(billingCycle || 'monthly').trim();

  const plan = await SubscriptionPlan.findOne({ name: normalizedPlanName, isActive: true });
  if (!plan) {
    const error = new Error('Selected plan is not available.');
    error.statusCode = 404;
    throw error;
  }

  const subscription = await ensureSubscription(user, organization);

  // 1. Enforce downgrade check
  const downgradeValidation = await validatePlanDowngrade(user, organization, subscription, plan);
  if (!downgradeValidation.valid) {
    const error = new Error(
      `${downgradeValidation.message}\n` + downgradeValidation.violations.join('\n')
    );
    error.statusCode = 400;
    error.violations = downgradeValidation.violations;
    throw error;
  }

  // 2. Perform immediate free switch or manual invoice adjust since it's a downgrade
  const now = new Date();
  const amount = (plan.price || 0) * cycleMultiplier(normalizedBillingCycle);
  const transactionId = `txn_dg_${Date.now()}`;

  return changePlanImmediate(user, organization, subscription, plan, normalizedBillingCycle, amount > 0 ? 'paid' : 'free', transactionId);
}

/**
 * Execute immediate database updates to activate a plan.
 */
async function changePlanImmediate(user, organization, subscription, plan, billingCycle, paymentStatus, transactionId) {
  const now = new Date();
  const amount = (plan.price || 0) * cycleMultiplier(billingCycle);
  const oldPlan = subscription.currentPlan;

  subscription.currentPlan = plan.name;
  subscription.billingCycle = billingCycle;
  subscription.startDate = now;
  subscription.expiryDate = null;
  subscription.nextBillingDate = addMonths(now, billingCycle === 'yearly' ? 12 : 1);
  subscription.paymentStatus = paymentStatus;
  subscription.status = 'active';
  subscription.cancelledAt = null;
  subscription.transactionId = transactionId;

  organization.subscriptionPlan = plan.name;
  organization.maxSeats = plan.seatLimit || organization.maxSeats;

  user.profile.plan = plan.name;

  // Create Invoice
  const invoice = await Invoice.create({
    invoiceNumber: generateInvoiceNumber(),
    userId: user._id,
    organizationId: organization._id,
    subscriptionId: subscription._id,
    planName: plan.name,
    amount,
    tax: 0,
    currency: plan.currency || 'INR',
    paymentStatus: amount > 0 ? 'paid' : 'pending',
    transactionId,
  });

  // Log Invoice Generated Audit event
  await auditService.logAudit({
    userId: user._id,
    action: 'Invoice Generated',
    description: `Invoice ${invoice.invoiceNumber} generated for ${plan.name} plan.`,
    status: 'Success'
  });

  // Compile PDF and save to persistent storage
  const invoiceStorageService = require('./invoiceStorage.service');
  try {
    const pdfBuffer = await invoicePdfService.generateInvoicePdf(invoice, user, organization);
    const { pdfUrl, storageProvider } = await invoiceStorageService.saveInvoicePdf(invoice.invoiceNumber, pdfBuffer);
    invoice.pdfUrl = pdfUrl;
    invoice.storageProvider = storageProvider;
    await invoice.save();
  } catch (pdfErr) {
    logger.error(`[billing-service] Failed to pre-generate and store invoice PDF: ${pdfErr.message}`);
  }

  // Send Invoice Email via Resend
  const { sendInvoiceEmail } = require('./email/resend.service');
  const backendUrl = process.env.BACKEND_URL;
  if (!backendUrl && !invoice.pdfUrl) {
    logger.error('[billing-service] BACKEND_URL is not configured in environment variables for invoice download link.');
  }
  const safeBackendUrl = (backendUrl || '').replace(/\/+$/, '');
  const downloadLink = invoice.pdfUrl || `${safeBackendUrl}/uploads/invoices/${invoice.invoiceNumber}.pdf`;
  
  invoice.emailDeliveryAttempts += 1;
  try {
    await sendInvoiceEmail({
      to: user.email,
      invoiceNumber: invoice.invoiceNumber,
      planName: plan.name,
      amount,
      date: invoice.generatedAt,
      downloadLink
    });
    invoice.emailDeliveryStatus = 'sent';
    invoice.emailDeliveryError = '';
  } catch (emailErr) {
    invoice.emailDeliveryStatus = 'failed';
    invoice.emailDeliveryError = emailErr.message;
    logger.error(`[billing-service] Failed to send invoice email to ${user.email}: ${emailErr.message}`);
  }
  await invoice.save();

  // Create or Update Payment Transaction
  let paymentTxn = await PaymentTransaction.findOne({ transactionId });
  if (paymentTxn) {
    paymentTxn.subscriptionId = subscription._id;
    paymentTxn.invoiceId = invoice._id;
    if (amount > 0) {
      paymentTxn.status = 'succeeded';
    }
    await paymentTxn.save();
  } else {
    await PaymentTransaction.create({
      userId: user._id,
      organizationId: organization._id,
      subscriptionId: subscription._id,
      invoiceId: invoice._id,
      provider: amount > 0 ? 'manual' : 'free',
      transactionId,
      amount,
      currency: plan.currency || 'INR',
      status: amount > 0 ? 'succeeded' : 'created',
      metadata: {
        planName: plan.name,
        billingCycle,
        source: 'immediate_activation'
      }
    });
  }

  await Promise.all([subscription.save(), organization.save(), user.save()]);

  // Log audit of plan upgrade/downgrade
  const oldIndex = PLAN_ORDER.indexOf(oldPlan);
  const nextIndex = PLAN_ORDER.indexOf(plan.name);
  let action = 'Plan Change';
  if (nextIndex > oldIndex) {
    action = 'Plan Upgrade';
  } else if (nextIndex < oldIndex) {
    action = 'Plan Downgrade';
  }
  
  await auditService.logAudit({
    userId: user._id,
    action,
    description: `Subscription plan changed from ${oldPlan} to ${plan.name} (${billingCycle}). Transaction ID: ${transactionId}.`,
    status: 'Success'
  });

  // Create System Notifications in MongoDB
  const Notification = require('../models/Notification');
  try {
    // 1. Plan Upgrade/Downgrade notification
    if (nextIndex > oldIndex) {
      await Notification.create({
        organizationId: organization._id,
        userId: user._id,
        email: user.email,
        type: 'PLAN_UPGRADED',
        title: 'Plan Upgraded',
        message: `Your subscription has been successfully upgraded to the ${plan.name} plan.`
      });
    } else if (nextIndex < oldIndex) {
      await Notification.create({
        organizationId: organization._id,
        userId: user._id,
        email: user.email,
        type: 'PLAN_DOWNGRADED',
        title: 'Plan Downgraded',
        message: `Your subscription has been downgraded to the ${plan.name} plan.`
      });
    }

    // 2. Invoice Generated notification
    await Notification.create({
      organizationId: organization._id,
      userId: user._id,
      email: user.email,
      type: 'INVOICE_GENERATED',
      title: 'Invoice Generated',
      message: `A new invoice (${invoice.invoiceNumber}) has been generated for your ${plan.name} plan.`
    });
  } catch (notifErr) {
    logger.error(`[billing-service] Failed to create system notifications: ${notifErr.message}`);
  }

  return {
    message: `${plan.name} plan activated successfully.`,
    overview: await getOverview(user._id)
  };
}

/**
 * Cancels auto-renew or cancels the subscription directly.
 */
async function cancelSubscription(userId) {
  const { user, organization, actorMember } = await teamService.getContext(userId);
  if (actorMember.role !== 'OWNER') {
    const error = new Error('Only the organization owner can cancel billing.');
    error.statusCode = 403;
    throw error;
  }

  const subscription = await Subscription.findOne({ organizationId: organization._id });
  if (!subscription) {
    const error = new Error('Subscription details not found.');
    error.statusCode = 404;
    throw error;
  }

  subscription.status = 'cancelled';
  subscription.paymentStatus = 'cancelled';
  subscription.autoRenew = false;
  subscription.cancelledAt = new Date();
  await subscription.save();

  await auditService.logAudit({
    userId: user._id,
    action: 'Subscription Cancelled',
    description: `Subscription auto-renew turned off. Active until ${subscription.nextBillingDate || subscription.expiryDate}.`,
    status: 'Success'
  });

  return {
    message: 'Subscription cancellation scheduled.',
    overview: await getOverview(user._id),
  };
}

/**
 * Compiles a specific invoice PDF buffer.
 */
async function getInvoicePdf(userId, invoiceId) {
  const { user, organization } = await teamService.getContext(userId);
  
  const invoice = await Invoice.findOne({ _id: invoiceId, organizationId: organization._id });
  if (!invoice) {
    const error = new Error('Invoice not found or unauthorized.');
    error.statusCode = 404;
    throw error;
  }

  const invoiceStorageService = require('./invoiceStorage.service');
  let pdfBuffer;
  try {
    // Retrieve historical invoice without regenerating PDF
    pdfBuffer = await invoiceStorageService.getInvoicePdf(invoice.invoiceNumber);
  } catch (err) {
    // Regenerate on-the-fly and save if missing
    pdfBuffer = await invoicePdfService.generateInvoicePdf(invoice, user, organization);
    await invoiceStorageService.saveInvoicePdf(invoice.invoiceNumber, pdfBuffer);
  }

  return {
    filename: `${invoice.invoiceNumber}.pdf`,
    buffer: pdfBuffer
  };
}

/**
 * Perform resource usage checks against configured thresholds and issue notifications.
 */
async function checkUsageAlerts(organizationId, userId) {
  const Subscription = require('../models/Subscription');
  const SubscriptionPlan = require('../models/SubscriptionPlan');
  const Notification = require('../models/Notification');
  const User = require('../models/User');
  const Organization = require('../models/Organization');
  const logger = require('../config/logger');

  try {
    const sub = await Subscription.findOne({ organizationId });
    if (!sub) return;

    const org = await Organization.findById(organizationId);
    if (!org) return;

    const plan = await SubscriptionPlan.findOne({ name: sub.currentPlan });
    if (!plan) return;

    const user = await User.findById(userId || sub.userId);
    if (!user) return;

    // Get current usage metrics
    const metrics = await getUsageMetrics(user, org, sub, plan);
    
    // Ensure sub.usageAlerts exists
    if (!sub.usageAlerts) {
      sub.usageAlerts = {
        domainsThreshold: 90,
        scansThreshold: 90,
        seatsThreshold: 90,
        lastAlertSent: { domains: 0, scans: 0, seats: 0 }
      };
    }

    const thresholds = [50, 75, 90, 100];
    
    for (const metric of metrics) {
      const used = metric.used;
      const limit = metric.rawLimit;
      if (!limit || limit >= 999999) continue; // Skip unlimited

      const pct = (used / limit) * 100;
      
      // Determine configured threshold
      const configuredThreshold = 
        metric.key === 'domains' ? sub.usageAlerts.domainsThreshold :
        metric.key === 'scans' ? sub.usageAlerts.scansThreshold :
        sub.usageAlerts.seatsThreshold;

      // Find the highest threshold that is hit and <= pct
      let hitThreshold = 0;
      for (const t of thresholds) {
        if (pct >= t) {
          hitThreshold = t;
        }
      }

      // Check if we need to send alert
      const lastSent = sub.usageAlerts.lastAlertSent?.[metric.key] || 0;
      
      if (hitThreshold >= configuredThreshold && hitThreshold > lastSent) {
        // Generate notification
        await Notification.create({
          organizationId,
          userId: user._id,
          email: user.email,
          type: 'USAGE_ALERT',
          title: `Usage Alert: ${metric.label}`,
          message: `Your ${metric.label.toLowerCase()} usage is at ${Math.round(pct)}% (${used}/${limit}).`
        });

        logger.info(`[usage-alerts] Sent alert for ${metric.key} at ${hitThreshold}% for Org ${organizationId}`);
        
        // Update lastAlertSent
        if (!sub.usageAlerts.lastAlertSent) {
          sub.usageAlerts.lastAlertSent = { domains: 0, scans: 0, seats: 0 };
        }
        sub.usageAlerts.lastAlertSent[metric.key] = hitThreshold;
        sub.markModified('usageAlerts');
        await sub.save();
      } else if (pct < configuredThreshold) {
        // Reset alert state if it dropped below threshold
        if (sub.usageAlerts.lastAlertSent?.[metric.key] !== 0) {
          if (!sub.usageAlerts.lastAlertSent) {
            sub.usageAlerts.lastAlertSent = { domains: 0, scans: 0, seats: 0 };
          }
          sub.usageAlerts.lastAlertSent[metric.key] = 0;
          sub.markModified('usageAlerts');
          await sub.save();
        }
      }
    }
  } catch (error) {
    logger.error(`[usage-alerts] Error running check: ${error.message}`);
  }
}

/**
 * Update usage alert configuration thresholds.
 */
async function updateUsageAlertSettings(userId, { domainsThreshold, scansThreshold, seatsThreshold }) {
  const { organization } = await teamService.getContext(userId);
  const subscription = await Subscription.findOne({ organizationId: organization._id });
  if (!subscription) {
    const error = new Error('Subscription not found.');
    error.statusCode = 404;
    throw error;
  }

  if (!subscription.usageAlerts) {
    subscription.usageAlerts = {
      domainsThreshold: 90,
      scansThreshold: 90,
      seatsThreshold: 90,
      lastAlertSent: { domains: 0, scans: 0, seats: 0 }
    };
  }

  const validThresholds = [50, 75, 90, 100];
  const validate = (t) => t === undefined || validThresholds.includes(Number(t));

  if (!validate(domainsThreshold) || !validate(scansThreshold) || !validate(seatsThreshold)) {
    const error = new Error('Invalid threshold value. Must be 50, 75, 90, or 100.');
    error.statusCode = 400;
    throw error;
  }

  if (domainsThreshold !== undefined) subscription.usageAlerts.domainsThreshold = Number(domainsThreshold);
  if (scansThreshold !== undefined) subscription.usageAlerts.scansThreshold = Number(scansThreshold);
  if (seatsThreshold !== undefined) subscription.usageAlerts.seatsThreshold = Number(seatsThreshold);

  subscription.markModified('usageAlerts');
  await subscription.save();

  return {
    message: 'Usage alert settings updated successfully.',
    usageAlerts: subscription.usageAlerts
  };
}

/**
 * Get billing audit timeline events.
 */
async function getTimeline(userId) {
  const { organization } = await teamService.getContext(userId);
  const AuditLog = require('../models/AuditLog');
  
  const billingActions = [
    'Plan Created',
    'Payment Success',
    'Payment Failure',
    'Plan Upgrade',
    'Plan Downgrade',
    'Subscription Cancelled',
    'Subscription Expired',
    'Invoice Generated'
  ];
  
  const TeamMember = require('../models/TeamMember');
  const orgMembers = await TeamMember.find({ organizationId: organization._id }).select('userId');
  const userIds = orgMembers.map(m => m.userId).filter(id => id != null);

  const logs = await AuditLog.find({
    userId: { $in: userIds },
    action: { $in: billingActions }
  }).sort({ createdAt: -1 });

  return logs.map(log => ({
    id: log._id,
    action: log.action,
    description: log.description,
    timestamp: log.createdAt,
    status: log.status
  }));
}

/**
 * Get SaaS-wide billing and worker health audit metrics for Super Admins.
 */
async function getBillingHealth() {
  const Subscription = require('../models/Subscription');
  const Invoice = require('../models/Invoice');
  const { getEmailStatus } = require('./email/resend.service');
  const fs = require('fs');
  const path = require('path');

  const invoicesCount = await Invoice.countDocuments();
  const dirPath = path.join(process.cwd(), 'uploads', 'invoices');
  const storageHealthy = fs.existsSync(dirPath);

  const [activeSubs, cancelledSubs, suspendedSubs] = await Promise.all([
    Subscription.countDocuments({ status: 'active' }),
    Subscription.countDocuments({ status: 'cancelled' }),
    Subscription.countDocuments({ status: 'suspended' })
  ]);

  const emailStatus = getEmailStatus();

  return {
    webhookStatus: process.env.RAZORPAY_WEBHOOK_SECRET ? 'configured' : 'missing_secret',
    workerStatus: {
      status: 'active',
      schedule: process.env.SUBSCRIPTION_EXPIRY_CRON || '0 0 * * *'
    },
    invoiceStatus: {
      count: invoicesCount,
      storageHealthy,
      storageProvider: process.env.STORAGE_PROVIDER || 'local'
    },
    subscriptionStatus: {
      active: activeSubs,
      cancelled: cancelledSubs,
      suspended: suspendedSubs
    },
    emailStatus
  };
}

module.exports = {
  getOverview,
  getUsageMetrics,
  validatePlanDowngrade,
  upgradePlan,
  downgradePlan,
  cancelSubscription,
  getInvoicePdf,
  changePlanImmediate,
  checkUsageAlerts,
  updateUsageAlertSettings,
  getTimeline,
  getBillingHealth
};
