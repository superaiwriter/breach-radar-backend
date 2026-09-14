const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const crypto = require('crypto');

const authenticateJWT = require('../middleware/auth');
const { requireTeamRole } = require('../middleware/teamRbac');
const SubscriptionPlan = require('../models/SubscriptionPlan');
const Subscription = require('../models/Subscription');
const PaymentTransaction = require('../models/PaymentTransaction');
const billingService = require('../services/billing.service');
const paypalService = require('../services/paypal.service');
const logger = require('../config/logger');
const {
  getRazorpayClient,
  getRazorpayCredentials,
  getRazorpayKeyInfo,
  logRazorpayError
} = require('../config/razorpay');

const RAZORPAY_ORDER_TIMEOUT_MS = Number(process.env.RAZORPAY_ORDER_TIMEOUT_MS || 15000);

function getRazorpayWebhookPaymentDetails(paymentEntity = {}) {
  return {
    paymentId: paymentEntity.id,
    orderId: paymentEntity.order_id,
    status: paymentEntity.status,
    method: paymentEntity.method,
    amount: paymentEntity.amount,
    currency: paymentEntity.currency,
    errorCode: paymentEntity.error_code,
    errorDescription: paymentEntity.error_description,
    errorReason: paymentEntity.error_reason,
    errorSource: paymentEntity.error_source,
    errorStep: paymentEntity.error_step,
    vpa: paymentEntity.vpa,
    bank: paymentEntity.bank,
    wallet: paymentEntity.wallet,
    cardId: paymentEntity.card_id
  };
}

function getRazorpayClientEventDetails(body = {}) {
  const details = body.details || {};
  return {
    event: body.event || 'unknown',
    orderId: body.orderId || details.orderId || details.backendOrderId || details.checkoutOrderId,
    paymentId: body.paymentId || details.paymentId,
    amount: body.amount || details.amount,
    currency: body.currency || details.currency,
    keyMode: body.keyMode || details.keyMode,
    code: body.code || details.code,
    description: body.description || details.description,
    reason: body.reason || details.reason,
    source: body.source || details.source,
    step: body.step || details.step,
    field: body.field || details.field,
    details
  };
}

function withTimeout(promise, ms, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      const error = new Error(message);
      error.statusCode = 504;
      error.code = 'RAZORPAY_TIMEOUT';
      reject(error);
    }, ms);
  });

  return Promise.race([
    promise.finally(() => clearTimeout(timeoutId)),
    timeout
  ]);
}

async function createRazorpayOrder(orderPayload) {
  try {
    const razorpay = getRazorpayClient();
    logger.info(`[payment-routes] razorpay.orders.create request=${JSON.stringify(orderPayload)}`);
    return await withTimeout(
      razorpay.orders.create(orderPayload),
      RAZORPAY_ORDER_TIMEOUT_MS,
      'Razorpay order creation timed out. Please check internet access and Razorpay test key configuration.'
    );
  } catch (err) {
    if (err.code === 'RAZORPAY_TIMEOUT') {
      throw err;
    }

    logRazorpayError('[payment-routes] Razorpay order creation failed', err);
    const error = new Error(err.error?.description || 'Razorpay order creation failed. Please verify Razorpay test keys and network access.');
    error.statusCode = err.statusCode || 502;
    error.code = 'RAZORPAY_ORDER_FAILED';
    error.details = {
      razorpayCode: err.error?.code,
      razorpayField: err.error?.field,
      razorpayReason: err.error?.reason
    };
    throw error;
  }
}

/**
 * POST /api/payment/create-order
 * Create a new Razorpay payment order for subscription upgrade.
 */
router.post('/create-order', authenticateJWT, requireTeamRole(['OWNER']), async (req, res, next) => {
  try {
    const { planId, billingCycle = 'monthly' } = req.body;
    logger.info(`[payment-routes] Order API called by user=${req.user?._id || 'unknown'} planId=${planId || 'missing'} billingCycle=${billingCycle}`);
    
    if (!planId) {
      return res.status(400).json({ message: 'planId is required.' });
    }

    if (!['monthly', 'yearly'].includes(billingCycle)) {
      return res.status(400).json({ message: 'billingCycle must be monthly or yearly.' });
    }

    // Find subscription plan by ObjectId or by Plan Name (Starter, Professional, etc.)
    let plan;
    if (mongoose.Types.ObjectId.isValid(planId)) {
      plan = await SubscriptionPlan.findById(planId);
    } else {
      plan = await SubscriptionPlan.findOne({ name: planId, isActive: true });
    }

    if (!plan) {
      return res.status(404).json({ message: 'Selected plan is not available.' });
    }

    const price = plan.price || 0;
    const cycleMultiplier = billingCycle === 'yearly' ? 10 : 1;
    const amountInINR = price * cycleMultiplier;
    
    // Razorpay amount is in paise (1 INR = 100 paise)
    const amountInPaise = Math.round(amountInINR * 100);
    logger.info(`[payment-routes] Creating Razorpay order amountInINR=${amountInINR} amountInPaise=${amountInPaise} currency=${plan.currency || 'INR'}`);

    if (amountInPaise <= 0) {
      return res.status(400).json({ message: 'Cannot create order for zero-amount plans.' });
    }

    const keyInfo = getRazorpayKeyInfo();
    logger.info(`[payment-routes] Active Razorpay key keyPrefix=${keyInfo.keyPrefix} mode=${keyInfo.mode}`);
    if (keyInfo.isLiveMode) {
      logger.error('[payment-routes] Live Razorpay key is active during checkout. Use rzp_test_ credentials for test payments.');
    }

    // Place order via Razorpay SDK
    const orderPayload = {
      amount: amountInPaise,
      currency: plan.currency || 'INR',
      receipt: `rcpt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      notes: {
        userId: req.user._id.toString(),
        organizationId: req.organization._id.toString(),
        planName: plan.name,
        billingCycle
      }
    };
    const rzpOrder = await createRazorpayOrder(orderPayload);

    if (!rzpOrder?.id) {
      const error = new Error('Razorpay did not return an order id.');
      error.statusCode = 502;
      error.code = 'RAZORPAY_ORDER_ID_MISSING';
      throw error;
    }

    // Save pending transaction in our database
    const transactionId = `txn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await PaymentTransaction.create({
      userId: req.user._id,
      organizationId: req.organization._id,
      provider: 'razorpay',
      providerOrderId: rzpOrder.id,
      transactionId,
      amount: amountInINR,
      currency: plan.currency || 'INR',
      status: 'pending',
      metadata: {
        planName: plan.name,
        billingCycle,
        source: 'billing_upgrade'
      }
    });

    logger.info(`[payment-routes] razorpay.orders.create response=${JSON.stringify({
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
    logger.info(`[payment-routes] Order created orderId=${rzpOrder.id} amount=${rzpOrder.amount} currency=${rzpOrder.currency} keyPrefix=${keyInfo.keyPrefix} mode=${keyInfo.mode}`);

    return res.status(200).json({
      orderId: rzpOrder.id,
      amount: rzpOrder.amount,
      currency: rzpOrder.currency,
      key: keyInfo.keyId,
      keyMode: keyInfo.mode,
      keyPrefix: keyInfo.keyPrefix
    });
  } catch (error) {
    logger.error(`[payment-routes] Create order request failed: ${error.message}`);
    next(error);
  }
});

/**
 * POST /api/payment/client-event
 * Persist browser-side Razorpay checkout diagnostics in backend logs.
 */
router.post('/client-event', authenticateJWT, requireTeamRole(['OWNER']), async (req, res, next) => {
  try {
    const eventDetails = getRazorpayClientEventDetails(req.body);
    const logPayload = {
      ...eventDetails,
      userId: req.user?._id,
      organizationId: req.organization?._id,
      userAgent: req.get('user-agent')
    };

    if (eventDetails.event === 'payment.failed' || eventDetails.event === 'handler.callback.failure') {
      logger.error(`[payment-routes] Razorpay client event=${JSON.stringify(logPayload)}`);
    } else if (eventDetails.event === 'modal.dismiss') {
      logger.warn(`[payment-routes] Razorpay client event=${JSON.stringify(logPayload)}`);
    } else {
      logger.info(`[payment-routes] Razorpay client event=${JSON.stringify(logPayload)}`);
    }

    if (eventDetails.event === 'payment.failed' && eventDetails.orderId) {
      await PaymentTransaction.findOneAndUpdate(
        { providerOrderId: eventDetails.orderId },
        {
          $set: {
            status: 'failed',
            providerPaymentId: eventDetails.paymentId || '',
            'metadata.razorpayClientFailure': eventDetails
          }
        }
      );
    }

    res.status(200).json({ status: 'ok' });
  } catch (error) {
    logger.error(`[payment-routes] Client event logging failed: ${error.message}`);
    next(error);
  }
});

/**
 * POST /api/payment/verify
 * Validate dynamic signature submitted by checkout modal and activate subscription plan.
 */
router.post('/verify', authenticateJWT, requireTeamRole(['OWNER']), async (req, res, next) => {
  const auditService = require('../services/audit.service');
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;
  try {
    logger.info(`[payment-routes] Verify payment request=${JSON.stringify({
      orderId: razorpay_order_id || 'missing',
      paymentId: razorpay_payment_id || 'missing',
      hasSignature: Boolean(razorpay_signature),
      userId: req.user?._id,
      organizationId: req.organization?._id
    })}`);

    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
      return res.status(400).json({ message: 'Missing Razorpay signature verification details.' });
    }

    // Verify cryptographic HMAC SHA256 signature
    const { keySecret } = getRazorpayCredentials();
    const hmac = crypto.createHmac('sha256', keySecret);
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const generatedSignature = hmac.digest('hex');

    if (generatedSignature !== razorpay_signature) {
      await auditService.logRequestAudit(
        req,
        'Payment Failure',
        `Signature verification failed for order ${razorpay_order_id}.`,
        'Failure'
      );
      try {
        const Notification = require('../models/Notification');
        await Notification.create({
          organizationId: req.organization._id,
          userId: req.user._id,
          email: req.user.email,
          type: 'PAYMENT_FAILURE',
          title: 'Payment Failed',
          message: `Signature verification failed for order ${razorpay_order_id}.`
        });
      } catch (notifErr) {
        logger.error(`[payment-routes] Failed to create payment failure notification: ${notifErr.message}`);
      }
      const responseBody = { message: 'Invalid payment signature verification failed.' };
      logger.warn(`[payment-routes] Verify payment response=${JSON.stringify({
        status: 400,
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        body: responseBody
      })}`);
      return res.status(400).json(responseBody);
    }

    // Fetch matching pending transaction
    const transaction = await PaymentTransaction.findOne({ providerOrderId: razorpay_order_id });
    if (!transaction) {
      const responseBody = { message: 'Transaction reference not found.' };
      logger.warn(`[payment-routes] Verify payment response=${JSON.stringify({
        status: 404,
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        body: responseBody
      })}`);
      return res.status(404).json(responseBody);
    }

    if (transaction.status === 'succeeded') {
      const responseBody = { message: 'Payment has already been processed.' };
      logger.info(`[payment-routes] Verify payment response=${JSON.stringify({
        status: 200,
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        transactionId: transaction.transactionId,
        body: responseBody
      })}`);
      return res.status(200).json(responseBody);
    }

    // Update transaction attributes
    transaction.status = 'succeeded';
    transaction.providerPaymentId = razorpay_payment_id;
    await transaction.save();

    const planName = transaction.metadata?.planName || 'Professional';
    const billingCycle = transaction.metadata?.billingCycle || 'monthly';

    // Retrieve active plan metadata
    const plan = await SubscriptionPlan.findOne({ name: planName, isActive: true });
    if (!plan) {
      return res.status(404).json({ message: `Target plan "${planName}" is not available.` });
    }

    // Fetch subscription document
    const subscription = await Subscription.findOne({ organizationId: req.organization._id });
    if (!subscription) {
      return res.status(404).json({ message: 'Subscription reference not found for this workspace.' });
    }

    // Activate the subscription immediately in the database
    await billingService.changePlanImmediate(
      req.user,
      req.organization,
      subscription,
      plan,
      billingCycle,
      'paid',
      transaction.transactionId
    );

    // Audit Log for Payment Success
    await auditService.logRequestAudit(
      req,
      'Payment Success',
      `Payment succeeded for plan ${plan.name} (${billingCycle}). Order ID: ${razorpay_order_id}. Payment ID: ${razorpay_payment_id}.`
    );

    logger.info(`[payment-routes] Payment success=${JSON.stringify({
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      transactionId: transaction.transactionId,
      plan: plan.name,
      billingCycle
    })}`);

    try {
      const Notification = require('../models/Notification');
      await Notification.create({
        organizationId: req.organization._id,
        userId: req.user._id,
        email: req.user.email,
        type: 'PAYMENT_SUCCESS',
        title: 'Payment Successful',
        message: `Your payment was verified successfully for the ${plan.name} plan.`
      });
    } catch (notifErr) {
      logger.error(`[payment-routes] Failed to create payment success notification: ${notifErr.message}`);
    }

    const responseBody = {
      message: 'Plan upgraded successfully.',
      planName: plan.name,
      razorpay_order_id,
      razorpay_payment_id
    };
    logger.info(`[payment-routes] Verify payment response=${JSON.stringify({
      status: 200,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      transactionId: transaction.transactionId,
      body: responseBody
    })}`);
    res.status(200).json(responseBody);
  } catch (error) {
    logger.error(`[payment-routes] Handler callback failure=${JSON.stringify({
      orderId: razorpay_order_id || 'missing',
      paymentId: razorpay_payment_id || 'missing',
      error: error.message,
      code: error.code,
      statusCode: error.statusCode
    })}`);
    // Log payment error audit
    await auditService.logRequestAudit(
      req,
      'Payment Failure',
      `Payment processing failed: ${error.message}`,
      'Failure'
    );
    try {
      const Notification = require('../models/Notification');
      await Notification.create({
        organizationId: req.organization._id,
        userId: req.user._id,
        email: req.user.email,
        type: 'PAYMENT_FAILURE',
        title: 'Payment Failed',
        message: `Payment processing failed: ${error.message}`
      });
    } catch (notifErr) {
      logger.error(`[payment-routes] Failed to create payment failure notification: ${notifErr.message}`);
    }
    next(error);
  }
});

/**
 * POST /api/payment/webhook
 * Razorpay Webhook receiver for async notification events.
 */
router.post('/webhook', async (req, res, next) => {
  const logger = require('../config/logger');
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) {
      return res.status(400).json({ message: 'Missing Razorpay webhook signature.' });
    }

    const secret = String(process.env.RAZORPAY_WEBHOOK_SECRET || '').trim();
    if (!secret) {
      return res.status(500).json({ message: 'Razorpay webhook secret is not configured.' });
    }
    
    // Validate signature using rawBody
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(req.rawBody || JSON.stringify(req.body));
    const generatedSignature = hmac.digest('hex');

    if (generatedSignature !== signature) {
      logger.warn('[webhook] Webhook signature verification failed.');
      return res.status(400).json({ message: 'Invalid webhook signature.' });
    }

    const event = req.body.event;
    const payload = req.body.payload || {};

    logger.info(`[webhook] Razorpay event received=${JSON.stringify({
      event,
      hasOrderPayload: Boolean(payload.order),
      hasPaymentPayload: Boolean(payload.payment),
      containsSignature: Boolean(signature)
    })}`);

    let providerOrderId = '';
    let providerPaymentId = '';
    let isSuccess = false;
    let isFailure = false;
    let failureReason = '';

    if (event === 'order.paid' && payload.order) {
      providerOrderId = payload.order.entity.id;
      isSuccess = true;
    } else if (event === 'payment.captured' && payload.payment) {
      providerOrderId = payload.payment.entity.order_id;
      providerPaymentId = payload.payment.entity.id;
      isSuccess = true;
    } else if (event === 'payment.failed' && payload.payment) {
      providerOrderId = payload.payment.entity.order_id;
      providerPaymentId = payload.payment.entity.id;
      isFailure = true;
      failureReason = payload.payment.entity.error_description || 'Payment failed';
      logger.error(`[webhook] Razorpay payment.failed payload=${JSON.stringify(getRazorpayWebhookPaymentDetails(payload.payment.entity))}`);
    }

    if (!providerOrderId) {
      return res.status(200).json({ status: 'ok', message: 'Event ignored: no order ID.' });
    }

    // Find pending transaction
    const transaction = await PaymentTransaction.findOne({ providerOrderId });
    if (!transaction) {
      logger.warn(`[webhook] Transaction not found for order: ${providerOrderId}`);
      return res.status(200).json({ status: 'ok', message: 'Transaction not found.' });
    }

    // Prevent duplicate processing
    if (transaction.status === 'succeeded') {
      logger.info(`[webhook] Transaction ${transaction.transactionId} already marked as succeeded. Preventing duplicate processing.`);
      return res.status(200).json({ status: 'ok', message: 'Payment already processed.' });
    }

    const auditService = require('../services/audit.service');

    if (isSuccess) {
      transaction.status = 'succeeded';
      if (providerPaymentId) {
        transaction.providerPaymentId = providerPaymentId;
      }
      await transaction.save();

      const planName = transaction.metadata?.planName || 'Professional';
      const billingCycle = transaction.metadata?.billingCycle || 'monthly';

      const plan = await SubscriptionPlan.findOne({ name: planName, isActive: true });
      if (!plan) {
        logger.error(`[webhook] Plan "${planName}" not found for transaction: ${transaction.transactionId}`);
        return res.status(404).json({ message: `Plan ${planName} not found` });
      }

      const User = require('../models/User');
      const Organization = require('../models/Organization');
      const Subscription = require('../models/Subscription');

      const user = await User.findById(transaction.userId);
      const organization = await Organization.findById(transaction.organizationId);
      if (!user || !organization) {
        logger.error(`[webhook] User/Org not found for transaction: ${transaction.transactionId}`);
        return res.status(404).json({ message: 'User or Org not found' });
      }

      const subscription = await Subscription.findOne({ organizationId: organization._id });
      if (!subscription) {
        logger.error(`[webhook] Subscription reference not found for Org: ${organization._id}`);
        return res.status(404).json({ message: 'Subscription reference not found' });
      }

      // Activate subscription & generate invoice in immediate activation logic
      await billingService.changePlanImmediate(
        user,
        organization,
        subscription,
        plan,
        billingCycle,
        'paid',
        transaction.transactionId
      );

      // Audit Log for Payment Success
      await auditService.logAudit({
        userId: user._id,
        action: 'Payment Success',
        description: `Razorpay payment captured via webhook. Order ID: ${providerOrderId}. Transaction ID: ${transaction.transactionId}.`,
        status: 'Success'
      });

      try {
        const Notification = require('../models/Notification');
        await Notification.create({
          organizationId: organization._id,
          userId: user._id,
          email: user.email,
          type: 'PAYMENT_SUCCESS',
          title: 'Payment Successful',
          message: `Your payment was captured successfully for the ${plan.name} plan via webhook.`
        });
      } catch (notifErr) {
        logger.error(`[webhook] Failed to create payment success notification: ${notifErr.message}`);
      }

      logger.info(`[webhook] Successfully processed payment and activated plan for organization: ${organization.name}`);

    } else if (isFailure) {
      transaction.status = 'failed';
      transaction.providerPaymentId = providerPaymentId || transaction.providerPaymentId;
      transaction.metadata = {
        ...(transaction.metadata || {}),
        razorpayFailure: getRazorpayWebhookPaymentDetails(payload.payment?.entity || {})
      };
      await transaction.save();

      // Audit Log for Payment Failure
      await auditService.logAudit({
        userId: transaction.userId,
        action: 'Payment Failure',
        description: `Razorpay payment failed via webhook. Order ID: ${providerOrderId}. Reason: ${failureReason}.`,
        status: 'Failure'
      });

      try {
        const User = require('../models/User');
        const Notification = require('../models/Notification');
        let userEmail = '';
        if (transaction.userId) {
          const u = await User.findById(transaction.userId);
          if (u) userEmail = u.email;
        }
        await Notification.create({
          organizationId: transaction.organizationId,
          userId: transaction.userId,
          email: userEmail,
          type: 'PAYMENT_FAILURE',
          title: 'Payment Failed',
          message: `Razorpay payment failed via webhook. Reason: ${failureReason}.`
        });
      } catch (notifErr) {
        logger.error(`[webhook] Failed to create payment failure notification: ${notifErr.message}`);
      }

      logger.info(`[webhook] Razorpay payment failed for order: ${providerOrderId}`);
    }

    res.status(200).json({ status: 'ok' });
  } catch (error) {
    logger.error(`[webhook] Webhook execution error: ${error.message}`);
    next(error);
  }
});

/**
 * POST /api/payment/paypal/create-order
 * Create a new PayPal payment order for subscription upgrade.
 */
router.post('/paypal/create-order', authenticateJWT, requireTeamRole(['OWNER']), async (req, res, next) => {
  try {
    const { planId, billingCycle = 'monthly', returnBaseUrl } = req.body;
    logger.info(`[payment-routes-paypal] Create order called by user=${req.user?._id || 'unknown'} planId=${planId} billingCycle=${billingCycle}`);

    if (!planId) {
      return res.status(400).json({ message: 'planId is required.' });
    }

    if (!['monthly', 'yearly'].includes(billingCycle)) {
      return res.status(400).json({ message: 'billingCycle must be monthly or yearly.' });
    }

    // Find plan
    let plan;
    if (mongoose.Types.ObjectId.isValid(planId)) {
      plan = await SubscriptionPlan.findById(planId);
    } else {
      plan = await SubscriptionPlan.findOne({ name: planId, isActive: true });
    }

    if (!plan) {
      return res.status(404).json({ message: 'Selected plan is not available.' });
    }

    const price = plan.price || 0;
    const cycleMultiplier = billingCycle === 'yearly' ? 10 : 1;
    const amountInINR = price * cycleMultiplier;

    if (amountInINR <= 0) {
      return res.status(400).json({ message: 'Cannot create order for zero-amount plans.' });
    }

    // PayPal does not support INR, so convert INR to USD (1 USD = 83 INR)
    const usdAmount = Number((amountInINR / 83).toFixed(2));
    logger.info(`[payment-routes-paypal] Converted amountINR=${amountInINR} to amountUSD=${usdAmount}`);

    const origin = returnBaseUrl || req.headers.origin || process.env.FRONTEND_URL || 'http://localhost:5180';
    const returnUrl = `${origin.split('?')[0]}?paypal-success=true`;
    const cancelUrl = `${origin.split('?')[0]}?paypal-cancel=true`;

    // Create PayPal order via PayPal Service
    const paypalOrder = await paypalService.createOrder(usdAmount, 'USD', returnUrl, cancelUrl);

    if (!paypalOrder?.id) {
      return res.status(502).json({ message: 'PayPal did not return an order ID.' });
    }

    // Find approval link
    const approveLinkObj = paypalOrder.links.find(link => link.rel === 'approve');
    if (!approveLinkObj) {
      return res.status(502).json({ message: 'PayPal order approval URL not found.' });
    }

    // Save pending transaction in our database
    const transactionId = `txn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await PaymentTransaction.create({
      userId: req.user._id,
      organizationId: req.organization._id,
      provider: 'paypal',
      providerOrderId: paypalOrder.id,
      transactionId,
      amount: usdAmount,
      currency: 'USD',
      status: 'pending',
      metadata: {
        planName: plan.name,
        billingCycle,
        amountInINR,
        source: 'billing_upgrade'
      }
    });

    logger.info(`[payment-routes-paypal] Created PayPal pending orderId=${paypalOrder.id} transactionId=${transactionId}`);

    return res.status(200).json({
      orderId: paypalOrder.id,
      approvalUrl: approveLinkObj.href,
      amount: usdAmount,
      currency: 'USD'
    });
  } catch (error) {
    logger.error(`[payment-routes-paypal] Create PayPal order failed: ${error.message}`);
    next(error);
  }
});

/**
 * POST /api/payment/paypal/capture
 * Capture approved PayPal order and activate subscription.
 */
router.post('/paypal/capture', authenticateJWT, requireTeamRole(['OWNER']), async (req, res, next) => {
  const auditService = require('../services/audit.service');
  const { orderId } = req.body;
  try {
    logger.info(`[payment-routes-paypal] Capture request orderId=${orderId} user=${req.user?._id}`);

    if (!orderId) {
      return res.status(400).json({ message: 'PayPal orderId is required.' });
    }

    // Find matching pending transaction
    const transaction = await PaymentTransaction.findOne({ providerOrderId: orderId, provider: 'paypal' });
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction reference not found.' });
    }

    if (transaction.status === 'succeeded') {
      return res.status(200).json({ message: 'Payment has already been processed.' });
    }

    // Execute PayPal capture
    const captureResult = await paypalService.captureOrder(orderId);

    // Get the capture ID from purchase units
    const purchaseUnit = captureResult.purchase_units?.[0];
    const capture = purchaseUnit?.payments?.captures?.[0];
    const captureStatus = capture?.status || captureResult.status;

    if (captureStatus !== 'COMPLETED') {
      logger.error(`[payment-routes-paypal] PayPal capture status not completed: ${captureStatus}`);
      return res.status(400).json({ message: `Payment capture status is ${captureStatus}` });
    }

    const providerPaymentId = capture?.id || 'paypal_capture';

    // Update transaction attributes
    transaction.status = 'succeeded';
    transaction.providerPaymentId = providerPaymentId;
    await transaction.save();

    const planName = transaction.metadata?.planName || 'Professional';
    const billingCycle = transaction.metadata?.billingCycle || 'monthly';

    // Retrieve plan metadata
    const plan = await SubscriptionPlan.findOne({ name: planName, isActive: true });
    if (!plan) {
      return res.status(404).json({ message: `Target plan "${planName}" is not available.` });
    }

    // Fetch subscription
    const subscription = await Subscription.findOne({ organizationId: req.organization._id });
    if (!subscription) {
      return res.status(404).json({ message: 'Subscription reference not found.' });
    }

    // Activate the subscription
    await billingService.changePlanImmediate(
      req.user,
      req.organization,
      subscription,
      plan,
      billingCycle,
      'paid',
      transaction.transactionId
    );

    // Audit Log for Payment Success
    await auditService.logRequestAudit(
      req,
      'Payment Success',
      `PayPal payment succeeded for plan ${plan.name} (${billingCycle}). Order ID: ${orderId}. Capture ID: ${providerPaymentId}.`
    );

    // Notification
    try {
      const Notification = require('../models/Notification');
      await Notification.create({
        organizationId: req.organization._id,
        userId: req.user._id,
        email: req.user.email,
        type: 'PAYMENT_SUCCESS',
        title: 'Payment Successful',
        message: `Your PayPal payment was verified successfully for the ${plan.name} plan.`
      });
    } catch (notifErr) {
      logger.error(`[payment-routes-paypal] Failed to create payment success notification: ${notifErr.message}`);
    }

    return res.status(200).json({
      message: 'Plan upgraded successfully.',
      planName: plan.name,
      paypalOrderId: orderId,
      paypalCaptureId: providerPaymentId
    });
  } catch (error) {
    logger.error(`[payment-routes-paypal] PayPal capture handler failed: ${error.message}`);
    next(error);
  }
});

/**
 * POST /api/payment/paypal/webhook
 * PayPal Webhook receiver for async payment events.
 */
router.post('/paypal/webhook', async (req, res, next) => {
  try {
    const webhookId = process.env.PAYPAL_WEBHOOK_ID;
    if (!webhookId) {
      logger.warn('[paypal-webhook] Webhook verification bypassed: PAYPAL_WEBHOOK_ID is not set.');
    } else {
      const isValid = await paypalService.verifyWebhookSignature(req.headers, req.body, webhookId);
      if (!isValid) {
        logger.warn('[paypal-webhook] Webhook signature verification failed.');
        return res.status(400).json({ message: 'Invalid webhook signature.' });
      }
    }

    const event = req.body;
    const eventType = event.event_type;
    const resource = event.resource;

    logger.info(`[paypal-webhook] PayPal event received=${eventType}`);

    if (eventType === 'PAYMENT.CAPTURE.COMPLETED') {
      const providerOrderId = resource.supplementary_data?.related_ids?.order_id || resource.parent_payment;
      const providerPaymentId = resource.id;

      if (providerOrderId) {
        const transaction = await PaymentTransaction.findOne({ providerOrderId, provider: 'paypal' });
        if (transaction && transaction.status !== 'succeeded') {
          transaction.status = 'succeeded';
          transaction.providerPaymentId = providerPaymentId;
          await transaction.save();

          const planName = transaction.metadata?.planName || 'Professional';
          const billingCycle = transaction.metadata?.billingCycle || 'monthly';

          const plan = await SubscriptionPlan.findOne({ name: planName, isActive: true });
          const User = require('../models/User');
          const Organization = require('../models/Organization');
          const Subscription = require('../models/Subscription');

          const user = await User.findById(transaction.userId);
          const organization = await Organization.findById(transaction.organizationId);
          const subscription = await Subscription.findOne({ organizationId: transaction.organizationId });

          if (plan && user && organization && subscription) {
            await billingService.changePlanImmediate(
              user,
              organization,
              subscription,
              plan,
              billingCycle,
              'paid',
              transaction.transactionId
            );
            logger.info(`[paypal-webhook] Successfully processed payment asynchronously for Org: ${organization.name}`);
          }
        }
      }
    }

    return res.status(200).json({ status: 'ok' });
  } catch (error) {
    logger.error(`[paypal-webhook] PayPal webhook error: ${error.message}`);
    next(error);
  }
});

module.exports = router;
