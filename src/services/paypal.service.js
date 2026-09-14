const axios = require('axios');
const logger = require('../config/logger');

const getPaypalBaseUrl = () => {
  return process.env.PAYPAL_ENVIRONMENT === 'production'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';
};

const getCredentials = () => {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;

  const isMock = !clientId || clientId.startsWith('mock_') || !clientSecret || clientSecret.startsWith('mock_');
  return { clientId, clientSecret, isMock };
};

/**
 * Obtain an OAuth2 Access Token from PayPal
 */
const getAccessToken = async () => {
  const { isMock, clientId, clientSecret } = getCredentials();
  if (isMock) {
    logger.info('[paypal-service] Using mock access token for local development.');
    return 'mock_access_token_12345';
  }

  try {
    const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const baseUrl = getPaypalBaseUrl();

    logger.info(`[paypal-service] Fetching OAuth token from ${baseUrl}/v1/oauth2/token`);
    const response = await axios({
      url: `${baseUrl}/v1/oauth2/token`,
      method: 'post',
      headers: {
        'Accept': 'application/json',
        'Accept-Language': 'en_US',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${auth}`
      },
      data: 'grant_type=client_credentials'
    });

    return response.data.access_token;
  } catch (error) {
    logger.error(`[paypal-service] Failed to get PayPal access token: ${error.message}`);
    if (error.response?.data) {
      logger.error(`[paypal-service] Token error response: ${JSON.stringify(error.response.data)}`);
    }
    throw new Error('PayPal authentication failed.');
  }
};

/**
 * Create a PayPal checkout order
 * @param {string} amount - Converted USD amount (e.g. '12.04')
 * @param {string} currency - Supported currency, e.g. 'USD'
 * @param {string} returnUrl - Redirect back to app on approval
 * @param {string} cancelUrl - Redirect back to app on cancellation
 */
const createOrder = async (amount, currency = 'USD', returnUrl, cancelUrl) => {
  const { isMock } = getCredentials();
  if (isMock) {
    const mockId = `mock_order_${Date.now()}`;
    logger.info(`[paypal-service] Creating mock PayPal order amount=${amount} currency=${currency} id=${mockId}`);
    return {
      id: mockId,
      status: 'CREATED',
      links: [
        {
          href: `${returnUrl}&token=${mockId}`,
          rel: 'approve',
          method: 'GET'
        }
      ]
    };
  }

  try {
    const token = await getAccessToken();
    const baseUrl = getPaypalBaseUrl();

    const orderPayload = {
      intent: 'CAPTURE',
      purchase_units: [
        {
          amount: {
            currency_code: currency,
            value: amount.toString()
          },
          description: 'PentestRadar Subscription Plan Upgrade'
        }
      ],
      application_context: {
        brand_name: 'PentestRadar',
        user_action: 'PAY_NOW',
        return_url: returnUrl,
        cancel_url: cancelUrl
      }
    };

    logger.info(`[paypal-service] Creating PayPal order amount=${amount} currency=${currency}`);
    const response = await axios({
      url: `${baseUrl}/v2/checkout/orders`,
      method: 'post',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      data: orderPayload
    });

    return response.data;
  } catch (error) {
    logger.error(`[paypal-service] Failed to create PayPal order: ${error.message}`);
    if (error.response?.data) {
      logger.error(`[paypal-service] Create order error response: ${JSON.stringify(error.response.data)}`);
    }
    throw new Error(error.response?.data?.message || 'PayPal order creation failed.');
  }
};

/**
 * Capture an approved PayPal checkout order
 * @param {string} orderId - PayPal Order ID
 */
const captureOrder = async (orderId) => {
  const { isMock } = getCredentials();
  if (isMock || orderId.startsWith('mock_')) {
    const mockCaptureId = `mock_capture_${Date.now()}`;
    logger.info(`[paypal-service] Capturing mock PayPal orderId=${orderId} captureId=${mockCaptureId}`);
    return {
      id: orderId,
      status: 'COMPLETED',
      purchase_units: [
        {
          payments: {
            captures: [
              {
                id: mockCaptureId,
                status: 'COMPLETED'
              }
            ]
          }
        }
      ]
    };
  }

  try {
    const token = await getAccessToken();
    const baseUrl = getPaypalBaseUrl();

    logger.info(`[paypal-service] Capturing PayPal orderId=${orderId}`);
    const response = await axios({
      url: `${baseUrl}/v2/checkout/orders/${orderId}/capture`,
      method: 'post',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    return response.data;
  } catch (error) {
    logger.error(`[paypal-service] Failed to capture PayPal order: ${error.message}`);
    if (error.response?.data) {
      logger.error(`[paypal-service] Capture order error response: ${JSON.stringify(error.response.data)}`);
    }
    throw new Error(error.response?.data?.message || 'PayPal payment capture failed.');
  }
};

/**
 * Verify Webhook Signature received from PayPal
 */
const verifyWebhookSignature = async (headers, rawBody, webhookId) => {
  const { isMock } = getCredentials();
  if (isMock) {
    logger.info('[paypal-service] Mock signature verification succeeded.');
    return true;
  }

  try {
    const token = await getAccessToken();
    const baseUrl = getPaypalBaseUrl();

    const verificationPayload = {
      transmission_id: headers['paypal-transmission-id'],
      transmission_time: headers['paypal-transmission-time'],
      cert_url: headers['paypal-cert-url'],
      auth_algo: headers['paypal-auth-algo'],
      transmission_sig: headers['paypal-transmission-sig'],
      webhook_id: webhookId,
      webhook_event: typeof rawBody === 'string' ? JSON.parse(rawBody) : rawBody
    };

    logger.info('[paypal-service] Verifying PayPal webhook signature...');
    const response = await axios({
      url: `${baseUrl}/v1/notifications/verify-webhook-signature`,
      method: 'post',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      data: verificationPayload
    });

    return response.data.verification_status === 'SUCCESS';
  } catch (error) {
    logger.error(`[paypal-service] Failed to verify PayPal webhook signature: ${error.message}`);
    return false;
  }
};

module.exports = {
  getAccessToken,
  createOrder,
  captureOrder,
  verifyWebhookSignature
};
