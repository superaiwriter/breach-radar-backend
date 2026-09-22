const SubscriptionPlan = require('../models/SubscriptionPlan');
const logger = require('../config/logger');

/**
 * GET /api/v1/plans
 * Public endpoint returning all active subscription plans, sorted for display.
 */
const getPublicPlans = async (req, res, next) => {
  try {
    const plans = await SubscriptionPlan.find({ isActive: true })
      .sort({ sortOrder: 1, price: 1 })
      .select('name displayName description price currency billingInterval seatLimit domainLimit scanLimit features sortOrder isPopular ctaText isActive');

    res.status(200).json({ plans });
  } catch (error) {
    logger.error(`Error fetching public plans: ${error.message}`);
    next(error);
  }
};

module.exports = { getPublicPlans };
