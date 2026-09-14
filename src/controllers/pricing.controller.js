const SubscriptionPlan = require('../models/SubscriptionPlan');
const logger = require('../config/logger');

/**
 * GET /api/v1/pricing
 * Public endpoint to fetch active pricing plans for the Landing Page.
 */
const getPublicPricingPlans = async (req, res, next) => {
  try {
    const plansRaw = await SubscriptionPlan.find({ isActive: true })
      .sort({ sortOrder: 1, price: 1 })
      .lean();

    const plans = plansRaw.map((plan) => {
      const isFree = plan.price === 0;
      const isCustom = isFree && plan.name.toLowerCase() === 'enterprise';
      const formattedPrice = plan.price.toLocaleString('en-IN');
      const suffix = plan.billingInterval === 'year' ? '/yr' : '/mo';

      return {
        id: plan._id,
        _id: plan._id,
        name: plan.name,
        displayName: plan.displayName || plan.name,
        desc: plan.description || '',
        description: plan.description || '',
        price: formattedPrice,
        rawPrice: plan.price,
        currency: plan.currency || 'INR',
        billingInterval: plan.billingInterval || 'month',
        suffix,
        popular: !!plan.isPopular,
        isPopular: !!plan.isPopular,
        seatLimit: plan.seatLimit,
        domainLimit: plan.domainLimit,
        scanLimit: plan.scanLimit,
        sortOrder: plan.sortOrder || 0,
        custom: isCustom,
        cta: plan.ctaText || (isFree ? 'Get Started Free' : 'Get Started'),
        ctaText: plan.ctaText || (isFree ? 'Get Started Free' : 'Get Started'),
        features: plan.features || []
      };
    });

    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    res.status(200).json({
      success: true,
      count: plans.length,
      plans
    });
  } catch (error) {
    logger.error(`[pricing.controller] Error fetching public pricing plans: ${error.message}`);
    next(error);
  }
};

module.exports = {
  getPublicPricingPlans
};
