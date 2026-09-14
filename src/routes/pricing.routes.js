const express = require('express');
const router = express.Router();
const pricingController = require('../controllers/pricing.controller');

/**
 * GET /api/v1/pricing
 * Public endpoint to fetch active pricing plans for the Landing Page.
 */
router.get('/', pricingController.getPublicPricingPlans);
router.get('/plans', pricingController.getPublicPricingPlans);

module.exports = router;
