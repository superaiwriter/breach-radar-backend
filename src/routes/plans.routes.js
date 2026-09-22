const express = require('express');
const router = express.Router();
const plansController = require('../controllers/plans.controller');

/**
 * GET /api/v1/plans
 * Public endpoint to fetch active subscription plans for the pricing page.
 */
router.get('/', plansController.getPublicPlans);

module.exports = router;
