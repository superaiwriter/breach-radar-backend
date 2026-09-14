const express = require('express');
const router = express.Router();
const statsController = require('../controllers/stats.controller');

/**
 * GET /api/v1/stats/platform or /api/stats/platform
 * Public endpoint to fetch platform statistics.
 */
router.get('/platform', statsController.getPlatformStats);

module.exports = router;
