const Scan = require('../models/Scan');
const Domain = require('../models/Domain');
const Vulnerability = require('../models/Vulnerability');
const logger = require('../config/logger');

/**
 * GET /api/v1/stats/platform
 * Retrieve platform-wide aggregate statistics.
 */
const getPlatformStats = async (req, res, next) => {
  try {
    // 1. Total Scans Performed (Completed, Failed, or In Progress)
    const totalScans = await Scan.countDocuments({
      status: { $in: ['Completed', 'Failed', 'In Progress'] }
    });

    // 2. Total Findings/Vulnerabilities detected
    const totalFindings = await Vulnerability.countDocuments();

    // 3. Unique target domains that have been scanned
    const distinctDomainIds = await Scan.distinct('domainId', {
      status: { $in: ['Completed', 'Failed', 'In Progress'] }
    });
    const domains = await Domain.distinct('domain', {
      _id: { $in: distinctDomainIds },
      domain: { $regex: /\S+/ }
    });
    const domainsScanned = domains.length;

    // 4. Platform Uptime (Hardcoded to 99.9% per user request)
    const uptime = 99.9;

    // 5. AI Models (Hardcoded to 10 per user request)
    const aiModels = 10;

    res.status(200).json({
      totalScans,
      totalFindings,
      domainsScanned,
      uptime,
      aiModels
    });
  } catch (error) {
    logger.error(`Error fetching platform stats: ${error.message}`);
    next(error);
  }
};

module.exports = {
  getPlatformStats
};
