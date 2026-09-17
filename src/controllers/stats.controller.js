const Scan = require('../models/Scan');
const Domain = require('../models/Domain');
const Vulnerability = require('../models/Vulnerability');
const User = require('../models/User');
const logger = require('../config/logger');

const getPlatformStats = async (req, res, next) => {
  try {
    const totalScans = await Scan.countDocuments({
      status: { $in: ['Completed', 'Failed', 'In Progress'] }
    });

    const totalFindings = await Vulnerability.countDocuments();

    const distinctDomainIds = await Scan.distinct('domainId', {
      status: { $in: ['Completed', 'Failed', 'In Progress'] }
    });
    const domains = await Domain.distinct('domain', {
      _id: { $in: distinctDomainIds },
      domain: { $regex: /\S+/ }
    });
    const domainsScanned = domains.length;

    const uptime = 99.9;

    const cyberSecurityExperts = await User.countDocuments({ accountType: 'cyber_security_expert' });
    const businesses = await User.countDocuments({ accountType: 'organization' });

    res.status(200).json({
      totalScans,
      totalFindings,
      domainsScanned,
      uptime,
      cyberSecurityExperts,
      businesses
    });
  } catch (error) {
    logger.error(`Error fetching platform stats: ${error.message}`);
    next(error);
  }
};

module.exports = {
  getPlatformStats
};
