const scanService = require('../services/scan.service');
const teamService = require('../services/team.service');
const logger = require('../config/logger');

// GET /api/v1/scans
const getScans = async (req, res, next) => {
  try {
    const scans = await scanService.getScanHistory(req.workspaceId, req.query);
    res.status(200).json(scans);
  } catch (error) {
    next(error);
  }
};

// GET /api/v1/scans/:id
const getScanById = async (req, res, next) => {
  try {
    const scan = await scanService.getScanById(req.workspaceId, req.params.id);
    res.status(200).json(scan);
  } catch (error) {
    next(error);
  }
};

// GET /api/v1/scans/:id/status
const getScanStatus = async (req, res, next) => {
  try {
    const status = await scanService.getScanStatus(req.workspaceId, req.params.id);
    res.status(200).json(status);
  } catch (error) {
    next(error);
  }
};

// GET /api/v1/scans/:id/results
const getScanResults = async (req, res, next) => {
  try {
    const results = await scanService.getScanResults(req.workspaceId, req.params.id);
    res.status(200).json(results);
  } catch (error) {
    next(error);
  }
};

// POST /api/v1/scans
const startScan = async (req, res, next) => {
  try {
    const { domain, scanType, checks, authProfileId } = req.body;

    const Workspace = require('../models/Workspace');
    const Organization = require('../models/Organization');
    const SubscriptionPlan = require('../models/SubscriptionPlan');
    const Subscription = require('../models/Subscription');
    const Scan = require('../models/Scan');

    const workspace = await Workspace.findById(req.workspaceId);
    if (!workspace) {
      return res.status(400).json({ message: 'Workspace context not found.' });
    }

    const org = await Organization.findOne({ ownerId: workspace.owner });
    if (org) {
      const plan = await SubscriptionPlan.findOne({ name: org.subscriptionPlan });
      const limit = plan ? plan.scanLimit : 5;
      
      if (limit < 999999) {
        const sub = await Subscription.findOne({ organizationId: org._id });
        const since = sub ? sub.startDate : new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const scansUsed = await Scan.countDocuments({ workspaceId: req.workspaceId, createdAt: { $gte: since } });
        
        if (scansUsed >= limit) {
          return res.status(403).json({
            message: `Scan limit reached. Your current plan (${org.subscriptionPlan}) allows max ${limit} scans per billing cycle. You have used ${scansUsed} scans. Please upgrade to run more scans.`,
            code: 'LIMIT_EXCEEDED'
          });
        }
      }
    }

    const scan = await scanService.startScan({
      workspaceId: req.workspaceId,
      userId: req.user._id,
      domain,
      scanType,
      checks,
      authProfileId
    });

    logger.info(`Scan started for ${domain} (Type: ${scanType}) by user ${req.user.email}`);
    
    if (org) {
      const billingService = require('../services/billing.service');
      billingService.checkUsageAlerts(org._id, req.user._id).catch(err => logger.error(`[alert-check-err] ${err.message}`));
    }

    const { logRequestAudit } = require('../services/audit.service');
    await logRequestAudit(req, 'Scan Started', `Scan started for domain ${domain}.`);

    await teamService.recordWorkspaceActivity({
      userId: req.user._id,
      action: 'Scan execution',
      target: domain,
      metadata: { scanId: scan._id, scanType }
    });

    res.status(202).json({
      message: 'Scan successfully queued and started.',
      scan
    });
  } catch (error) {
    next(error);
  }
};

// POST /api/v1/scans/:id/rerun
const rerunScan = async (req, res, next) => {
  try {
    const Workspace = require('../models/Workspace');
    const Organization = require('../models/Organization');
    const SubscriptionPlan = require('../models/SubscriptionPlan');
    const Subscription = require('../models/Subscription');
    const Scan = require('../models/Scan');

    const workspace = await Workspace.findById(req.workspaceId);
    if (!workspace) {
      return res.status(400).json({ message: 'Workspace context not found.' });
    }

    const org = await Organization.findOne({ ownerId: workspace.owner });
    if (org) {
      const plan = await SubscriptionPlan.findOne({ name: org.subscriptionPlan });
      const limit = plan ? plan.scanLimit : 5;
      
      if (limit < 999999) {
        const sub = await Subscription.findOne({ organizationId: org._id });
        const since = sub ? sub.startDate : new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const scansUsed = await Scan.countDocuments({ workspaceId: req.workspaceId, createdAt: { $gte: since } });
        
        if (scansUsed >= limit) {
          return res.status(403).json({
            message: `Scan limit reached. Your current plan (${org.subscriptionPlan}) allows max ${limit} scans per billing cycle. You have used ${scansUsed} scans. Please upgrade to run more scans.`,
            code: 'LIMIT_EXCEEDED'
          });
        }
      }
    }

    const scan = await scanService.rerunScan({
      workspaceId: req.workspaceId,
      userId: req.user._id,
      scanId: req.params.id
    });

    logger.info(`Scan re-run queued for ${scan.domainId?.domain} by user ${req.user.email}`);
    
    if (org) {
      const billingService = require('../services/billing.service');
      billingService.checkUsageAlerts(org._id, req.user._id).catch(err => logger.error(`[alert-check-err] ${err.message}`));
    }

    const { logRequestAudit } = require('../services/audit.service');
    await logRequestAudit(req, 'Scan Started', `Scan re-run started for domain ${scan.domainId?.domain || ''}.`);

    await teamService.recordWorkspaceActivity({
      userId: req.user._id,
      action: 'Scan execution',
      target: scan.domainId?.domain || String(scan._id),
      metadata: { scanId: scan._id, rerun: true }
    });

    res.status(202).json({
      message: 'Scan successfully re-queued.',
      scan
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getScans,
  getScanById,
  getScanStatus,
  getScanResults,
  startScan,
  rerunScan
};