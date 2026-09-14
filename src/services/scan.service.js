const mongoose = require('mongoose');
const Scan = require('../models/Scan');
const Domain = require('../models/Domain');
const Vulnerability = require('../models/Vulnerability');
const { SCAN_TYPES, SCAN_STATUS } = require('../constants');
const { addScanJob } = require('./queue.service');
const { assertDomainVerified } = require('./domain.verification.service');
const { validatePublicDomainTarget } = require('../utils/validators');
const logger = require('../config/logger');

const DOMAIN_POPULATE = {
  path: 'domainId',
  select: 'domain score scoreLabel scoreTone status statusDetail lastScanAt verificationStatus verifiedAt'
};

function assertWorkspaceId(workspaceId) {
  if (!workspaceId) {
    const error = new Error('Workspace ID context required');
    error.statusCode = 400;
    throw error;
  }
}

function assertValidObjectId(id, label = 'scan') {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    const error = new Error(`Invalid ${label} ID format`);
    error.statusCode = 400;
    throw error;
  }
}

function buildDefaultChecks(scanType, checks = {}) {
  return {
    owasp: true,
    ssl: true,
    headers: true,
    ports: scanType === SCAN_TYPES.FULL || scanType === SCAN_TYPES.CUSTOM,
    malware: true,
    compliance: scanType === SCAN_TYPES.FULL,
    businessLogic: true,
    apiSecurity: true,
    cloudInfrastructure: true,
    ...checks
  };
}

async function resolveDomain(workspaceId, domainName) {
  const domainValidation = validatePublicDomainTarget(domainName);
  if (!domainValidation.valid) {
    const error = new Error(domainValidation.message);
    error.statusCode = 400;
    throw error;
  }

  const domain = await Domain.findOne({
    workspaceId,
    domain: domainValidation.domain
  });

  if (!domain) {
    const error = new Error(`Domain "${domainName}" is not registered in this workspace.`);
    error.statusCode = 404;
    throw error;
  }

  assertDomainVerified(domain);

  if (domain.status !== 'Active') {
    const error = new Error(`Domain "${domain.domain}" scanning is currently disabled.`);
    error.statusCode = 403;
    error.code = 'DOMAIN_SCAN_DISABLED';
    throw error;
  }

  return domain;
}

async function findScanInWorkspace(workspaceId, scanId) {
  assertValidObjectId(scanId);

  const scan = await Scan.findOne({ _id: scanId, workspaceId }).populate(DOMAIN_POPULATE);
  if (!scan) {
    const error = new Error('Scan not found or unauthorized.');
    error.statusCode = 404;
    throw error;
  }

  return scan;
}

async function queueScanJob(scan, domainName, checks) {
  await addScanJob(scan._id, domainName, checks);
  logger.info(`Scan job queued for ${domainName} (Scan ID: ${scan._id})`);
}

/**
 * GET /scans — scan history for the active workspace
 */
async function getScanHistory(workspaceId, filters = {}) {
  assertWorkspaceId(workspaceId);

  const { status, domain } = filters;
  const query = { workspaceId };

  if (status && status !== 'All') {
    query.status = status;
  }

  if (domain) {
    const domainObj = await Domain.findOne({
      workspaceId,
      domain: domain.trim().toLowerCase()
    });

    if (!domainObj) {
      return [];
    }

    query.domainId = domainObj._id;
  }

  return Scan.find(query).populate(DOMAIN_POPULATE).sort({ createdAt: -1 });
}

/**
 * GET /scans/:id — full scan record
 */
async function getScanById(workspaceId, scanId) {
  assertWorkspaceId(workspaceId);
  return findScanInWorkspace(workspaceId, scanId);
}

/**
 * GET /scans/:id/status — lightweight scan status payload
 */
async function getScanStatus(workspaceId, scanId) {
  const scan = await getScanById(workspaceId, scanId);

  return {
    id: scan._id,
    status: scan.status,
    domain: scan.domainId?.domain || null,
    scanType: scan.scanType,
    startedAt: scan.startedAt || null,
    completedAt: scan.completedAt || null,
    scheduledTime: scan.scheduledTime || null,
    riskScore: scan.status === SCAN_STATUS.COMPLETED ? scan.riskScore : null,
    errorDetail: scan.errorDetail || null,
    lifecycle: mapScanLifecycle(scan.status),
    isActive:
      scan.status === SCAN_STATUS.QUEUED || scan.status === SCAN_STATUS.IN_PROGRESS
  };
}

function mapScanLifecycle(status) {
  switch (status) {
    case SCAN_STATUS.QUEUED:
    case SCAN_STATUS.SCHEDULED:
      return 'pending';
    case SCAN_STATUS.IN_PROGRESS:
      return 'running';
    case SCAN_STATUS.COMPLETED:
      return 'completed';
    case SCAN_STATUS.FAILED:
      return 'failed';
    default:
      return 'pending';
  }
}

/**
 * GET /scans/:id/results — scan findings and summary
 */
async function getScanResults(workspaceId, scanId) {
  const scan = await findScanInWorkspace(workspaceId, scanId);

  const vulnerabilities = await Vulnerability.find({ workspaceId, scanId: scan._id })
    .populate('domainId', 'domain')
    .sort({ detectedAt: -1 });

  const counts = scan.vulnerabilitiesCount || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalFindings = Object.values(counts).reduce((sum, value) => sum + value, 0);

  return {
    scan: {
      id: scan._id,
      status: scan.status,
      scanType: scan.scanType,
      checks: scan.checks,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      errorDetail: scan.errorDetail || null,
      lifecycle: mapScanLifecycle(scan.status)
    },
    domain: scan.domainId,
    summary: {
      vulnerabilitiesCount: counts,
      riskScore: scan.riskScore,
      totalFindings,
      securityScore: scan.domainId?.score ?? null,
      securityScoreLabel: scan.domainId?.scoreLabel ?? null
    },
    vulnerabilities,
    ready: scan.status === SCAN_STATUS.COMPLETED
  };
}

/**
 * POST /scans — queue a new scan background job
 */
async function startScan({ workspaceId, userId, domain, scanType, checks }) {
  assertWorkspaceId(workspaceId);

  if (!domain) {
    const error = new Error('Domain name is required.');
    error.statusCode = 400;
    throw error;
  }

  if (!scanType) {
    const error = new Error('Scan type is required.');
    error.statusCode = 400;
    throw error;
  }

  if (!Object.values(SCAN_TYPES).includes(scanType)) {
    const error = new Error('Invalid scan type.');
    error.statusCode = 400;
    throw error;
  }

  const domainObj = await resolveDomain(workspaceId, domain);
  const mergedChecks = buildDefaultChecks(scanType, checks);

  const scan = new Scan({
    workspaceId,
    domainId: domainObj._id,
    scanType,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: userId,
    checks: mergedChecks
  });

  await scan.save();
  await queueScanJob(scan, domainObj.domain, mergedChecks);

  return scan.populate(DOMAIN_POPULATE);
}

/**
 * POST /scans/:id/rerun — re-queue a scan with the same configuration
 */
async function rerunScan({ workspaceId, userId, scanId }) {
  assertWorkspaceId(workspaceId);
  assertValidObjectId(scanId);

  const oldScan = await Scan.findOne({ _id: scanId, workspaceId }).populate('domainId');
  if (!oldScan) {
    const error = new Error('Scan record not found or unauthorized.');
    error.statusCode = 404;
    throw error;
  }

  assertDomainVerified(oldScan.domainId);
  if (oldScan.domainId.status !== 'Active') {
    const error = new Error(`Domain "${oldScan.domainId.domain}" scanning is currently disabled.`);
    error.statusCode = 403;
    error.code = 'DOMAIN_SCAN_DISABLED';
    throw error;
  }

  const scan = new Scan({
    workspaceId,
    domainId: oldScan.domainId._id,
    scanType: oldScan.scanType,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: userId,
    checks: oldScan.checks
  });

  await scan.save();
  await queueScanJob(scan, oldScan.domainId.domain, oldScan.checks);

  return scan.populate(DOMAIN_POPULATE);
}

module.exports = {
  getScanHistory,
  getScanById,
  getScanStatus,
  getScanResults,
  startScan,
  rerunScan
};
