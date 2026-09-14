const mongoose = require('mongoose');
const User = require('../models/User');
const Domain = require('../models/Domain');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const Workspace = require('../models/Workspace');
const SubscriptionPlan = require('../models/SubscriptionPlan');
const Subscription = require('../models/Subscription');
const Invoice = require('../models/Invoice');
const PaymentTransaction = require('../models/PaymentTransaction');
const SupportTicket = require('../models/SupportTicket');
const AuditLog = require('../models/AuditLog');
const Organization = require('../models/Organization');
const TeamInvitation = require('../models/TeamInvitation');
const { getRedisClient } = require('../config/redis');
const { addScanJob } = require('../services/queue.service');
const { logAuditEvent } = require('../utils/auditLogger');
const { SCAN_STATUS, SCAN_TYPES } = require('../constants');
const logger = require('../config/logger');

// 1. DASHBOARD ANALYTICS
const getDashboardStats = async (req, res, next) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalDomains = await Domain.countDocuments();
    const totalScans = await Scan.countDocuments();
    const totalVulnerabilities = await Vulnerability.countDocuments();

    // Calculate total revenue from payment histories (succeeded - refunded)
    const succeededPayments = await PaymentTransaction.aggregate([
      { $match: { status: 'succeeded' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const refundedPayments = await PaymentTransaction.aggregate([
      { $match: { status: 'refunded' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const revSucceeded = succeededPayments[0]?.total || 0;
    const revRefunded = refundedPayments[0]?.total || 0;
    const totalRevenue = Math.max(0, revSucceeded - revRefunded);

    // Active subscriptions count (users with active status and non-free plans, or active user count)
    const activeSubscriptions = await Subscription.countDocuments({
      status: 'active'
    });

    // Scan Activity Chart (grouped by last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const scanActivityRaw = await Scan.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Fill missing dates in scan activity
    const scanActivity = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const match = scanActivityRaw.find(item => item._id === dateStr);
      scanActivity.push({
        date: dateStr,
        scans: match ? match.count : 0
      });
    }

    // Vulnerability Severity Distribution
    const severityDistribution = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const vulnsRaw = await Vulnerability.aggregate([
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]);
    vulnsRaw.forEach(item => {
      if (item._id && severityDistribution[item._id] !== undefined) {
        severityDistribution[item._id] = item.count;
      }
    });

    // Revenue Analytics (grouped by month or recent payments)
    const revenueAnalyticsRaw = await PaymentTransaction.aggregate([
      { $match: { status: 'succeeded' } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m', date: '$createdAt' } },
          revenue: { $sum: '$amount' }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    const revenueAnalytics = revenueAnalyticsRaw.map(item => ({
      month: item._id,
      revenue: item.revenue
    }));

    // Recent Users Table
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('email profile role status createdAt');

    // Recent Scans Table
    const recentScans = await Scan.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate({
        path: 'domainId',
        select: 'domain'
      });

    // Support Tickets Overview
    const ticketsOverview = { open: 0, assigned: 0, closed: 0 };
    const ticketsRaw = await SupportTicket.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    ticketsRaw.forEach(item => {
      if (item._id === 'Open') {
        ticketsOverview.open += item.count;
      } else if (['In Progress', 'Waiting for Customer', 'Resolved'].includes(item._id)) {
        ticketsOverview.assigned += item.count;
      } else if (item._id === 'Closed') {
        ticketsOverview.closed += item.count;
      } else if (item._id && ticketsOverview[item._id] !== undefined) {
        ticketsOverview[item._id] += item.count;
      }
    });

    // System Health Widget
    const mongoStatus = mongoose.connection.readyState === 1 ? 'Healthy' : 'Disconnected';
    const redis = getRedisClient();
    let redisStatus = 'Unavailable';
    if (redis) {
      try {
        await redis.ping();
        redisStatus = 'Healthy';
      } catch (err) {
        redisStatus = 'Error';
      }
    }

    res.status(200).json({
      stats: {
        totalUsers,
        totalDomains,
        totalScans,
        totalVulnerabilities,
        totalRevenue,
        activeSubscriptions
      },
      charts: {
        scanActivity,
        severityDistribution,
        revenueAnalytics
      },
      recentUsers,
      recentScans,
      ticketsOverview,
      systemHealth: {
        apiStatus: 'Healthy',
        mongodbStatus: mongoStatus,
        redisStatus: redisStatus,
        workerStatus: 'Healthy',
        queueStatus: 'Healthy'
      }
    });
  } catch (error) {
    next(error);
  }
};

// 2. USERS MANAGEMENT
const getUsers = async (req, res, next) => {
  try {
    const { search, role, status, plan } = req.query;
    const query = {};

    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { 'profile.name': { $regex: search, $options: 'i' } }
      ];
    }
    if (role && role !== 'all') {
      query.role = role;
    }
    if (status && status !== 'all') {
      query.status = status;
    }
    // Simple plan search filter in profile/plan if applicable
    if (plan && plan !== 'all') {
      query['profile.plan'] = plan; 
    }

    const users = await User.find(query)
      .select('-passwordHash')
      .sort({ createdAt: -1 });

    // Fetch counts of domains and scans for each user
    const usersWithStats = await Promise.all(
      users.map(async (u) => {
        const workspace = await Workspace.findOne({ owner: u._id });
        let domainCount = 0;
        let scanCount = 0;
        if (workspace) {
          domainCount = await Domain.countDocuments({ workspaceId: workspace._id });
          scanCount = await Scan.countDocuments({ workspaceId: workspace._id });
        }
        return {
          ...u.toObject(),
          domainCount,
          scanCount,
          planName: u.profile.plan || 'Free'
        };
      })
    );

    res.status(200).json(usersWithStats);
  } catch (error) {
    next(error);
  }
};

const exportUsers = async (req, res, next) => {
  try {
    const { format } = req.query;
    
    // Default format to csv if not provided or invalid
    const allowedFormats = ['csv', 'xlsx', 'json'];
    const exportFormat = allowedFormats.includes(format) ? format : 'csv';

    // Stream/fetch all users using cursor to handle large datasets safely
    const cursor = User.find({}).sort({ createdAt: -1 }).cursor();
    
    const rows = [];
    let doc;
    while ((doc = await cursor.next())) {
      const user = doc;
      
      // Fetch user's workspace
      const workspace = await Workspace.findOne({ owner: user._id });
      
      // Fetch domains related to the workspace
      let domainNames = '';
      let domainCount = 0;
      if (workspace) {
        const domains = await Domain.find({ workspaceId: workspace._id });
        domainNames = domains.map(d => d.domain).join(', ');
        domainCount = domains.length;
      }
      
      // Fetch scans count related to the workspace
      let scanCount = 0;
      if (workspace) {
        scanCount = await Scan.countDocuments({ workspaceId: workspace._id });
      }
      
      // Fetch subscription details
      const subscription = await Subscription.findOne({ userId: user._id });
      
      // Fetch payment transactions
      const payments = await PaymentTransaction.find({ userId: user._id });
      const totalPaid = payments.reduce((acc, p) => p.status === 'succeeded' ? acc + p.amount : acc, 0);
      const totalRefunded = payments.reduce((acc, p) => p.status === 'refunded' ? acc + p.amount : acc, 0);
      const paymentHistory = payments
        .map(p => `${p.transactionId}: ${p.status} (${p.amount} ${p.currency})`)
        .join('; ');

      // Build safe row object (never export passwords or security keys!)
      const row = {
        'User ID': user._id.toString(),
        'Name': user.profile?.name || '',
        'Email': user.email,
        'Role': user.role,
        'Status': user.status,
        'Plan': user.profile?.plan || 'Starter',
        'Email Verified': user.isEmailVerified ? 'Yes' : 'No',
        'Last Login': user.lastLogin ? user.lastLogin.toISOString() : '',
        'MFA Enabled': user.security?.mfaEnabled ? 'Yes' : 'No',
        'Language': user.preferences?.language || 'en',
        'Timezone': user.preferences?.timezone || 'UTC',
        'Phone Number': user.profile?.phoneNumber || '',
        'Organization': user.profile?.organization || '',
        'Job Title': user.profile?.jobTitle || '',
        'Country': user.profile?.country || '',
        'Workspace ID': workspace ? workspace._id.toString() : '',
        'Workspace Name': workspace ? workspace.name : '',
        'Domain Count': domainCount,
        'Domains': domainNames,
        'Scan Count': scanCount,
        'Subscription Plan': subscription ? subscription.currentPlan : '',
        'Subscription Status': subscription ? subscription.status : '',
        'Subscription Payment Status': subscription ? subscription.paymentStatus : '',
        'Subscription Start': subscription && subscription.startDate ? subscription.startDate.toISOString() : '',
        'Subscription Expiry': subscription && subscription.expiryDate ? subscription.expiryDate.toISOString() : '',
        'Subscription Next Billing': subscription && subscription.nextBillingDate ? subscription.nextBillingDate.toISOString() : '',
        'Total Paid (INR)': totalPaid,
        'Total Refunded (INR)': totalRefunded,
        'Payment Transactions': paymentHistory,
        'Created At': user.createdAt ? user.createdAt.toISOString() : '',
        'Updated At': user.updatedAt ? user.updatedAt.toISOString() : ''
      };
      
      rows.push(row);
    }

    const todayStr = new Date().toISOString().split('T')[0];

    if (exportFormat === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=users-export-${todayStr}.json`);
      return res.status(200).send(JSON.stringify(rows, null, 2));
    }

    if (exportFormat === 'xlsx') {
      const XLSX = require('xlsx');
      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(rows);
      XLSX.utils.book_append_sheet(wb, ws, 'Users');
      const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
      
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename=users-export-${todayStr}.xlsx`);
      return res.status(200).send(buffer);
    }

    // Default: CSV format
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=users-export-${todayStr}.csv`);
    
    if (rows.length === 0) {
      return res.status(200).send('');
    }

    const headers = Object.keys(rows[0]);
    const escapeCSV = (val) => {
      if (val === null || val === undefined) return '';
      let str = String(val);
      str = str.replace(/"/g, '""');
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str}"`;
      }
      return str;
    };

    let csvContent = headers.join(',') + '\n';
    for (const r of rows) {
      csvContent += headers.map(h => escapeCSV(r[h])).join(',') + '\n';
    }
    
    return res.status(200).send(csvContent);

  } catch (error) {
    next(error);
  }
};

const getUserDetails = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-passwordHash');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const workspace = await Workspace.findOne({ owner: user._id });
    let domains = [];
    let scans = [];
    if (workspace) {
      domains = await Domain.find({ workspaceId: workspace._id });
      scans = await Scan.find({ workspaceId: workspace._id }).sort({ createdAt: -1 });
    }

    res.status(200).json({
      user,
      domains,
      scans
    });
  } catch (error) {
    next(error);
  }
};

const updateUserStatus = async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!['active', 'suspended'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select('-passwordHash');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await logAuditEvent({
      req,
      action: 'User Status Change',
      description: `Suspended or activated user ${user.email} (New Status: ${status})`,
      userId: req.user._id
    });

    res.status(200).json({ message: `User account is now ${status}`, user });
  } catch (error) {
    next(error);
  }
};

const updateUserRole = async (req, res, next) => {
  try {
    const { role } = req.body;
    if (!['user', 'admin', 'super_admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select('-passwordHash');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await logAuditEvent({
      req,
      action: 'Role Changes',
      description: `Role of ${user.email} updated to ${role}`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'User role updated successfully', user });
  } catch (error) {
    next(error);
  }
};

const upgradeUserSubscription = async (req, res, next) => {
  try {
    const { planName } = req.body;
    const plan = await SubscriptionPlan.findOne({ name: planName });
    if (!plan && planName !== 'Free') {
      return res.status(400).json({ message: 'Invalid plan selected' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.profile.plan = planName;
    await user.save();

    const org = await Organization.findOne({ ownerId: user._id });
    if (org) {
      org.subscriptionPlan = planName;
      if (plan) org.maxSeats = plan.seatLimit;
      await org.save();

      const sub = await Subscription.findOne({ organizationId: org._id });
      if (sub) {
        sub.currentPlan = planName;
        sub.paymentStatus = planName === 'Starter' || planName === 'Free' ? 'free' : 'paid';
        await sub.save();
      }
    }

    await logAuditEvent({
      req,
      action: 'Subscription Changes',
      description: `Upgraded subscription for user ${user.email} to plan ${planName}`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'User plan upgraded successfully', user });
  } catch (error) {
    next(error);
  }
};

const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const workspace = await Workspace.findOne({ owner: user._id });
    if (workspace) {
      // Remove workspace, domains, scans, vulnerabilities
      await Domain.deleteMany({ workspaceId: workspace._id });
      await Scan.deleteMany({ workspaceId: workspace._id });
      await Vulnerability.deleteMany({ workspaceId: workspace._id });
      await Workspace.deleteOne({ _id: workspace._id });
    }

    await User.deleteOne({ _id: user._id });

    await logAuditEvent({
      req,
      action: 'User Deletion',
      description: `Deleted user ${user.email} and all their registered targets.`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'User and all associated assets deleted successfully' });
  } catch (error) {
    next(error);
  }
};

// 3. DOMAINS MANAGEMENT
const getDomains = async (req, res, next) => {
  try {
    const { search, status } = req.query;
    const query = {};

    if (search) {
      query.domain = { $regex: search, $options: 'i' };
    }
    if (status && status !== 'all') {
      query.status = status;
    }

    const domains = await Domain.find(query)
      .populate({
        path: 'workspaceId',
        select: 'name owner',
        populate: {
          path: 'owner',
          select: 'email profile.name'
        }
      })
      .sort({ createdAt: -1 });

    res.status(200).json(domains);
  } catch (error) {
    next(error);
  }
};

const forceScanDomain = async (req, res, next) => {
  try {
    const { domainId } = req.body;
    const domain = await Domain.findById(domainId);
    if (!domain) {
      return res.status(404).json({ message: 'Domain not found' });
    }

    // Trigger immediate scan
    const scan = new Scan({
      workspaceId: domain.workspaceId,
      domainId: domain._id,
      scanType: SCAN_TYPES.FULL,
      status: SCAN_STATUS.QUEUED,
      triggeredBy: req.user._id,
      checks: {
        owasp: true,
        ssl: true,
        headers: true,
        ports: true,
        malware: true,
        compliance: true
      }
    });

    await scan.save();
    await addScanJob(scan._id, domain.domain, scan.checks);

    logger.info(`Forced scan started for domain ${domain.domain} by superadmin`);

    res.status(200).json({ message: 'Force scan successfully triggered', scan });
  } catch (error) {
    next(error);
  }
};

// 4. SCANS MANAGEMENT
const getScans = async (req, res, next) => {
  try {
    const { status } = req.query;
    const query = {};

    if (status && status !== 'all') {
      query.status = status;
    }

    const scans = await Scan.find(query)
      .populate('domainId', 'domain')
      .populate('workspaceId', 'name')
      .sort({ createdAt: -1 });

    res.status(200).json(scans);
  } catch (error) {
    next(error);
  }
};

const cancelScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    if (scan.status !== SCAN_STATUS.QUEUED && scan.status !== SCAN_STATUS.IN_PROGRESS) {
      return res.status(400).json({ message: 'Scan is not currently active' });
    }

    scan.status = SCAN_STATUS.FAILED;
    scan.errorDetail = 'Cancelled by system administrator';
    await scan.save();

    res.status(200).json({ message: 'Scan successfully cancelled', scan });
  } catch (error) {
    next(error);
  }
};

const restartScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    const domain = await Domain.findById(scan.domainId);
    if (!domain) {
      return res.status(404).json({ message: 'Domain is no longer registered' });
    }

    const newScan = new Scan({
      workspaceId: scan.workspaceId,
      domainId: scan.domainId,
      scanType: scan.scanType,
      status: SCAN_STATUS.QUEUED,
      triggeredBy: req.user._id,
      checks: scan.checks
    });

    await newScan.save();
    await addScanJob(newScan._id, domain.domain, newScan.checks);

    res.status(200).json({ message: 'Scan successfully restarted', scan: newScan });
  } catch (error) {
    next(error);
  }
};

// 5. VULNERABILITY MANAGEMENT
const getVulnerabilities = async (req, res, next) => {
  try {
    const { severity, domain, user } = req.query;
    const query = {};

    if (severity && severity !== 'all') {
      query.severity = severity;
    }

    if (domain) {
      const domains = await Domain.find({ domain: { $regex: domain, $options: 'i' } });
      query.domainId = { $in: domains.map(d => d._id) };
    }

    if (user) {
      const users = await User.find({ email: { $regex: user, $options: 'i' } });
      const workspaces = await Workspace.find({ owner: { $in: users.map(u => u._id) } });
      query.workspaceId = { $in: workspaces.map(w => w._id) };
    }

    const vulnerabilities = await Vulnerability.find(query)
      .populate('domainId', 'domain')
      .populate('workspaceId', 'name')
      .sort({ createdAt: -1 });

    res.status(200).json(vulnerabilities);
  } catch (error) {
    next(error);
  }
};

// 6. SUBSCRIPTION PLAN MANAGEMENT
const getSubscriptionPlans = async (req, res, next) => {
  try {
    const plans = await SubscriptionPlan.find();
    res.status(200).json(plans);
  } catch (error) {
    next(error);
  }
};

const createSubscriptionPlan = async (req, res, next) => {
  try {
    const { name, price, domainLimit, scanLimit, features } = req.body;
    const plan = new SubscriptionPlan({
      name,
      price,
      domainLimit,
      scanLimit,
      features
    });

    await plan.save();

    await logAuditEvent({
      req,
      action: 'Plan Changes',
      description: `Created new subscription plan: ${name}`,
      userId: req.user._id
    });

    res.status(201).json({ message: 'Plan created successfully', plan });
  } catch (error) {
    next(error);
  }
};

const updateSubscriptionPlan = async (req, res, next) => {
  try {
    const { name, price, domainLimit, scanLimit, features } = req.body;
    const plan = await SubscriptionPlan.findByIdAndUpdate(
      req.params.id,
      { name, price, domainLimit, scanLimit, features },
      { new: true }
    );

    if (!plan) {
      return res.status(404).json({ message: 'Plan not found' });
    }

    await logAuditEvent({
      req,
      action: 'Plan Changes',
      description: `Updated subscription plan: ${plan.name}`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'Plan updated successfully', plan });
  } catch (error) {
    next(error);
  }
};

const deleteSubscriptionPlan = async (req, res, next) => {
  try {
    const plan = await SubscriptionPlan.findById(req.params.id);
    if (!plan) {
      return res.status(404).json({ message: 'Plan not found' });
    }

    await SubscriptionPlan.deleteOne({ _id: plan._id });

    await logAuditEvent({
      req,
      action: 'Plan Changes',
      description: `Deleted subscription plan: ${plan.name}`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'Plan deleted successfully' });
  } catch (error) {
    next(error);
  }
};

// 7. PAYMENTS MANAGEMENT
const getPayments = async (req, res, next) => {
  try {
    const payments = await PaymentTransaction.find()
      .populate('userId', 'email profile.name')
      .sort({ createdAt: -1 });

    // Calculate revenue summary stats
    const totalAmount = payments.reduce((acc, curr) => {
      if (curr.status === 'succeeded') return acc + curr.amount;
      if (curr.status === 'refunded') return acc - curr.amount;
      return acc;
    }, 0);

    res.status(200).json({
      payments,
      summary: {
        totalRevenue: Math.max(0, totalAmount),
        succeededCount: payments.filter(p => p.status === 'succeeded').length,
        refundedCount: payments.filter(p => p.status === 'refunded').length
      }
    });
  } catch (error) {
    next(error);
  }
};

const refundPayment = async (req, res, next) => {
  try {
    const payment = await PaymentTransaction.findById(req.params.id);
    if (!payment) {
      return res.status(404).json({ message: 'Payment transaction record not found' });
    }

    if (payment.status === 'refunded') {
      return res.status(400).json({ message: 'Payment is already refunded' });
    }

    payment.status = 'refunded';
    await payment.save();

    // Mark corresponding invoice as cancelled/refunded if exists
    if (payment.invoiceId) {
      await Invoice.findByIdAndUpdate(payment.invoiceId, { paymentStatus: 'cancelled' });
    }

    await logAuditEvent({
      req,
      action: 'Payment Refunded',
      description: `Refunded payment transaction ${payment.transactionId} of ${payment.currency} ${payment.amount}`,
      userId: req.user._id
    });

    res.status(200).json({ message: 'Payment transaction successfully refunded', payment });
  } catch (error) {
    next(error);
  }
};

// 8. SUPPORT TICKETS MANAGEMENT
const getSupportTickets = async (req, res, next) => {
  try {
    const { status } = req.query;
    const query = {};

    if (status && status !== 'all') {
      const legacyStatusMap = {
        open: 'Open',
        assigned: 'In Progress',
        closed: 'Closed'
      };
      query.status = legacyStatusMap[status] || status;
    }

    const tickets = await SupportTicket.find(query)
      .populate('assignedTo', 'email profile.name')
      .sort({ updatedAt: -1 });

    res.status(200).json(tickets);
  } catch (error) {
    next(error);
  }
};

const assignSupportTicket = async (req, res, next) => {
  try {
    const { assignedToUserId } = req.body;
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Support ticket not found' });
    }

    ticket.assignedTo = assignedToUserId || req.user._id;
    ticket.status = 'In Progress';
    await ticket.save();

    res.status(200).json({ message: 'Ticket assigned successfully', ticket });
  } catch (error) {
    next(error);
  }
};

const replySupportTicket = async (req, res, next) => {
  try {
    const { message } = req.body;

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Support ticket not found' });
    }

    ticket.adminNotes = [ticket.adminNotes, message].filter(Boolean).join('\n\n');

    if (ticket.status === 'Open') {
      ticket.status = 'In Progress';
      ticket.assignedTo = req.user._id;
    }

    await ticket.save();

    res.status(200).json({ message: 'Reply submitted successfully', ticket });
  } catch (error) {
    next(error);
  }
};

const resolveSupportTicket = async (req, res, next) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Support ticket not found' });
    }

    ticket.status = 'Resolved';
    await ticket.save();

    res.status(200).json({ message: 'Support ticket marked as resolved', ticket });
  } catch (error) {
    next(error);
  }
};

// 9. AUDIT LOGS MANAGEMENT
const getAuditLogs = async (req, res, next) => {
  try {
    const { user, action } = req.query;
    const query = {};

    if (user) {
      const users = await User.find({ email: { $regex: user, $options: 'i' } });
      query.userId = { $in: users.map(u => u._id) };
    }

    if (action && action !== 'all') {
      query.action = action;
    }

    const logs = await AuditLog.find(query)
      .populate('userId', 'email profile.name')
      .sort({ createdAt: -1 })
      .limit(100);

    res.status(200).json(logs);
  } catch (error) {
    next(error);
  }
};

// 10. SYSTEM HEALTH
const getSystemHealth = async (req, res, next) => {
  try {
    const mongoStatus = mongoose.connection.readyState === 1 ? 'Healthy' : 'Disconnected';
    
    // Check Redis Status
    const redis = getRedisClient();
    let redisStatus = 'Unavailable';
    if (redis) {
      try {
        await redis.ping();
        redisStatus = 'Healthy';
      } catch (err) {
        redisStatus = 'Error';
      }
    }

    res.status(200).json({
      apiStatus: 'Healthy',
      mongodbStatus: mongoStatus,
      redisStatus: redisStatus,
      workerStatus: 'Healthy',
      queueStatus: 'Healthy',
      timestamp: new Date()
    });
  } catch (error) {
    next(error);
  }
};

const getReports = async (req, res, next) => {
  try {
    const Report = require('../models/Report');
    const reports = await Report.find()
      .populate('workspaceId', 'name')
      .sort({ createdAt: -1 });
    res.status(200).json(reports);
  } catch (error) {
    next(error);
  }
};

const getOrganizations = async (req, res, next) => {
  try {
    const organizations = await Organization.find()
      .populate('ownerId', 'email profile')
      .sort({ createdAt: -1 });
    res.status(200).json(organizations);
  } catch (error) {
    next(error);
  }
};

const getInvitations = async (req, res, next) => {
  try {
    const invitations = await TeamInvitation.find()
      .populate('organizationId', 'name')
      .populate('invitedBy', 'email profile')
      .sort({ createdAt: -1 });
    res.status(200).json(invitations);
  } catch (error) {
    next(error);
  }
};

const getCustomerSubscriptions = async (req, res, next) => {
  try {
    const subscriptions = await Subscription.find()
      .populate('userId', 'email profile.name')
      .populate('organizationId', 'name')
      .sort({ createdAt: -1 });
    res.status(200).json(subscriptions);
  } catch (error) {
    next(error);
  }
};

const changeCustomerPlan = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { planName } = req.body;

    const plan = await SubscriptionPlan.findOne({ name: planName });
    if (!plan) {
      return res.status(404).json({ message: `Plan "${planName}" not found.` });
    }

    const subscription = await Subscription.findById(id);
    if (!subscription) {
      return res.status(404).json({ message: 'Subscription details not found.' });
    }

    subscription.currentPlan = plan.name;
    subscription.paymentStatus = plan.price > 0 ? 'paid' : 'free';
    await subscription.save();

    const organization = await Organization.findById(subscription.organizationId);
    if (organization) {
      organization.subscriptionPlan = plan.name;
      organization.maxSeats = plan.seatLimit;
      await organization.save();
    }

    const user = await User.findById(subscription.userId);
    if (user) {
      user.profile.plan = plan.name;
      await user.save();
    }

    await logAuditEvent({
      req,
      action: 'Superadmin Manual Upgrade',
      description: `Superadmin manual adjustment of org ${organization?.name} to plan ${planName}`,
      userId: req.user._id
    });

    res.status(200).json({ message: `Manually changed subscription to ${planName}.`, subscription });
  } catch (error) {
    next(error);
  }
};

const updateCustomerSubscriptionStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['active', 'suspended', 'cancelled', 'expired'].includes(status)) {
      return res.status(400).json({ message: 'Invalid subscription status.' });
    }

    const subscription = await Subscription.findById(id);
    if (!subscription) {
      return res.status(404).json({ message: 'Subscription details not found.' });
    }

    subscription.status = status;
    if (status === 'suspended') {
      subscription.suspendedAt = new Date();
      subscription.paymentStatus = 'suspended';
    } else if (status === 'active') {
      subscription.suspendedAt = null;
      subscription.paymentStatus = subscription.currentPlan === 'Starter' ? 'free' : 'paid';
    }
    await subscription.save();

    res.status(200).json({ message: `Subscription status updated to ${status}.`, subscription });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getDashboardStats,
  getUsers,
  exportUsers,
  getUserDetails,
  updateUserStatus,
  updateUserRole,
  upgradeUserSubscription,
  deleteUser,
  getDomains,
  forceScanDomain,
  getScans,
  cancelScan,
  restartScan,
  getVulnerabilities,
  getSubscriptionPlans,
  createSubscriptionPlan,
  updateSubscriptionPlan,
  deleteSubscriptionPlan,
  getPayments,
  refundPayment,
  getSupportTickets,
  assignSupportTicket,
  replySupportTicket,
  resolveSupportTicket,
  getAuditLogs,
  getSystemHealth,
  getReports,
  getOrganizations,
  getInvitations,
  getCustomerSubscriptions,
  changeCustomerPlan,
  updateCustomerSubscriptionStatus
};
