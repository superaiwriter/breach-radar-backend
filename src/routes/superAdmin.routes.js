const express = require('express');
const router = express.Router();
const superAdminController = require('../controllers/superAdmin.controller');
const authenticateJWT = require('../middleware/auth');
const requireSuperAdmin = require('../middleware/requireSuperAdmin');

// Apply JWT verification and check global role: must be super_admin
router.use(authenticateJWT);
router.use(requireSuperAdmin);

// Dashboard stats and charts
router.get('/dashboard', superAdminController.getDashboardStats);

// Users Management
router.get('/users', superAdminController.getUsers);
router.get('/users/export', superAdminController.exportUsers);
router.get('/users/:id', superAdminController.getUserDetails);
router.put('/users/:id/status', superAdminController.updateUserStatus);
router.put('/users/:id/role', superAdminController.updateUserRole);
router.put('/users/:id/subscription', superAdminController.upgradeUserSubscription);
router.delete('/users/:id', superAdminController.deleteUser);

// Organization and invitation visibility
router.get('/organizations', superAdminController.getOrganizations);
router.get('/invitations', superAdminController.getInvitations);

// Domains Management
router.get('/domains', superAdminController.getDomains);
router.post('/domains/force-scan', superAdminController.forceScanDomain);

// Scans Management
router.get('/scans', superAdminController.getScans);
router.post('/scans/:id/cancel', superAdminController.cancelScan);
router.post('/scans/:id/restart', superAdminController.restartScan);

// Vulnerability Management
router.get('/vulnerabilities', superAdminController.getVulnerabilities);

// Reports audit
router.get('/reports', superAdminController.getReports);

// Subscriptions Management (Tiers)
router.get('/subscriptions', superAdminController.getSubscriptionPlans);
router.post('/subscriptions', superAdminController.createSubscriptionPlan);
router.put('/subscriptions/:id', superAdminController.updateSubscriptionPlan);
router.delete('/subscriptions/:id', superAdminController.deleteSubscriptionPlan);

// Customer Subscriptions Visibility & Operations
router.get('/subscriptions/customers', superAdminController.getCustomerSubscriptions);
router.put('/subscriptions/customers/:id/plan', superAdminController.changeCustomerPlan);
router.put('/subscriptions/customers/:id/status', superAdminController.updateCustomerSubscriptionStatus);

// Payments Management
router.get('/payments', superAdminController.getPayments);
router.post('/payments/:id/refund', superAdminController.refundPayment);

// Support Desk Tickets
router.get('/tickets', superAdminController.getSupportTickets);
router.post('/tickets/:id/assign', superAdminController.assignSupportTicket);
router.post('/tickets/:id/reply', superAdminController.replySupportTicket);
router.post('/tickets/:id/resolve', superAdminController.resolveSupportTicket);

// Compliance Audit Logs
router.get('/audit-logs', superAdminController.getAuditLogs);

// System Health Overview
router.get('/system-health', superAdminController.getSystemHealth);

module.exports = router;
