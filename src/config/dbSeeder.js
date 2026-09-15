const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('../models/User');
const Workspace = require('../models/Workspace');
const SubscriptionPlan = require('../models/SubscriptionPlan');
const Subscription = require('../models/Subscription');
const Invoice = require('../models/Invoice');
const PaymentTransaction = require('../models/PaymentTransaction');
const Organization = require('../models/Organization');
const TeamMember = require('../models/TeamMember');
const SupportTicket = require('../models/SupportTicket');
const AuditLog = require('../models/AuditLog');
const logger = require('./logger');

const dbSeeder = async () => {
  try {
    logger.info('Running database seeder...');

    // 1. Seed/Update Subscription Plans
    logger.info('Seeding default subscription plans...');
    const planDefinitions = [
      {
        name: 'Free',
        displayName: 'Free',
        description: 'Perfect for individuals getting started',
        price: 0,
        currency: 'INR',
        billingInterval: 'month',
        seatLimit: 1,
        domainLimit: 1,
        scanLimit: 2,
        sortOrder: 1,
        isActive: true,
        isPopular: false,
        ctaText: 'Get Started Free',
        features: ['1 User Seat', '1 Verified Domain', '2 Scans / month', 'Basic Reports', 'Community Support']
      },
      {
        name: 'Starter',
        displayName: 'Starter',
        description: 'Perfect for small websites & startups',
        price: 999,
        currency: 'INR',
        billingInterval: 'month',
        seatLimit: 3,
        domainLimit: 5,
        scanLimit: 30,
        sortOrder: 2,
        isActive: true,
        isPopular: false,
        ctaText: 'Get Started',
        features: ['3 User Seats', '5 Verified Domains', '30 Scans / month', 'Email Alerts', 'Standard Support', 'Basic API Access']
      },
      {
        name: 'Professional',
        displayName: 'Professional',
        description: 'Great for growing businesses',
        price: 2999,
        currency: 'INR',
        billingInterval: 'month',
        seatLimit: 10,
        domainLimit: 25,
        scanLimit: 200,
        sortOrder: 3,
        isActive: true,
        isPopular: true,
        ctaText: 'Get Started',
        features: ['10 User Seats', '25 Verified Domains', '200 Scans / month', 'Continuous Monitoring', 'Full API Access', 'Priority Support', 'Compliance Reports']
      },
      {
        name: 'Enterprise',
        displayName: 'Enterprise',
        description: 'For large organizations',
        price: 9999,
        currency: 'INR',
        billingInterval: 'month',
        seatLimit: 999999,
        domainLimit: 999999,
        scanLimit: 999999,
        sortOrder: 4,
        isActive: true,
        isPopular: false,
        ctaText: 'Get Started',
        features: ['Unlimited User Seats', 'Unlimited Domains', 'Unlimited Scans', 'Custom Scanning Agents', 'SAML SSO Integration', 'Dedicated TAM', 'Custom Integrations']
      }
    ];

    for (const planDef of planDefinitions) {
      await SubscriptionPlan.findOneAndUpdate(
        { name: planDef.name },
        { $setOnInsert: planDef },
        { upsert: true, new: true }
      );
    }
    logger.info('Subscription plans seeded (preserving custom edits).');

    if (process.env.NODE_ENV === 'production') {
      logger.info('Production mode detected. Skipping seeding of mock admin, user accounts, tickets, transactions, and test domains.');
      logger.info('Database seeder finished checking/seeding.');
      return;
    }

    // 2. Seed Super Admin User
    const superAdminEmail = 'superadmin@pentestradar.com';
    let superAdmin = await User.findOne({ $or: [{ email: superAdminEmail }, { email: 'superadmin@breachradar.com' }] });
    if (!superAdmin) {
      logger.info(`Creating default Super Admin user (${superAdminEmail})...`);
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash('Password123!', salt);

      superAdmin = new User({
        email: superAdminEmail,
        passwordHash,
        role: 'super_admin',
        status: 'active',
        profile: {
          name: 'PentestRadar Super Admin',
          avatar: '',
          phoneNumber: '+15550199'
        }
      });

      await superAdmin.save();

      // Create workspace for Super Admin
      const workspace = new Workspace({
        name: "Super Admin's Workspace",
        owner: superAdmin._id,
        members: []
      });
      await workspace.save();

      superAdmin.preferences.activeWorkspaceId = workspace._id;
      await superAdmin.save();

      logger.info(`Super Admin user created successfully. User: ${superAdminEmail} / Password123!`);
    }

    // 3. Seed Normal Test User & their Subscription Architecture
    const testUserEmail = 'user@pentestradar.com';
    let testUser = await User.findOne({ $or: [{ email: testUserEmail }, { email: 'user@breachradar.com' }] });
    if (!testUser) {
      logger.info(`Creating default test user (${testUserEmail})...`);
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash('Password123!', salt);

      testUser = new User({
        email: testUserEmail,
        passwordHash,
        role: 'user',
        status: 'active',
        profile: {
          name: 'Rahul Sharma',
          avatar: '',
          phoneNumber: '+919876543210'
        }
      });
      await testUser.save();
    }

    // Ensure Organization exists for testUser
    let testOrg = await Organization.findOne({ ownerId: testUser._id });
    if (!testOrg) {
      logger.info(`Creating default organization for test user...`);
      testOrg = await Organization.create({
        name: 'Sharma Tech Solutions',
        ownerId: testUser._id,
        subscriptionPlan: 'Professional',
        maxSeats: 5
      });
    }

    // Ensure Workspace exists for testUser
    let testWorkspace = await Workspace.findOne({ owner: testUser._id });
    if (!testWorkspace) {
      logger.info(`Creating default workspace for test user...`);
      testWorkspace = await Workspace.create({
        name: 'Sharma Tech Primary Workspace',
        owner: testUser._id,
        members: []
      });
    }

    // Link user preferences
    let userUpdated = false;
    if (!testUser.preferences?.activeOrganizationId) {
      testUser.preferences.activeOrganizationId = testOrg._id;
      userUpdated = true;
    }
    if (!testUser.preferences?.activeWorkspaceId) {
      testUser.preferences.activeWorkspaceId = testWorkspace._id;
      userUpdated = true;
    }
    if (userUpdated) {
      await testUser.save();
    }

    // Ensure Owner TeamMember exists
    let testMember = await TeamMember.findOne({ organizationId: testOrg._id, userId: testUser._id });
    if (!testMember) {
      testMember = await TeamMember.create({
        organizationId: testOrg._id,
        userId: testUser._id,
        role: 'OWNER',
        status: 'ACTIVE',
        joinedAt: new Date()
      });
    }

    // Ensure Active Subscription document exists for Organization
    let testSub = await Subscription.findOne({ organizationId: testOrg._id });
    if (!testSub) {
      logger.info(`Creating default active Professional subscription...`);
      testSub = await Subscription.create({
        userId: testUser._id,
        organizationId: testOrg._id,
        currentPlan: 'Professional',
        billingCycle: 'monthly',
        startDate: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // Started 15 days ago
        nextBillingDate: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000), // Renews in 15 days
        paymentStatus: 'paid',
        status: 'active',
        autoRenew: true,
        transactionId: 'txn_init_seeded_99a8b7'
      });
    }

    // 4. Seed Support Tickets if empty
    const ticketsCount = await SupportTicket.countDocuments();
    if (ticketsCount === 0) {
      logger.info('Seeding mock support tickets...');
      await SupportTicket.insertMany([
        {
          userId: testUser._id,
          title: 'Scan stuck in Queued status',
          description: 'My scan has been showing "Queued" for over 4 hours. Can you check if the scanner is active?',
          status: 'open',
          priority: 'high',
          messages: [
            {
              senderId: testUser._id,
              senderName: testUser.profile.name,
              message: 'Hello support, my scan is currently stuck. Help please.'
            }
          ]
        },
        {
          userId: testUser._id,
          title: 'SSO request for Enterprise plan',
          description: 'We are looking to upgrade to the Enterprise plan and want to configure SAML SSO. Do you support Okta integration?',
          status: 'assigned',
          priority: 'medium',
          assignedTo: superAdmin._id,
          messages: [
            {
              senderId: testUser._id,
              senderName: testUser.profile.name,
              message: 'Looking for details regarding Okta integration.'
            },
            {
              senderId: superAdmin._id,
              senderName: superAdmin.profile.name,
              message: 'Hello! Yes, we do support Okta and Azure AD integration on the Enterprise plan. Let me know your details.'
            }
          ]
        },
        {
          userId: testUser._id,
          title: 'Billing Query: Duplicate Charge',
          description: 'I was billed twice for the Professional plan upgrade this month. Please refund the duplicate transaction.',
          status: 'closed',
          priority: 'critical',
          messages: [
            {
              senderId: testUser._id,
              senderName: testUser.profile.name,
              message: 'Please resolve this duplicate billing charge.'
            },
            {
              senderId: superAdmin._id,
              senderName: superAdmin.profile.name,
              message: 'Apologies for the inconvenience. The duplicate charge has been refunded successfully.'
            }
          ]
        }
      ]);
    }

    // 5. Seed Payment Transactions and Invoices if empty
    const txnCount = await PaymentTransaction.countDocuments();
    if (txnCount === 0) {
      logger.info('Seeding mock payment transactions and invoices...');

      const txns = [
        {
          userId: testUser._id,
          organizationId: testOrg._id,
          subscriptionId: testSub._id,
          provider: 'razorpay',
          providerOrderId: 'order_12345_seeded',
          providerPaymentId: 'pay_12345_seeded',
          transactionId: 'txn_init_seeded_99a8b7',
          amount: 1,
          currency: 'INR',
          status: 'succeeded',
          createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000)
        },
        {
          userId: testUser._id,
          organizationId: testOrg._id,
          subscriptionId: testSub._id,
          provider: 'razorpay',
          providerOrderId: 'order_12346_seeded',
          providerPaymentId: 'pay_12346_seeded',
          transactionId: 'txn_dup_seeded_11b2c3',
          amount: 1,
          currency: 'INR',
          status: 'refunded',
          createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000)
        }
      ];

      const createdTxns = await PaymentTransaction.insertMany(txns);

      await Invoice.insertMany([
        {
          invoiceNumber: 'INV-20260601-A1B2',
          userId: testUser._id,
          organizationId: testOrg._id,
          subscriptionId: testSub._id,
          planName: 'Professional',
          amount: 1,
          tax: 0,
          currency: 'INR',
          paymentStatus: 'paid',
          transactionId: createdTxns[0].transactionId,
          generatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000)
        },
        {
          invoiceNumber: 'INV-20260601-C3D4',
          userId: testUser._id,
          organizationId: testOrg._id,
          subscriptionId: testSub._id,
          planName: 'Professional',
          amount: 1,
          tax: 0,
          currency: 'INR',
          paymentStatus: 'cancelled',
          transactionId: createdTxns[1].transactionId,
          generatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000)
        }
      ]);
    }

    // 6. Seed initial Audit Logs if empty
    const auditLogsCount = await AuditLog.countDocuments();
    if (auditLogsCount === 0) {
      logger.info('Seeding initial audit logs...');
      await AuditLog.insertMany([
        {
          userId: superAdmin._id,
          action: 'Login',
          description: 'Super Admin logged in successfully.',
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          status: 'Success'
        },
        {
          userId: superAdmin._id,
          action: 'Role Changes',
          description: 'Created superadmin role config.',
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          status: 'Success'
        }
      ]);
    }

    // 7. Seed Domain and AuthProfiles for BOLA local test
    const bolaDomainName = 'localhost:5000';
    const Domain = require('../models/Domain');
    const AuthProfile = require('../models/AuthProfile');
    const { encryptSecret } = require('../utils/authProfileCrypto');

    let bolaDomain = await Domain.findOne({ workspaceId: testWorkspace._id, domain: bolaDomainName });
    if (!bolaDomain) {
      bolaDomain = await Domain.create({
        workspaceId: testWorkspace._id,
        domain: bolaDomainName,
        status: 'Active',
        statusDetail: 'Configured for BOLA local scanning',
        verificationStatus: 'verified',
        verifiedAt: new Date()
      });
      logger.info('Seeded local domain localhost:5000');
    }

    // Seed Profile for User A
    const profileA = await AuthProfile.findOne({ workspaceId: testWorkspace._id, domainId: bolaDomain._id, username: 'usera@securescan.local' });
    if (!profileA) {
      await AuthProfile.create({
        workspaceId: testWorkspace._id,
        domainId: bolaDomain._id,
        label: 'BOLA User A Profile',
        authType: 'credentials',
        username: 'usera@securescan.local',
        passwordEncrypted: encryptSecret('Password123!'),
        loginUrl: '/api/v1/test-bola/login-page',
        createdBy: testUser._id,
        oneTimeUse: false
      });
      logger.info('Seeded BOLA User A AuthProfile');
    }

    // Seed Profile for User B
    const profileB = await AuthProfile.findOne({ workspaceId: testWorkspace._id, domainId: bolaDomain._id, username: 'userb@securescan.local' });
    if (!profileB) {
      await AuthProfile.create({
        workspaceId: testWorkspace._id,
        domainId: bolaDomain._id,
        label: 'BOLA User B Profile',
        authType: 'credentials',
        username: 'userb@securescan.local',
        passwordEncrypted: encryptSecret('Password123!'),
        loginUrl: '/api/v1/test-bola/login-page',
        createdBy: testUser._id,
        oneTimeUse: false
      });
      logger.info('Seeded BOLA User B AuthProfile');
    }

    // Seed Profile for Admin (BFLA testing)
    const profileAdmin = await AuthProfile.findOne({ workspaceId: testWorkspace._id, domainId: bolaDomain._id, username: 'admin@securescan.local' });
    if (!profileAdmin) {
      await AuthProfile.create({
        workspaceId: testWorkspace._id,
        domainId: bolaDomain._id,
        label: 'BFLA Admin Profile',
        authType: 'credentials',
        username: 'admin@securescan.local',
        passwordEncrypted: encryptSecret('Password123!'),
        loginUrl: '/api/v1/test-bfla/login-page',
        createdBy: testUser._id,
        oneTimeUse: false
      });
      logger.info('Seeded BFLA Admin AuthProfile');
    }

    logger.info('Database seeder finished checking/seeding.');
  } catch (error) {
    logger.error(`Database seeder error: ${error.message}`);
  }
};

module.exports = dbSeeder;