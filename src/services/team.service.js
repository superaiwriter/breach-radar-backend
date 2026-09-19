const crypto = require('crypto');
const mongoose = require('mongoose');
const Organization = require('../models/Organization');
const TeamMember = require('../models/TeamMember');
const TeamInvitation = require('../models/TeamInvitation');
const TeamActivity = require('../models/TeamActivity');
const Notification = require('../models/Notification');
const User = require('../models/User');
const logger = require('../config/logger');
const { validateEmailFormat } = require('../utils/validators');
const { logTeamAudit } = require('../utils/teamAuditLogger');
const {
  buildInvitationLink,
  getEmailStatus,
  sendInvitationEmail,
  verifySenderDomainStatus,
} = require('./email/resend.service');

const ROLES = ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER', 'AUDITOR'];
const INVITABLE_ROLES = ['ADMIN', 'ANALYST', 'VIEWER', 'AUDITOR'];

const ROLE_PERMISSIONS = [
  { feature: 'Run Scan', OWNER: true, ADMIN: true, ANALYST: true, VIEWER: false, AUDITOR: false },
  { feature: 'Create Domain', OWNER: true, ADMIN: true, ANALYST: true, VIEWER: false, AUDITOR: false },
  { feature: 'Delete Domain', OWNER: true, ADMIN: true, ANALYST: false, VIEWER: false, AUDITOR: false },
  { feature: 'Manage Team', OWNER: true, ADMIN: true, ANALYST: false, VIEWER: false, AUDITOR: false },
  { feature: 'Billing Access', OWNER: true, ADMIN: false, ANALYST: false, VIEWER: false, AUDITOR: false },
  { feature: 'View Reports', OWNER: true, ADMIN: true, ANALYST: true, VIEWER: true, AUDITOR: true },
  { feature: 'Audit Logs', OWNER: true, ADMIN: true, ANALYST: false, VIEWER: false, AUDITOR: true },
];

function normalizeRole(role) {
  return String(role || '').trim().toUpperCase();
}

function toObjectId(value, label = 'id') {
  if (!mongoose.Types.ObjectId.isValid(value)) {
    const error = new Error(`Invalid ${label} format.`);
    error.statusCode = 400;
    throw error;
  }
  return value;
}

function assertOwner(actorMember) {
  if (actorMember.role !== 'OWNER') {
    const error = new Error('Only the organization owner can perform this action.');
    error.statusCode = 403;
    throw error;
  }
}

function assertManager(actorMember) {
  if (!['OWNER', 'ADMIN'].includes(actorMember.role)) {
    const error = new Error('Owner or Admin access is required to manage the team.');
    error.statusCode = 403;
    throw error;
  }
}

function mapUser(user) {
  if (!user) return null;
  return {
    id: user._id,
    email: user.email,
    name: user.profile?.name || '',
    avatar: user.profile?.avatar || '',
    lastLogin: user.lastLogin || null,
  };
}

function mapMember(member) {
  const user = mapUser(member.userId);
  return {
    id: member._id,
    type: 'member',
    userId: user?.id || null,
    name: user?.name || '',
    email: user?.email || '',
    avatar: user?.avatar || '',
    role: member.role,
    status: member.status,
    joinedAt: member.joinedAt,
    lastLogin: member.lastLogin || user?.lastLogin || null,
  };
}

function mapInvitation(invitation) {
  return {
    id: invitation._id,
    type: 'invitation',
    userId: null,
    name: '',
    email: invitation.email,
    avatar: '',
    role: invitation.role,
    status: invitation.status,
    joinedAt: null,
    lastLogin: null,
    expiresAt: invitation.expiresAt,
    invitedBy: mapUser(invitation.invitedBy),
    createdAt: invitation.createdAt,
    acceptedAt: invitation.acceptedAt,
    inviteLink: invitation.token ? buildInvitationLink(invitation.token) : null,
  };
}

function mapOrganization(organization) {
  return {
    id: organization._id,
    name: organization.name,
    ownerId: organization.ownerId,
    subscriptionPlan: organization.subscriptionPlan,
    maxSeats: organization.maxSeats,
    logo: organization.logo || '',
    companyWebsite: organization.companyWebsite || '',
    industry: organization.industry || '',
    timezone: organization.timezone || 'UTC',
    createdAt: organization.createdAt,
    updatedAt: organization.updatedAt,
  };
}

async function logTeamActivity({ organizationId, userId, action, target = '', metadata = {} }) {
  if (!organizationId) return null;
  return TeamActivity.create({ organizationId, userId, action, target, metadata });
}

async function notify({ organizationId, userId = null, email = '', type, title, message }) {
  return Notification.create({ organizationId, userId, email, type, title, message });
}

function mapEmailFailure(error) {
  return {
    success: false,
    error: error.message,
    code: error.code || 'EMAIL_DELIVERY_FAILED',
    statusCode: error.statusCode || null,
  };
}

async function deliverInvitationEmail({ email, organization, role, token, expiresAt, resend = false }) {
  logger.info(`[team-invite] Email sending function executing for ${email}.`);

  try {
    const response = await sendInvitationEmail({
      to: email,
      organizationName: organization.name,
      role,
      token,
      expiresAt,
    });

    return {
      success: true,
      provider: 'resend',
      responseId: response?.id || null,
      resent: resend,
    };
  } catch (error) {
    logger.error(`[team-invite] Email delivery failed for ${email}: ${error.message}`);
    if (error.details) {
      logger.error(`[team-invite] Exact Resend error payload: ${JSON.stringify(error.details)}`);
    }
    return mapEmailFailure(error);
  }
}

async function ensureOrganizationForUser(user) {
  if (user.preferences?.activeOrganizationId) {
    const activeMember = await TeamMember.findOne({
      organizationId: user.preferences.activeOrganizationId,
      userId: user._id,
      status: 'ACTIVE',
    }).populate('organizationId');

    if (activeMember?.organizationId) {
      return activeMember.organizationId;
    }
  }

  let organization = await Organization.findOne({ ownerId: user._id });

  if (!organization) {
    const member = await TeamMember.findOne({ userId: user._id }).populate('organizationId');
    if (member?.organizationId) {
      return member.organizationId;
    }

    const SubscriptionPlan = require('../models/SubscriptionPlan');
    const freePlan = await SubscriptionPlan.findOne({ name: 'Free' });
    const freeSeatLimit = freePlan ? freePlan.seatLimit : 1;

    organization = await Organization.create({
      name: `${user.profile?.name || user.email}'s Organization`,
      ownerId: user._id,
      subscriptionPlan: 'Free',
      maxSeats: freeSeatLimit,
      timezone: user.preferences?.timezone || 'UTC',
    });
  }

  await TeamMember.findOneAndUpdate(
    { organizationId: organization._id, userId: user._id },
    {
      $setOnInsert: {
        role: 'OWNER',
        status: 'ACTIVE',
        invitedBy: user._id,
        joinedAt: user.createdAt || new Date(),
      },
      $set: { lastLogin: user.lastLogin || null },
    },
    { upsert: true, new: true }
  );

  if (!user.preferences?.activeOrganizationId) {
    user.preferences.activeOrganizationId = organization._id;
    await user.save();
  }

  return organization;
}

async function getContext(userId) {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error('Authenticated user not found.');
    error.statusCode = 401;
    throw error;
  }

  const organization = await ensureOrganizationForUser(user);
  const actorMember = await TeamMember.findOne({
    organizationId: organization._id,
    userId: user._id,
    status: { $ne: 'SUSPENDED' },
  });

  if (!actorMember) {
    const error = new Error('You are not an active member of this organization.');
    error.statusCode = 403;
    throw error;
  }

  return { user, organization, actorMember };
}

async function countSeats(organizationId) {
  const memberCount = await TeamMember.countDocuments({
    organizationId,
    status: { $in: ['ACTIVE', 'PENDING', 'SUSPENDED'] },
  });
  const inviteCount = await TeamInvitation.countDocuments({
    organizationId,
    status: 'PENDING',
    expiresAt: { $gt: new Date() },
  });

  return memberCount + inviteCount;
}

async function expirePendingInvitations(organizationId = null) {
  const query = {
    status: 'PENDING',
    expiresAt: { $lte: new Date() },
  };
  if (organizationId) query.organizationId = organizationId;

  const expired = await TeamInvitation.find(query);
  if (!expired.length) return 0;

  await TeamInvitation.updateMany(
    { _id: { $in: expired.map((invitation) => invitation._id) } },
    { status: 'EXPIRED' }
  );

  await Promise.all(expired.map((invitation) => Promise.all([
    logTeamActivity({
      organizationId: invitation.organizationId,
      userId: invitation.invitedBy,
      action: 'Invitation Expired',
      target: invitation.email,
    }),
    notify({
      organizationId: invitation.organizationId,
      email: invitation.email,
      type: 'INVITATION_EXPIRED',
      title: 'Invitation expired',
      message: 'A team invitation expired before it was accepted.',
    }),
  ])));

  return expired.length;
}

async function assertSeatAvailable(organization) {
  const SubscriptionPlan = require('../models/SubscriptionPlan');
  const plan = await SubscriptionPlan.findOne({ name: organization.subscriptionPlan });
  const limit = plan ? plan.seatLimit : 1;

  if (limit >= 999999) return;

  const used = await countSeats(organization._id);
  if (used >= limit) {
    const error = new Error(`Seat limit reached for ${organization.subscriptionPlan} plan.`);
    error.statusCode = 403;
    throw error;
  }
}

async function getDashboard(userId, query = {}) {
  const { organization, actorMember } = await getContext(userId);
  await expirePendingInvitations(organization._id);
  const page = Math.max(Number(query.page) || 1, 1);
  const limit = Math.min(Math.max(Number(query.limit) || 10, 1), 50);
  const search = String(query.search || '').trim().toLowerCase();
  const role = normalizeRole(query.role);

  const [membersRaw, invitationsRaw, activitiesRaw] = await Promise.all([
    TeamMember.find({ organizationId: organization._id })
      .populate('userId', 'email profile lastLogin')
      .sort({ role: 1, createdAt: -1 }),
    TeamInvitation.find({ organizationId: organization._id })
      .populate('invitedBy', 'email profile')
      .sort({ createdAt: -1 }),
    TeamActivity.find({ organizationId: organization._id })
      .populate('userId', 'email profile')
      .sort({ createdAt: -1 })
      .limit(12),
  ]);

  let rows = [...membersRaw.map(mapMember), ...invitationsRaw.map(mapInvitation)];
  if (role && ROLES.includes(role)) rows = rows.filter((row) => row.role === role);
  if (search) {
    rows = rows.filter((row) =>
      [row.name, row.email, row.role, row.status].some((value) => String(value || '').toLowerCase().includes(search))
    );
  }

  const total = rows.length;
  const pagedRows = rows.slice((page - 1) * limit, page * limit);
  const active = membersRaw.filter((member) => member.status === 'ACTIVE').length;
  const pending = membersRaw.filter((member) => member.status === 'PENDING').length + invitationsRaw.length;
  const admins = membersRaw.filter((member) => ['OWNER', 'ADMIN'].includes(member.role)).length;

  return {
    organization: mapOrganization(organization),
    currentUserRole: actorMember.role,
    roles: ROLES,
    manageableRoles: INVITABLE_ROLES,
    permissions: ROLE_PERMISSIONS,
    stats: {
      members: membersRaw.length + invitationsRaw.length,
      active,
      pending,
      admins,
      seatsUsed: await countSeats(organization._id),
      maxSeats: await (async () => {
        const SubscriptionPlan = require('../models/SubscriptionPlan');
        const plan = await SubscriptionPlan.findOne({ name: organization.subscriptionPlan });
        const limit = plan ? plan.seatLimit : organization.maxSeats;
        return limit >= 999999 ? 'Unlimited' : limit;
      })(),
    },
    members: pagedRows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.max(Math.ceil(total / limit), 1),
    },
    activities: activitiesRaw.map((activity) => ({
      id: activity._id,
      user: activity.userId
        ? {
            name: activity.userId.profile?.name || activity.userId.email,
            email: activity.userId.email,
            avatar: activity.userId.profile?.avatar || '',
          }
        : null,
      action: activity.action,
      target: activity.target,
      timestamp: activity.createdAt,
    })),
  };
}

async function inviteMember(userId, payload) {
  logger.info(`[team-invite] Invitation request received from user ${userId}.`);
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);
  await expirePendingInvitations(organization._id);
  await assertSeatAvailable(organization);

  const email = String(payload.email || '').trim().toLowerCase();
  const role = normalizeRole(payload.role);

  if (!email || !validateEmailFormat(email)) {
    const error = new Error('Enter a valid email address.');
    error.statusCode = 400;
    throw error;
  }

  if (!INVITABLE_ROLES.includes(role)) {
    const error = new Error('Select a valid team role.');
    error.statusCode = 400;
    throw error;
  }

  if (role === 'ADMIN' && actorMember.role !== 'OWNER') {
    const error = new Error('Only the owner can invite Admin members.');
    error.statusCode = 403;
    throw error;
  }

  const existingUser = await User.findOne({ email }).select('_id email');
  if (existingUser) {
    const existingMember = await TeamMember.findOne({
      organizationId: organization._id,
      userId: existingUser._id,
      status: { $in: ['ACTIVE', 'SUSPENDED', 'PENDING'] },
    });

    if (existingMember) {
      const error = new Error('This user is already a member of the organization.');
      error.statusCode = 409;
      throw error;
    }
  }

  const duplicateInvite = await TeamInvitation.findOne({
    organizationId: organization._id,
    email,
    status: 'PENDING',
    expiresAt: { $gt: new Date() },
  });

  if (duplicateInvite) {
    const error = new Error('An active invitation already exists for this email.');
    error.statusCode = 409;
    throw error;
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const invitation = await TeamInvitation.create({
    organizationId: organization._id,
    email,
    role,
    token,
    expiresAt,
    invitedBy: userId,
  });
  logger.info(`[team-invite] Invitation saved: ${invitation._id} for ${email}.`);

  const emailDelivery = await deliverInvitationEmail({
    email,
    organization,
    role,
    token,
    expiresAt,
  });

  await Promise.all([
    logTeamActivity({ organizationId: organization._id, userId, action: 'Invitation Sent', target: email, metadata: { role } }),
    logTeamAudit({
      userId,
      action: 'Invitation Sent',
      description: `Invitation sent to ${email} for ${organization.name} as ${role}.`,
    }),
    notify({
      organizationId: organization._id,
      email,
      type: 'INVITATION_SENT',
      title: 'Invitation sent',
      message: `You were invited to join ${organization.name} as ${role}.`,
    }),
  ]);

  const billingService = require('./billing.service');
  billingService.checkUsageAlerts(organization._id, userId).catch(err => logger.error(`[alert-check-err] ${err.message}`));

  const message = emailDelivery.success
    ? `Invitation sent to ${email}.`
    : 'Invitation created but email delivery failed.';

  return {
    message,
    invitation: mapInvitation(invitation),
    emailDelivery,
  };
}

async function getInvitationByToken(token) {
  const invitation = await TeamInvitation.findOne({ token })
    .populate('organizationId', 'name logo companyWebsite industry timezone')
    .populate('invitedBy', 'email profile');

  if (!invitation) {
    const error = new Error('Invitation link is invalid.');
    error.statusCode = 404;
    throw error;
  }

  if (invitation.status === 'PENDING' && invitation.expiresAt <= new Date()) {
    invitation.status = 'EXPIRED';
    await invitation.save();
    await Promise.all([
      logTeamActivity({
        organizationId: invitation.organizationId._id,
        userId: invitation.invitedBy?._id,
        action: 'Invitation Expired',
        target: invitation.email,
      }),
      logTeamAudit({
        userId: invitation.invitedBy?._id,
        action: 'Invitation Expired',
        description: `Invitation for ${invitation.email} expired.`,
      }),
    ]);
  }

  if (invitation.status !== 'PENDING') {
    const error = new Error(`Invitation is ${invitation.status.toLowerCase()}.`);
    error.statusCode = invitation.status === 'EXPIRED' ? 410 : 409;
    error.code = invitation.status;
    throw error;
  }

  return {
    organization: mapOrganization(invitation.organizationId),
    role: invitation.role,
    email: invitation.email,
    expiresAt: invitation.expiresAt,
    invitedBy: mapUser(invitation.invitedBy),
  };
}

async function acceptInvitation(userId, token, req = null) {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error('Authenticated user not found.');
    error.statusCode = 401;
    throw error;
  }

  const invitation = await TeamInvitation.findOne({ token }).populate('organizationId');
  if (!invitation) {
    const error = new Error('Invitation link is invalid.');
    error.statusCode = 404;
    throw error;
  }

  if (invitation.status === 'PENDING' && invitation.expiresAt <= new Date()) {
    invitation.status = 'EXPIRED';
    await invitation.save();
  }

  if (invitation.status !== 'PENDING') {
    const error = new Error(`Invitation is ${invitation.status.toLowerCase()}.`);
    error.statusCode = invitation.status === 'EXPIRED' ? 410 : 409;
    throw error;
  }

  if (String(user.email).toLowerCase() !== invitation.email) {
    const error = new Error(`This invitation was sent to ${invitation.email}. Sign in with that email to accept it.`);
    error.statusCode = 403;
    throw error;
  }

  const existingMember = await TeamMember.findOne({
    organizationId: invitation.organizationId._id,
    userId: user._id,
  });

  if (existingMember && existingMember.status === 'SUSPENDED') {
    const error = new Error('Your membership for this organization is suspended.');
    error.statusCode = 403;
    throw error;
  }

  const member = await TeamMember.findOneAndUpdate(
    { organizationId: invitation.organizationId._id, userId: user._id },
    {
      role: invitation.role,
      status: 'ACTIVE',
      invitedBy: invitation.invitedBy,
      joinedAt: existingMember?.joinedAt || new Date(),
      lastLogin: user.lastLogin || new Date(),
    },
    { upsert: true, new: true }
  ).populate('userId', 'email profile lastLogin');

  invitation.status = 'ACCEPTED';
  invitation.acceptedAt = new Date();
  await invitation.save();

  user.preferences.activeOrganizationId = invitation.organizationId._id;
  await user.save();

  const billingService = require('./billing.service');
  billingService.checkUsageAlerts(invitation.organizationId._id, user._id).catch(err => logger.error(`[alert-check-err] ${err.message}`));

  await Promise.all([
    logTeamActivity({
      organizationId: invitation.organizationId._id,
      userId: user._id,
      action: 'Invitation Accepted',
      target: invitation.email,
      metadata: { role: invitation.role },
    }),
    logTeamActivity({
      organizationId: invitation.organizationId._id,
      userId: user._id,
      action: 'Member Joined Team',
      target: invitation.email,
      metadata: { role: invitation.role },
    }),
    logTeamAudit({
      req,
      userId: user._id,
      action: 'Invitation Accepted',
      description: `${user.email} accepted invitation to ${invitation.organizationId.name}.`,
    }),
    notify({
      organizationId: invitation.organizationId._id,
      userId: user._id,
      type: 'INVITATION_ACCEPTED',
      title: 'Invitation accepted',
      message: `You joined ${invitation.organizationId.name} as ${invitation.role}.`,
    }),
    notify({
      organizationId: invitation.organizationId._id,
      userId: user._id,
      type: 'MEMBER_JOINED',
      title: 'Member joined',
      message: `${user.email} joined ${invitation.organizationId.name}.`,
    }),
    notify({
      organizationId: invitation.organizationId._id,
      userId: user._id,
      type: 'ROLE_ASSIGNED',
      title: 'Role assigned',
      message: `Your role in ${invitation.organizationId.name} is ${invitation.role}.`,
    }),
  ]);

  return {
    message: 'Invitation accepted. Welcome to the team.',
    organization: mapOrganization(invitation.organizationId),
    member: mapMember(member),
  };
}

async function getInvitations(userId, query = {}) {
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);
  await expirePendingInvitations(organization._id);

  const status = String(query.status || '').trim().toUpperCase();
  const filter = { organizationId: organization._id };
  if (['PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED'].includes(status)) filter.status = status;

  const invitations = await TeamInvitation.find(filter)
    .populate('invitedBy', 'email profile')
    .sort({ createdAt: -1 });

  return { invitations: invitations.map(mapInvitation) };
}

async function resendInvitation(userId, invitationId) {
  toObjectId(invitationId, 'invitation ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);
  await expirePendingInvitations(organization._id);

  const invitation = await TeamInvitation.findOne({ _id: invitationId, organizationId: organization._id });
  if (!invitation) {
    const error = new Error('Invitation not found.');
    error.statusCode = 404;
    throw error;
  }
  if (invitation.status !== 'PENDING') {
    const error = new Error('Only pending invitations can be resent.');
    error.statusCode = 409;
    throw error;
  }

  invitation.token = crypto.randomBytes(32).toString('hex');
  invitation.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await invitation.save();
  logger.info(`[team-invite] Resend invitation saved with fresh token: ${invitation._id} for ${invitation.email}.`);

  const emailDelivery = await deliverInvitationEmail({
    email: invitation.email,
    organization,
    role: invitation.role,
    token: invitation.token,
    expiresAt: invitation.expiresAt,
    resend: true,
  });

  await Promise.all([
    logTeamActivity({ organizationId: organization._id, userId, action: 'Invitation Sent', target: invitation.email, metadata: { resent: true } }),
    logTeamAudit({ userId, action: 'Invitation Sent', description: `Invitation resent to ${invitation.email}.` }),
    notify({
      organizationId: organization._id,
      email: invitation.email,
      type: 'INVITATION_SENT',
      title: 'Invitation resent',
      message: `A fresh invitation was sent to ${invitation.email}.`,
    }),
  ]);

  const message = emailDelivery.success
    ? `Invitation resent to ${invitation.email}.`
    : 'Invitation created but email delivery failed.';

  return { message, invitation: mapInvitation(invitation), emailDelivery };
}

async function getEmailDebugStatus() {
  let senderDomain = null;
  try {
    senderDomain = await verifySenderDomainStatus();
  } catch (error) {
    logger.error(`[team-invite-email] Sender domain verification failed: ${error.message}`);
    senderDomain = {
      senderEmail: getEmailStatus().senderEmail,
      verified: false,
      reason: error.message,
    };
  }

  return {
    ...getEmailStatus(),
    senderDomain,
  };
}

async function revokeInvitation(userId, invitationId) {
  toObjectId(invitationId, 'invitation ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);

  const invitation = await TeamInvitation.findOne({ _id: invitationId, organizationId: organization._id });
  if (!invitation) {
    const error = new Error('Invitation not found.');
    error.statusCode = 404;
    throw error;
  }
  if (invitation.status !== 'PENDING') {
    const error = new Error('Only pending invitations can be revoked.');
    error.statusCode = 409;
    throw error;
  }

  invitation.status = 'REVOKED';
  await invitation.save();

  await Promise.all([
    logTeamActivity({ organizationId: organization._id, userId, action: 'Invitation Revoked', target: invitation.email }),
    logTeamAudit({ userId, action: 'Invitation Revoked', description: `Invitation revoked for ${invitation.email}.` }),
    notify({
      organizationId: organization._id,
      email: invitation.email,
      type: 'INVITATION_REVOKED',
      title: 'Invitation revoked',
      message: `Invitation for ${invitation.email} was revoked.`,
    }),
  ]);

  return { message: 'Invitation revoked.', invitation: mapInvitation(invitation) };
}

async function deleteInvitation(userId, invitationId) {
  toObjectId(invitationId, 'invitation ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);

  const invitation = await TeamInvitation.findOne({ _id: invitationId, organizationId: organization._id });
  if (!invitation) {
    const error = new Error('Invitation not found.');
    error.statusCode = 404;
    throw error;
  }

  await invitation.deleteOne();
  await logTeamActivity({ organizationId: organization._id, userId, action: 'Invitation Deleted', target: invitation.email });
  return { message: 'Invitation deleted.' };
}

async function updateMemberRole(userId, memberId, nextRoleValue) {
  toObjectId(memberId, 'member ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);

  const nextRole = normalizeRole(nextRoleValue);
  if (!ROLES.includes(nextRole)) {
    const error = new Error('Select a valid team role.');
    error.statusCode = 400;
    throw error;
  }

  const member = await TeamMember.findOne({ _id: memberId, organizationId: organization._id }).populate('userId', 'email profile');
  if (!member) {
    const error = new Error('Team member not found.');
    error.statusCode = 404;
    throw error;
  }

  if (member.role === 'OWNER' && actorMember.role !== 'OWNER') {
    const error = new Error('Admins cannot modify the Owner.');
    error.statusCode = 403;
    throw error;
  }

  const ownerOnlyChange = nextRole === 'OWNER' || nextRole === 'ADMIN' || member.role === 'ADMIN';
  if (ownerOnlyChange) assertOwner(actorMember);

  if (nextRole === 'OWNER') {
    await TeamMember.updateOne({ _id: actorMember._id }, { role: 'ADMIN' });
    organization.ownerId = member.userId._id;
    await organization.save();
  }

  member.role = nextRole;
  await member.save();

  await Promise.all([
    logTeamActivity({
      organizationId: organization._id,
      userId,
      action: 'Role change',
      target: member.userId?.email || String(member._id),
      metadata: { role: nextRole },
    }),
    notify({
      organizationId: organization._id,
      userId: member.userId?._id,
      type: 'ROLE_CHANGED',
      title: 'Your team role changed',
      message: `Your role in ${organization.name} is now ${nextRole}.`,
    }),
  ]);

  return { message: 'Team member role updated.', member: mapMember(member) };
}

async function setMemberStatus(userId, memberId, statusValue) {
  toObjectId(memberId, 'member ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);

  const status = String(statusValue || '').trim().toUpperCase();
  if (!['ACTIVE', 'SUSPENDED'].includes(status)) {
    const error = new Error('Status must be ACTIVE or SUSPENDED.');
    error.statusCode = 400;
    throw error;
  }

  const member = await TeamMember.findOne({ _id: memberId, organizationId: organization._id }).populate('userId', 'email profile');
  if (!member) {
    const error = new Error('Team member not found.');
    error.statusCode = 404;
    throw error;
  }

  if (member.role === 'OWNER') {
    const error = new Error('The Owner cannot be suspended.');
    error.statusCode = 403;
    throw error;
  }
  if (member.role === 'ADMIN') assertOwner(actorMember);

  member.status = status;
  await member.save();

  await Promise.all([
    logTeamActivity({
      organizationId: organization._id,
      userId,
      action: status === 'ACTIVE' ? 'Member activated' : 'Member suspended',
      target: member.userId?.email || String(member._id),
    }),
    notify({
      organizationId: organization._id,
      userId: member.userId?._id,
      type: status === 'ACTIVE' ? 'TEAM_MEMBER_ACTIVATED' : 'TEAM_MEMBER_SUSPENDED',
      title: status === 'ACTIVE' ? 'Team access activated' : 'Team access suspended',
      message: `Your access in ${organization.name} is now ${status}.`,
    }),
  ]);

  return { message: `Team member ${status.toLowerCase()}.`, member: mapMember(member) };
}

async function removeMember(userId, memberId) {
  toObjectId(memberId, 'member ID');
  const { organization, actorMember } = await getContext(userId);
  assertManager(actorMember);

  const member = await TeamMember.findOne({ _id: memberId, organizationId: organization._id }).populate('userId', 'email profile');
  if (!member) {
    const error = new Error('Team member not found.');
    error.statusCode = 404;
    throw error;
  }

  if (member.role === 'OWNER') {
    const error = new Error('Transfer ownership before removing the Owner.');
    error.statusCode = 403;
    throw error;
  }
  if (member.role === 'ADMIN') assertOwner(actorMember);

  await member.deleteOne();
  await Promise.all([
    logTeamActivity({
      organizationId: organization._id,
      userId,
      action: 'Member removed',
      target: member.userId?.email || String(member._id),
    }),
    notify({
      organizationId: organization._id,
      userId: member.userId?._id,
      type: 'TEAM_MEMBER_REMOVED',
      title: 'Removed from team',
      message: `You were removed from ${organization.name}.`,
    }),
  ]);

  return { message: 'Team member removed.' };
}

async function updateOrganization(userId, payload) {
  const { organization, actorMember } = await getContext(userId);
  assertOwner(actorMember);

  const name = String(payload.name || '').trim();
  if (!name) {
    const error = new Error('Organization name is required.');
    error.statusCode = 400;
    throw error;
  }

  organization.name = name;
  organization.logo = String(payload.logo || '').trim();
  organization.companyWebsite = String(payload.companyWebsite || '').trim();
  organization.industry = String(payload.industry || '').trim();
  organization.timezone = String(payload.timezone || 'UTC').trim() || 'UTC';
  await organization.save();

  await logTeamActivity({
    organizationId: organization._id,
    userId,
    action: 'Organization settings updated',
    target: organization.name,
  });

  return { message: 'Organization settings saved.', organization: mapOrganization(organization) };
}

async function recordLogin(user) {
  const organization = await ensureOrganizationForUser(user);
  await TeamMember.updateOne(
    { organizationId: organization._id, userId: user._id },
    { lastLogin: user.lastLogin || new Date(), status: 'ACTIVE' }
  );
  await logTeamActivity({ organizationId: organization._id, userId: user._id, action: 'User login', target: user.email });
}

async function recordWorkspaceActivity({ userId, action, target = '', metadata = {} }) {
  const user = await User.findById(userId);
  if (!user) return;
  const organization = await ensureOrganizationForUser(user);
  await logTeamActivity({ organizationId: organization._id, userId, action, target, metadata });
}

module.exports = {
  ROLES,
  ROLE_PERMISSIONS,
  ensureOrganizationForUser,
  getContext,
  getDashboard,
  inviteMember,
  getInvitationByToken,
  acceptInvitation,
  getInvitations,
  resendInvitation,
  getEmailDebugStatus,
  revokeInvitation,
  deleteInvitation,
  updateMemberRole,
  setMemberStatus,
  removeMember,
  updateOrganization,
  recordLogin,
  recordWorkspaceActivity,
};
