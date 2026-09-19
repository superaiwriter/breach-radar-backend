const mongoose = require('mongoose');
const { USER_ROLES } = require('../constants');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: Object.values(USER_ROLES),
    default: USER_ROLES.USER
  },
  accountType: {
    type: String,
    enum: ['individual', 'cyber_security_expert', 'organization'],
    default: 'individual'
  },
  status: {
    type: String,
    enum: ['active', 'suspended', 'pending_verification'],
    default: 'active'
  },
  profile: {
    name: { type: String, required: true },
    avatar: { type: String, default: '' },
    phoneNumber: { type: String, default: '' },
    organization: { type: String, default: '' },
    jobTitle: { type: String, default: '' },
    country: { type: String, default: '' },
    plan: { type: String, default: 'Free' }
  },
  preferences: {
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'UTC' },
    dateFormat: { type: String, default: 'YYYY-MM-DD' },
    activeWorkspaceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Workspace' },
    activeOrganizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', default: null }
  },
  security: {
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String, default: '' },
    lastPasswordChange: { type: Date, default: Date.now },
    sessionTimeoutMinutes: { type: Number, default: 60 },
    trustedIps: [{ type: String }]
  },
  // PASSWORD RESET FIELDS
  passwordResetToken: { type: String, default: null },
  passwordResetExpires: { type: Date, default: null },

  // EMAIL VERIFICATION FIELDS
  isEmailVerified: { type: Boolean, default: false },
  emailVerifyToken: { type: String, default: null },
  emailVerifyExpires: { type: Date, default: null },

  notifications: {
    emailAlerts: { type: Boolean, default: true },
    scanCompleted: { type: Boolean, default: true },
    vulnerabilityDetected: { type: Boolean, default: true },
    weeklyReports: { type: Boolean, default: true },
    billingAlerts: { type: Boolean, default: true },
    teamInvitations: { type: Boolean, default: true },
    marketingEmails: { type: Boolean, default: false }
  },
  lastLogin: { type: Date, default: null }
}, {
  timestamps: true
});

module.exports = mongoose.model('User', UserSchema);