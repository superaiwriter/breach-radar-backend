const mongoose = require('mongoose');

// Stores what's needed to establish an authenticated session for a scan.
// All secret fields are stored ENCRYPTED (see utils/authProfileCrypto.js) —
// never plaintext, and never selected by default on generic queries.
const AuthProfileSchema = new mongoose.Schema(
  {
    workspaceId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Workspace',
      required: true,
      index: true
    },
    domainId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Domain',
      required: true,
      index: true
    },
    label: {
      type: String,
      trim: true,
      default: 'Authenticated Scan'
    },
    authType: {
      type: String,
      enum: ['credentials', 'cookie', 'jwt'],
      required: true
    },

    // authType: 'credentials'
    username: { type: String, select: false, default: null },
    passwordEncrypted: { type: String, select: false, default: null },
    loginUrl: { type: String, default: null }, // optional override; else auto-detected

    // authType: 'cookie'
    cookiesEncrypted: { type: String, select: false, default: null },

    // authType: 'jwt'
    jwtEncrypted: { type: String, select: false, default: null },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },

    // One-time-use profiles are deleted right after the scan consumes them;
    // reusable profiles persist until the user deletes them.
    oneTimeUse: {
      type: Boolean,
      default: true
    },

    lastUsedAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('AuthProfile', AuthProfileSchema);