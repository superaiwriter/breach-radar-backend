const mongoose = require('mongoose');
const AuthProfile = require('../models/AuthProfile');
const Domain = require('../models/Domain');
const { encryptSecret, decryptSecret } = require('../utils/authProfileCrypto');

function assertValidObjectId(id, label = 'id') {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    const error = new Error(`Invalid ${label} format`);
    error.statusCode = 400;
    throw error;
  }
}

/**
 * Creates an AuthProfile. Accepts exactly one credential shape:
 *   { authType: 'credentials', username, password, loginUrl? }
 *   { authType: 'cookie', cookies }
 *   { authType: 'jwt', jwt }
 * Secrets are encrypted before being written to Mongo.
 */
async function createAuthProfile({ workspaceId, domainName, userId, authType, username, password, loginUrl, cookies, jwt, label, oneTimeUse }) {
  if (!workspaceId || !userId) {
    const error = new Error('Workspace and user context required.');
    error.statusCode = 400;
    throw error;
  }

  if (!['credentials', 'cookie', 'jwt'].includes(authType)) {
    const error = new Error('authType must be one of: credentials, cookie, jwt.');
    error.statusCode = 400;
    throw error;
  }

  const domain = await Domain.findOne({ _id: domainName, workspaceId }).catch(() => null)
    || await Domain.findOne({ workspaceId, domain: String(domainName).trim().toLowerCase() });

  if (!domain) {
    const error = new Error('Domain not found in this workspace.');
    error.statusCode = 404;
    throw error;
  }

  if (authType === 'credentials' && (!username || !password)) {
    const error = new Error('username and password are required for authType "credentials".');
    error.statusCode = 400;
    throw error;
  }
  if (authType === 'cookie' && !cookies) {
    const error = new Error('cookies value is required for authType "cookie".');
    error.statusCode = 400;
    throw error;
  }
  if (authType === 'jwt' && !jwt) {
    const error = new Error('jwt value is required for authType "jwt".');
    error.statusCode = 400;
    throw error;
  }

  const profile = new AuthProfile({
    workspaceId,
    domainId: domain._id,
    label: label || 'Authenticated Scan',
    authType,
    createdBy: userId,
    oneTimeUse: oneTimeUse !== false, // default true unless explicitly saved for reuse
    username: authType === 'credentials' ? username : undefined,
    passwordEncrypted: authType === 'credentials' ? encryptSecret(password) : undefined,
    loginUrl: authType === 'credentials' ? (loginUrl || null) : undefined,
    cookiesEncrypted: authType === 'cookie' ? encryptSecret(cookies) : undefined,
    jwtEncrypted: authType === 'jwt' ? encryptSecret(jwt) : undefined
  });

  await profile.save();

  // Never return secret fields to the caller.
  return {
    _id: profile._id,
    workspaceId: profile.workspaceId,
    domainId: profile.domainId,
    label: profile.label,
    authType: profile.authType,
    oneTimeUse: profile.oneTimeUse,
    createdAt: profile.createdAt
  };
}

/**
 * Internal use only (scan pipeline) — fetches a profile WITH decrypted
 * secrets. Never expose this over an API response.
 */
async function resolveDecryptedProfile(workspaceId, authProfileId) {
  assertValidObjectId(authProfileId, 'authProfileId');

  const profile = await AuthProfile.findOne({ _id: authProfileId, workspaceId })
    .select('+username +passwordEncrypted +cookiesEncrypted +jwtEncrypted');

  if (!profile) {
    const error = new Error('Auth profile not found or unauthorized.');
    error.statusCode = 404;
    throw error;
  }

  const decrypted = {
    authType: profile.authType,
    username: profile.username || null,
    password: decryptSecret(profile.passwordEncrypted),
    loginUrl: profile.loginUrl || null,
    cookies: decryptSecret(profile.cookiesEncrypted),
    jwt: decryptSecret(profile.jwtEncrypted)
  };

  profile.lastUsedAt = new Date();
  await profile.save();

  if (profile.oneTimeUse) {
    await AuthProfile.deleteOne({ _id: profile._id });
  }

  return decrypted;
}

async function listAuthProfiles(workspaceId, domainId) {
  const query = { workspaceId };
  if (domainId) query.domainId = domainId;
  return AuthProfile.find(query).select('-username -passwordEncrypted -cookiesEncrypted -jwtEncrypted').sort({ createdAt: -1 });
}

async function deleteAuthProfile(workspaceId, authProfileId) {
  assertValidObjectId(authProfileId, 'authProfileId');
  const result = await AuthProfile.deleteOne({ _id: authProfileId, workspaceId });
  if (result.deletedCount === 0) {
    const error = new Error('Auth profile not found or unauthorized.');
    error.statusCode = 404;
    throw error;
  }
  return { deleted: true };
}

module.exports = {
  createAuthProfile,
  resolveDecryptedProfile,
  listAuthProfiles,
  deleteAuthProfile
};