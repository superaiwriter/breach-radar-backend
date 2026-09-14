const fs = require('fs/promises');
const path = require('path');
const User = require('../models/User');
const { validateEmailFormat } = require('../utils/validators');
const { USER_ROLES } = require('../constants');

const LOCAL_UPLOAD_PREFIX = '/uploads/avatars/';

function buildProfileResponse(user) {
  return {
    id: user._id,
    email: user.email,
    role: user.role,
    status: user.status,
    profile: {
      name: user.profile?.name || '',
      avatar: user.profile?.avatar || '',
      phoneNumber: user.profile?.phoneNumber || '',
      organization: user.profile?.organization || '',
      jobTitle: user.profile?.jobTitle || '',
      country: user.profile?.country || '',
    },
    preferences: {
      timezone: user.preferences?.timezone || '',
    },
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
}

function validatePhoneNumber(phoneNumber) {
  if (!phoneNumber) return true;
  return /^[+]?[\d\s().-]{7,20}$/.test(phoneNumber);
}

async function getCurrentUserProfile(userId) {
  const user = await User.findById(userId).select('-passwordHash');
  if (!user) {
    const error = new Error('User profile not found.');
    error.statusCode = 404;
    throw error;
  }

  return buildProfileResponse(user);
}

async function updateCurrentUserProfile(userId, payload) {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error('User profile not found.');
    error.statusCode = 404;
    throw error;
  }

  // Admins cannot change their own email from the profile form; only
  // super admins (and regular users) retain that ability.
  const allowEmailChange = user.role !== USER_ROLES.ADMIN;

  const name = String(payload.name || '').trim();
  const email = allowEmailChange ? String(payload.email || '').trim().toLowerCase() : user.email;
  const phoneNumber = String(payload.phoneNumber || '').trim();
  const organization = String(payload.organization || '').trim();
  const jobTitle = String(payload.jobTitle || '').trim();
  const country = String(payload.country || '').trim();
  const timezone = String(payload.timezone || '').trim();

  if (!name) {
    const error = new Error('Full name is required.');
    error.statusCode = 400;
    throw error;
  }

  if (allowEmailChange) {
    if (!email || !validateEmailFormat(email)) {
      const error = new Error('Enter a valid email address.');
      error.statusCode = 400;
      throw error;
    }

    const emailOwner = await User.findOne({ email, _id: { $ne: userId } }).select('_id');
    if (emailOwner) {
      const error = new Error('This email address is already in use.');
      error.statusCode = 409;
      throw error;
    }
  }

  if (!validatePhoneNumber(phoneNumber)) {
    const error = new Error('Enter a valid phone number.');
    error.statusCode = 400;
    throw error;
  }

  user.email = email;
  user.profile.name = name;
  user.profile.phoneNumber = phoneNumber;
  user.profile.organization = organization;
  user.profile.jobTitle = jobTitle;
  user.profile.country = country;
  user.preferences.timezone = timezone || 'UTC';

  await user.save();
  return buildProfileResponse(user);
}

async function removeLocalAvatar(avatarUrl) {
  if (!avatarUrl || !avatarUrl.startsWith(LOCAL_UPLOAD_PREFIX)) return;

  const relativePath = avatarUrl.replace(/^\/uploads\//, '');
  const uploadsDir = process.env.UPLOADS_DIR || path.resolve(__dirname, '../../uploads');
  const absolutePath = path.join(uploadsDir, relativePath);

  try {
    await fs.unlink(absolutePath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      // Safely ignore or non-fatal
    }
  }
}

async function updateCurrentUserAvatar(userId, file) {
  if (!file) {
    const error = new Error('Profile picture is required.');
    error.statusCode = 400;
    throw error;
  }

  const user = await User.findById(userId);
  if (!user) {
    const error = new Error('User profile not found.');
    error.statusCode = 404;
    throw error;
  }

  await removeLocalAvatar(user.profile.avatar);
  user.profile.avatar = `${LOCAL_UPLOAD_PREFIX}${file.filename}`;
  await user.save();

  return buildProfileResponse(user);
}

async function removeCurrentUserAvatar(userId) {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error('User profile not found.');
    error.statusCode = 404;
    throw error;
  }

  await removeLocalAvatar(user.profile.avatar);
  user.profile.avatar = '';
  await user.save();

  return buildProfileResponse(user);
}

module.exports = {
  getCurrentUserProfile,
  updateCurrentUserProfile,
  updateCurrentUserAvatar,
  removeCurrentUserAvatar,
};