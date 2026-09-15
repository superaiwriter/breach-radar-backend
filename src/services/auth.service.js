const User = require('../models/User');
const Workspace = require('../models/Workspace');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');
const { validateEmailFormat } = require('../utils/validators');
const logger = require('../config/logger');
const teamService = require('./team.service');
const { sendEmail, sendWelcomeEmail } = require('./email/resend.service');

const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

const verifyPassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

const registerUser = async ({ email, password, name }) => {
  if (!email || !password || !name) {
    const err = new Error('Email, password, and name are required.');
    err.statusCode = 400;
    throw err;
  }

  if (!validateEmailFormat(email)) {
    const err = new Error('Invalid email address format.');
    err.statusCode = 400;
    throw err;
  }

  if (password.length < 8) {
    const err = new Error('Password must be at least 8 characters long.');
    err.statusCode = 400;
    throw err;
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    const err = new Error('A user with this email address already exists.');
    err.statusCode = 409;
    throw err;
  }

  const passwordHash = await hashPassword(password);

  // Generate email verification token
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const verifyTokenHash = crypto.createHash('sha256').update(verifyToken).digest('hex');

  const user = new User({
    email,
    passwordHash,
    status: 'pending_verification',
    isEmailVerified: false,
    emailVerifyToken: verifyTokenHash,
    emailVerifyExpires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    profile: { name, avatar: '', phoneNumber: '' }
  });

  await user.save();

  const workspace = new Workspace({
    name: `${name}'s Workspace`,
    owner: user._id,
    members: []
  });

  await workspace.save();

  user.preferences.activeWorkspaceId = workspace._id;
  await user.save();
  await teamService.ensureOrganizationForUser(user);

  logger.info(`New user registered: ${email} (Workspace ID: ${workspace._id})`);

  // Send verification email
  const frontendUrl = process.env.FRONTEND_URL;
  if (!frontendUrl) {
    logger.error('[auth] FRONTEND_URL is not configured in environment variables. Verification link cannot be constructed safely.');
  }
  const baseUrl = (frontendUrl || '').replace(/\/+$/, '');
  const verifyUrl = `${baseUrl}/verify-email?token=${verifyToken}&email=${encodeURIComponent(email)}`;

  const html = `
    <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
      <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
          <div style="width:36px;height:36px;background:#16e095;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:18px">P</div>
          <span style="font-size:20px;font-weight:900;color:#ffffff">PentestRadar</span>
        </div>
        <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">Verify Your Email Address</h1>
        <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">
          Hi <strong style="color:#ffffff">${name}</strong>,<br><br>
          Thank you for creating your PentestRadar account! Please verify your email to activate it.
        </p>
        <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
          <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px">Account Email</p>
          <strong style="display:block;margin-bottom:16px;color:#ffffff">${email}</strong>
          <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px">Link Expires In</p>
          <strong style="display:block;color:#16e095">24 Hours</strong>
        </div>
        <a href="${verifyUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
          Verify Email Address →
        </a>
        <p style="margin:24px 0 0;color:#aeb8c7;font-size:13px;line-height:1.6">
          If you did not create this account, ignore this email.<br><br>
          If the button does not work, copy this link:<br>
          <a href="${verifyUrl}" style="color:#16e095">${verifyUrl}</a>
        </p>
      </div>
    </div>
  `;

  sendEmail({
    to: email,
    subject: 'PentestRadar — Verify Your Email Address',
    html,
    text: `Verify your email: ${verifyUrl}\n\nExpires in 24 hours.`
  }).catch((err) => {
    logger.warn(`[register] Verification email failed for ${email}: ${err.message}`);
  });

  return {
    message: 'Registration successful! Please check your email to verify your account.',
    requiresVerification: true,
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      status: user.status,
      isEmailVerified: false,
      profile: user.profile,
    }
  };
};

const loginUser = async ({ email, password, rememberMe = true }) => {
  if (!email || !password) {
    const err = new Error('Email and password are required.');
    err.statusCode = 400;
    throw err;
  }

  const user = await User.findOne({ email });
  if (!user) {
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  if (user.status === 'suspended') {
    const err = new Error('Your account has been suspended.');
    err.statusCode = 403;
    throw err;
  }

  // New signups stay blocked until they verify. Legacy active accounts are allowed
  // once and backfilled below so old users are not locked out by the new flag.
  if (user.status === 'pending_verification') {
    const err = new Error('Please verify your email address before logging in. Check your inbox for the verification link.');
    err.statusCode = 403;
    err.code = 'EMAIL_NOT_VERIFIED';
    err.email = user.email;
    throw err;
  }

  const isMatch = await verifyPassword(password, user.passwordHash);
  if (!isMatch) {
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  if (!user.isEmailVerified) {
    user.isEmailVerified = true;
    user.emailVerifyToken = null;
    user.emailVerifyExpires = null;
  }

  user.lastLogin = new Date();
  await user.save();
  await teamService.recordLogin(user);

  const activeWorkspaceId = user.preferences.activeWorkspaceId;
  const accessToken = generateAccessToken(user, activeWorkspaceId);
  const refreshToken = generateRefreshToken(user, { rememberMe });

  logger.info(`User logged in: ${email}`);

  return {
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      status: user.status,
      profile: user.profile,
      preferences: user.preferences,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    },
    accessToken,
    refreshToken,
    rememberMe: Boolean(rememberMe),
  };
};

const loginAdmin = async ({ email, password }) => {
  if (!email || !password) {
    const err = new Error('Email and password are required.');
    err.statusCode = 400;
    throw err;
  }

  const user = await User.findOne({ email });
  if (!user) {
    const err = new Error('Invalid credentials.');
    err.statusCode = 401;
    throw err;
  }

  if (user.role !== 'admin' && user.role !== 'super_admin') {
    logger.warn(`Unauthorized admin panel login attempt from: ${email}`);
    const err = new Error('Access denied: Administrative privileges required.');
    err.statusCode = 403;
    throw err;
  }

  if (user.status === 'suspended') {
    const err = new Error('Account suspended.');
    err.statusCode = 403;
    throw err;
  }

  const isMatch = await verifyPassword(password, user.passwordHash);
  if (!isMatch) {
    const err = new Error('Invalid credentials.');
    err.statusCode = 401;
    throw err;
  }

  user.lastLogin = new Date();
  await user.save();
  await teamService.recordLogin(user);

  const accessToken = generateAccessToken(user, user.preferences.activeWorkspaceId);
  const refreshToken = generateRefreshToken(user);

  logger.info(`Admin logged in: ${email} (Role: ${user.role})`);

  return {
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      status: user.status,
      profile: user.profile,
      preferences: user.preferences,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    },
    accessToken,
    refreshToken
  };
};

const refreshTokens = async (token) => {
  if (!token) {
    const err = new Error('Refresh token is required.');
    err.statusCode = 400;
    throw err;
  }

  const secret = process.env.JWT_REFRESH_SECRET || 'super_secret_jwt_refresh_key_67890!';

  let decoded;
  try {
    decoded = jwt.verify(token, secret);
  } catch (err) {
    const error = new Error('Invalid or expired refresh token.');
    error.statusCode = 401;
    throw error;
  }

  const user = await User.findById(decoded.userId);
  if (!user) {
    const err = new Error('User not found.');
    err.statusCode = 401;
    throw err;
  }

  if (user.status === 'suspended') {
    const err = new Error('User account is suspended.');
    err.statusCode = 403;
    throw err;
  }

  const accessToken = generateAccessToken(user, user.preferences.activeWorkspaceId);
  const newRefreshToken = generateRefreshToken(user, { rememberMe: decoded.rememberMe });

  return { accessToken, refreshToken: newRefreshToken, rememberMe: Boolean(decoded.rememberMe) };
};

// ─── PASSWORD RESET ────────────────────────────────────────────────────────

const forgotPassword = async ({ email }) => {
  if (!email) {
    const err = new Error('Email is required.');
    err.statusCode = 400;
    throw err;
  }

  if (!validateEmailFormat(email)) {
    const err = new Error('Invalid email address format.');
    err.statusCode = 400;
    throw err;
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });

  // Security: same response whether user exists or not (prevents email enumeration)
  if (!user) {
    logger.info(`[forgot-password] Email not found (silent): ${email}`);
    return { message: 'If this email exists, a reset link has been sent.' };
  }

  // Generate secure random token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

  // Save hashed token to DB — expires in 1 hour
  user.passwordResetToken = resetTokenHash;
  user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await user.save();

  // Build reset link
  const frontendUrl = process.env.FRONTEND_URL;
  if (!frontendUrl) {
    logger.error('[auth] FRONTEND_URL is not configured in environment variables. Password reset link cannot be constructed safely.');
  }
  const baseUrl = (frontendUrl || '').replace(/\/+$/, '');
  const resetUrl = `${baseUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;

  const html = `
    <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
      <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
        <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">Reset Your Password</h1>
        <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">
          We received a request to reset the password for your Pentestradar account.
          Click the button below to set a new password.
        </p>
        <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
          <p style="margin:0 0 8px;color:#aeb8c7">Account Email</p>
          <strong style="display:block;margin-bottom:16px;font-size:18px;color:#ffffff">${email}</strong>
          <p style="margin:0 0 8px;color:#aeb8c7">Link Expires In</p>
          <strong style="display:block;color:#16e095">1 Hour</strong>
        </div>
        <a href="${resetUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:13px 24px;border-radius:8px">
          Reset Password
        </a>
        <p style="margin:24px 0 0;color:#aeb8c7;font-size:13px;line-height:1.6">
          If you did not request this, you can safely ignore this email. Your password will not change.<br><br>
          If the button does not work, copy and paste this link:<br>
          <a href="${resetUrl}" style="color:#16e095">${resetUrl}</a>
        </p>
      </div>
    </div>
  `;

  const text = `Reset Your Password\n\nClick this link to reset your password:\n${resetUrl}\n\nThis link expires in 1 hour.\n\nIf you did not request this, ignore this email.`;

  try {
    await sendEmail({
      to: email,
      subject: 'Pentestradar — Reset Your Password',
      html,
      text
    });
    logger.info(`[forgot-password] Reset email sent to: ${email}`);
  } catch (emailErr) {
    logger.error(`[forgot-password] Email send failed: ${emailErr.message}`);
    // Don't leak provider failure details to client
  }

  return { message: 'If that email is registered, a password reset link has been sent.' };
};

const resetPassword = async ({ token, email, newPassword }) => {
  if (!token || !email || !newPassword) {
    const err = new Error('Token, email, and new password are required.');
    err.statusCode = 400;
    throw err;
  }

  if (newPassword.length < 8) {
    const err = new Error('Password must be at least 8 characters long.');
    err.statusCode = 400;
    throw err;
  }

  // Hash incoming token to match DB
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    email: email.toLowerCase().trim(),
    passwordResetToken: tokenHash,
    passwordResetExpires: { $gt: new Date() } // Must not be expired
  });

  if (!user) {
    const err = new Error('Password reset token is invalid or has expired. Please request a new one.');
    err.statusCode = 400;
    throw err;
  }

  // Hash new password & clear reset token fields
  user.passwordHash = await hashPassword(newPassword);
  user.passwordResetToken = null;
  user.passwordResetExpires = null;
  user.refreshTokens = []; // Invalidate all existing sessions on password change
  await user.save();

  logger.info(`Password successfully reset for: ${email}`);
  return { message: 'Password has been reset successfully. You can now log in.' };
};

// ─── EMAIL VERIFICATION ────────────────────────────────────────────────────────

const verifyEmail = async ({ token, email }) => {
  if (!token || !email) {
    const err = new Error('Verification token and email are required.');
    err.statusCode = 400;
    throw err;
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  // TEMP DEBUG
  logger.info(`[DEBUG verify] email=${email} receivedTokenHash=${tokenHash}`);

  const user = await User.findOne({
    email: email.toLowerCase().trim(),
    emailVerifyToken: tokenHash,
    emailVerifyExpires: { $gt: new Date() }
  });

  if (!user) {
    // TEMP DEBUG — see what's actually stored for this email
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    logger.info(`[DEBUG verify] no match. DB has token=${existingUser?.emailVerifyToken} expires=${existingUser?.emailVerifyExpires} now=${new Date()}`);

    const err = new Error('Verification link is invalid or has expired. Please request a new one.');
    err.statusCode = 400;
    throw err;
  }

  user.isEmailVerified = true;
  user.emailVerifyToken = null;
  user.emailVerifyExpires = null;
  if (user.status === 'pending_verification') {
    user.status = 'active';
  }
  await user.save();

  // Send welcome email now that they verified
  sendWelcomeEmail({ to: user.email, name: user.profile.name }).catch(() => {});

  logger.info(`[verify-email] Email verified: ${email}`);
  return { message: 'Email verified successfully! You can now log in.' };
};

const resendVerificationEmail = async ({ email }) => {
  if (!email) {
    const err = new Error('Email is required.');
    err.statusCode = 400;
    throw err;
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });

  // Always return same response for security
  if (!user || user.isEmailVerified) {
    return { message: 'If your email is registered and unverified, a new link has been sent.' };
  }

  // Generate new token
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const verifyTokenHash = crypto.createHash('sha256').update(verifyToken).digest('hex');

  user.emailVerifyToken = verifyTokenHash;
  user.emailVerifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await user.save();

  // TEMP DEBUG
  logger.info(`[DEBUG resend] email=${email} newTokenHash=${verifyTokenHash} expires=${user.emailVerifyExpires}`);

  const frontendUrl = process.env.FRONTEND_URL;
  if (!frontendUrl) {
    logger.error('[auth] FRONTEND_URL is not configured in environment variables. Verification link cannot be constructed safely.');
  }
  const baseUrl = (frontendUrl || '').replace(/\/+$/, '');
  const verifyUrl = `${baseUrl}/verify-email?token=${verifyToken}&email=${encodeURIComponent(email)}`;

  const html = `
    <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
      <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
          <div style="width:36px;height:36px;background:#16e095;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:18px">P</div>
          <span style="font-size:20px;font-weight:900;color:#ffffff">PentestRadar</span>
        </div>
        <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">New Verification Link</h1>
        <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">
          Here is your new email verification link. Click below to verify your account.
        </p>
        <a href="${verifyUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
          Verify Email Address →
        </a>
        <p style="margin:24px 0 0;color:#aeb8c7;font-size:13px">
          This link expires in 24 hours.<br>
          <a href="${verifyUrl}" style="color:#16e095">${verifyUrl}</a>
        </p>
      </div>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: 'PentestRadar — New Verification Link',
    html,
    text: `New verification link: ${verifyUrl}`
  });

  logger.info(`[resend-verification] Sent to: ${email}`);
  return { message: 'If your email is registered and unverified, a new link has been sent.' };
};

module.exports = {
  hashPassword,
  verifyPassword,
  registerUser,
  loginUser,
  loginAdmin,
  refreshTokens,
  forgotPassword,
  resetPassword,
  verifyEmail,
  resendVerificationEmail
};