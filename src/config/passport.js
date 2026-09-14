const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const User = require('../models/User');
const Workspace = require('../models/Workspace');
const teamService = require('../services/team.service');
const logger = require('./logger');

const passportSetup = (app) => {
  // Only setup if Google credentials are configured
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    logger.warn('[passport] GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET missing — Google OAuth disabled.');
    return;
  }

  let callbackURL = process.env.GOOGLE_CALLBACK_URL;
  if (!callbackURL && process.env.BACKEND_URL) {
    callbackURL = `${process.env.BACKEND_URL}/api/v1/auth/google/callback`;
  }
  if (!callbackURL) {
    callbackURL = 'http://localhost:5000/api/v1/auth/google/callback';
  }

  if (process.env.NODE_ENV === 'production' && (callbackURL.includes('localhost') || callbackURL.includes('127.0.0.1'))) {
    logger.warn('[passport] GOOGLE_CALLBACK_URL is configured with a localhost URL in production. Google OAuth callbacks may fail until updated to a production domain.');
  }

  app.use(passport.initialize());

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL,
        scope: ['profile', 'email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value?.toLowerCase();
          const name = profile.displayName || profile.name?.givenName || 'User';

          if (!email) {
            return done(new Error('Google account has no email address.'), null);
          }

          // Check if user already exists
          let user = await User.findOne({ email });

          if (user) {
            // Existing user — just log them in
            user.lastLogin = new Date();
            await user.save();
            logger.info(`[google-oauth] Existing user logged in: ${email}`);
            return done(null, user);
          }

          // New user — create account
          const bcrypt = require('bcryptjs');
          const crypto = require('crypto');
          const randomPassword = crypto.randomBytes(32).toString('hex');
          const salt = await bcrypt.genSalt(10);
          const passwordHash = await bcrypt.hash(randomPassword, salt);

          user = new User({
            email,
            passwordHash,
            profile: {
              name,
              avatar: profile.photos?.[0]?.value || '',
              phoneNumber: '',
            },
          });
          await user.save();

          // Create workspace
          const workspace = new Workspace({
            name: `${name}'s Workspace`,
            owner: user._id,
            members: [],
          });
          await workspace.save();

          user.preferences.activeWorkspaceId = workspace._id;
          await user.save();
          await teamService.ensureOrganizationForUser(user);

          logger.info(`[google-oauth] New user registered via Google: ${email}`);
          return done(null, user);
        } catch (err) {
          logger.error(`[google-oauth] Error: ${err.message}`);
          return done(err, null);
        }
      }
    )
  );

  logger.info('[passport] Google OAuth strategy registered.');
};

module.exports = passportSetup;
