const authProfileService = require('../services/authProfile.service');
const logger = require('../config/logger');

// POST /api/v1/auth-profiles
const createAuthProfile = async (req, res, next) => {
  try {
    const { domain, authType, username, password, loginUrl, cookies, jwt, label, oneTimeUse } = req.body;

    const profile = await authProfileService.createAuthProfile({
      workspaceId: req.workspaceId,
      userId: req.user._id,
      domainName: domain,
      authType,
      username,
      password,
      loginUrl,
      cookies,
      jwt,
      label,
      oneTimeUse
    });

    logger.info(`Auth profile created for domain scan (workspace ${req.workspaceId}) by ${req.user.email}`);

    res.status(201).json({ message: 'Auth profile created.', authProfile: profile });
  } catch (error) {
    next(error);
  }
};

// GET /api/v1/auth-profiles?domainId=
const getAuthProfiles = async (req, res, next) => {
  try {
    const profiles = await authProfileService.listAuthProfiles(req.workspaceId, req.query.domainId);
    res.status(200).json(profiles);
  } catch (error) {
    next(error);
  }
};

// DELETE /api/v1/auth-profiles/:id
const deleteAuthProfile = async (req, res, next) => {
  try {
    await authProfileService.deleteAuthProfile(req.workspaceId, req.params.id);
    res.status(200).json({ message: 'Auth profile deleted.' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createAuthProfile,
  getAuthProfiles,
  deleteAuthProfile
};