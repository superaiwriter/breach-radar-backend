const express = require('express');
const router = express.Router();
const authProfileController = require('../controllers/authProfile.controller');
const authenticateJWT = require('../middleware/auth');
const enforceIpWhitelist = require('../middleware/ipWhitelist');
const { checkWorkspaceRole } = require('../middleware/rbac');
const { WORKSPACE_ROLES } = require('../constants');

router.use(authenticateJWT);
router.use(enforceIpWhitelist);

// Creating/deleting auth profiles handles live credentials — restrict to
// Owner/Admin, same bar as starting a scan.
router.post(
  '/',
  checkWorkspaceRole([WORKSPACE_ROLES.OWNER, WORKSPACE_ROLES.ADMIN]),
  authProfileController.createAuthProfile
);

router.get('/', authProfileController.getAuthProfiles);

router.delete(
  '/:id',
  checkWorkspaceRole([WORKSPACE_ROLES.OWNER, WORKSPACE_ROLES.ADMIN]),
  authProfileController.deleteAuthProfile
);

module.exports = router;