const express = require('express');
const authenticateJWT = require('../middleware/auth');
const notificationController = require('../controllers/notification.controller');

const router = express.Router();

router.use(authenticateJWT);

router.get('/', notificationController.getNotifications);
router.get('/settings', notificationController.getSettings);
router.put('/settings', notificationController.updateSettings);
router.post('/test', notificationController.sendTestNotification);
router.patch('/read-all', notificationController.markAllAsRead);
router.patch('/:id/read', notificationController.markAsRead);
router.delete('/:id', notificationController.deleteNotification);
router.delete('/', notificationController.clearAllNotifications);

module.exports = router;
