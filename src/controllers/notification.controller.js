const Notification = require('../models/Notification');
const Workspace = require('../models/Workspace');
const teamService = require('../services/team.service');

const getNotifications = async (req, res, next) => {
  try {
    const orgId = req.user.preferences?.activeOrganizationId;
    const userId = req.user._id;
    const email = req.user.email ? req.user.email.toLowerCase() : '';

    const orConditions = [{ userId }];
    if (orgId) {
      orConditions.push({ organizationId: orgId });
    }
    if (email) {
      orConditions.push({ email });
    }

    const list = await Notification.find({ $or: orConditions })
      .sort({ createdAt: -1 })
      .limit(50);

    res.status(200).json(list);
  } catch (error) {
    next(error);
  }
};

const getSettings = async (req, res, next) => {
  try {
    const workspace = await Workspace.findById(req.workspaceId);
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found.' });
    }

    const notifications = workspace.notifications || {
      channels: {
        email: { enabled: true, recipients: [] },
        slack: { enabled: false, webhookUrl: '' },
        webhook: { enabled: false, endpointUrl: '' },
        inApp: { enabled: true },
        dashboard: { enabled: true },
        sms: { enabled: false, phoneNumber: '' }
      },
      events: {
        criticalFound: true,
        highFound: true,
        digestEnabled: false,
        digestFrequency: 'weekly',
        criticalVulnerabilities: true,
        scanCompleted: true,
        monitorDown: true,
        reportReady: true,
        remediationDue: false
      },
      digest: {
        frequency: 'Daily',
        time: '08:00',
        recipient: ''
      }
    };

    res.status(200).json(notifications);
  } catch (error) {
    next(error);
  }
};

const updateSettings = async (req, res, next) => {
  try {
    const workspace = await Workspace.findById(req.workspaceId);
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found.' });
    }

    const { channels, events, digest } = req.body;

    if (channels) workspace.notifications.channels = channels;
    if (events) workspace.notifications.events = events;
    if (digest) workspace.notifications.digest = digest;

    workspace.markModified('notifications');
    await workspace.save();

    res.status(200).json({
      message: 'Notification settings updated successfully.',
      notifications: workspace.notifications
    });
  } catch (error) {
    next(error);
  }
};

const sendTestNotification = async (req, res, next) => {
  try {
    const orgId = req.user.preferences?.activeOrganizationId;
    const userId = req.user._id;

    await teamService.recordWorkspaceActivity({
      userId,
      action: 'Sent Test Notification',
      target: 'Workspace Settings'
    }).catch(() => {});

    const notification = await Notification.create({
      organizationId: orgId || null,
      userId,
      type: 'TEST_ALERT',
      title: 'Test alert triggered',
      message: 'This is a live test notification generated from your PentestRadar Notification preferences.'
    });

    res.status(200).json({
      message: 'Test notification sent successfully.',
      notification
    });
  } catch (error) {
    next(error);
  }
};

const markAsRead = async (req, res, next) => {
  try {
    const { id } = req.params;
    const notification = await Notification.findByIdAndUpdate(
      id,
      { readAt: new Date() },
      { new: true }
    );
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found.' });
    }
    res.status(200).json({ success: true, notification });
  } catch (error) {
    next(error);
  }
};

const markAllAsRead = async (req, res, next) => {
  try {
    const orgId = req.user.preferences?.activeOrganizationId;
    const userId = req.user._id;
    const email = req.user.email ? req.user.email.toLowerCase() : '';

    const orConditions = [{ userId }];
    if (orgId) orConditions.push({ organizationId: orgId });
    if (email) orConditions.push({ email });

    await Notification.updateMany(
      { $or: orConditions, readAt: null },
      { $set: { readAt: new Date() } }
    );

    res.status(200).json({ success: true, message: 'All notifications marked as read.' });
  } catch (error) {
    next(error);
  }
};

const deleteNotification = async (req, res, next) => {
  try {
    const { id } = req.params;
    await Notification.findByIdAndDelete(id);
    res.status(200).json({ success: true, message: 'Notification deleted.' });
  } catch (error) {
    next(error);
  }
};

const clearAllNotifications = async (req, res, next) => {
  try {
    const orgId = req.user.preferences?.activeOrganizationId;
    const userId = req.user._id;
    const email = req.user.email ? req.user.email.toLowerCase() : '';

    const orConditions = [{ userId }];
    if (orgId) orConditions.push({ organizationId: orgId });
    if (email) orConditions.push({ email });

    await Notification.deleteMany({ $or: orConditions });

    res.status(200).json({ success: true, message: 'All notifications cleared.' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getNotifications,
  getSettings,
  updateSettings,
  sendTestNotification,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  clearAllNotifications
};
