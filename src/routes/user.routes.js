const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const authenticateJWT = require('../middleware/auth');
const userController = require('../controllers/user.controller');

const router = express.Router();
const uploadRoot = process.env.AVATAR_UPLOAD_DIR || path.resolve(__dirname, '../../uploads/avatars');
const allowedMimeTypes = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp']);

try {
  fs.mkdirSync(uploadRoot, { recursive: true });
} catch (e) {
  // Directory might already exist
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadRoot),
  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname || '').toLowerCase();
    cb(null, `${req.user._id}-${Date.now()}${extension}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const extension = path.extname(file.originalname || '').toLowerCase();
    const allowedExtension = ['.jpg', '.jpeg', '.png', '.webp'].includes(extension);

    if (!allowedMimeTypes.has(file.mimetype) || !allowedExtension) {
      const error = new Error('Profile picture must be a JPG, JPEG, PNG, or WEBP image.');
      error.statusCode = 400;
      return cb(error);
    }

    return cb(null, true);
  },
});

function handleUploadError(req, res, next) {
  upload.single('avatar')(req, res, (error) => {
    if (!error) return next();

    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'Profile picture must be 5 MB or smaller.' });
    }

    return res.status(error.statusCode || 400).json({
      message: error.message || 'Invalid profile picture upload.',
    });
  });
}

router.use(authenticateJWT);

router.get('/profile', userController.getProfile);
router.put('/profile', userController.updateProfile);
router.post('/avatar', handleUploadError, userController.uploadAvatar);
router.delete('/avatar', userController.removeAvatar);

module.exports = router;
