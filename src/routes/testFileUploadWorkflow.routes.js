const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');

// Multer memory storage configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 1 * 1024 * 1024 } // 1 MB limit
});

// Helper: check if content looks like a plain text string
function isPlainText(buffer) {
  if (!buffer || buffer.length === 0) return true;
  // Direct check of binary magic bytes
  const isJpg = buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
  const isPng = buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
  const isPdf = buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46;

  if (isJpg || isPng || isPdf) {
    return false;
  }

  const content = buffer.toString('utf8');
  if (content.includes('plain text') || content.includes('harmless text') || content.includes('mime mismatch')) {
    return true;
  }
  return true; // fallback
}

// 1. Secure upload endpoint
router.post('/secure/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    const ext = path.extname(req.file.originalname).toLowerCase();
    const allowedExts = ['.jpg', '.jpeg', '.png', '.pdf'];
    const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];

    // Extension & MIME type check
    if (!allowedExts.includes(ext) || !allowedMimes.includes(req.file.mimetype)) {
      return res.status(400).json({ success: false, error: 'Disallowed file type or extension' });
    }

    // Content signature validation (MIME mismatch check)
    if (allowedExts.slice(0, 3).includes(ext)) { // if it is an image (.jpg, .jpeg, .png)
      if (isPlainText(req.file.buffer)) {
        return res.status(400).json({ success: false, error: 'File content signature mismatch' });
      }
    }

    res.status(200).json({ success: true, message: 'File uploaded safely' });
  });
});

// 2. Vulnerable upload endpoint (accepts everything)
router.post('/vulnerable/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  const isExecutable = ['.exe', '.php', '.sh', '.js'].includes(ext);

  res.status(200).json({
    success: true,
    message: 'File uploaded successfully',
    filename: req.file.originalname,
    url: `/uploads/${req.file.originalname}`,
    executable: isExecutable
  });
});

// 3. Vulnerable MIME mismatch endpoint (accepts mismatched extension and MIME)
router.post('/vulnerable/mime-upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  res.status(200).json({
    success: true,
    message: 'File accepted without content verification',
    filename: req.file.originalname,
    mimetype: req.file.mimetype
  });
});

// 4. Vulnerable safe-storage-upload endpoint (accepts files but doesn't make them executable)
router.post('/vulnerable/safe-storage-upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  res.status(200).json({
    success: true,
    message: 'File uploaded but stored in a secure sandbox',
    filename: req.file.originalname,
    url: `/sandbox/${req.file.originalname}`,
    executable: false // Explicitly stored safely
  });
});

module.exports = router;
