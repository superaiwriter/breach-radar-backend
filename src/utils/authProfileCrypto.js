const crypto = require('crypto');

// Reversible encryption for authenticated-scan credentials (username/password,
// optional cookies, optional JWT). This is intentionally NOT bcrypt/argon2 —
// those are one-way and unusable here because the scanner has to present the
// *plaintext* credential to the target site to log in on the user's behalf.
//
// Requires AUTH_PROFILE_ENCRYPTION_KEY in .env: a 64-char hex string
// (32 raw bytes) for AES-256. Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // recommended IV length for GCM

function getKey() {
  const hex = process.env.AUTH_PROFILE_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error(
      'AUTH_PROFILE_ENCRYPTION_KEY is missing or invalid. Set a 64-character hex string (32 bytes) in .env.'
    );
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypts a plaintext string. Returns null if input is null/undefined/empty
 * so optional fields (cookies, jwt) don't get encrypted into garbage.
 */
function encryptSecret(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return null;

  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Store as iv:authTag:ciphertext, all hex, so it's a single string field in Mongo.
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts a string produced by encryptSecret. Returns null for null input.
 */
function decryptSecret(payload) {
  if (payload === null || payload === undefined || payload === '') return null;

  const [ivHex, authTagHex, dataHex] = String(payload).split(':');
  if (!ivHex || !authTagHex || !dataHex) {
    throw new Error('Malformed encrypted payload.');
  }

  const key = getKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = {
  encryptSecret,
  decryptSecret
};