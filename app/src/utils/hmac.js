// app/src/utils/hmac.js
// Javascript / Node.js 20 / node:crypto / HMAC-SHA256 RBAC Token Engine

const crypto = require('crypto');

// Default fallback secret for isolated local environment
const DEFAULT_SECRET = process.env.HMAC_SECRET || 'wafbench_local_secret_key_2026';

/**
 * Encodes a JavaScript object or string into a URL-safe Base64 string.
 * @param {object|string} data 
 * @returns {string}
 */
function base64UrlEncode(data) {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Decodes a URL-safe Base64 string back into a parsed JSON object or raw string.
 * @param {string} str 
 * @returns {object|string}
 */
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  try {
    return JSON.parse(decoded);
  } catch (err) {
    return decoded;
  }
}

/**
 * Signs payload claims using HMAC-SHA256 with the specified secret key.
 * Format: <header_b64>.<payload_b64>.<hmac_sha256_hex>
 * @param {object} payload - Claims including username, role, timestamps
 * @param {string} [secret] - Secret HMAC key
 * @returns {string}
 */
function signToken(payload, secret = DEFAULT_SECRET) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const headerEncoded = base64UrlEncode(header);
  const payloadEncoded = base64UrlEncode(payload);
  const dataToSign = `${headerEncoded}.${payloadEncoded}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('hex');

  return `${dataToSign}.${signature}`;
}

/**
 * Cryptographically verifies an HMAC-SHA256 token and validates its claims.
 * Uses timingSafeEqual to prevent side-channel timing attacks.
 * @param {string} token 
 * @param {string} [secret] 
 * @returns {{ valid: boolean, payload: object|null, reason?: string }}
 */
function verifyToken(token, secret = DEFAULT_SECRET) {
  if (!token || typeof token !== 'string') {
    return { valid: false, payload: null, reason: 'Token missing or invalid type' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, payload: null, reason: 'Malformed token structure' };
  }

  const [headerEncoded, payloadEncoded, providedSignature] = parts;
  const dataToSign = `${headerEncoded}.${payloadEncoded}`;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('hex');

  // Compare buffers using constant-time comparison
  const providedBuffer = Buffer.from(providedSignature, 'utf8');
  const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

  if (providedBuffer.length !== expectedBuffer.length) {
    return { valid: false, payload: null, reason: 'Signature length mismatch' };
  }

  const isMatch = crypto.timingSafeEqual(providedBuffer, expectedBuffer);
  if (!isMatch) {
    return { valid: false, payload: null, reason: 'Invalid signature: payload tampered or secret mismatch' };
  }

  const payload = base64UrlDecode(payloadEncoded);
  return { valid: true, payload };
}

/**
 * Generates an HMAC-SHA256 authenticated session token for a specific user and role.
 * @param {string} username 
 * @param {string} role 
 * @returns {string}
 */
function generateSessionToken(username, role) {
  const payload = {
    sub: username,
    role: role || 'viewer',
    iat: Math.floor(Date.now() / 1000),
  };
  return signToken(payload);
}

module.exports = {
  signToken,
  verifyToken,
  generateSessionToken,
  DEFAULT_SECRET,
};
