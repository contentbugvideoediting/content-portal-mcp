// server_Production.js
// ContentBug Production MCP Server v2.1.0
// Handles: Make webhooks, Claude/OpenAI AI, Airtable storage, GHL forwarding, chat, auth, AND Google Drive
// Deploy to Railway - runs 24/7

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const { Readable } = require('stream');
require('dotenv').config();

// ============================================
// GOOGLE DRIVE SERVICE (PRODUCTION HARDENED)
// ============================================
// Uses service account auth only - no OAuth
// Scope: drive.file (minimal - can only access files it creates)
// Never logs credentials, never writes to disk

let googleDrive = null;
let driveServiceReady = false;
let driveInitError = null;

// Allowed MIME types for upload security
const ALLOWED_MIME_TYPES = {
  // Video
  'video/mp4': { ext: '.mp4', category: 'video' },
  'video/quicktime': { ext: '.mov', category: 'video' },
  'video/x-msvideo': { ext: '.avi', category: 'video' },
  'video/webm': { ext: '.webm', category: 'video' },
  'video/x-matroska': { ext: '.mkv', category: 'video' },
  'video/x-m4v': { ext: '.m4v', category: 'video' },
  // Audio
  'audio/mpeg': { ext: '.mp3', category: 'audio' },
  'audio/wav': { ext: '.wav', category: 'audio' },
  'audio/x-wav': { ext: '.wav', category: 'audio' },
  'audio/aac': { ext: '.aac', category: 'audio' },
  'audio/x-m4a': { ext: '.m4a', category: 'audio' },
  'audio/mp4': { ext: '.m4a', category: 'audio' },
  // Images
  'image/jpeg': { ext: '.jpg', category: 'image' },
  'image/png': { ext: '.png', category: 'image' },
  'image/gif': { ext: '.gif', category: 'image' },
  'image/webp': { ext: '.webp', category: 'image' },
  'image/svg+xml': { ext: '.svg', category: 'image' }
};

// Upload limits by category
const UPLOAD_LIMITS = {
  video: 500 * 1024 * 1024,    // 500MB
  audio: 100 * 1024 * 1024,    // 100MB
  image: 25 * 1024 * 1024,     // 25MB
  default: 50 * 1024 * 1024    // 50MB fallback
};

// Drive folder structure constants
const DRIVE_FOLDER_STRUCTURE = {
  ROOT_NAME: 'Content Bug Clients',
  SUBFOLDERS: ['Brand Assets', 'Raw Uploads', 'Creator Lab Recordings', 'Approved Exports'],
  BRAND_ASSET_SUBFOLDERS: ['Logos', 'Thumbnails', 'Headshots']
};

// Initialize Google Drive with security checks
function initGoogleDrive() {
  try {
    const credentialsJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

    if (!credentialsJson) {
      driveInitError = 'GOOGLE_SERVICE_ACCOUNT_JSON not configured';
      console.warn(`[Drive] ${driveInitError} - file uploads disabled`);
      return false;
    }

    // Parse credentials (never log the actual content)
    let credentials;
    try {
      credentials = JSON.parse(credentialsJson);
    } catch (parseErr) {
      driveInitError = 'Invalid JSON in GOOGLE_SERVICE_ACCOUNT_JSON';
      console.error(`[Drive] ${driveInitError}`);
      return false;
    }

    // Validate required fields exist (without logging values)
    const requiredFields = ['type', 'project_id', 'private_key', 'client_email'];
    const missingFields = requiredFields.filter(f => !credentials[f]);
    if (missingFields.length > 0) {
      driveInitError = `Missing required fields: ${missingFields.join(', ')}`;
      console.error(`[Drive] ${driveInitError}`);
      return false;
    }

    if (credentials.type !== 'service_account') {
      driveInitError = 'Credentials must be service_account type';
      console.error(`[Drive] ${driveInitError}`);
      return false;
    }

    const { google } = require('googleapis');

    const auth = new google.auth.GoogleAuth({
      credentials: credentials,
      scopes: ['https://www.googleapis.com/auth/drive.file'] // Minimal scope
    });

    googleDrive = google.drive({ version: 'v3', auth });
    driveServiceReady = true;

    console.log(`[Drive] Service initialized (project: ${credentials.project_id})`);
    return true;

  } catch (e) {
    driveInitError = e.message;
    console.error('[Drive] Initialization failed:', e.message);
    return false;
  }
}

// Initialize Drive on startup
initGoogleDrive();

// File upload config with validation
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB absolute max
    files: 1 // Single file per request
  },
  fileFilter: (req, file, cb) => {
    const mimeInfo = ALLOWED_MIME_TYPES[file.mimetype];
    if (!mimeInfo) {
      return cb(new Error(`File type not allowed: ${file.mimetype}`), false);
    }

    // Attach category for later size validation
    file.category = mimeInfo.category;
    cb(null, true);
  }
});

// Try to load argon2 - fall back to crypto if not available
let argon2;
try {
  argon2 = require('argon2');
} catch (e) {
  console.warn('argon2 not available, using fallback crypto hashing');
  argon2 = null;
}

// Try to load otplib for TOTP
let authenticator;
try {
  const otplib = require('otplib');
  authenticator = otplib.authenticator;
} catch (e) {
  console.warn('otplib not available, TOTP disabled');
  authenticator = null;
}

const PORT = process.env.PORT || 3000;
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const CLAUDE_API_URL = process.env.CLAUDE_API_URL || 'https://api.anthropic.com/v1/messages';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-4-20250514';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;
const AIRTABLE_TABLE = process.env.AIRTABLE_TABLE || 'Conversations';
const AIRTABLE_CHAT_TABLE = process.env.AIRTABLE_CHAT_TABLE || 'ChatMessages';
const GHL_WEBHOOK_URL = process.env.GHL_WEBHOOK_URL;
const MAKE_SHARED_SECRET = process.env.MAKE_SHARED_SECRET || '';
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET || '';
const HMAC_HEADER = process.env.HMAC_HEADER || 'x-mcp-signature';
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS || '800', 10);

// Auth config
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE_MS = parseInt(process.env.SESSION_MAX_AGE_MS || String(24 * 60 * 60 * 1000), 10); // 24h default
const OTP_EXPIRY_MS = parseInt(process.env.OTP_EXPIRY_MS || String(10 * 60 * 1000), 10); // 10 min
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || '5', 10);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const app = express();

// CORS - allow portal frontend with credentials
app.use(cors({
  origin: ['https://app.contentbug.io', 'https://go.contentbug.io', 'https://contentbug.io', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-make-secret', 'x-ghl-secret']
}));

app.use(bodyParser.json({ limit: '1mb' }));
app.use(cookieParser(SESSION_SECRET));

// Trust proxy for rate limiting behind Railway/nginx
app.set('trust proxy', 1);

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests', retry_after: 15 * 60 }
});
app.use(globalLimiter);

// Health check
app.get('/healthz', (req, res) => res.json({
  ok: true,
  ts: Date.now(),
  version: 'production-2.1.0',
  auth: true,
  portal: true,
  drive: {
    ready: driveServiceReady,
    error: driveServiceReady ? null : driveInitError
  }
}));

// ============================================
// PORTAL STATIC FILE SERVING
// ============================================

// Portal directory - adjust based on deployment
const PORTAL_DIR = process.env.PORTAL_DIR || path.join(__dirname, 'portal');

// Serve shared assets (CSS, JS)
app.use('/shared', express.static(path.join(PORTAL_DIR, 'shared'), {
  maxAge: IS_PRODUCTION ? '1d' : 0
}));

// Portal route mappings
const portalRoutes = {
  '/login': 'client/login.html',
  '/dashboard': 'client/dashboard.html',
  '/projects': 'client/projects.html',
  '/review': 'client/review.html',
  '/chat': 'client/chat.html',
  '/step-1-create-account': 'client/step-1.html',
  '/step-2-style-blueprint': 'client/step-2.html',
  '/blueprint-builder': 'client/step-2-builder.html',
  '/step-3-submit-project': 'client/step-3.html',
  '/admin': 'admin/admin.html',
  '/editor': 'admin/admin.html', // Editors use same admin page with role-based UI
  '/account': 'client/account.html',
  '/settings': 'client/settings.html',
  '/team': 'admin/team.html',
  '/book-call': 'client/book-call.html',
  '/onboarding-complete': 'client/onboarding-complete.html'
};

// Serve portal pages
Object.entries(portalRoutes).forEach(([route, file]) => {
  app.get(route, (req, res) => {
    const filePath = path.join(PORTAL_DIR, file);
    res.sendFile(filePath, (err) => {
      if (err) {
        console.warn(`Portal page not found: ${file}`);
        res.status(404).send('Page not found');
      }
    });
  });
});

// Root redirect to login
app.get('/', (req, res) => {
  res.redirect('/login');
});

// ============================================
// AUTHENTICATION & SECURITY
// ============================================

function verifySecret(headerName, expectedSecret) {
  return (req, res, next) => {
    if (!expectedSecret) return next();
    const incoming = req.get(headerName) || req.get(headerName.toLowerCase());
    if (!incoming) return res.status(401).json({ error: 'missing signature header' });
    if (incoming === expectedSecret) return next();
    try {
      const parts = incoming.split('=');
      if (parts.length === 2) {
        const algo = parts[0];
        const sig = parts[1];
        const hmac = crypto.createHmac(algo, expectedSecret).update(JSON.stringify(req.body)).digest('hex');
        if (crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(sig, 'hex'))) return next();
      }
    } catch (e) {}
    return res.status(401).json({ error: 'invalid signature' });
  };
}

// Simple API key auth for chat endpoints
function verifyApiKey(req, res, next) {
  const apiKey = req.get('x-api-key') || req.query.api_key;
  const validKey = process.env.CHAT_API_KEY;
  if (!validKey) return next(); // No key configured = open (for dev)
  if (apiKey === validKey) return next();
  return res.status(401).json({ error: 'invalid api key' });
}

// ============================================
// AIRTABLE HELPERS
// ============================================

async function airtableCreate(table, fields) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return null;
  try {
    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}`;
    const res = await axios.post(url, { fields }, {
      headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' }
    });
    return res.data;
  } catch (err) {
    console.warn('Airtable create error:', err?.response?.data || err.message);
    return null;
  }
}

async function airtableQuery(table, filterFormula, options = {}) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return { records: [] };
  try {
    const params = new URLSearchParams();
    if (filterFormula) params.append('filterByFormula', filterFormula);
    if (options.maxRecords) params.append('maxRecords', options.maxRecords);
    if (options.sort) {
      options.sort.forEach((s, i) => {
        params.append(`sort[${i}][field]`, s.field);
        params.append(`sort[${i}][direction]`, s.direction || 'asc');
      });
    }
    if (options.offset) params.append('offset', options.offset);

    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?${params}`;
    const res = await axios.get(url, { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } });
    return res.data;
  } catch (err) {
    console.warn('Airtable query error:', err?.response?.data || err.message);
    return { records: [] };
  }
}

async function airtableUpdate(table, recordId, fields) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return null;
  try {
    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}/${recordId}`;
    const res = await axios.patch(url, { fields }, {
      headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' }
    });
    return res.data;
  } catch (err) {
    console.warn('Airtable update error:', err?.response?.data || err.message);
    return null;
  }
}

// Legacy helper for backwards compatibility
async function saveToAirtable(fields) {
  return airtableCreate(AIRTABLE_TABLE, fields);
}

// ============================================
// AUTH SYSTEM - OTP, Sessions, Passwords, 2FA
// ============================================

// Hashing helpers with fallback
async function hashValue(value) {
  if (argon2) {
    return await argon2.hash(value, { type: argon2.argon2id });
  }
  // Fallback: SHA-256 with salt
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(value, salt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2:${salt}:${hash}`;
}

async function verifyHash(value, stored) {
  if (argon2 && !stored.startsWith('pbkdf2:')) {
    return await argon2.verify(stored, value);
  }
  // Fallback verification
  if (stored.startsWith('pbkdf2:')) {
    const [, salt, hash] = stored.split(':');
    const verify = crypto.pbkdf2Sync(value, salt, 100000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verify, 'hex'));
  }
  return false;
}

// Generate 6-digit OTP
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Generate secure session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Rate limiters for auth endpoints
const authRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 OTP requests per 15 min per IP
  keyGenerator: (req) => req.ip,
  message: { error: 'too_many_requests', message: 'Too many OTP requests. Try again in 15 minutes.' }
});

const authVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // 20 verify attempts per 15 min per IP
  keyGenerator: (req) => req.ip,
  message: { error: 'too_many_attempts', message: 'Too many verification attempts.' }
});

const authEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 OTP requests per hour per email
  keyGenerator: (req) => req.body?.email?.toLowerCase() || req.ip,
  message: { error: 'email_rate_limited', message: 'Too many requests for this email. Try again in 1 hour.' }
});

// Audit log helper
async function logAuthEvent(eventType, details) {
  try {
    await airtableCreate('AuthAuditLog', {
      EventType: eventType,
      Email: details.email || '',
      IP: details.ip || '',
      UserAgent: details.userAgent || '',
      Success: details.success || false,
      Details: JSON.stringify(details.extra || {}),
      Timestamp: new Date().toISOString()
    });
  } catch (e) {
    console.warn('Auth audit log failed:', e.message);
  }
}

// Session middleware - checks for valid session cookie
async function sessionMiddleware(req, res, next) {
  const sessionToken = req.signedCookies?.cb_session;

  if (!sessionToken) {
    req.user = null;
    return next();
  }

  try {
    // Look up session
    const sessions = await airtableQuery('AuthSessions', `{SessionToken}='${sessionToken}'`, { maxRecords: 1 });
    const session = sessions.records?.[0];

    if (!session) {
      req.user = null;
      res.clearCookie('cb_session');
      return next();
    }

    // Check expiry
    const expiresAt = new Date(session.fields.ExpiresAt);
    if (expiresAt < new Date()) {
      req.user = null;
      res.clearCookie('cb_session');
      return next();
    }

    // Attach user info to request
    req.user = {
      sessionId: session.id,
      userId: session.fields.UserID,
      email: session.fields.Email,
      role: session.fields.Role || 'client',
      userRecordId: session.fields.UserRecordID
    };

    // Update last activity (throttled - not every request)
    const lastActivity = new Date(session.fields.LastActivity || 0);
    if (Date.now() - lastActivity.getTime() > 60000) { // Update every minute max
      airtableUpdate('AuthSessions', session.id, { LastActivity: new Date().toISOString() }).catch(() => {});
    }

    return next();
  } catch (err) {
    console.warn('Session lookup error:', err.message);
    req.user = null;
    return next();
  }
}

// Require auth middleware
function requireAuth(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'unauthorized', message: 'Please log in' });
    }
    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden', message: 'Insufficient permissions' });
    }
    return next();
  };
}

// Apply session middleware globally
app.use(sessionMiddleware);

// ============================================
// AUTH ENDPOINTS
// ============================================

// POST /auth/request-code - Request email OTP
app.post('/auth/request-code', authRequestLimiter, authEmailLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'invalid_email', message: 'Valid email required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Generate OTP
    const otp = generateOTP();
    const otpHash = await hashValue(otp);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS).toISOString();

    // Check if user exists
    const contacts = await airtableQuery('Contacts', `{Email}='${normalizedEmail}'`, { maxRecords: 1 });
    const existingUser = contacts.records?.[0];

    // Also check Team table for editors/admins
    let teamMember = null;
    if (!existingUser) {
      const team = await airtableQuery('Team', `{Email}='${normalizedEmail}'`, { maxRecords: 1 });
      teamMember = team.records?.[0];
    }

    const isNewUser = !existingUser && !teamMember;
    const userType = teamMember ? 'team' : 'contact';
    const userRecordId = existingUser?.id || teamMember?.id || null;
    const userRole = teamMember?.fields?.Role || 'client';

    // Store OTP in AuthOTPs table
    await airtableCreate('AuthOTPs', {
      Email: normalizedEmail,
      OTPHash: otpHash,
      ExpiresAt: expiresAt,
      Attempts: 0,
      Used: false,
      UserType: userType,
      UserRecordID: userRecordId,
      CreatedAt: new Date().toISOString()
    });

    // Send OTP via GHL (email/SMS)
    if (GHL_WEBHOOK_URL) {
      try {
        await axios.post(GHL_WEBHOOK_URL, {
          type: 'auth_otp',
          email: normalizedEmail,
          otp: otp,
          expires_minutes: Math.floor(OTP_EXPIRY_MS / 60000),
          is_new_user: isNewUser
        }, { timeout: 10000 });
      } catch (e) {
        console.warn('GHL OTP send failed:', e.message);
      }
    }

    // Log event
    await logAuthEvent('otp_requested', {
      email: normalizedEmail,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true,
      extra: { isNewUser, userType }
    });

    return res.json({
      success: true,
      message: 'Code sent to your email',
      is_new_user: isNewUser,
      expires_in: OTP_EXPIRY_MS
    });

  } catch (err) {
    console.error('OTP request error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/verify-code - Verify OTP and create session
app.post('/auth/verify-code', authVerifyLimiter, async (req, res) => {
  try {
    const { email, code, name, phone } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'missing_fields', message: 'Email and code required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const normalizedCode = String(code).replace(/\s/g, '');

    // Find latest unused OTP for this email
    const otps = await airtableQuery('AuthOTPs',
      `AND({Email}='${normalizedEmail}', {Used}=FALSE())`,
      { maxRecords: 1, sort: [{ field: 'CreatedAt', direction: 'desc' }] }
    );
    const otpRecord = otps.records?.[0];

    if (!otpRecord) {
      await logAuthEvent('otp_verify_failed', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: false,
        extra: { reason: 'no_otp_found' }
      });
      return res.status(400).json({ error: 'invalid_code', message: 'Invalid or expired code' });
    }

    // Check expiry
    const expiresAt = new Date(otpRecord.fields.ExpiresAt);
    if (expiresAt < new Date()) {
      await airtableUpdate('AuthOTPs', otpRecord.id, { Used: true });
      return res.status(400).json({ error: 'code_expired', message: 'Code has expired. Please request a new one.' });
    }

    // Check attempts
    const attempts = (otpRecord.fields.Attempts || 0) + 1;
    if (attempts > OTP_MAX_ATTEMPTS) {
      await airtableUpdate('AuthOTPs', otpRecord.id, { Used: true });
      await logAuthEvent('otp_lockout', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: false,
        extra: { attempts }
      });
      return res.status(429).json({ error: 'too_many_attempts', message: 'Too many attempts. Please request a new code.' });
    }

    // Verify OTP
    const isValid = await verifyHash(normalizedCode, otpRecord.fields.OTPHash);

    // Update attempts
    await airtableUpdate('AuthOTPs', otpRecord.id, { Attempts: attempts });

    if (!isValid) {
      await logAuthEvent('otp_verify_failed', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: false,
        extra: { reason: 'wrong_code', attempts }
      });
      return res.status(400).json({
        error: 'invalid_code',
        message: 'Invalid code',
        attempts_remaining: OTP_MAX_ATTEMPTS - attempts
      });
    }

    // Mark OTP as used
    await airtableUpdate('AuthOTPs', otpRecord.id, { Used: true, VerifiedAt: new Date().toISOString() });

    // Get or create user
    let userRecordId = otpRecord.fields.UserRecordID;
    let userRole = 'client';
    let userName = name || '';

    if (!userRecordId) {
      // New user - create contact
      const newContact = await airtableCreate('Contacts', {
        Email: normalizedEmail,
        'Contact Name': name || normalizedEmail.split('@')[0],
        'First Name': name?.split(' ')[0] || '',
        Phone: phone || '',
        'Email Verified': true,
        'Entitlement Status': 'trial',
        OnboardingStep: 'step-1',
        CreatedAt: new Date().toISOString()
      });
      userRecordId = newContact?.id;
    } else {
      // Existing user - mark email verified and get role
      if (otpRecord.fields.UserType === 'team') {
        const team = await airtableQuery('Team', `RECORD_ID()='${userRecordId}'`, { maxRecords: 1 });
        userRole = team.records?.[0]?.fields?.Role || 'editor';
        userName = team.records?.[0]?.fields?.Name || '';
        await airtableUpdate('Team', userRecordId, { 'Email Verified': true });
      } else {
        const contact = await airtableQuery('Contacts', `RECORD_ID()='${userRecordId}'`, { maxRecords: 1 });
        userName = contact.records?.[0]?.fields?.['Contact Name'] || contact.records?.[0]?.fields?.['First Name'] || '';
        await airtableUpdate('Contacts', userRecordId, { 'Email Verified': true });
      }
    }

    // Create session
    const sessionToken = generateSessionToken();
    const sessionExpiresAt = new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();

    await airtableCreate('AuthSessions', {
      SessionToken: sessionToken,
      UserID: normalizedEmail,
      UserRecordID: userRecordId,
      Email: normalizedEmail,
      Role: userRole,
      ExpiresAt: sessionExpiresAt,
      LastActivity: new Date().toISOString(),
      IP: req.ip,
      UserAgent: req.get('User-Agent'),
      CreatedAt: new Date().toISOString()
    });

    // Set session cookie
    res.cookie('cb_session', sessionToken, {
      httpOnly: true,
      secure: IS_PRODUCTION,
      signed: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      maxAge: SESSION_MAX_AGE_MS,
      domain: IS_PRODUCTION ? '.contentbug.io' : undefined
    });

    // Log success
    await logAuthEvent('login_success', {
      email: normalizedEmail,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true,
      extra: { role: userRole, isNewUser: !otpRecord.fields.UserRecordID }
    });

    return res.json({
      success: true,
      user: {
        email: normalizedEmail,
        name: userName,
        role: userRole,
        record_id: userRecordId
      },
      is_new_user: !otpRecord.fields.UserRecordID,
      session_expires_at: sessionExpiresAt
    });

  } catch (err) {
    console.error('OTP verify error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/logout - Destroy session
app.post('/auth/logout', async (req, res) => {
  try {
    const sessionToken = req.signedCookies?.cb_session;

    if (sessionToken) {
      // Find and delete session
      const sessions = await airtableQuery('AuthSessions', `{SessionToken}='${sessionToken}'`, { maxRecords: 1 });
      const session = sessions.records?.[0];

      if (session) {
        await airtableUpdate('AuthSessions', session.id, {
          LoggedOutAt: new Date().toISOString(),
          SessionToken: '' // Invalidate
        });

        await logAuthEvent('logout', {
          email: session.fields.Email,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          success: true
        });
      }
    }

    res.clearCookie('cb_session', {
      httpOnly: true,
      secure: IS_PRODUCTION,
      signed: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      domain: IS_PRODUCTION ? '.contentbug.io' : undefined
    });

    return res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// GET /auth/me - Get current user info with subscription data
app.get('/auth/me', requireAuth(), async (req, res) => {
  try {
    let subscriptionData = {};

    // Fetch subscription info from Contacts table for clients
    if (req.user.role === 'client' && req.user.userRecordId) {
      const contacts = await airtableQuery('Contacts',
        `RECORD_ID()='${req.user.userRecordId}'`,
        { maxRecords: 1 }
      );
      const contact = contacts.records?.[0];
      if (contact?.fields) {
        subscriptionData = {
          subscription_status: contact.fields['Subscription Status'] || 'Free Trial',
          subscription_type: contact.fields['Subscription Type'] || 'Free Trial',
          plan: contact.fields['Subscription Type'] || 'Free Trial',
          entitlement_status: contact.fields['Entitlement Status'] || 'trial',
          onboarding_step: contact.fields['OnboardingStep'] || null,
          name: contact.fields['Contact Name'] || contact.fields['First Name'] || ''
        };

        // Calculate edit slots based on plan
        const planSlots = {
          'Pro': 3,
          'Gold': 2,
          'Silver': 1,
          'Basic': 1,
          'Creator': 2,
          'Growth': 1,
          'Starter': 1,
          'Free Trial': 1
        };
        subscriptionData.edit_slots = planSlots[subscriptionData.plan] || 1;
      }
    }

    return res.json({
      authenticated: true,
      user: {
        email: req.user.email,
        role: req.user.role,
        record_id: req.user.userRecordId,
        ...subscriptionData
      }
    });
  } catch (err) {
    console.error('Auth me error:', err);
    // Return basic info on error
    return res.json({
      authenticated: true,
      user: {
        email: req.user.email,
        role: req.user.role,
        record_id: req.user.userRecordId
      }
    });
  }
});

// GET /auth/status - Check auth status (no auth required)
app.get('/auth/status', (req, res) => {
  return res.json({
    authenticated: !!req.user,
    user: req.user ? {
      email: req.user.email,
      role: req.user.role
    } : null
  });
});

// ============================================
// PASSWORD AUTH (SCAFFOLD)
// ============================================

// POST /auth/set-password - Set password for account
app.post('/auth/set-password', requireAuth(), async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password.length < 8) {
      return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters' });
    }

    // Check password strength (basic)
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    if (!hasUpper || !hasLower || !hasNumber) {
      return res.status(400).json({
        error: 'weak_password',
        message: 'Password must contain uppercase, lowercase, and numbers'
      });
    }

    const passwordHash = await hashValue(password);

    // Store in AuthCredentials table (NOT Airtable for production - use encrypted storage)
    // For now, scaffold with Airtable
    const existing = await airtableQuery('AuthCredentials', `{Email}='${req.user.email}'`, { maxRecords: 1 });

    if (existing.records?.[0]) {
      await airtableUpdate('AuthCredentials', existing.records[0].id, {
        PasswordHash: passwordHash,
        UpdatedAt: new Date().toISOString()
      });
    } else {
      await airtableCreate('AuthCredentials', {
        Email: req.user.email,
        UserRecordID: req.user.userRecordId,
        PasswordHash: passwordHash,
        HasPassword: true,
        CreatedAt: new Date().toISOString()
      });
    }

    await logAuthEvent('password_set', {
      email: req.user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    return res.json({ success: true, message: 'Password set successfully' });
  } catch (err) {
    console.error('Set password error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/login-password - Login with email + password
app.post('/auth/login-password', authVerifyLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Get stored credentials
    const creds = await airtableQuery('AuthCredentials', `{Email}='${normalizedEmail}'`, { maxRecords: 1 });
    const credential = creds.records?.[0];

    if (!credential || !credential.fields.PasswordHash) {
      await logAuthEvent('password_login_failed', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: false,
        extra: { reason: 'no_password_set' }
      });
      return res.status(400).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
    }

    // Verify password
    const isValid = await verifyHash(password, credential.fields.PasswordHash);

    if (!isValid) {
      await logAuthEvent('password_login_failed', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: false,
        extra: { reason: 'wrong_password' }
      });
      return res.status(400).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
    }

    // Get user details
    let userRole = 'client';
    let userName = '';
    const userRecordId = credential.fields.UserRecordID;

    const contacts = await airtableQuery('Contacts', `RECORD_ID()='${userRecordId}'`, { maxRecords: 1 });
    if (contacts.records?.[0]) {
      userName = contacts.records[0].fields['Contact Name'] || contacts.records[0].fields['First Name'] || '';
    } else {
      const team = await airtableQuery('Team', `RECORD_ID()='${userRecordId}'`, { maxRecords: 1 });
      if (team.records?.[0]) {
        userRole = team.records[0].fields.Role || 'editor';
        userName = team.records[0].fields.Name || '';
      }
    }

    // Create session
    const sessionToken = generateSessionToken();
    const sessionExpiresAt = new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();

    await airtableCreate('AuthSessions', {
      SessionToken: sessionToken,
      UserID: normalizedEmail,
      UserRecordID: userRecordId,
      Email: normalizedEmail,
      Role: userRole,
      ExpiresAt: sessionExpiresAt,
      LastActivity: new Date().toISOString(),
      IP: req.ip,
      UserAgent: req.get('User-Agent'),
      CreatedAt: new Date().toISOString()
    });

    res.cookie('cb_session', sessionToken, {
      httpOnly: true,
      secure: IS_PRODUCTION,
      signed: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      maxAge: SESSION_MAX_AGE_MS,
      domain: IS_PRODUCTION ? '.contentbug.io' : undefined
    });

    await logAuthEvent('password_login_success', {
      email: normalizedEmail,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    return res.json({
      success: true,
      user: {
        email: normalizedEmail,
        name: userName,
        role: userRole,
        record_id: userRecordId
      }
    });
  } catch (err) {
    console.error('Password login error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/change-password - Change password (requires current password)
app.post('/auth/change-password', requireAuth(), async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    if (new_password.length < 8) {
      return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters' });
    }

    // Get current credentials
    const creds = await airtableQuery('AuthCredentials', `{Email}='${req.user.email}'`, { maxRecords: 1 });
    const credential = creds.records?.[0];

    if (!credential || !credential.fields.PasswordHash) {
      return res.status(400).json({ error: 'no_password_set' });
    }

    // Verify current password
    const isValid = await verifyHash(current_password, credential.fields.PasswordHash);
    if (!isValid) {
      return res.status(400).json({ error: 'invalid_current_password' });
    }

    // Hash and save new password
    const newHash = await hashValue(new_password);
    await airtableUpdate('AuthCredentials', credential.id, {
      PasswordHash: newHash,
      UpdatedAt: new Date().toISOString()
    });

    await logAuthEvent('password_changed', {
      email: req.user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    return res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ============================================
// 2FA SCAFFOLD (TOTP)
// ============================================

// POST /auth/2fa/setup - Generate TOTP secret
app.post('/auth/2fa/setup', requireAuth(), async (req, res) => {
  try {
    if (!authenticator) {
      return res.status(501).json({ error: 'totp_not_available', message: '2FA not configured on server' });
    }

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(req.user.email, 'ContentBug', secret);

    // Store secret temporarily (not enabled until verified)
    const existing = await airtableQuery('AuthCredentials', `{Email}='${req.user.email}'`, { maxRecords: 1 });

    if (existing.records?.[0]) {
      await airtableUpdate('AuthCredentials', existing.records[0].id, {
        TOTPSecretPending: secret,
        TOTPSetupAt: new Date().toISOString()
      });
    } else {
      await airtableCreate('AuthCredentials', {
        Email: req.user.email,
        UserRecordID: req.user.userRecordId,
        TOTPSecretPending: secret,
        TOTPSetupAt: new Date().toISOString()
      });
    }

    // Generate recovery codes
    const recoveryCodes = Array.from({ length: 8 }, () =>
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    return res.json({
      success: true,
      secret,
      otpauth_url: otpauth,
      recovery_codes: recoveryCodes, // Show once - hash before storing
      message: 'Scan QR code with authenticator app, then verify with a code'
    });
  } catch (err) {
    console.error('2FA setup error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/2fa/verify-setup - Verify TOTP and enable 2FA
app.post('/auth/2fa/verify-setup', requireAuth(), async (req, res) => {
  try {
    if (!authenticator) {
      return res.status(501).json({ error: 'totp_not_available' });
    }

    const { code, recovery_codes } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'missing_code' });
    }

    const creds = await airtableQuery('AuthCredentials', `{Email}='${req.user.email}'`, { maxRecords: 1 });
    const credential = creds.records?.[0];

    if (!credential || !credential.fields.TOTPSecretPending) {
      return res.status(400).json({ error: 'no_pending_setup' });
    }

    const isValid = authenticator.verify({
      token: code,
      secret: credential.fields.TOTPSecretPending
    });

    if (!isValid) {
      return res.status(400).json({ error: 'invalid_code' });
    }

    // Hash recovery codes
    const hashedCodes = await Promise.all(
      (recovery_codes || []).map(c => hashValue(c))
    );

    // Enable 2FA
    await airtableUpdate('AuthCredentials', credential.id, {
      TOTPSecret: credential.fields.TOTPSecretPending, // Move to active
      TOTPSecretPending: '',
      TOTPEnabled: true,
      TOTPEnabledAt: new Date().toISOString(),
      RecoveryCodesHash: JSON.stringify(hashedCodes)
    });

    await logAuthEvent('2fa_enabled', {
      email: req.user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    return res.json({ success: true, message: '2FA enabled successfully' });
  } catch (err) {
    console.error('2FA verify setup error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /auth/2fa/disable - Disable 2FA
app.post('/auth/2fa/disable', requireAuth(), async (req, res) => {
  try {
    const { code } = req.body;

    const creds = await airtableQuery('AuthCredentials', `{Email}='${req.user.email}'`, { maxRecords: 1 });
    const credential = creds.records?.[0];

    if (!credential || !credential.fields.TOTPEnabled) {
      return res.status(400).json({ error: '2fa_not_enabled' });
    }

    // Verify with TOTP code
    if (authenticator && code) {
      const isValid = authenticator.verify({
        token: code,
        secret: credential.fields.TOTPSecret
      });

      if (!isValid) {
        return res.status(400).json({ error: 'invalid_code' });
      }
    }

    await airtableUpdate('AuthCredentials', credential.id, {
      TOTPSecret: '',
      TOTPEnabled: false,
      TOTPDisabledAt: new Date().toISOString(),
      RecoveryCodesHash: ''
    });

    await logAuthEvent('2fa_disabled', {
      email: req.user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    return res.json({ success: true, message: '2FA disabled' });
  } catch (err) {
    console.error('2FA disable error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ============================================
// AI PROVIDERS
// ============================================

async function callClaude(prompt, opts = {}) {
  if (!CLAUDE_API_KEY) throw new Error('No CLAUDE_API_KEY configured');

  // Use Messages API format
  const payload = {
    model: opts.model || CLAUDE_MODEL,
    max_tokens: opts.max_tokens || MAX_TOKENS,
    messages: [{ role: 'user', content: prompt }]
  };

  if (typeof opts.temperature === 'number') {
    payload.temperature = opts.temperature;
  }

  const res = await axios.post(CLAUDE_API_URL, payload, {
    headers: {
      'x-api-key': CLAUDE_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    }
  });

  const raw = res.data;
  let text = '';
  if (raw?.content?.[0]?.text) {
    text = raw.content[0].text;
  } else if (raw?.completion) {
    text = raw.completion;
  } else {
    text = JSON.stringify(raw);
  }

  return { text: String(text).trim(), raw };
}

async function callOpenAI(messages, opts = {}) {
  if (!OPENAI_API_KEY) throw new Error('No OPENAI_API_KEY configured');
  const url = process.env.OPENAI_API_URL || 'https://api.openai.com/v1/chat/completions';
  const payload = {
    model: opts.model || 'gpt-4o-mini',
    messages,
    max_tokens: opts.max_tokens || MAX_TOKENS,
    temperature: typeof opts.temperature === 'number' ? opts.temperature : 0.2
  };
  const res = await axios.post(url, payload, {
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' }
  });
  const raw = res.data;
  const text = raw?.choices?.[0]?.message?.content || raw?.choices?.[0]?.text || JSON.stringify(raw);
  return { text: String(text).trim(), raw };
}

// ============================================
// MAKE.COM WEBHOOK ENDPOINTS (existing)
// ============================================

app.post('/webhook', verifySecret('x-make-secret', MAKE_SHARED_SECRET), async (req, res) => {
  try {
    const body = req.body || {};
    const input = body.input || body.message || body.text;
    const provider = (body.provider || 'claude').toLowerCase();
    const convoId = body.conversation_id || `conv-${Date.now()}`;
    if (!input) return res.status(400).json({ error: 'missing input' });

    let aiResult;
    if (provider === 'openai') {
      const messages = [{ role: 'user', content: input }];
      aiResult = await callOpenAI(messages, { model: body.model, max_tokens: body.max_tokens, temperature: body.temperature });
    } else {
      aiResult = await callClaude(input, { model: body.model, max_tokens: body.max_tokens, temperature: body.temperature });
    }

    await saveToAirtable({
      ConversationID: convoId,
      Source: body.source || 'make',
      Input: input,
      Response: aiResult.text,
      Provider: provider,
      Raw: JSON.stringify(aiResult.raw).slice(0, 30000)
    });

    if (GHL_WEBHOOK_URL) {
      try {
        await axios.post(GHL_WEBHOOK_URL, { conversation_id: convoId, provider, response: aiResult.text }, { timeout: 5000 });
      } catch (err) {
        console.warn('GHL forward failed:', err?.message || err);
      }
    }

    return res.json({ conversation_id: convoId, response: aiResult.text, provider, raw: aiResult.raw });
  } catch (err) {
    console.error('Webhook error:', err?.response?.data || err.message || err);
    return res.status(500).json({ error: 'internal_error', details: err?.response?.data || err.message });
  }
});

app.post('/webhook/ghl', verifySecret('x-ghl-secret', GHL_SHARED_SECRET), async (req, res, next) => {
  const payload = req.body || {};
  const normalized = {
    input: payload?.message || payload?.text || payload?.lead_message,
    provider: payload?.provider || 'claude',
    conversation_id: payload?.conversation_id
  };
  req.body = normalized;
  return app._router.handle(req, res, next);
});

app.get('/conversation/:id', async (req, res) => {
  const id = req.params.id;
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return res.status(501).json({ error: 'persistence not configured' });
  try {
    const result = await airtableQuery(AIRTABLE_TABLE, `{ConversationID}='${id}'`, { maxRecords: 1 });
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'airtable_error', details: err?.response?.data || err.message });
  }
});

// ============================================
// CHAT SYSTEM ENDPOINTS (NEW)
// ============================================

// POST /chat/messages - Send a new message
app.post('/chat/messages', verifyApiKey, async (req, res) => {
  try {
    const { channel_id, sender_id, sender_name, sender_role, content, message_type } = req.body;

    if (!channel_id || !sender_id || !content) {
      return res.status(400).json({ error: 'missing required fields: channel_id, sender_id, content' });
    }

    const messageId = `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const record = await airtableCreate(AIRTABLE_CHAT_TABLE, {
      MessageID: messageId,
      ChannelID: channel_id,
      SenderID: sender_id,
      SenderName: sender_name || 'Unknown',
      SenderRole: sender_role || 'client', // client, editor, admin
      Content: content,
      MessageType: message_type || 'text', // text, file, system
      Timestamp: new Date().toISOString(),
      Read: false
    });

    if (!record) {
      return res.status(500).json({ error: 'failed to save message' });
    }

    return res.json({
      success: true,
      message_id: messageId,
      record_id: record.id,
      timestamp: record.fields.Timestamp
    });
  } catch (err) {
    console.error('Chat send error:', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// GET /chat/messages/:channel_id - Get messages for a channel
app.get('/chat/messages/:channel_id', verifyApiKey, async (req, res) => {
  try {
    const { channel_id } = req.params;
    const { since, limit } = req.query;

    let filter = `{ChannelID}='${channel_id}'`;
    if (since) {
      // Get messages since timestamp
      filter = `AND({ChannelID}='${channel_id}', IS_AFTER({Timestamp}, '${since}'))`;
    }

    const result = await airtableQuery(AIRTABLE_CHAT_TABLE, filter, {
      maxRecords: parseInt(limit) || 50,
      sort: [{ field: 'Timestamp', direction: 'desc' }]
    });

    // Format for frontend
    const messages = result.records.map(r => ({
      id: r.id,
      message_id: r.fields.MessageID,
      channel_id: r.fields.ChannelID,
      sender_id: r.fields.SenderID,
      sender_name: r.fields.SenderName,
      sender_role: r.fields.SenderRole,
      content: r.fields.Content,
      message_type: r.fields.MessageType,
      timestamp: r.fields.Timestamp,
      read: r.fields.Read
    })).reverse(); // Reverse to get chronological order

    return res.json({ messages, count: messages.length });
  } catch (err) {
    console.error('Chat fetch error:', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// GET /chat/channels/:user_id - Get channels for a user
app.get('/chat/channels/:user_id', verifyApiKey, async (req, res) => {
  try {
    const { user_id } = req.params;
    const { role } = req.query;

    // For admins/editors, get all channels. For clients, get their channel only.
    let filter;
    if (role === 'admin' || role === 'editor') {
      filter = ''; // Get all
    } else {
      filter = `FIND('${user_id}', {Members})`;
    }

    const result = await airtableQuery('ChatChannels', filter, {
      sort: [{ field: 'LastActivity', direction: 'desc' }]
    });

    const channels = result.records.map(r => ({
      id: r.id,
      channel_id: r.fields.ChannelID,
      name: r.fields.Name,
      type: r.fields.Type, // client, team, project
      members: r.fields.Members,
      last_activity: r.fields.LastActivity,
      unread_count: r.fields.UnreadCount || 0
    }));

    return res.json({ channels });
  } catch (err) {
    console.error('Channels fetch error:', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// POST /chat/channels - Create a new channel
app.post('/chat/channels', verifyApiKey, async (req, res) => {
  try {
    const { name, type, members, created_by } = req.body;

    if (!name || !type) {
      return res.status(400).json({ error: 'missing required fields: name, type' });
    }

    const channelId = `ch-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    const record = await airtableCreate('ChatChannels', {
      ChannelID: channelId,
      Name: name,
      Type: type, // client, team, project
      Members: members || '',
      CreatedBy: created_by,
      CreatedAt: new Date().toISOString(),
      LastActivity: new Date().toISOString()
    });

    if (!record) {
      return res.status(500).json({ error: 'failed to create channel' });
    }

    return res.json({
      success: true,
      channel_id: channelId,
      record_id: record.id
    });
  } catch (err) {
    console.error('Channel create error:', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// PATCH /chat/messages/:record_id/read - Mark message as read
app.patch('/chat/messages/:record_id/read', verifyApiKey, async (req, res) => {
  try {
    const { record_id } = req.params;

    const result = await airtableUpdate(AIRTABLE_CHAT_TABLE, record_id, { Read: true });

    if (!result) {
      return res.status(500).json({ error: 'failed to update message' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Mark read error:', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// GET /chat/poll/:channel_id - Long-polling endpoint for real-time-ish updates
app.get('/chat/poll/:channel_id', verifyApiKey, async (req, res) => {
  try {
    const { channel_id } = req.params;
    const { since } = req.query;

    // Check for new messages
    let filter = `{ChannelID}='${channel_id}'`;
    if (since) {
      filter = `AND({ChannelID}='${channel_id}', IS_AFTER({Timestamp}, '${since}'))`;
    }

    const result = await airtableQuery(AIRTABLE_CHAT_TABLE, filter, {
      maxRecords: 20,
      sort: [{ field: 'Timestamp', direction: 'desc' }]
    });

    const messages = result.records.map(r => ({
      id: r.id,
      message_id: r.fields.MessageID,
      sender_id: r.fields.SenderID,
      sender_name: r.fields.SenderName,
      sender_role: r.fields.SenderRole,
      content: r.fields.Content,
      timestamp: r.fields.Timestamp
    })).reverse();

    return res.json({
      has_new: messages.length > 0,
      messages,
      server_time: new Date().toISOString()
    });
  } catch (err) {
    console.error('Poll error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ============================================
// TEAM INBOX ENDPOINTS (for editors/admins)
// ============================================

// GET /inbox - Get all channels with unread messages
app.get('/inbox', verifyApiKey, async (req, res) => {
  try {
    const { role } = req.query;

    if (role !== 'admin' && role !== 'editor') {
      return res.status(403).json({ error: 'inbox only available for admins and editors' });
    }

    // Get all channels with recent activity
    const channels = await airtableQuery('ChatChannels', '', {
      sort: [{ field: 'LastActivity', direction: 'desc' }],
      maxRecords: 50
    });

    // For each channel, get latest message preview
    const inbox = await Promise.all(channels.records.map(async (ch) => {
      const messages = await airtableQuery(AIRTABLE_CHAT_TABLE, `{ChannelID}='${ch.fields.ChannelID}'`, {
        maxRecords: 1,
        sort: [{ field: 'Timestamp', direction: 'desc' }]
      });

      const lastMessage = messages.records[0];

      return {
        channel_id: ch.fields.ChannelID,
        name: ch.fields.Name,
        type: ch.fields.Type,
        last_activity: ch.fields.LastActivity,
        last_message: lastMessage ? {
          content: lastMessage.fields.Content?.substring(0, 100),
          sender: lastMessage.fields.SenderName,
          timestamp: lastMessage.fields.Timestamp
        } : null,
        unread_count: ch.fields.UnreadCount || 0
      };
    }));

    return res.json({ inbox });
  } catch (err) {
    console.error('Inbox error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ============================================
// GOOGLE DRIVE FILE UPLOAD (PRODUCTION HARDENED)
// ============================================

// Root folder for all client content
const DRIVE_ROOT_FOLDER_ID = process.env.GOOGLE_DRIVE_ROOT_FOLDER || '131CAkK8L0cWy2BJX9o8m-h3arwFvPr5c';

// In-memory cache for folder IDs (persisted to Airtable)
const folderCache = new Map();

/**
 * Get or create a folder in Drive
 * @param {string} name - Folder name
 * @param {string} parentId - Parent folder ID
 * @returns {Promise<{id: string, webViewLink: string}>}
 */
async function getOrCreateFolder(name, parentId) {
  if (!driveServiceReady) return null;

  const cacheKey = `${parentId}:${name}`;
  if (folderCache.has(cacheKey)) {
    return folderCache.get(cacheKey);
  }

  try {
    // Search for existing folder
    const searchResponse = await googleDrive.files.list({
      q: `name='${name.replace(/'/g, "\\'")}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      fields: 'files(id, name, webViewLink)',
      pageSize: 1
    });

    if (searchResponse.data.files && searchResponse.data.files.length > 0) {
      const folder = searchResponse.data.files[0];
      folderCache.set(cacheKey, folder);
      return folder;
    }

    // Create new folder
    const createResponse = await googleDrive.files.create({
      requestBody: {
        name: name,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [parentId]
      },
      fields: 'id, name, webViewLink'
    });

    const folder = createResponse.data;
    folderCache.set(cacheKey, folder);
    console.log(`[Drive] Created folder: ${name} (${folder.id})`);
    return folder;

  } catch (err) {
    console.error(`[Drive] Folder operation failed for ${name}:`, err.message);
    return null;
  }
}

/**
 * Get or create complete client folder structure
 * @param {string} clientName - Client display name
 * @param {string} clientId - Airtable client ID
 * @returns {Promise<object>} Folder IDs for each subfolder
 */
async function getClientFolderStructure(clientName, clientId) {
  if (!driveServiceReady) return null;

  const sanitizedName = clientName.replace(/[<>:"/\\|?*]/g, '').trim();
  const clientFolderName = `${sanitizedName} (${clientId})`;

  // Get or create client root folder
  const clientFolder = await getOrCreateFolder(clientFolderName, DRIVE_ROOT_FOLDER_ID);
  if (!clientFolder) return null;

  // Create all subfolders
  const structure = {
    root: clientFolder.id,
    rootLink: clientFolder.webViewLink
  };

  for (const subfolderName of DRIVE_FOLDER_STRUCTURE.SUBFOLDERS) {
    const subfolder = await getOrCreateFolder(subfolderName, clientFolder.id);
    if (subfolder) {
      const key = subfolderName.toLowerCase().replace(/\s+/g, '_');
      structure[key] = subfolder.id;
      structure[`${key}_link`] = subfolder.webViewLink;
    }

    // Create Brand Asset subfolders
    if (subfolderName === 'Brand Assets' && subfolder) {
      for (const brandSub of DRIVE_FOLDER_STRUCTURE.BRAND_ASSET_SUBFOLDERS) {
        const brandSubfolder = await getOrCreateFolder(brandSub, subfolder.id);
        if (brandSubfolder) {
          const brandKey = `brand_${brandSub.toLowerCase()}`;
          structure[brandKey] = brandSubfolder.id;
          structure[`${brandKey}_link`] = brandSubfolder.webViewLink;
        }
      }
    }
  }

  return structure;
}

/**
 * Upload file to Drive with full validation
 * @param {object} file - Multer file object
 * @param {string} folderId - Target folder ID
 * @param {string} customName - Optional custom filename
 * @returns {Promise<object>} Upload result
 */
async function uploadToDrive(file, folderId, customName = null) {
  if (!driveServiceReady) {
    return { success: false, error: 'drive_not_ready' };
  }

  // Validate file size by category
  const category = file.category || 'default';
  const maxSize = UPLOAD_LIMITS[category] || UPLOAD_LIMITS.default;

  if (file.size > maxSize) {
    return {
      success: false,
      error: 'file_too_large',
      message: `${category} files must be under ${Math.round(maxSize / 1024 / 1024)}MB`
    };
  }

  try {
    const bufferStream = new Readable();
    bufferStream.push(file.buffer);
    bufferStream.push(null);

    const fileName = customName || file.originalname;

    const driveResponse = await googleDrive.files.create({
      requestBody: {
        name: fileName,
        parents: [folderId]
      },
      media: {
        mimeType: file.mimetype,
        body: bufferStream
      },
      fields: 'id, name, webViewLink, size, mimeType, createdTime'
    });

    const driveFile = driveResponse.data;

    // Set link sharing (reader access for anyone with link)
    await googleDrive.permissions.create({
      fileId: driveFile.id,
      requestBody: {
        role: 'reader',
        type: 'anyone'
      }
    });

    console.log(`[Drive] Uploaded: ${driveFile.name} (${Math.round(file.size / 1024 / 1024)}MB) -> ${driveFile.id}`);

    return {
      success: true,
      file: {
        id: driveFile.id,
        name: driveFile.name,
        size: parseInt(driveFile.size),
        mimeType: driveFile.mimeType,
        viewLink: driveFile.webViewLink || `https://drive.google.com/file/d/${driveFile.id}/view`,
        directLink: `https://drive.google.com/uc?export=download&id=${driveFile.id}`,
        embedLink: `https://drive.google.com/file/d/${driveFile.id}/preview`,
        createdTime: driveFile.createdTime,
        folderId: folderId
      }
    };

  } catch (err) {
    console.error('[Drive] Upload failed:', err.message);
    return { success: false, error: 'upload_failed', message: err.message };
  }
}

// Upload rate limiter (more restrictive for uploads)
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 uploads per 15 min
  message: { error: 'upload_rate_limit', message: 'Too many uploads, try again later' }
});

// GET /api/drive/status - Check Drive service status
app.get('/api/drive/status', (req, res) => {
  return res.json({
    available: driveServiceReady,
    error: driveServiceReady ? null : driveInitError,
    limits: {
      video: `${UPLOAD_LIMITS.video / 1024 / 1024}MB`,
      audio: `${UPLOAD_LIMITS.audio / 1024 / 1024}MB`,
      image: `${UPLOAD_LIMITS.image / 1024 / 1024}MB`
    },
    supportedTypes: Object.keys(ALLOWED_MIME_TYPES)
  });
});

// Backward compatibility alias
app.get('/api/upload/status', (req, res) => {
  return res.json({
    available: driveServiceReady,
    maxSize: '500MB',
    supportedTypes: ['video/*', 'audio/*', 'image/*']
  });
});

// POST /api/drive/init-client - Initialize client folder structure
app.post('/api/drive/init-client', requireAuth(), async (req, res) => {
  try {
    if (!driveServiceReady) {
      return res.json({ success: false, error: 'drive_not_available' });
    }

    const { clientName, clientId } = req.body;

    if (!clientName || !clientId) {
      return res.status(400).json({ error: 'missing_fields', message: 'clientName and clientId required' });
    }

    const structure = await getClientFolderStructure(clientName, clientId);

    if (!structure) {
      return res.status(500).json({ error: 'folder_creation_failed' });
    }

    // Save folder structure to Airtable
    if (AIRTABLE_API_KEY) {
      try {
        await airtableUpdate('Contacts', clientId, {
          'Drive Root Folder': structure.root,
          'Drive Root Link': structure.rootLink,
          'Drive Raw Uploads': structure.raw_uploads || '',
          'Drive Brand Assets': structure.brand_assets || '',
          'Drive Approved Exports': structure.approved_exports || ''
        });
      } catch (atErr) {
        console.warn('[Drive] Could not save folder structure to Airtable:', atErr.message);
      }
    }

    return res.json({ success: true, folders: structure });

  } catch (err) {
    console.error('[Drive] Init client error:', err);
    return res.status(500).json({ error: 'internal_error', message: err.message });
  }
});

// POST /api/drive/upload - Upload file to Drive (production endpoint)
app.post('/api/drive/upload', requireAuth(), uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    // Check Drive availability
    if (!driveServiceReady) {
      return res.json({
        success: false,
        error: 'drive_not_available',
        message: 'File uploads are currently disabled'
      });
    }

    // Validate file exists
    if (!req.file) {
      return res.status(400).json({ error: 'no_file', message: 'No file provided' });
    }

    const file = req.file;
    const {
      clientId,
      clientName,
      uploadType,      // 'raw_upload', 'logo', 'thumbnail', 'headshot', 'creator_lab', 'export'
      projectId,
      customFileName
    } = req.body;

    // Determine target folder
    let targetFolderId = DRIVE_ROOT_FOLDER_ID;

    if (clientId && clientName) {
      const structure = await getClientFolderStructure(clientName, clientId);

      if (structure) {
        // Route to correct subfolder based on upload type
        switch (uploadType) {
          case 'logo':
            targetFolderId = structure.brand_logos || structure.brand_assets || structure.root;
            break;
          case 'thumbnail':
            targetFolderId = structure.brand_thumbnails || structure.brand_assets || structure.root;
            break;
          case 'headshot':
            targetFolderId = structure.brand_headshots || structure.brand_assets || structure.root;
            break;
          case 'creator_lab':
            targetFolderId = structure.creator_lab_recordings || structure.root;
            break;
          case 'export':
            targetFolderId = structure.approved_exports || structure.root;
            break;
          case 'raw_upload':
          default:
            targetFolderId = structure.raw_uploads || structure.root;
            break;
        }
      }
    }

    // Perform upload
    const result = await uploadToDrive(file, targetFolderId, customFileName);

    if (!result.success) {
      return res.status(400).json(result);
    }

    // Save to Airtable if project/client provided
    if (AIRTABLE_API_KEY && result.file) {
      try {
        // Determine which table and field to update
        if (projectId) {
          const fieldMap = {
            raw_upload: 'Raw Footage Link',
            export: 'Deliverable Link'
          };
          const field = fieldMap[uploadType] || 'Raw Footage Link';

          await airtableUpdate('Projects', projectId, {
            [field]: result.file.viewLink,
            'Drive File ID': result.file.id,
            'Drive Folder ID': targetFolderId,
            'Upload Timestamp': new Date().toISOString()
          });
        } else if (clientId && uploadType) {
          const fieldMap = {
            logo: 'Logo URL',
            thumbnail: 'Thumbnail URL',
            headshot: 'Headshot URL'
          };
          const field = fieldMap[uploadType];

          if (field) {
            await airtableUpdate('Contacts', clientId, {
              [field]: result.file.viewLink,
              [`${field} Drive ID`]: result.file.id
            });
          }
        }
      } catch (atErr) {
        console.warn('[Drive] Airtable update failed:', atErr.message);
        // Don't fail the upload if Airtable update fails
      }
    }

    return res.json({
      success: true,
      file: result.file,
      uploadType: uploadType || 'raw_upload',
      savedToAirtable: !!AIRTABLE_API_KEY
    });

  } catch (err) {
    // Handle multer errors
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'file_too_large', message: 'File exceeds maximum size' });
    }
    if (err.message && err.message.includes('File type not allowed')) {
      return res.status(400).json({ error: 'invalid_file_type', message: err.message });
    }

    console.error('[Drive] Upload endpoint error:', err);
    return res.status(500).json({ error: 'upload_failed', message: err.message });
  }
});

// Backward compatibility: /api/upload still works
app.post('/api/upload', requireAuth(), uploadLimiter, upload.single('file'), async (req, res) => {
  // Redirect to new endpoint logic
  req.body.uploadType = req.body.uploadType || 'raw_upload';
  return res.redirect(307, '/api/drive/upload');
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`ContentBug Production MCP Server v2.1.0`);
  console.log(`${'='.repeat(50)}`);
  console.log(`Port: ${PORT}`);
  console.log(`Environment: ${IS_PRODUCTION ? 'PRODUCTION' : 'development'}`);
  console.log(`Health check: /healthz`);
  console.log(`\nServices:`);
  console.log(`  Auth:    enabled`);
  console.log(`  Chat:    enabled`);
  console.log(`  Drive:   ${driveServiceReady ? 'enabled' : 'DISABLED - ' + driveInitError}`);
  console.log(`\n${'='.repeat(50)}\n`);
});
