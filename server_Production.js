// server_Production.js
// ContentBug Production MCP Server v2.4.0
// Handles: Make webhooks, Claude/OpenAI AI, Airtable storage, GHL forwarding, chat, auth, Google Drive, Apify Research, Creator Intelligence
// v2.4.0: UNIFIED PORTAL - Single portal.html for all roles (client, editor, admin, owner)
// v2.3.2: Added DEV_AUTH_BYPASS for founder testing (sean@contentbug.io only)
// v2.3.1: Improved OTP delivery with GHL API direct email + webhook fallback
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

// Apify config
const APIFY_API_TOKEN = process.env.APIFY_API_TOKEN || '';
const APIFY_API_URL = 'https://api.apify.com/v2';

// GHL API config for direct email sending
const GHL_API_KEY = process.env.GHL_API_KEY || '';
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || '';
const GHL_API_URL = 'https://services.leadconnectorhq.com';
const GHL_PRIVATE_TOKEN = process.env.GHL_PRIVATE_INTEGRATION || '';

// Email delivery debug mode (set EMAIL_DELIVERY_DEBUG=true to log OTP)
const EMAIL_DELIVERY_DEBUG = process.env.EMAIL_DELIVERY_DEBUG === 'true';

// DEV AUTH BYPASS - FOUNDER ONLY (sean@contentbug.io)
// Set DEV_AUTH_BYPASS=true in Railway to enable, false to disable (default)
const DEV_AUTH_BYPASS = process.env.DEV_AUTH_BYPASS === 'true';
const DEV_BYPASS_EMAIL = 'sean@contentbug.io';
const DEV_BYPASS_CODE = '000000';

// Admin notification emails for OTP requests
const OTP_NOTIFY_EMAILS = ['stockton@contentbug.io', 'sean@contentbug.io'];

// Auth config
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE_MS = parseInt(process.env.SESSION_MAX_AGE_MS || String(24 * 60 * 60 * 1000), 10); // 24h default
const OTP_EXPIRY_MS = parseInt(process.env.OTP_EXPIRY_MS || String(10 * 60 * 1000), 10); // 10 min
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || '5', 10);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const app = express();

// CORS - allow portal frontend with credentials
app.use(cors({
  origin: ['https://app.contentbug.io', 'https://go.contentbug.io', 'https://portalv2.contentbug.io', 'https://contentbug.io', 'https://content-portal-mcp-production.up.railway.app', 'http://localhost:3000', 'http://127.0.0.1:5500'],
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
  version: 'production-2.5.1',
  auth: true,
  portal: true,
  drive: {
    ready: driveServiceReady,
    error: driveServiceReady ? null : driveInitError
  },
  apify: {
    configured: !!APIFY_API_TOKEN,
    ready: !!APIFY_API_TOKEN
  },
  otp: {
    ghl_api: !!GHL_API_KEY && !!GHL_LOCATION_ID,
    ghl_webhook: !!GHL_WEBHOOK_URL,
    debug_mode: EMAIL_DELIVERY_DEBUG,
    dev_bypass: DEV_AUTH_BYPASS
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
// v2.5.0: UNIFIED PORTAL - Clean flat file structure
const portalRoutes = {
  '/login': 'login.html',              // Client login
  '/signup': 'signup.html',            // Client signup (free trial)
  '/team-login': 'team-login.html',    // Team/editor login
  '/team-signup': 'team-signup.html',  // Team/editor signup
  '/editor-signup': 'editor-signup.html',  // Editor invite signup
  '/portal': 'portal.html',            // UNIFIED portal for ALL roles
  '/dashboard': 'portal.html',         // Dashboard = portal
  '/admin': 'portal.html',             // Admin = portal
  '/editor': 'portal.html',            // Editor = portal
  '/team': 'portal.html',              // Team = portal
  '/projects': 'portal.html',          // Projects = portal
  '/chat': 'portal.html',              // Chat = portal
  '/review': 'review.html',            // Video review player
  '/record': 'record.html',            // Recording
  '/style-blueprint': 'style-blueprint.html',  // Blueprint builder
  '/blueprint-builder': 'style-blueprint.html',
  '/submit-project': 'submit-project.html',    // Project submission
  '/step-1-create-account': 'signup.html',
  '/step-2-style-blueprint': 'style-blueprint.html',
  '/step-3-submit-project': 'submit-project.html'
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

    // DEV BYPASS: Sean-only bypass when DEV_AUTH_BYPASS=true
    if (DEV_AUTH_BYPASS && normalizedEmail === DEV_BYPASS_EMAIL) {
      console.log(`[DEV BYPASS] Auth bypass triggered for ${normalizedEmail}`);

      // Log bypass event
      await logAuthEvent('auth_bypass_request', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: true,
        extra: { bypass_type: 'dev_founder' }
      });

      return res.json({
        success: true,
        bypass: true,
        message: 'Dev bypass enabled - use code 000000',
        code_hint: 'Use 000000',
        expires_in: 600000
      });
    }

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
      UserRecordID: userRecordId || '',
      CreatedAt: new Date().toISOString()
    });

    // Debug mode - log OTP to console (disable in production)
    if (EMAIL_DELIVERY_DEBUG) {
      console.log(`[OTP DEBUG] Email: ${normalizedEmail}, Code: ${otp}, Expires: ${Math.floor(OTP_EXPIRY_MS / 60000)} min`);
    }

    // Send OTP via multiple channels for reliability
    let emailSent = false;
    let deliveryMethod = 'none';

    // Method 1: Try GHL API direct email
    if (GHL_API_KEY && GHL_LOCATION_ID) {
      try {
        // First, find or create contact in GHL
        let contactId = null;

        // Search for existing contact
        const searchRes = await axios.get(
          `${GHL_API_URL}/contacts/search/duplicate`,
          {
            params: { locationId: GHL_LOCATION_ID, email: normalizedEmail },
            headers: {
              'Authorization': `Bearer ${GHL_API_KEY}`,
              'Version': '2021-07-28'
            },
            timeout: 10000
          }
        ).catch(() => null);

        if (searchRes?.data?.contact?.id) {
          contactId = searchRes.data.contact.id;
        } else {
          // Create contact
          const createRes = await axios.post(
            `${GHL_API_URL}/contacts/`,
            {
              locationId: GHL_LOCATION_ID,
              email: normalizedEmail,
              name: normalizedEmail.split('@')[0],
              tags: ['portal-user']
            },
            {
              headers: {
                'Authorization': `Bearer ${GHL_API_KEY}`,
                'Version': '2021-07-28',
                'Content-Type': 'application/json'
              },
              timeout: 10000
            }
          ).catch(() => null);

          contactId = createRes?.data?.contact?.id;
        }

        if (contactId) {
          // Send email via GHL conversations/messages API
          await axios.post(
            `${GHL_API_URL}/conversations/messages`,
            {
              type: 'Email',
              contactId: contactId,
              html: `<div style="font-family: Inter, -apple-system, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                  <img src="https://storage.googleapis.com/msgsndr/mCNHhjy593eUueqfuqyU/media/6930abb0e0f092608f6ec5e6.png" alt="Content Bug" style="height: 50px;">
                </div>
                <h2 style="color: #ffffff; text-align: center; margin-bottom: 20px;">Your Login Code</h2>
                <div style="background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%); border-radius: 12px; padding: 30px; text-align: center; margin: 20px 0;">
                  <span style="font-size: 36px; font-weight: 800; color: #ffffff; letter-spacing: 8px;">${otp}</span>
                </div>
                <p style="color: #94a3b8; text-align: center; font-size: 14px; margin-top: 20px;">This code expires in 10 minutes.</p>
                <p style="color: #64748b; text-align: center; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
              </div>`,
              subject: 'Your Content Bug Login Code'
            },
            {
              headers: {
                'Authorization': `Bearer ${GHL_API_KEY}`,
                'Version': '2021-07-28',
                'Content-Type': 'application/json'
              },
              timeout: 15000
            }
          );
          emailSent = true;
          deliveryMethod = 'ghl_api';
          console.log(`[OTP] Email sent via GHL API to ${normalizedEmail}`);
        }
      } catch (e) {
        console.warn('[OTP] GHL API email failed:', e.response?.data || e.message);
      }
    }

    // Method 2: Fallback to webhook trigger (for workflow)
    if (!emailSent && GHL_WEBHOOK_URL) {
      try {
        await axios.post(GHL_WEBHOOK_URL, {
          type: 'auth_otp',
          email: normalizedEmail,
          otp: otp,
          code: otp, // alias for workflow compatibility
          expires_minutes: Math.floor(OTP_EXPIRY_MS / 60000),
          is_new_user: isNewUser
        }, { timeout: 10000 });
        deliveryMethod = 'ghl_webhook';
        console.log(`[OTP] Webhook triggered for ${normalizedEmail}`);
      } catch (e) {
        console.warn('[OTP] GHL webhook failed:', e.message);
      }
    }

    // Send internal notification to admins
    if (OTP_NOTIFY_EMAILS.length > 0 && GHL_WEBHOOK_URL) {
      try {
        await axios.post(GHL_WEBHOOK_URL, {
          type: 'otp_admin_notify',
          otp_email: normalizedEmail,
          timestamp: new Date().toISOString(),
          delivery_method: deliveryMethod,
          is_new_user: isNewUser
        }, { timeout: 5000 });
      } catch (e) {
        // Silent fail for admin notifications
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

    // DEV BYPASS: Sean-only bypass when DEV_AUTH_BYPASS=true and code is 000000
    if (DEV_AUTH_BYPASS && normalizedEmail === DEV_BYPASS_EMAIL && normalizedCode === DEV_BYPASS_CODE) {
      console.log(`[DEV BYPASS] Auth bypass verify for ${normalizedEmail}`);

      // Get or create Sean's user record
      let userRecordId = null;
      let userRole = 'owner';
      let userName = 'Sean Conley';

      const contacts = await airtableQuery('Contacts', `{Email}='${normalizedEmail}'`, { maxRecords: 1 });
      if (contacts.records?.[0]) {
        userRecordId = contacts.records[0].id;
        userName = contacts.records[0].fields?.['Contact Name'] || 'Sean Conley';
      } else {
        // Check Team table
        const team = await airtableQuery('Team', `{Email}='${normalizedEmail}'`, { maxRecords: 1 });
        if (team.records?.[0]) {
          userRecordId = team.records[0].id;
          userRole = team.records[0].fields?.Role || 'owner';
          userName = team.records[0].fields?.Name || 'Sean Conley';
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

      // Set session cookie - detect domain from request
      const isContentBugDomain = req.hostname?.includes('contentbug.io');
      res.cookie('cb_session', sessionToken, {
        httpOnly: true,
        secure: IS_PRODUCTION,
        signed: true,
        sameSite: IS_PRODUCTION ? 'none' : 'lax',
        maxAge: SESSION_MAX_AGE_MS,
        domain: isContentBugDomain ? '.contentbug.io' : undefined
      });

      // Log bypass login
      await logAuthEvent('auth_bypass_used', {
        email: normalizedEmail,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        success: true,
        extra: { bypass_type: 'dev_founder', role: userRole }
      });

      return res.json({
        success: true,
        bypass: true,
        user: {
          email: normalizedEmail,
          name: userName,
          role: userRole,
          record_id: userRecordId
        },
        is_new_user: false,
        session_expires_at: sessionExpiresAt
      });
    }

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

    // Set session cookie - detect domain from request
    const isContentBugDomain = req.hostname?.includes('contentbug.io');
    res.cookie('cb_session', sessionToken, {
      httpOnly: true,
      secure: IS_PRODUCTION,
      signed: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      maxAge: SESSION_MAX_AGE_MS,
      domain: isContentBugDomain ? '.contentbug.io' : undefined
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

    // Set session cookie - detect domain from request
    const isContentBugDomain = req.hostname?.includes('contentbug.io');
    res.cookie('cb_session', sessionToken, {
      httpOnly: true,
      secure: IS_PRODUCTION,
      signed: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      maxAge: SESSION_MAX_AGE_MS,
      domain: isContentBugDomain ? '.contentbug.io' : undefined
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
// APIFY SOCIAL RESEARCH (ADMIN ONLY)
// ============================================
// Backend tool for studying accounts, posts, thumbnails, etc.
// Uses Apify actors for YouTube, TikTok, Instagram, Facebook

// Rate limiter for Apify endpoints (expensive API calls)
const apifyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // 50 research requests per hour
  message: { error: 'apify_rate_limit', message: 'Research rate limit exceeded. Try again later.' }
});

// Apify helper function
async function callApifyActor(actorId, input, options = {}) {
  if (!APIFY_API_TOKEN) {
    return { success: false, error: 'apify_not_configured' };
  }

  try {
    // Start the actor run
    const runResponse = await axios.post(
      `${APIFY_API_URL}/acts/${actorId}/runs`,
      input,
      {
        headers: {
          'Authorization': `Bearer ${APIFY_API_TOKEN}`,
          'Content-Type': 'application/json'
        },
        params: {
          timeout: options.timeout || 300, // 5 min default timeout
          memory: options.memory || 1024,  // 1GB memory
          waitForFinish: options.waitForFinish || 120 // Wait up to 2 min for completion
        }
      }
    );

    const run = runResponse.data.data;

    // If still running, return run ID for polling
    if (run.status === 'RUNNING') {
      return {
        success: true,
        status: 'running',
        runId: run.id,
        pollUrl: `/api/research/status/${run.id}`
      };
    }

    // If finished, get results
    if (run.status === 'SUCCEEDED') {
      const datasetId = run.defaultDatasetId;
      const resultsResponse = await axios.get(
        `${APIFY_API_URL}/datasets/${datasetId}/items`,
        {
          headers: { 'Authorization': `Bearer ${APIFY_API_TOKEN}` },
          params: { limit: options.limit || 100 }
        }
      );

      return {
        success: true,
        status: 'completed',
        runId: run.id,
        itemCount: resultsResponse.data.length,
        data: resultsResponse.data
      };
    }

    // Handle other statuses
    return {
      success: false,
      status: run.status,
      runId: run.id,
      error: run.status === 'FAILED' ? 'Actor run failed' : `Unexpected status: ${run.status}`
    };

  } catch (err) {
    console.error('[Apify] Actor call failed:', err.response?.data || err.message);
    return {
      success: false,
      error: 'apify_error',
      message: err.response?.data?.error?.message || err.message
    };
  }
}

// GET /api/research/status - Check Apify availability
app.get('/api/research/status', requireAuth(['admin', 'owner']), (req, res) => {
  return res.json({
    available: !!APIFY_API_TOKEN,
    actors: {
      youtube: 'streamers~youtube-scraper',
      tiktok: 'clockworks~tiktok-scraper',
      instagram_reels: 'apify~instagram-reel-scraper',
      instagram_profile: 'apify~instagram-profile-scraper',
      facebook_posts: 'apify~facebook-posts-scraper'
    }
  });
});

// GET /api/research/run/:runId - Check status of a running scrape
app.get('/api/research/run/:runId', requireAuth(['admin', 'owner']), async (req, res) => {
  if (!APIFY_API_TOKEN) {
    return res.status(503).json({ error: 'apify_not_configured' });
  }

  try {
    const { runId } = req.params;

    const runResponse = await axios.get(
      `${APIFY_API_URL}/actor-runs/${runId}`,
      { headers: { 'Authorization': `Bearer ${APIFY_API_TOKEN}` } }
    );

    const run = runResponse.data.data;

    if (run.status === 'SUCCEEDED') {
      // Get results
      const resultsResponse = await axios.get(
        `${APIFY_API_URL}/datasets/${run.defaultDatasetId}/items`,
        {
          headers: { 'Authorization': `Bearer ${APIFY_API_TOKEN}` },
          params: { limit: 100 }
        }
      );

      return res.json({
        status: 'completed',
        runId: run.id,
        itemCount: resultsResponse.data.length,
        data: resultsResponse.data
      });
    }

    return res.json({
      status: run.status.toLowerCase(),
      runId: run.id,
      startedAt: run.startedAt,
      finishedAt: run.finishedAt
    });

  } catch (err) {
    console.error('[Apify] Status check failed:', err.message);
    return res.status(500).json({ error: 'status_check_failed', message: err.message });
  }
});

// POST /api/research/youtube/channel - Scrape YouTube channel data
app.post('/api/research/youtube/channel', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { channelUrl, channelId, maxVideos } = req.body;

    if (!channelUrl && !channelId) {
      return res.status(400).json({ error: 'missing_input', message: 'channelUrl or channelId required' });
    }

    const input = {
      startUrls: channelUrl ? [{ url: channelUrl }] : [],
      channelIds: channelId ? [channelId] : [],
      maxResults: maxVideos || 50,
      sortBy: 'date',
      downloadSubtitles: false,
      downloadThumbnails: false, // We store URLs, not actual thumbnails
      extendOutputFunction: `async ({ data, item, page, request, customData }) => {
        return {
          ...item,
          thumbnailUrl: item.thumbnails?.[0]?.url || item.thumbnail?.url || null,
          channelUrl: item.channelUrl,
          viewCount: item.viewCount,
          likeCount: item.likeCount,
          duration: item.duration
        };
      }`
    };

    const result = await callApifyActor('streamers~youtube-scraper', input, {
      timeout: 600,
      waitForFinish: 180
    });

    // Log the research request
    await airtableCreate('ResearchLog', {
      Type: 'youtube_channel',
      Input: JSON.stringify({ channelUrl, channelId }),
      Status: result.status || 'error',
      RunID: result.runId || '',
      ResultCount: result.itemCount || 0,
      RequestedBy: req.user.email,
      Timestamp: new Date().toISOString()
    }).catch(() => {});

    return res.json(result);

  } catch (err) {
    console.error('[Research] YouTube channel error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/youtube/videos - Scrape specific YouTube videos
app.post('/api/research/youtube/videos', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { videoUrls, videoIds } = req.body;

    if ((!videoUrls || videoUrls.length === 0) && (!videoIds || videoIds.length === 0)) {
      return res.status(400).json({ error: 'missing_input', message: 'videoUrls or videoIds array required' });
    }

    // Limit to 100 videos per request
    const urls = (videoUrls || []).slice(0, 100);
    const ids = (videoIds || []).slice(0, 100);

    const input = {
      startUrls: urls.map(url => ({ url })),
      videoIds: ids,
      downloadSubtitles: false,
      downloadThumbnails: false
    };

    const result = await callApifyActor('streamers~youtube-scraper', input, {
      timeout: 600,
      waitForFinish: 180,
      limit: 100
    });

    // Log the research request
    await airtableCreate('ResearchLog', {
      Type: 'youtube_videos',
      Input: JSON.stringify({ videoCount: urls.length + ids.length }),
      Status: result.status || 'error',
      RunID: result.runId || '',
      ResultCount: result.itemCount || 0,
      RequestedBy: req.user.email,
      Timestamp: new Date().toISOString()
    }).catch(() => {});

    return res.json(result);

  } catch (err) {
    console.error('[Research] YouTube videos error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/youtube/search - Search YouTube for videos
app.post('/api/research/youtube/search', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { query, maxResults, sortBy } = req.body;

    if (!query) {
      return res.status(400).json({ error: 'missing_input', message: 'query required' });
    }

    const input = {
      searchQueries: [query],
      maxResults: Math.min(maxResults || 30, 100),
      sortBy: sortBy || 'relevance', // relevance, date, viewCount
      downloadSubtitles: false,
      downloadThumbnails: false
    };

    const result = await callApifyActor('streamers~youtube-scraper', input, {
      timeout: 300,
      waitForFinish: 120
    });

    return res.json(result);

  } catch (err) {
    console.error('[Research] YouTube search error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/tiktok/profile - Scrape TikTok profile
app.post('/api/research/tiktok/profile', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { username, profileUrl, maxVideos } = req.body;

    if (!username && !profileUrl) {
      return res.status(400).json({ error: 'missing_input', message: 'username or profileUrl required' });
    }

    const input = {
      profiles: username ? [username] : [],
      profileUrls: profileUrl ? [profileUrl] : [],
      resultsPerPage: Math.min(maxVideos || 30, 100),
      shouldDownloadVideos: false,
      shouldDownloadCovers: false
    };

    const result = await callApifyActor('clockworks~tiktok-scraper', input, {
      timeout: 300,
      waitForFinish: 120
    });

    // Log research
    await airtableCreate('ResearchLog', {
      Type: 'tiktok_profile',
      Input: JSON.stringify({ username, profileUrl }),
      Status: result.status || 'error',
      RunID: result.runId || '',
      ResultCount: result.itemCount || 0,
      RequestedBy: req.user.email,
      Timestamp: new Date().toISOString()
    }).catch(() => {});

    return res.json(result);

  } catch (err) {
    console.error('[Research] TikTok profile error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/instagram/profile - Scrape Instagram profile
app.post('/api/research/instagram/profile', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { username, profileUrl, maxPosts } = req.body;

    if (!username && !profileUrl) {
      return res.status(400).json({ error: 'missing_input', message: 'username or profileUrl required' });
    }

    const input = {
      usernames: username ? [username] : [],
      directUrls: profileUrl ? [profileUrl] : [],
      resultsLimit: Math.min(maxPosts || 30, 100)
    };

    const result = await callApifyActor('apify~instagram-profile-scraper', input, {
      timeout: 300,
      waitForFinish: 120
    });

    return res.json(result);

  } catch (err) {
    console.error('[Research] Instagram profile error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/instagram/reels - Scrape Instagram reels
app.post('/api/research/instagram/reels', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { username, reelUrls, maxReels } = req.body;

    if (!username && (!reelUrls || reelUrls.length === 0)) {
      return res.status(400).json({ error: 'missing_input', message: 'username or reelUrls required' });
    }

    const input = {
      username: username || undefined,
      directUrls: reelUrls || [],
      resultsLimit: Math.min(maxReels || 30, 100)
    };

    const result = await callApifyActor('apify~instagram-reel-scraper', input, {
      timeout: 300,
      waitForFinish: 120
    });

    return res.json(result);

  } catch (err) {
    console.error('[Research] Instagram reels error:', err);
    return res.status(500).json({ error: 'research_failed', message: err.message });
  }
});

// POST /api/research/thumbnails/analyze - Store thumbnail metadata for analysis
// This stores URLs and metadata - NOT the actual images
app.post('/api/research/thumbnails/analyze', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { thumbnails, source, category } = req.body;

    if (!thumbnails || !Array.isArray(thumbnails) || thumbnails.length === 0) {
      return res.status(400).json({ error: 'missing_input', message: 'thumbnails array required' });
    }

    // Limit to 100 thumbnails per request
    const batch = thumbnails.slice(0, 100);

    // Store each thumbnail's metadata in Airtable
    const stored = [];
    for (const thumb of batch) {
      const record = await airtableCreate('ThumbnailResearch', {
        ThumbnailURL: thumb.url || thumb.thumbnailUrl,
        VideoTitle: thumb.title || thumb.videoTitle || '',
        VideoURL: thumb.videoUrl || thumb.url || '',
        ChannelName: thumb.channelName || thumb.channelTitle || '',
        ViewCount: thumb.viewCount || thumb.views || 0,
        UploadDate: thumb.uploadDate || thumb.publishedAt || '',
        Source: source || 'youtube',
        Category: category || 'uncategorized',
        AnalyzedAt: new Date().toISOString(),
        AddedBy: req.user.email
      });

      if (record) {
        stored.push(record.id);
      }
    }

    return res.json({
      success: true,
      stored: stored.length,
      total: batch.length
    });

  } catch (err) {
    console.error('[Research] Thumbnail analyze error:', err);
    return res.status(500).json({ error: 'storage_failed', message: err.message });
  }
});

// GET /api/research/thumbnails - Get stored thumbnail research data
app.get('/api/research/thumbnails', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { category, source, limit, offset } = req.query;

    let filter = '';
    if (category) {
      filter = `{Category}='${category}'`;
    }
    if (source) {
      filter = filter ? `AND(${filter}, {Source}='${source}')` : `{Source}='${source}'`;
    }

    const result = await airtableQuery('ThumbnailResearch', filter, {
      maxRecords: parseInt(limit) || 50,
      sort: [{ field: 'AnalyzedAt', direction: 'desc' }],
      offset: offset || undefined
    });

    const thumbnails = result.records.map(r => ({
      id: r.id,
      thumbnailUrl: r.fields.ThumbnailURL,
      videoTitle: r.fields.VideoTitle,
      videoUrl: r.fields.VideoURL,
      channelName: r.fields.ChannelName,
      viewCount: r.fields.ViewCount,
      uploadDate: r.fields.UploadDate,
      source: r.fields.Source,
      category: r.fields.Category,
      analyzedAt: r.fields.AnalyzedAt
    }));

    return res.json({
      thumbnails,
      count: thumbnails.length,
      hasMore: !!result.offset
    });

  } catch (err) {
    console.error('[Research] Thumbnail fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ============================================
// THUMBNAIL INTELLIGENCE ENGINE (ADMIN ONLY)
// ============================================
// Scrapes seed creators, stores thumbnails, analyzes patterns
// Never says "AI" - uses "proven high-performing layouts"

// Seed creators for thumbnail intelligence
const SEED_CREATORS = [
  { name: 'Alex Hormozi', channelId: 'UCHGNcNAMJpuw1Xay_dZNJuQ' },
  { name: 'MrBeast', channelId: 'UCX6OQ3DkcsbYNE6H8uQQuVA' },
  { name: 'Ali Abdaal', channelId: 'UCoOae5nYA7VqaXzerajD0lg' },
  { name: 'Course Creator Pro', channelId: 'UCfLYr5q5m1p1JE8lDJRzg0A' },
  { name: 'Full Time Filmmaker', channelId: 'UCfJQRIvnC5v0gMiWZE1SZEA' }
];

// POST /api/intelligence/scrape-creator - Scrape a seed creator's videos + thumbnails
app.post('/api/intelligence/scrape-creator', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { creatorName, channelId, maxVideos } = req.body;

    if (!channelId) {
      return res.status(400).json({ error: 'missing_input', message: 'channelId required' });
    }

    const input = {
      channelIds: [channelId],
      maxResults: maxVideos || 250,
      sortBy: 'date',
      downloadSubtitles: false,
      downloadThumbnails: false
    };

    const result = await callApifyActor('streamers~youtube-scraper', input, {
      timeout: 900,
      waitForFinish: 300,
      limit: 500
    });

    if (result.success && result.data) {
      // Process and store each video
      let stored = 0;
      for (const video of result.data) {
        // Calculate performance metrics
        const views = video.viewCount || 0;
        const subs = video.channelSubscribers || 0;
        const ratio = subs > 0 ? views / subs : 0;

        // Get highest res thumbnail
        let thumbnailUrl = '';
        if (video.thumbnails && video.thumbnails.length > 0) {
          thumbnailUrl = video.thumbnails[video.thumbnails.length - 1].url;
        } else if (video.thumbnail) {
          thumbnailUrl = video.thumbnail.url || video.thumbnail;
        }

        // Store in Thumbnail_Intelligence
        await airtableCreate('Thumbnail_Intelligence', {
          Creator: creatorName || video.channelTitle,
          VideoURL: video.url || `https://www.youtube.com/watch?v=${video.id}`,
          VideoID: video.id,
          Title: video.title,
          Views: views,
          Subscribers: subs,
          ViewsPerSubRatio: Math.round(ratio * 10000) / 10000,
          TitleLength: (video.title || '').length,
          PublishDate: video.uploadDate || video.date,
          UploadAgeDays: Math.floor((Date.now() - new Date(video.uploadDate || video.date).getTime()) / (1000 * 60 * 60 * 24)),
          ThumbnailURL: thumbnailUrl,
          ScrapedAt: new Date().toISOString()
        });
        stored++;
      }

      // Update Seed_Creators table
      const seedCreators = await airtableQuery('Seed_Creators', `{YouTubeChannelID}='${channelId}'`, { maxRecords: 1 });
      if (seedCreators.records?.[0]) {
        await airtableUpdate('Seed_Creators', seedCreators.records[0].id, {
          LastScraped: new Date().toISOString(),
          VideosSscraped: stored,
          Status: 'Active',
          Subscribers: result.data[0]?.channelSubscribers || 0
        });
      }

      return res.json({
        success: true,
        creator: creatorName,
        videosProcessed: stored,
        runId: result.runId
      });
    }

    return res.json(result);

  } catch (err) {
    console.error('[Intelligence] Scrape creator error:', err);
    return res.status(500).json({ error: 'scrape_failed', message: err.message });
  }
});

// POST /api/intelligence/scrape-all-creators - Scrape all seed creators
app.post('/api/intelligence/scrape-all-creators', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { maxVideosPerCreator } = req.body;
    const results = [];

    for (const creator of SEED_CREATORS) {
      // Log start
      console.log(`[Intelligence] Starting scrape for ${creator.name}...`);

      const input = {
        channelIds: [creator.channelId],
        maxResults: maxVideosPerCreator || 250,
        sortBy: 'date',
        downloadSubtitles: false,
        downloadThumbnails: false
      };

      const result = await callApifyActor('streamers~youtube-scraper', input, {
        timeout: 900,
        waitForFinish: 300,
        limit: 500
      });

      results.push({
        creator: creator.name,
        status: result.status,
        runId: result.runId,
        itemCount: result.itemCount || 0
      });
    }

    return res.json({
      success: true,
      message: 'Scrape jobs initiated for all seed creators',
      results
    });

  } catch (err) {
    console.error('[Intelligence] Scrape all creators error:', err);
    return res.status(500).json({ error: 'batch_scrape_failed', message: err.message });
  }
});

// POST /api/intelligence/calculate-performance-tiers - Calculate performance tiers for all videos
app.post('/api/intelligence/calculate-performance-tiers', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { creator } = req.body;

    let filter = '';
    if (creator) {
      filter = `{Creator}='${creator}'`;
    }

    // Get all videos
    const videos = await airtableQuery('Thumbnail_Intelligence', filter, {
      maxRecords: 1000,
      sort: [{ field: 'Views', direction: 'desc' }]
    });

    if (videos.records.length === 0) {
      return res.json({ success: false, message: 'No videos found' });
    }

    // Calculate percentiles
    const total = videos.records.length;
    const top10Idx = Math.floor(total * 0.1);
    const top25Idx = Math.floor(total * 0.25);
    const medianIdx = Math.floor(total * 0.5);

    let updated = 0;
    for (let i = 0; i < videos.records.length; i++) {
      const record = videos.records[i];
      let tier = 'Below Median';

      if (i < top10Idx) tier = 'Top 10%';
      else if (i < top25Idx) tier = 'Top 25%';
      else if (i < medianIdx) tier = 'Median';

      await airtableUpdate('Thumbnail_Intelligence', record.id, {
        PerformanceTier: tier
      });
      updated++;
    }

    return res.json({
      success: true,
      totalVideos: total,
      updated,
      tiers: {
        'Top 10%': top10Idx,
        'Top 25%': top25Idx - top10Idx,
        'Median': medianIdx - top25Idx,
        'Below Median': total - medianIdx
      }
    });

  } catch (err) {
    console.error('[Intelligence] Calculate tiers error:', err);
    return res.status(500).json({ error: 'calculation_failed', message: err.message });
  }
});

// GET /api/intelligence/top-thumbnails - Get top performing thumbnails
app.get('/api/intelligence/top-thumbnails', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { creator, tier, limit } = req.query;

    let filter = `{PerformanceTier}='Top 10%'`;
    if (creator) {
      filter = `AND(${filter}, {Creator}='${creator}')`;
    }
    if (tier) {
      filter = `{PerformanceTier}='${tier}'`;
      if (creator) {
        filter = `AND(${filter}, {Creator}='${creator}')`;
      }
    }

    const result = await airtableQuery('Thumbnail_Intelligence', filter, {
      maxRecords: parseInt(limit) || 50,
      sort: [{ field: 'Views', direction: 'desc' }]
    });

    const thumbnails = result.records.map(r => ({
      id: r.id,
      creator: r.fields.Creator,
      title: r.fields.Title,
      views: r.fields.Views,
      viewsPerSubRatio: r.fields.ViewsPerSubRatio,
      thumbnailUrl: r.fields.ThumbnailURL,
      videoUrl: r.fields.VideoURL,
      tier: r.fields.PerformanceTier
    }));

    return res.json({ thumbnails, count: thumbnails.length });

  } catch (err) {
    console.error('[Intelligence] Top thumbnails error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ============================================
// CREATOR PROFILE INTELLIGENCE (CLIENT METRICS)
// ============================================
// Scrapes client social profiles, tracks performance over time

// POST /api/client/save-profiles - Save client social profile URLs
app.post('/api/client/save-profiles', requireAuth(), async (req, res) => {
  try {
    const { youtube, instagram, tiktok, twitter } = req.body;
    const clientId = req.user.userRecordId;

    if (!clientId) {
      return res.status(400).json({ error: 'no_client_id' });
    }

    // Save to Contacts table
    const profileUrls = JSON.stringify({
      youtube: youtube || null,
      instagram: instagram || null,
      tiktok: tiktok || null,
      twitter: twitter || null
    });

    await airtableUpdate('Contacts', clientId, {
      ProfileURLs: profileUrls
    });

    return res.json({ success: true, message: 'Profile URLs saved' });

  } catch (err) {
    console.error('[Profiles] Save error:', err);
    return res.status(500).json({ error: 'save_failed', message: err.message });
  }
});

// GET /api/client/profiles - Get client's saved profile URLs
app.get('/api/client/profiles', requireAuth(), async (req, res) => {
  try {
    const clientId = req.user.userRecordId;

    if (!clientId) {
      return res.status(400).json({ error: 'no_client_id' });
    }

    const contact = await airtableQuery('Contacts', `RECORD_ID()='${clientId}'`, { maxRecords: 1 });

    if (!contact.records?.[0]) {
      return res.json({ profiles: {} });
    }

    let profiles = {};
    try {
      profiles = JSON.parse(contact.records[0].fields.ProfileURLs || '{}');
    } catch (e) {
      profiles = {};
    }

    return res.json({ profiles });

  } catch (err) {
    console.error('[Profiles] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/client/scrape-profile - Scrape a specific client profile (admin triggered)
app.post('/api/client/scrape-profile', requireAuth(['admin', 'owner']), apifyLimiter, async (req, res) => {
  try {
    const { clientId, platform, profileUrl } = req.body;

    if (!clientId || !platform || !profileUrl) {
      return res.status(400).json({ error: 'missing_input', message: 'clientId, platform, and profileUrl required' });
    }

    let result;
    let stats = {};

    switch (platform.toLowerCase()) {
      case 'youtube':
        result = await callApifyActor('streamers~youtube-scraper', {
          startUrls: [{ url: profileUrl }],
          maxResults: 30,
          downloadSubtitles: false,
          downloadThumbnails: false
        }, { timeout: 300, waitForFinish: 120 });

        if (result.success && result.data?.[0]) {
          const channelData = result.data[0];
          stats = {
            followers: channelData.subscriberCount || channelData.channelSubscribers,
            totalPosts: result.data.length,
            avgViews: Math.round(result.data.reduce((sum, v) => sum + (v.viewCount || 0), 0) / result.data.length),
            avgEngagement: 0 // Would need likes+comments/views calculation
          };
        }
        break;

      case 'instagram':
        result = await callApifyActor('apify~instagram-profile-scraper', {
          directUrls: [profileUrl],
          resultsLimit: 30
        }, { timeout: 300, waitForFinish: 120 });

        if (result.success && result.data?.[0]) {
          const profile = result.data[0];
          stats = {
            followers: profile.followersCount,
            totalPosts: profile.postsCount,
            avgViews: 0,
            avgEngagement: profile.engagement || 0
          };
        }
        break;

      case 'tiktok':
        result = await callApifyActor('clockworks~tiktok-scraper', {
          profileUrls: [profileUrl],
          resultsPerPage: 30,
          shouldDownloadVideos: false
        }, { timeout: 300, waitForFinish: 120 });

        if (result.success && result.data?.[0]) {
          const profile = result.data[0];
          stats = {
            followers: profile.authorMeta?.fans || 0,
            totalPosts: result.data.length,
            avgViews: Math.round(result.data.reduce((sum, v) => sum + (v.playCount || 0), 0) / result.data.length),
            avgEngagement: 0
          };
        }
        break;

      default:
        return res.status(400).json({ error: 'unsupported_platform', message: 'Use youtube, instagram, or tiktok' });
    }

    // Get previous stats to calculate trend
    const prevStats = await airtableQuery('Creator_Profile_Stats',
      `AND({ClientID}='${clientId}', {Platform}='${platform}')`,
      { maxRecords: 1, sort: [{ field: 'LastScrapedAt', direction: 'desc' }] }
    );

    let trend = 'Flat';
    if (prevStats.records?.[0]) {
      const prevFollowers = prevStats.records[0].fields.Followers || 0;
      if (stats.followers > prevFollowers * 1.02) trend = 'Up';
      else if (stats.followers < prevFollowers * 0.98) trend = 'Down';
    }

    // Save new stats
    await airtableCreate('Creator_Profile_Stats', {
      ClientID: clientId,
      Platform: platform.charAt(0).toUpperCase() + platform.slice(1),
      ProfileURL: profileUrl,
      Username: profileUrl.split('/').pop(),
      Followers: stats.followers || 0,
      TotalPosts: stats.totalPosts || 0,
      AvgViewsPerPost: stats.avgViews || 0,
      AvgEngagementPercent: stats.avgEngagement || 0,
      TrendDirection: trend,
      LastScrapedAt: new Date().toISOString(),
      HistoricalData: JSON.stringify([{
        date: new Date().toISOString(),
        followers: stats.followers,
        avgViews: stats.avgViews
      }])
    });

    return res.json({
      success: true,
      platform,
      stats,
      trend
    });

  } catch (err) {
    console.error('[Profiles] Scrape error:', err);
    return res.status(500).json({ error: 'scrape_failed', message: err.message });
  }
});

// GET /api/client/performance - Get client's content performance stats
app.get('/api/client/performance', requireAuth(), async (req, res) => {
  try {
    const clientId = req.user.userRecordId;

    if (!clientId) {
      return res.status(400).json({ error: 'no_client_id' });
    }

    const stats = await airtableQuery('Creator_Profile_Stats',
      `{ClientID}='${clientId}'`,
      { sort: [{ field: 'LastScrapedAt', direction: 'desc' }] }
    );

    // Get latest stats per platform
    const platforms = {};
    for (const record of stats.records) {
      const platform = record.fields.Platform?.toLowerCase();
      if (platform && !platforms[platform]) {
        platforms[platform] = {
          followers: record.fields.Followers,
          totalPosts: record.fields.TotalPosts,
          avgViews: record.fields.AvgViewsPerPost,
          avgEngagement: record.fields.AvgEngagementPercent,
          trend: record.fields.TrendDirection,
          lastUpdated: record.fields.LastScrapedAt
        };
      }
    }

    return res.json({
      success: true,
      platforms,
      hasData: Object.keys(platforms).length > 0
    });

  } catch (err) {
    console.error('[Performance] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ============================================
// THUMBNAIL PREFERENCES & DELIVERY
// ============================================

// POST /api/client/thumbnail-preferences - Save client thumbnail preferences
app.post('/api/client/thumbnail-preferences', requireAuth(), async (req, res) => {
  try {
    const { includeThumbnails, inspiredBy, preferredEmotion, textApproval, customNotes } = req.body;
    const clientId = req.user.userRecordId;

    if (!clientId) {
      return res.status(400).json({ error: 'no_client_id' });
    }

    // Check if preferences already exist
    const existing = await airtableQuery('Thumbnail_Preferences', `{ClientID}='${clientId}'`, { maxRecords: 1 });

    if (existing.records?.[0]) {
      await airtableUpdate('Thumbnail_Preferences', existing.records[0].id, {
        IncludeThumbnails: includeThumbnails || false,
        InspiredBy: inspiredBy || null,
        PreferredEmotion: preferredEmotion || 'No Preference',
        TextApproval: textApproval || 'Let Content Bug Decide',
        CustomNotes: customNotes || '',
        UpdatedAt: new Date().toISOString()
      });
    } else {
      await airtableCreate('Thumbnail_Preferences', {
        ClientID: clientId,
        IncludeThumbnails: includeThumbnails || false,
        InspiredBy: inspiredBy || null,
        PreferredEmotion: preferredEmotion || 'No Preference',
        TextApproval: textApproval || 'Let Content Bug Decide',
        CustomNotes: customNotes || '',
        CreatedAt: new Date().toISOString(),
        UpdatedAt: new Date().toISOString()
      });
    }

    return res.json({ success: true, message: 'Thumbnail preferences saved' });

  } catch (err) {
    console.error('[Thumbnail Prefs] Save error:', err);
    return res.status(500).json({ error: 'save_failed', message: err.message });
  }
});

// GET /api/client/thumbnail-preferences - Get client thumbnail preferences
app.get('/api/client/thumbnail-preferences', requireAuth(), async (req, res) => {
  try {
    const clientId = req.user.userRecordId;

    if (!clientId) {
      return res.status(400).json({ error: 'no_client_id' });
    }

    const prefs = await airtableQuery('Thumbnail_Preferences', `{ClientID}='${clientId}'`, { maxRecords: 1 });

    if (!prefs.records?.[0]) {
      return res.json({
        exists: false,
        preferences: {
          includeThumbnails: false,
          inspiredBy: null,
          preferredEmotion: 'No Preference',
          textApproval: 'Let Content Bug Decide'
        }
      });
    }

    const record = prefs.records[0];
    return res.json({
      exists: true,
      preferences: {
        includeThumbnails: record.fields.IncludeThumbnails,
        inspiredBy: record.fields.InspiredBy,
        preferredEmotion: record.fields.PreferredEmotion,
        textApproval: record.fields.TextApproval,
        customNotes: record.fields.CustomNotes
      }
    });

  } catch (err) {
    console.error('[Thumbnail Prefs] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/project/thumbnails - Create thumbnail options for a project (admin)
app.post('/api/project/thumbnails', requireAuth(['admin', 'owner', 'editor']), async (req, res) => {
  try {
    const { projectId, clientId, options } = req.body;

    if (!projectId || !clientId || !options || options.length < 1) {
      return res.status(400).json({ error: 'missing_input', message: 'projectId, clientId, and options array required' });
    }

    const thumbnailData = {
      ProjectID: projectId,
      ClientID: clientId,
      Status: 'Ready for Review',
      GeneratedAt: new Date().toISOString()
    };

    // Add up to 3 options
    for (let i = 0; i < Math.min(options.length, 3); i++) {
      const opt = options[i];
      const num = i + 1;
      thumbnailData[`Option${num}URL`] = opt.url;
      thumbnailData[`Option${num}Explanation`] = opt.explanation || `Hand-selected using proven high-performing layouts from top creators.`;
      thumbnailData[`Option${num}CTRRange`] = opt.ctrRange || '4-7%';
    }

    const record = await airtableCreate('Project_Thumbnails', thumbnailData);

    return res.json({
      success: true,
      recordId: record?.id,
      message: 'Thumbnail options created'
    });

  } catch (err) {
    console.error('[Thumbnails] Create options error:', err);
    return res.status(500).json({ error: 'create_failed', message: err.message });
  }
});

// GET /api/project/:projectId/thumbnails - Get thumbnail options for a project
app.get('/api/project/:projectId/thumbnails', requireAuth(), async (req, res) => {
  try {
    const { projectId } = req.params;

    const thumbnails = await airtableQuery('Project_Thumbnails', `{ProjectID}='${projectId}'`, { maxRecords: 1 });

    if (!thumbnails.records?.[0]) {
      return res.json({ exists: false });
    }

    const record = thumbnails.records[0];
    const options = [];

    for (let i = 1; i <= 3; i++) {
      const url = record.fields[`Option${i}URL`];
      if (url) {
        options.push({
          number: i,
          url,
          explanation: record.fields[`Option${i}Explanation`],
          ctrRange: record.fields[`Option${i}CTRRange`]
        });
      }
    }

    return res.json({
      exists: true,
      recordId: record.id,
      status: record.fields.Status,
      selectedOption: record.fields.SelectedOption,
      finalThumbnailUrl: record.fields.FinalThumbnailURL,
      options
    });

  } catch (err) {
    console.error('[Thumbnails] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/project/:projectId/thumbnails/select - Client selects a thumbnail
app.post('/api/project/:projectId/thumbnails/select', requireAuth(), async (req, res) => {
  try {
    const { projectId } = req.params;
    const { selectedOption } = req.body;

    if (!selectedOption || !['Option 1', 'Option 2', 'Option 3'].includes(selectedOption)) {
      return res.status(400).json({ error: 'invalid_option' });
    }

    const thumbnails = await airtableQuery('Project_Thumbnails', `{ProjectID}='${projectId}'`, { maxRecords: 1 });

    if (!thumbnails.records?.[0]) {
      return res.status(404).json({ error: 'not_found' });
    }

    const record = thumbnails.records[0];
    const optionNum = selectedOption.split(' ')[1];
    const finalUrl = record.fields[`Option${optionNum}URL`];

    await airtableUpdate('Project_Thumbnails', record.id, {
      SelectedOption: selectedOption,
      FinalThumbnailURL: finalUrl,
      Status: 'Selected',
      SelectedAt: new Date().toISOString()
    });

    return res.json({
      success: true,
      selectedOption,
      finalThumbnailUrl: finalUrl
    });

  } catch (err) {
    console.error('[Thumbnails] Select error:', err);
    return res.status(500).json({ error: 'select_failed', message: err.message });
  }
});

// ============================================
// CLIENT RAW THUMBNAIL UPLOAD (Camera Capture)
// ============================================

// POST /api/client/thumbnail-photo - Upload a raw thumbnail photo
app.post('/api/client/thumbnail-photo', requireAuth(), uploadLimiter, upload.single('photo'), async (req, res) => {
  try {
    const clientId = req.user.userRecordId;
    const { sessionId, lightingScore, focusScore, framingScore, uploadMethod } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'no_file' });
    }

    // Upload to Drive
    const clientName = req.user.email?.split('@')[0] || 'unknown';
    const structure = await getClientFolderStructure(clientName, clientId);

    if (!structure) {
      return res.status(500).json({ error: 'drive_not_ready' });
    }

    const targetFolder = structure.brand_thumbnails || structure.brand_assets || structure.root;
    const fileName = `thumb_${Date.now()}_${Math.random().toString(36).substr(2, 6)}.jpg`;

    const uploadResult = await uploadToDrive(req.file, targetFolder, fileName);

    if (!uploadResult.success) {
      return res.status(500).json(uploadResult);
    }

    // Calculate overall score
    const lighting = parseInt(lightingScore) || 0;
    const focus = parseInt(focusScore) || 0;
    const framing = parseInt(framingScore) || 0;
    const overall = Math.round((lighting + focus + framing) / 3);

    // Store in Airtable
    await airtableCreate('Client_Raw_Thumbnails', {
      ClientID: clientId,
      SessionID: sessionId || `session_${Date.now()}`,
      PhotoURL: uploadResult.file.viewLink,
      DriveFileID: uploadResult.file.id,
      LightingScore: lighting,
      FocusScore: focus,
      FramingScore: framing,
      OverallScore: overall,
      Status: 'Raw',
      CapturedAt: new Date().toISOString(),
      UploadMethod: uploadMethod || 'Manual Upload'
    });

    return res.json({
      success: true,
      photoUrl: uploadResult.file.viewLink,
      driveId: uploadResult.file.id,
      scores: { lighting, focus, framing, overall }
    });

  } catch (err) {
    console.error('[Thumbnail Photo] Upload error:', err);
    return res.status(500).json({ error: 'upload_failed', message: err.message });
  }
});

// GET /api/client/thumbnail-photos - Get client's raw thumbnail photos
app.get('/api/client/thumbnail-photos', requireAuth(), async (req, res) => {
  try {
    const clientId = req.user.userRecordId;
    const { status } = req.query;

    let filter = `{ClientID}='${clientId}'`;
    if (status) {
      filter = `AND(${filter}, {Status}='${status}')`;
    }

    const photos = await airtableQuery('Client_Raw_Thumbnails', filter, {
      maxRecords: 50,
      sort: [{ field: 'CapturedAt', direction: 'desc' }]
    });

    const results = photos.records.map(r => ({
      id: r.id,
      photoUrl: r.fields.PhotoURL,
      overallScore: r.fields.OverallScore,
      status: r.fields.Status,
      capturedAt: r.fields.CapturedAt,
      uploadMethod: r.fields.UploadMethod
    }));

    return res.json({ photos: results, count: results.length });

  } catch (err) {
    console.error('[Thumbnail Photos] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ============================================
// PROJECT ENDPOINTS
// ============================================

// Calculate Edit Tier from Blueprint complexity
function calculateEditTier(blueprint) {
  if (!blueprint) return { tier: 'Tier 2', score: 50, sla: '3-5' };

  let score = 0;
  const fields = blueprint.fields || blueprint;

  // B-Roll complexity (0-20 points)
  const brollFreq = (fields['B-Roll Frequency'] || '').toLowerCase();
  if (brollFreq.includes('heavy') || brollFreq.includes('high')) score += 20;
  else if (brollFreq.includes('moderate') || brollFreq.includes('medium')) score += 12;
  else if (brollFreq.includes('minimal') || brollFreq.includes('light')) score += 5;

  // Caption complexity (0-15 points)
  const captionStyle = (fields['Caption Style'] || '').toLowerCase();
  if (captionStyle.includes('animated') || captionStyle.includes('kinetic')) score += 15;
  else if (captionStyle.includes('styled') || captionStyle.includes('custom')) score += 10;
  else score += 3;

  // Title animations (0-15 points)
  const titleStyle = (fields['Title Animation Style'] || '').toLowerCase();
  if (titleStyle.includes('complex') || titleStyle.includes('custom')) score += 15;
  else if (titleStyle.includes('animated') || titleStyle.includes('motion')) score += 10;
  else score += 3;

  // SFX (0-10 points)
  const sfxFreq = (fields['SFX Frequency'] || '').toLowerCase();
  if (sfxFreq.includes('heavy') || sfxFreq.includes('frequent')) score += 10;
  else if (sfxFreq.includes('moderate')) score += 6;
  else score += 2;

  // Color grading (0-10 points)
  const colorGrading = (fields['Color Grading'] || '').toLowerCase();
  if (colorGrading.includes('custom') || colorGrading.includes('cinematic')) score += 10;
  else if (colorGrading.includes('branded') || colorGrading.includes('stylized')) score += 6;
  else score += 2;

  // PNG overlays (0-10 points)
  const pngOverlays = (fields['PNG Overlays'] || '').toLowerCase();
  if (pngOverlays.includes('heavy') || pngOverlays.includes('frequent')) score += 10;
  else if (pngOverlays.includes('moderate') || pngOverlays.includes('some')) score += 5;
  else score += 1;

  // Cut speed (0-10 points)
  const cutSpeed = (fields['Cut Speed'] || '').toLowerCase();
  if (cutSpeed.includes('fast') || cutSpeed.includes('rapid')) score += 10;
  else if (cutSpeed.includes('dynamic') || cutSpeed.includes('varied')) score += 7;
  else score += 3;

  // Music (0-10 points)
  const musicType = (fields['Music Type'] || '').toLowerCase();
  if (musicType.includes('custom') || musicType.includes('original')) score += 10;
  else if (musicType.includes('licensed') || musicType.includes('premium')) score += 6;
  else score += 2;

  // Determine tier and SLA
  let tier, sla;
  if (score >= 70) {
    tier = 'Tier 3';
    sla = '5-7';
  } else if (score >= 40) {
    tier = 'Tier 2';
    sla = '3-5';
  } else {
    tier = 'Tier 1';
    sla = '2-3';
  }

  return { tier, score, sla };
}

// GET /api/projects - Get projects for current user
app.get('/api/projects', requireAuth(), async (req, res) => {
  try {
    const userEmail = req.user.email;
    const userRole = req.user.role || 'client';
    const { status } = req.query;

    let filter;
    if (['admin', 'owner'].includes(userRole)) {
      // Admins/owners see all projects
      filter = status ? `{Status}='${status}'` : '';
    } else if (userRole === 'editor') {
      // Editors see assigned projects
      filter = `OR({Contact Assigned Editor #1}='${req.user.name}',{Contact Assigned Editor #2}='${req.user.name}',{Contact Assigned Editor #3}='${req.user.name}')`;
      if (status) filter = `AND(${filter},{Status}='${status}')`;
    } else {
      // Clients see their own projects
      filter = `{Contact Email}='${userEmail}'`;
      if (status) filter = `AND(${filter},{Status}='${status}')`;
    }

    const projects = await airtableQuery('Projects', filter, {
      maxRecords: 100,
      sort: [{ field: 'Project Date Created', direction: 'desc' }]
    });

    // Fetch blueprints for tier calculation if needed
    const blueprintCache = {};

    const results = await Promise.all(projects.records.map(async (r) => {
      const f = r.fields;

      // Get blueprint for tier if not set
      let editTier = f['Edit Tier'];
      let blueprintName = f['Blueprint Name'] || f['Project Style'] || '';

      if (!editTier && f['Style Blueprint']?.[0]) {
        const bpId = f['Style Blueprint'][0];
        if (!blueprintCache[bpId]) {
          try {
            const bp = await airtableQuery('Blueprints', `RECORD_ID()='${bpId}'`, { maxRecords: 1 });
            blueprintCache[bpId] = bp.records?.[0] || null;
          } catch (e) { blueprintCache[bpId] = null; }
        }
        if (blueprintCache[bpId]) {
          const tierInfo = calculateEditTier(blueprintCache[bpId]);
          editTier = tierInfo.tier;
          blueprintName = blueprintCache[bpId].fields?.['Contact Name'] || blueprintName;
        }
      }

      // Determine project type badge
      let projectTypeBadge = 'Short';
      const projectType = (f['Project Type'] || '').toLowerCase();
      const duration = f['Duration'] || f['Video Duration'] || '';

      if (projectType.includes('long') || projectType.includes('youtube')) {
        projectTypeBadge = 'Long';
      } else if (projectType.includes('podcast')) {
        projectTypeBadge = 'Podcast';
      } else if (projectType.includes('youtube')) {
        projectTypeBadge = 'YouTube';
      } else if (duration) {
        // Parse duration to determine type
        const parts = duration.split(':').map(Number);
        const totalSeconds = parts.length === 3
          ? parts[0] * 3600 + parts[1] * 60 + parts[2]
          : parts.length === 2
            ? parts[0] * 60 + parts[1]
            : parts[0];
        if (totalSeconds > 90) projectTypeBadge = 'Long';
      }

      // Format dates
      const dateCreated = f['Project Date Created']
        ? new Date(f['Project Date Created']).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' })
        : null;
      const eta = f['Project ETA']
        ? new Date(f['Project ETA']).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' })
        : null;

      // Map status
      const statusMap = {
        'queued': 'Queued',
        'in_edit': 'In Edit',
        'review': 'Review',
        'revisions': 'Revisions',
        'approved': 'Approved',
        'active': 'In Edit',
        'completed': 'Approved'
      };
      const normalizedStatus = (f['Status'] || f['Project Status'] || 'queued').toLowerCase().replace(/\s+/g, '_');
      const displayStatus = statusMap[normalizedStatus] || f['Status'] || 'Queued';

      return {
        id: r.id,
        projectId: f['Project ID'] || f['Project UUID'] || r.id,
        title: f['Project Name'] || 'Untitled Project',
        projectType: projectTypeBadge,
        blueprintName: blueprintName,
        editTier: editTier || 'Tier 2',
        assignedEditor: f['Contact Assigned Editor #1'] || null,
        dateSubmitted: dateCreated,
        eta: eta,
        status: displayStatus,
        duration: f['Duration'] || f['Video Duration'] || null,
        thumbnailUrl: f['ThumbnailURL'] || null,
        reviewVideoUrl: f['ReviewVideoURL'] || null,
        revisionCount: f['Project Revision Count'] || 0,
        feedbackCount: f['FeedbackCount'] || 0,
        resolvedCount: f['ResolvedCount'] || 0
      };
    }));

    // Group by status for dashboard
    const grouped = {
      inEdit: results.filter(p => p.status === 'In Edit'),
      review: results.filter(p => p.status === 'Review'),
      queued: results.filter(p => p.status === 'Queued'),
      revisions: results.filter(p => p.status === 'Revisions'),
      approved: results.filter(p => p.status === 'Approved')
    };

    return res.json({
      success: true,
      projects: results,
      grouped,
      total: results.length
    });

  } catch (err) {
    console.error('[Projects] Fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/projects - Create a new project
app.post('/api/projects', requireAuth(), async (req, res) => {
  try {
    const { title, projectType, blueprintId, rawFootageLink, hookPreference, batchNotes } = req.body;
    const userEmail = req.user.email;
    const userName = req.user.name;

    if (!title) {
      return res.status(400).json({ error: 'missing_title', message: 'Project title required' });
    }

    // Get blueprint for tier calculation
    let editTier = 'Tier 2';
    let blueprintName = '';
    let sla = '3-5';

    if (blueprintId) {
      try {
        const bp = await airtableQuery('Blueprints', `RECORD_ID()='${blueprintId}'`, { maxRecords: 1 });
        if (bp.records?.[0]) {
          const tierInfo = calculateEditTier(bp.records[0]);
          editTier = tierInfo.tier;
          sla = tierInfo.sla;
          blueprintName = bp.records[0].fields?.['Contact Name'] || '';
        }
      } catch (e) { console.error('[Projects] Blueprint fetch error:', e); }
    }

    // Calculate ETA based on tier SLA
    const etaDays = parseInt(sla.split('-')[1]) || 5;
    const etaDate = new Date();
    let addedDays = 0;
    while (addedDays < etaDays) {
      etaDate.setDate(etaDate.getDate() + 1);
      if (etaDate.getDay() !== 0 && etaDate.getDay() !== 6) addedDays++;
    }

    const projectData = {
      'Project Name': title,
      'Project Type': projectType || 'Short Form',
      'Contact Email': userEmail,
      'Contact Name': userName,
      'Status': 'queued',
      'Edit Tier': editTier,
      'Blueprint Name': blueprintName,
      'Project Date Created': new Date().toISOString(),
      'Project ETA': etaDate.toISOString(),
      'Project Revision Count': 0,
      'Hook Preference': hookPreference || '',
      'Batch Notes': batchNotes || '',
      'Raw Footage Link': rawFootageLink || ''
    };

    if (blueprintId) {
      projectData['Style Blueprint'] = [blueprintId];
    }

    const record = await airtableCreate('Projects', projectData);

    return res.json({
      success: true,
      projectId: record.id,
      editTier,
      sla: `${sla} business days`,
      eta: etaDate.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' })
    });

  } catch (err) {
    console.error('[Projects] Create error:', err);
    return res.status(500).json({ error: 'create_failed', message: err.message });
  }
});

// PATCH /api/projects/:id - Update project status
app.patch('/api/projects/:id', requireAuth(), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, assignedEditor, eta } = req.body;
    const userRole = req.user.role || 'client';

    const updateData = {};

    if (status) {
      updateData['Status'] = status;
      if (status === 'approved') {
        updateData['Project Date Approved'] = new Date().toISOString();
      }
    }

    if (assignedEditor && ['admin', 'owner'].includes(userRole)) {
      updateData['Contact Assigned Editor #1'] = assignedEditor;
    }

    if (eta && ['admin', 'owner', 'editor'].includes(userRole)) {
      updateData['Project ETA'] = new Date(eta).toISOString();
    }

    await airtableUpdate('Projects', id, updateData);

    return res.json({ success: true, updated: Object.keys(updateData) });

  } catch (err) {
    console.error('[Projects] Update error:', err);
    return res.status(500).json({ error: 'update_failed', message: err.message });
  }
});

// ============================================
// DISCORD-STYLE CHAT ENDPOINTS
// ============================================

// GET /api/chat/channels - Get user's chat channels
app.get('/api/chat/channels', requireAuth(), async (req, res) => {
  try {
    const userEmail = req.user.email;
    const userRole = req.user.role || 'client';

    let filter;
    if (['admin', 'owner'].includes(userRole)) {
      filter = ''; // See all channels
    } else {
      filter = `OR(FIND('${userEmail}', {Participants}) > 0, {CreatedBy}='${userEmail}')`;
    }

    const channels = await airtableQuery('Chat-Channels', filter, {
      maxRecords: 50,
      sort: [{ field: 'LastMessageAt', direction: 'desc' }]
    });

    const results = channels.records.map(r => ({
      id: r.id,
      channelId: r.fields['ChannelID'] || r.id,
      name: r.fields['Name'] || 'General',
      type: r.fields['Type'] || 'project', // project, private, support
      projectId: r.fields['ProjectID'],
      projectName: r.fields['ProjectName'],
      participants: (r.fields['Participants'] || '').split(',').filter(Boolean),
      lastMessage: r.fields['LastMessage'],
      lastMessageAt: r.fields['LastMessageAt'],
      unreadCount: r.fields['UnreadCount'] || 0,
      createdAt: r.fields['CreatedAt']
    }));

    return res.json({ success: true, channels: results });

  } catch (err) {
    console.error('[Chat] Channels fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// GET /api/chat/channels/:channelId/messages - Get messages for a channel
app.get('/api/chat/channels/:channelId/messages', requireAuth(), async (req, res) => {
  try {
    const { channelId } = req.params;
    const { limit = 50, before } = req.query;

    let filter = `{ChannelID}='${channelId}'`;
    if (before) {
      filter = `AND(${filter}, IS_BEFORE({CreatedAt}, '${before}'))`;
    }

    const messages = await airtableQuery('Chat-Messages', filter, {
      maxRecords: parseInt(limit),
      sort: [{ field: 'CreatedAt', direction: 'desc' }]
    });

    const results = messages.records.map(r => ({
      id: r.id,
      messageId: r.fields['MessageID'] || r.id,
      channelId: r.fields['ChannelID'],
      senderId: r.fields['SenderID'],
      senderName: r.fields['SenderName'],
      senderRole: r.fields['SenderRole'] || 'client',
      senderAvatar: r.fields['SenderAvatar'],
      content: r.fields['Content'],
      type: r.fields['Type'] || 'text', // text, system, link, file
      attachments: r.fields['Attachments'] ? JSON.parse(r.fields['Attachments']) : [],
      linkPreview: r.fields['LinkPreview'] ? JSON.parse(r.fields['LinkPreview']) : null,
      createdAt: r.fields['CreatedAt'],
      editedAt: r.fields['EditedAt'],
      isRead: r.fields['IsRead'] || false
    })).reverse(); // Reverse to get chronological order

    return res.json({ success: true, messages: results, hasMore: results.length >= parseInt(limit) });

  } catch (err) {
    console.error('[Chat] Messages fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/chat/channels/:channelId/messages - Send a message
app.post('/api/chat/channels/:channelId/messages', requireAuth(), async (req, res) => {
  try {
    const { channelId } = req.params;
    const { content, type = 'text', attachments } = req.body;
    const user = req.user;

    if (!content && !attachments?.length) {
      return res.status(400).json({ error: 'empty_message' });
    }

    // Detect links and generate preview placeholder
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const links = content?.match(urlRegex) || [];
    let linkPreview = null;
    if (links.length > 0) {
      linkPreview = { url: links[0], pending: true };
    }

    const messageData = {
      'ChannelID': channelId,
      'SenderID': user.email,
      'SenderName': user.name || user.email.split('@')[0],
      'SenderRole': user.role || 'client',
      'Content': content,
      'Type': type,
      'CreatedAt': new Date().toISOString(),
      'IsRead': false
    };

    if (attachments?.length) {
      messageData['Attachments'] = JSON.stringify(attachments);
    }
    if (linkPreview) {
      messageData['LinkPreview'] = JSON.stringify(linkPreview);
    }

    const record = await airtableCreate('Chat-Messages', messageData);

    // Update channel's last message
    const channelRecords = await airtableQuery('Chat-Channels', `{ChannelID}='${channelId}'`, { maxRecords: 1 });
    if (channelRecords.records?.[0]) {
      await airtableUpdate('Chat-Channels', channelRecords.records[0].id, {
        'LastMessage': content?.substring(0, 100) || '[Attachment]',
        'LastMessageAt': new Date().toISOString()
      });
    }

    return res.json({
      success: true,
      message: {
        id: record.id,
        channelId,
        senderName: user.name,
        content,
        type,
        createdAt: messageData['CreatedAt']
      }
    });

  } catch (err) {
    console.error('[Chat] Send message error:', err);
    return res.status(500).json({ error: 'send_failed', message: err.message });
  }
});

// POST /api/chat/channels - Create a new channel
app.post('/api/chat/channels', requireAuth(), async (req, res) => {
  try {
    const { name, type = 'private', projectId, participants } = req.body;
    const user = req.user;

    const channelData = {
      'ChannelID': `ch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      'Name': name || 'New Channel',
      'Type': type,
      'CreatedBy': user.email,
      'Participants': [user.email, ...(participants || [])].join(','),
      'CreatedAt': new Date().toISOString(),
      'UnreadCount': 0
    };

    if (projectId) {
      channelData['ProjectID'] = projectId;
      // Fetch project name
      const projects = await airtableQuery('Projects', `RECORD_ID()='${projectId}'`, { maxRecords: 1 });
      if (projects.records?.[0]) {
        channelData['ProjectName'] = projects.records[0].fields['Project Name'];
      }
    }

    const record = await airtableCreate('Chat-Channels', channelData);

    // Create system message for channel creation
    await airtableCreate('Chat-Messages', {
      'ChannelID': channelData['ChannelID'],
      'SenderID': 'system',
      'SenderName': 'Content Bug',
      'SenderRole': 'system',
      'Content': `${user.name || user.email} created this channel`,
      'Type': 'system',
      'CreatedAt': new Date().toISOString()
    });

    return res.json({
      success: true,
      channel: {
        id: record.id,
        channelId: channelData['ChannelID'],
        name: channelData['Name'],
        type: channelData['Type']
      }
    });

  } catch (err) {
    console.error('[Chat] Create channel error:', err);
    return res.status(500).json({ error: 'create_failed', message: err.message });
  }
});

// ============================================
// PART A: SAMPLE DATA PURGE SYSTEM
// ============================================

// Tables that can contain sample data
const PURGEABLE_TABLES = [
  'Projects',
  'Chat-Channels',
  'Chat-Messages',
  'Style-Blueprints',
  'Client_Raw_Thumbnails',
  'Project_Thumbnails',
  'Creator_Profile_Stats',
  'Creator_Analysis_Reports',
  'Seed_Creators',
  'Thumbnail_Intelligence',
  'Thumbnail_Patterns'
];

// Helper to delete records from a table with isSample=true
async function purgeTableSampleData(table) {
  try {
    const records = await airtableQuery(table, `{isSample}=TRUE()`, { maxRecords: 100 });
    if (!records.records?.length) {
      return { table, deleted: 0, status: 'no_samples' };
    }

    let deleted = 0;
    for (const record of records.records) {
      try {
        const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}/${record.id}`;
        await axios.delete(url, { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } });
        deleted++;
      } catch (e) {
        console.warn(`[Purge] Failed to delete ${record.id} from ${table}:`, e.message);
      }
    }
    return { table, deleted, status: 'purged' };
  } catch (err) {
    return { table, deleted: 0, status: 'error', error: err.message };
  }
}

// POST /admin/purge-sample-data - Purge all sample data (owner only)
app.post('/admin/purge-sample-data', requireAuth(['owner']), async (req, res) => {
  try {
    const { confirmation } = req.body;

    if (confirmation !== 'PURGE SAMPLE DATA') {
      return res.status(400).json({
        error: 'confirmation_required',
        message: 'Must type "PURGE SAMPLE DATA" to confirm'
      });
    }

    // Log the purge action
    await airtableCreate('AuthAuditLog', {
      EventType: 'sample_data_purge',
      Email: req.user.email,
      IP: req.ip,
      UserAgent: req.get('user-agent'),
      Success: true,
      Details: JSON.stringify({ tables: PURGEABLE_TABLES, initiatedAt: new Date().toISOString() }),
      Timestamp: new Date().toISOString()
    });

    const results = [];
    for (const table of PURGEABLE_TABLES) {
      const result = await purgeTableSampleData(table);
      results.push(result);
    }

    // Also cleanup stale sessions (older than 14 days)
    const staleDate = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
    const staleSessions = await airtableQuery('AuthSessions',
      `IS_BEFORE({CreatedAt}, '${staleDate}')`, { maxRecords: 100 });
    let staleDeleted = 0;
    for (const session of (staleSessions.records || [])) {
      try {
        const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/AuthSessions/${session.id}`;
        await axios.delete(url, { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } });
        staleDeleted++;
      } catch (e) {}
    }
    results.push({ table: 'AuthSessions', deleted: staleDeleted, status: 'stale_cleanup' });

    return res.json({
      success: true,
      message: 'Sample data purge complete',
      results,
      totalDeleted: results.reduce((sum, r) => sum + r.deleted, 0)
    });

  } catch (err) {
    console.error('[Purge] Error:', err);
    return res.status(500).json({ error: 'purge_failed', message: err.message });
  }
});

// GET /admin/sample-data-count - Preview what would be purged
app.get('/admin/sample-data-count', requireAuth(['owner']), async (req, res) => {
  try {
    const counts = [];
    for (const table of PURGEABLE_TABLES) {
      try {
        const records = await airtableQuery(table, `{isSample}=TRUE()`, { maxRecords: 1000 });
        counts.push({ table, count: records.records?.length || 0 });
      } catch (e) {
        counts.push({ table, count: 0, error: e.message });
      }
    }
    return res.json({ counts, total: counts.reduce((s, c) => s + c.count, 0) });
  } catch (err) {
    return res.status(500).json({ error: 'count_failed', message: err.message });
  }
});

// ============================================
// PART B: TEAM PORTAL + UNIFIED ROUTING
// ============================================

// GET /api/team/members - Get all team members (for assignment board)
app.get('/api/team/members', requireAuth(['editor', 'admin', 'owner']), async (req, res) => {
  try {
    const { activeOnly } = req.query;
    let filter = '';
    if (activeOnly === 'true') {
      filter = `{Active}=TRUE()`;
    }

    const result = await airtableQuery('Team', filter, {
      maxRecords: 100,
      sort: [{ field: 'Name', direction: 'asc' }]
    });

    const members = result.records.map(r => ({
      id: r.id,
      name: r.fields.Name,
      email: r.fields.Email,
      role: r.fields.Role,
      avatarURL: r.fields.AvatarURL,
      specialization: r.fields.Specialization,
      activeProjectCount: r.fields.ActiveProjectCount || 0,
      avgTurnaroundScore: r.fields.AvgTurnaroundScore || 0,
      avgQualityScore: r.fields.AvgQualityScore || 0,
      lateProjectCount: r.fields.LateProjectCount || 0,
      activeClients: r.fields.ActiveClients || 0,
      currentPayout: r.fields.CurrentPayout || 0,
      lastActiveAt: r.fields.LastActiveAt,
      active: r.fields.Active !== false
    }));

    return res.json({ members });
  } catch (err) {
    console.error('[Team] Members fetch error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// GET /api/team/unassigned-clients - Get clients without an assigned editor
app.get('/api/team/unassigned-clients', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    // Get contacts where EditorAssigned is empty
    const result = await airtableQuery('Contacts',
      `AND({EditorAssigned}='', OR({Plan}!='', {Entitlement Status}='active'))`,
      { maxRecords: 100, sort: [{ field: 'CreatedAt', direction: 'desc' }] }
    );

    const clients = result.records.map(r => ({
      id: r.id,
      name: r.fields['Contact Name'] || r.fields.Email?.split('@')[0],
      email: r.fields.Email,
      plan: r.fields.Plan || 'Free Trial',
      avatarURL: r.fields.AvatarURL,
      projectsSubmitted: r.fields.ProjectsSubmitted || 0,
      lastActiveAt: r.fields.LastActiveAt,
      createdAt: r.fields.CreatedAt
    }));

    return res.json({ clients });
  } catch (err) {
    console.error('[Team] Unassigned clients error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// GET /api/team/editor/:editorId/clients - Get clients assigned to an editor
app.get('/api/team/editor/:editorId/clients', requireAuth(['editor', 'admin', 'owner']), async (req, res) => {
  try {
    const { editorId } = req.params;

    // If editor, only allow viewing own clients
    if (req.user.role === 'editor' && req.user.userRecordId !== editorId) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const result = await airtableQuery('Contacts',
      `{EditorAssignedId}='${editorId}'`,
      { maxRecords: 100, sort: [{ field: 'Contact Name', direction: 'asc' }] }
    );

    const clients = result.records.map(r => ({
      id: r.id,
      name: r.fields['Contact Name'] || r.fields.Email?.split('@')[0],
      email: r.fields.Email,
      plan: r.fields.Plan || 'Free Trial',
      avatarURL: r.fields.AvatarURL,
      projectsSubmitted: r.fields.ProjectsSubmitted || 0,
      lastActiveAt: r.fields.LastActiveAt
    }));

    return res.json({ clients });
  } catch (err) {
    console.error('[Team] Editor clients error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// POST /api/team/assign-client - Assign a client to an editor
app.post('/api/team/assign-client', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    const { clientId, editorId } = req.body;

    if (!clientId || !editorId) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    // Get editor info
    const editor = await airtableQuery('Team', `RECORD_ID()='${editorId}'`, { maxRecords: 1 });
    if (!editor.records?.[0]) {
      return res.status(404).json({ error: 'editor_not_found' });
    }

    // Update client with editor assignment
    await airtableUpdate('Contacts', clientId, {
      'EditorAssignedId': editorId,
      'EditorAssignedEmail': editor.records[0].fields.Email,
      'EditorAssignedName': editor.records[0].fields.Name
    });

    // Update editor's active client count
    const editorClients = await airtableQuery('Contacts', `{EditorAssignedId}='${editorId}'`, { maxRecords: 1000 });
    await airtableUpdate('Team', editorId, {
      'ActiveClients': editorClients.records?.length || 0
    });

    // Create team ops notification (in a team channel if exists)
    const teamChannel = await airtableQuery('Chat-Channels', `{Name}='#team-ops'`, { maxRecords: 1 });
    if (teamChannel.records?.[0]) {
      await airtableCreate('Chat-Messages', {
        'ChannelID': teamChannel.records[0].fields.ChannelID,
        'SenderID': 'system',
        'SenderName': 'Content Bug',
        'SenderRole': 'system',
        'Content': `${req.user.name || req.user.email} assigned client to ${editor.records[0].fields.Name}`,
        'Type': 'system',
        'CreatedAt': new Date().toISOString()
      });
    }

    return res.json({ success: true, message: 'Client assigned' });
  } catch (err) {
    console.error('[Team] Assign client error:', err);
    return res.status(500).json({ error: 'assign_failed', message: err.message });
  }
});

// ============================================
// PART C: KANBAN BOARD ENDPOINTS
// ============================================

// Project status constants for Kanban columns
const KANBAN_COLUMNS = {
  'queued': { label: 'Project Queue', order: 1 },
  'in_edit': { label: 'In Progress', order: 2 },
  'review_ready': { label: 'Needs Review', order: 3 },
  'revisions': { label: 'In Revision', order: 4 },
  'approved': { label: 'Approved Edits', order: 5 },
  'delivered': { label: 'Delivered', order: 6 }
};

// Editor-allowed status transitions
const EDITOR_TRANSITIONS = {
  'queued': ['in_edit'],
  'in_edit': ['review_ready'],
  'review_ready': ['revisions'], // Only if client requests
  'revisions': ['review_ready']
};

// GET /api/kanban/projects - Get projects organized by Kanban columns
app.get('/api/kanban/projects', requireAuth(), async (req, res) => {
  try {
    const user = req.user;
    const { editorId, clientId, status } = req.query;

    let filter = '';

    // Role-based filtering
    if (user.role === 'client') {
      // Clients only see their own projects
      filter = `{ClientEmail}='${user.email}'`;
    } else if (user.role === 'editor') {
      // Editors see projects assigned to them
      filter = `{AssignedEditorId}='${user.userRecordId}'`;
    } else {
      // Admin/Owner see all, but can filter
      if (editorId) {
        filter = `{AssignedEditorId}='${editorId}'`;
      }
      if (clientId) {
        filter = filter ? `AND(${filter}, {ClientId}='${clientId}')` : `{ClientId}='${clientId}'`;
      }
    }

    // Status filter
    if (status) {
      const statusFilter = `{Status}='${status}'`;
      filter = filter ? `AND(${filter}, ${statusFilter})` : statusFilter;
    }

    // Exclude archived
    const archiveFilter = `{Status}!='archived'`;
    filter = filter ? `AND(${filter}, ${archiveFilter})` : archiveFilter;

    const result = await airtableQuery('Projects', filter, {
      maxRecords: 200,
      sort: [{ field: 'CreatedAt', direction: 'desc' }]
    });

    // Organize by columns
    const columns = {};
    Object.keys(KANBAN_COLUMNS).forEach(status => {
      columns[status] = {
        ...KANBAN_COLUMNS[status],
        projects: []
      };
    });

    // Get blueprint data for tier calculation
    for (const record of result.records || []) {
      const fields = record.fields;
      const status = fields.Status || 'queued';

      // Calculate if late
      const editorDueDate = fields['Editor Due Date'] ? new Date(fields['Editor Due Date']) : null;
      const isLate = editorDueDate && new Date() > editorDueDate && !['approved', 'delivered', 'archived'].includes(status);
      const daysLate = isLate ? Math.ceil((new Date() - editorDueDate) / (1000 * 60 * 60 * 24)) : 0;

      // Revision risk flag
      const revisionCount = fields['Revision Round Count'] || 0;
      const revisionFlag = revisionCount >= 6 ? 'critical' : revisionCount >= 4 ? 'warning' : 'normal';

      const project = {
        id: record.id,
        uuid: fields['Project UUID'],
        title: fields['Project Name'] || 'Untitled Project',
        status: status,
        projectType: fields['Project Format'] === 'long' ? 'Long-Form' : 'Short',
        tier: fields['Project Tier'] || 'tier_2',
        blueprintName: fields['Blueprint Name'] || null,
        assignedEditor: fields['AssignedEditorName'] || null,
        assignedEditorId: fields['AssignedEditorId'] || null,
        dateSubmitted: fields.CreatedAt ? new Date(fields.CreatedAt).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' }) : null,
        eta: fields.ETA ? new Date(fields.ETA).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' }) : null,
        editorDueDate: fields['Editor Due Date'] ? new Date(fields['Editor Due Date']).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' }) : null,
        thumbnailURL: fields.ThumbnailURL,
        revisionCount,
        revisionFlag,
        isLate,
        daysLate,
        clientName: fields['ClientName'],
        clientEmail: fields['ClientEmail']
      };

      if (columns[status]) {
        columns[status].projects.push(project);
      } else {
        // Fallback to queued for unknown statuses
        columns['queued'].projects.push(project);
      }
    }

    return res.json({ columns, userRole: user.role });
  } catch (err) {
    console.error('[Kanban] Projects error:', err);
    return res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// PATCH /api/kanban/project/:id/status - Update project status (drag-drop)
app.patch('/api/kanban/project/:id/status', requireAuth(['editor', 'admin', 'owner']), async (req, res) => {
  try {
    const { id } = req.params;
    const { newStatus, reason } = req.body;
    const user = req.user;

    // Validate status
    if (!KANBAN_COLUMNS[newStatus]) {
      return res.status(400).json({ error: 'invalid_status', message: 'Status not recognized' });
    }

    // Get current project
    const project = await airtableQuery('Projects', `RECORD_ID()='${id}'`, { maxRecords: 1 });
    if (!project.records?.[0]) {
      return res.status(404).json({ error: 'project_not_found' });
    }

    const currentStatus = project.records[0].fields.Status || 'queued';

    // Editor permission check
    if (user.role === 'editor') {
      // Check if editor is assigned to this project
      if (project.records[0].fields.AssignedEditorId !== user.userRecordId) {
        return res.status(403).json({ error: 'not_assigned', message: 'You are not assigned to this project' });
      }

      // Check if transition is allowed for editors
      const allowedTransitions = EDITOR_TRANSITIONS[currentStatus] || [];
      if (!allowedTransitions.includes(newStatus)) {
        return res.status(403).json({
          error: 'transition_not_allowed',
          message: `Editors cannot move from ${currentStatus} to ${newStatus}`
        });
      }

      // Editors cannot approve - that's client action only
      if (newStatus === 'approved') {
        return res.status(403).json({ error: 'approval_requires_client' });
      }
    }

    // Update status
    const updateFields = {
      'Status': newStatus,
      'StatusUpdatedAt': new Date().toISOString(),
      'StatusUpdatedBy': user.email
    };

    // Add to revision history if moving to revisions
    if (newStatus === 'revisions') {
      const currentHistory = project.records[0].fields['Revision History'] || '[]';
      let history = [];
      try { history = JSON.parse(currentHistory); } catch(e) {}
      history.push({
        timestamp: new Date().toISOString(),
        by: user.email,
        reason: reason || 'Revision requested'
      });
      updateFields['Revision History'] = JSON.stringify(history);
      updateFields['Revision Round Count'] = (project.records[0].fields['Revision Round Count'] || 0) + 1;
    }

    await airtableUpdate('Projects', id, updateFields);

    // Log the transition
    await airtableCreate('Errors', {
      ErrorID: `status_change_${Date.now()}`,
      Timestamp: new Date().toISOString(),
      UserRole: user.role,
      UserID: user.email,
      Context: 'kanban_status_change',
      Message: `Project ${id} moved from ${currentStatus} to ${newStatus}`,
      Page: '/team'
    });

    return res.json({
      success: true,
      previousStatus: currentStatus,
      newStatus,
      message: `Project moved to ${KANBAN_COLUMNS[newStatus].label}`
    });
  } catch (err) {
    console.error('[Kanban] Status update error:', err);
    return res.status(500).json({ error: 'update_failed', message: err.message });
  }
});

// POST /api/kanban/project/:id/approve - Client approves project
app.post('/api/kanban/project/:id/approve', requireAuth(), async (req, res) => {
  try {
    const { id } = req.params;
    const { qualityRating } = req.body;
    const user = req.user;

    // Get project
    const project = await airtableQuery('Projects', `RECORD_ID()='${id}'`, { maxRecords: 1 });
    if (!project.records?.[0]) {
      return res.status(404).json({ error: 'project_not_found' });
    }

    // Verify client owns this project
    if (user.role === 'client' && project.records[0].fields.ClientEmail !== user.email) {
      return res.status(403).json({ error: 'not_your_project' });
    }

    // Must be in review_ready status
    if (project.records[0].fields.Status !== 'review_ready') {
      return res.status(400).json({ error: 'not_in_review', message: 'Project must be in review to approve' });
    }

    await airtableUpdate('Projects', id, {
      'Status': 'approved',
      'QualityScore': qualityRating || null,
      'ApprovedAt': new Date().toISOString(),
      'ApprovedBy': user.email
    });

    return res.json({ success: true, showConfetti: true, message: 'Project approved!' });
  } catch (err) {
    console.error('[Kanban] Approve error:', err);
    return res.status(500).json({ error: 'approve_failed', message: err.message });
  }
});

// GET /api/team/stats - Get team-wide stats for dashboard
app.get('/api/team/stats', requireAuth(['admin', 'owner']), async (req, res) => {
  try {
    // Get counts by status
    const allProjects = await airtableQuery('Projects', `{Status}!='archived'`, { maxRecords: 1000 });

    const statusCounts = {};
    Object.keys(KANBAN_COLUMNS).forEach(s => statusCounts[s] = 0);

    let lateCount = 0;
    let atRiskCount = 0;

    for (const r of allProjects.records || []) {
      const status = r.fields.Status || 'queued';
      if (statusCounts[status] !== undefined) statusCounts[status]++;

      // Check SLA
      const editorDue = r.fields['Editor Due Date'] ? new Date(r.fields['Editor Due Date']) : null;
      if (editorDue && !['approved', 'delivered', 'archived'].includes(status)) {
        if (new Date() > editorDue) lateCount++;
        else if (new Date() > new Date(editorDue.getTime() - 24 * 60 * 60 * 1000)) atRiskCount++;
      }
    }

    // Get unassigned clients count
    const unassigned = await airtableQuery('Contacts',
      `AND({EditorAssignedId}='', OR({Plan}!='', {Entitlement Status}='active'))`,
      { maxRecords: 100 });

    // Get active editors count
    const editors = await airtableQuery('Team', `AND({Role}='editor', {Active}=TRUE())`, { maxRecords: 50 });

    return res.json({
      statusCounts,
      lateCount,
      atRiskCount,
      unassignedClientsCount: unassigned.records?.length || 0,
      activeEditorsCount: editors.records?.length || 0,
      totalActiveProjects: allProjects.records?.length || 0
    });
  } catch (err) {
    console.error('[Team] Stats error:', err);
    return res.status(500).json({ error: 'stats_failed', message: err.message });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`ContentBug Production MCP Server v2.4.0`);
  console.log(`${'='.repeat(50)}`);
  console.log(`Port: ${PORT}`);
  console.log(`Environment: ${IS_PRODUCTION ? 'PRODUCTION' : 'development'}`);
  console.log(`Health check: /healthz`);
  console.log(`\nServices:`);
  console.log(`  Auth:    enabled`);
  console.log(`  Chat:    enabled`);
  console.log(`  Drive:   ${driveServiceReady ? 'enabled' : 'DISABLED - ' + driveInitError}`);
  console.log(`  Apify:   ${APIFY_API_TOKEN ? 'enabled' : 'DISABLED - no token'}`);
  console.log(`  OTP:     GHL API=${!!GHL_API_KEY}, Webhook=${!!GHL_WEBHOOK_URL}, Debug=${EMAIL_DELIVERY_DEBUG}`);
  console.log(`\n${'='.repeat(50)}\n`);
});
