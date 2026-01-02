// ContentBug Portal MCP Server v3.5.0
// GHL is source of truth for contacts - GHL natively syncs to Airtable
// Chat/Messages stored in Airtable directly
// Zoom integration for instant meetings
// Updated: 2025-01-01

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// ENVIRONMENT VARIABLES
// ============================================
const GHL_API_KEY = process.env.GHL_API_KEY || process.env.GHL_PRIVATE_INTEGRATION;
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || 'mCNHhjy593eUueqfuqyU';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const APIFY_API_TOKEN = process.env.APIFY_API_TOKEN;
const GOOGLE_SERVICE_ACCOUNT_JSON = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

// Airtable Configuration
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY || 'patW8QGZbjGkib5kY.ee72a270de99dbeb731ff11ddfab6505b6612f988555e1b1f0cf77bf938c04e3';
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID || 'appIrlFuwtsxj8hly';
const AIRTABLE_API = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}`;

// Airtable Table IDs
const AT_TABLES = {
  channels: 'tbluzdmKjuhC2Bvra',
  messages: 'tbl98EutZ8YB6Tc2E',
  clients: 'tbl4XuHJAcVDUVYGX',
  team: 'tblHlgg1sHKFt052x'
};

// Zoom Configuration (Server-to-Server OAuth)
const ZOOM_ACCOUNT_ID = process.env.ZOOM_ACCOUNT_ID || 'грRxnFg8QnKOzхCrF_хP7w';
const ZOOM_CLIENT_ID = process.env.ZOOM_CLIENT_ID || 'Da0ubYM3QrSpY1ZHjSOtlg';
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET || 'хуJfh9Vgb6401Qqc3hmВuS00naIHZs7j';
const ZOOM_WEBHOOK_SECRET = process.env.ZOOM_WEBHOOK_SECRET || '2W9_jl6oT36Gaisjq3F9ZQ';

// GHL WEBHOOK - triggers workflow that creates contact + sends email
const GHL_EMAIL_WEBHOOK = 'https://services.leadconnectorhq.com/hooks/mCNHhjy593eUueqfuqyU/webhook-trigger/8e7bf1a8-4355-4f40-a944-b16b4ca86fa9';

// GHL Custom Field IDs (from your GHL account)
const GHL_FIELDS = {
  verificationCode: 'CBbaL4SuA8FZDZVgQjfi',
  subscriptionStatus: 'Ghjqnou2JlvisuhyEXBl',
  portalAccess: 'ztoUhJfmTbr1UyDfPinN',
  userRole: 'HOgOPP9ZkjeqBNRIlf2j',
  onboardingStatus: 'KfDkeejhohHXTHHH4NXx',
  subscriptionName: 'IsFHpDJyHPLLCBEv6p7v',
  lastLogin: 'Ajx6J8PsXSzYzmUAMZLJ',
  billingFrequency: '1y2GjGu7NdBmKLvMGbYA',
  paymentAmount: '7qsOanEB7Cn3BurU56TY',
  googleDriveFolderLink: '4QyBtRG058GOVWbyy4qG',
  paymentUpdateLink: '96abL07qy7XYRoWtxqhi'
};

// ============================================
// GOOGLE DRIVE SETUP
// ============================================
let googleDrive = null;
let driveReady = false;

function initGoogleDrive() {
  try {
    if (!GOOGLE_SERVICE_ACCOUNT_JSON) return false;
    const credentials = JSON.parse(GOOGLE_SERVICE_ACCOUNT_JSON);
    const { google } = require('googleapis');
    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/drive.file']
    });
    googleDrive = google.drive({ version: 'v3', auth });
    driveReady = true;
    console.log('[Drive] Initialized');
    return true;
  } catch (err) {
    console.error('[Drive] Init failed:', err.message);
    return false;
  }
}
initGoogleDrive();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') {
    next();
  } else {
    express.json({ limit: '10mb' })(req, res, next);
  }
});

// ============================================
// STATIC FILE SERVING (Portal HTML)
// ============================================
const path = require('path');
app.use('/portal', express.static(path.join(__dirname, 'portal')));

// Route aliases for clean URLs
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'signup.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'portal.html')));
app.get('/review', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'review.html')));
app.get('/record', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'record.html')));
app.get('/blueprint', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'style-blueprint.html')));
app.get('/submit', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'submit-project.html')));
app.get('/team-login', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'team-login.html')));
app.get('/team-signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'team-signup.html')));
app.get('/editor-signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor-signup.html')));
app.get('/team', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'team-index.html')));

// ============================================
// ADMIN PORTAL ROUTES
// ============================================
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'dashboard.html')));
app.get('/admin/clients', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'clients.html')));
app.get('/admin/editors', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'editors.html')));
app.get('/admin/projects', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'projects.html')));
app.get('/admin/leads', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'leads.html')));
app.get('/admin/sales', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'sales.html')));
app.get('/admin/kpi', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'admin', 'kpi.html')));

// ============================================
// EDITOR PORTAL ROUTES
// ============================================
app.get('/editor', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'index.html')));
app.get('/editor/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'dashboard.html')));
app.get('/editor/clients', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'clients.html')));
app.get('/editor/pipeline', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'pipeline.html')));
app.get('/editor/chat', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'chat.html')));
app.get('/editor/payouts', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'payouts.html')));
app.get('/editor/leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'leaderboard.html')));
app.get('/editor/schedule', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'schedule.html')));
app.get('/editor/meeting', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'meeting.html')));

// ============================================
// CLIENT PORTAL ROUTES
// ============================================
app.get('/client', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'index.html')));
app.get('/client/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'dashboard.html')));
app.get('/client/pipeline', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'pipeline.html')));
app.get('/client/chat', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'chat.html')));
app.get('/client/blueprint', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'blueprint.html')));
app.get('/client/submit', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'submit.html')));
app.get('/client/review', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'review.html')));
app.get('/client/record', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'record.html')));
app.get('/client/storage', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'storage.html')));
app.get('/client/store', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'store.html')));

// ============================================
// SHARED ROUTES
// ============================================
app.get('/shared/login', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'shared', 'login.html')));
app.get('/shared/team-signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'shared', 'team-signup.html')));

// Root redirect to login
app.get('/', (req, res) => res.redirect('/login'));

// ============================================
// AIRTABLE HELPERS
// ============================================
const airtableHeaders = {
  'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
  'Content-Type': 'application/json'
};

async function airtableGet(table, filterFormula = null, maxRecords = 100) {
  try {
    let url = `${AIRTABLE_API}/${table}?maxRecords=${maxRecords}`;
    if (filterFormula) {
      url += `&filterByFormula=${encodeURIComponent(filterFormula)}`;
    }
    const res = await axios.get(url, { headers: airtableHeaders });
    return res.data.records || [];
  } catch (err) {
    console.error('[Airtable Get]', err.response?.data || err.message);
    return [];
  }
}

async function airtableCreate(table, fields) {
  try {
    const res = await axios.post(
      `${AIRTABLE_API}/${table}`,
      { fields },
      { headers: airtableHeaders }
    );
    return res.data;
  } catch (err) {
    console.error('[Airtable Create]', err.response?.data || err.message);
    return null;
  }
}

async function airtableUpdate(table, recordId, fields) {
  try {
    const res = await axios.patch(
      `${AIRTABLE_API}/${table}/${recordId}`,
      { fields },
      { headers: airtableHeaders }
    );
    return res.data;
  } catch (err) {
    console.error('[Airtable Update]', err.response?.data || err.message);
    return null;
  }
}

// ============================================
// HEALTH CHECK
// ============================================
app.get('/healthz', (req, res) => res.json({
  ok: true,
  version: '3.5.0-admin-editor-client-portals',
  ts: Date.now(),
  services: {
    ghl: !!GHL_API_KEY,
    claude: !!CLAUDE_API_KEY,
    openai: !!OPENAI_API_KEY,
    stripe: !!STRIPE_SECRET_KEY,
    apify: !!APIFY_API_TOKEN,
    drive: driveReady,
    airtable: !!AIRTABLE_API_KEY,
    zoom: !!(ZOOM_CLIENT_ID && ZOOM_CLIENT_SECRET && ZOOM_ACCOUNT_ID)
  }
}));

// ============================================
// GHL HELPERS
// ============================================
async function ghlFindByEmail(email) {
  if (!GHL_API_KEY) return null;
  try {
    const res = await axios.get(
      `https://services.leadconnectorhq.com/contacts/?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    return res.data?.contacts?.[0] || null;
  } catch (err) {
    console.error('[GHL Find]', err.message);
    return null;
  }
}

async function ghlUpdateContact(contactId, data) {
  if (!GHL_API_KEY) return null;
  try {
    const res = await axios.put(
      `https://services.leadconnectorhq.com/contacts/${contactId}`,
      data,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
    );
    return res.data;
  } catch (err) {
    console.error('[GHL Update]', err.message);
    return null;
  }
}

async function ghlAddTags(contactId, tags) {
  if (!GHL_API_KEY) return null;
  try {
    await axios.post(
      `https://services.leadconnectorhq.com/contacts/${contactId}/tags`,
      { tags },
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
    );
    return true;
  } catch (err) {
    return false;
  }
}

// ============================================
// VERIFICATION SYSTEM
// ============================================
const verificationCodes = new Map();

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateId() {
  return crypto.randomBytes(12).toString('hex');
}

// ============================================
// AUTH ENDPOINTS
// ============================================

app.post('/api/auth/send-code', async (req, res) => {
  try {
    const { email, source = 'portal_login', firstName = '' } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const code = generateCode();

    verificationCodes.set(normalizedEmail, {
      code,
      createdAt: Date.now(),
      attempts: 0
    });

    let template = 'portal_login_trial';

    if (source === 'pricing_unlock' || source === 'pricing_page') {
      template = 'pricing_unlock';
    } else {
      const contact = await ghlFindByEmail(normalizedEmail);
      if (contact?.customFields) {
        const subStatus = contact.customFields.find(f => f.id === GHL_FIELDS.subscriptionStatus)?.value;
        if (subStatus === 'Active') template = 'portal_login_active';
        else if (subStatus === 'Failed Payment') template = 'portal_login_failed';
        else if (subStatus === 'Canceled') template = 'portal_login_canceled';
      }
    }

    const webhookPayload = {
      email: normalizedEmail,
      first_name: firstName,
      verification_code: code,
      template: template,
      source: source,
      timestamp: new Date().toISOString()
    };

    console.log(`[Auth] Webhook payload:`, JSON.stringify(webhookPayload));

    await axios.post(GHL_EMAIL_WEBHOOK, webhookPayload, {
      headers: { 'Content-Type': 'application/json' }
    });

    console.log(`[Auth] Sent code ${code} to GHL for ${normalizedEmail} (${template})`);

    res.json({ success: true, message: 'Verification code sent' });

  } catch (err) {
    console.error('[Auth Send]', err.message);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

app.post('/api/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let stored = verificationCodes.get(normalizedEmail);
    let storedCode = stored?.code;

    let contact = null;
    if (!storedCode && GHL_API_KEY) {
      contact = await ghlFindByEmail(normalizedEmail);
      if (contact?.customFields) {
        const codeField = contact.customFields.find(f => f.id === GHL_FIELDS.verificationCode);
        storedCode = codeField?.value;
        stored = { code: storedCode, createdAt: Date.now() - 300000, attempts: 0 };
      }
    }

    if (!storedCode) {
      return res.status(400).json({ error: 'No code found. Please request a new one.' });
    }

    if (stored && Date.now() - stored.createdAt > 600000) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });
    }

    if (stored && stored.attempts >= 5) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Too many attempts. Request a new code.' });
    }

    if (storedCode !== code) {
      if (stored) stored.attempts++;
      return res.status(400).json({ error: 'Invalid code' });
    }

    // SUCCESS
    verificationCodes.delete(normalizedEmail);

    if (!contact) {
      contact = await ghlFindByEmail(normalizedEmail);
    }

    let contactData = {
      email: normalizedEmail,
      firstName: '',
      lastName: '',
      subscriptionStatus: '',
      portalAccess: 'Limited',
      userRole: 'Lead',
      onboardingStatus: '',
      subscriptionName: ''
    };

    if (contact) {
      contactData.firstName = contact.firstName || '';
      contactData.lastName = contact.lastName || '';
      contactData.phone = contact.phone || '';
      contactData.ghlContactId = contact.id;

      if (contact.customFields) {
        for (const cf of contact.customFields) {
          if (cf.id === GHL_FIELDS.subscriptionStatus) contactData.subscriptionStatus = cf.value || '';
          if (cf.id === GHL_FIELDS.portalAccess) contactData.portalAccess = cf.value || 'Limited';
          if (cf.id === GHL_FIELDS.userRole) contactData.userRole = cf.value || 'Lead';
          if (cf.id === GHL_FIELDS.onboardingStatus) contactData.onboardingStatus = cf.value || '';
          if (cf.id === GHL_FIELDS.subscriptionName) contactData.subscriptionName = cf.value || '';
        }
      }

      await ghlUpdateContact(contact.id, {
        customFields: [
          { id: GHL_FIELDS.verificationCode, value: '' },
          { id: GHL_FIELDS.lastLogin, value: new Date().toISOString() }
        ]
      });

      await ghlAddTags(contact.id, ['email-verified']);
    }

    const token = Buffer.from(`${normalizedEmail}:${Date.now()}`).toString('base64');

    console.log(`[Auth] Verified: ${normalizedEmail}`);

    res.json({
      success: true,
      verified: true,
      token,
      ...contactData
    });

  } catch (err) {
    console.error('[Auth Verify]', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============================================
// CHAT ENDPOINTS (Airtable Storage)
// ============================================

/**
 * GET /inbox - Team inbox (all channels for admin/editor)
 * Filters by role: admin/owner see all, editor sees assigned only
 */
app.get('/inbox', async (req, res) => {
  try {
    const userEmail = req.headers['x-user-email'];
    const userRole = req.headers['x-user-role'] || 'editor';

    let filter = '';
    if (userRole === 'editor') {
      // Editors only see channels where they're assigned
      filter = `FIND("${userEmail}", {participant_emails})`;
    }
    // Admin/Owner see all channels

    const channels = await airtableGet(AT_TABLES.channels, filter, 100);

    const formatted = channels.map(ch => ({
      id: ch.id,
      channel_id: ch.fields.channel_id,
      type: ch.fields.type || 'client',
      name: ch.fields.name,
      client_email: ch.fields.client_email,
      client_tier: ch.fields.client_tier || 'trial',
      client_status: ch.fields.client_status || 'active',
      assigned_editor: ch.fields.assigned_editor,
      last_message_at: ch.fields.last_message_at,
      unread_team: ch.fields.unread_team || 0,
      unread_client: ch.fields.unread_client || 0,
      badges: ch.fields.badges ? JSON.parse(ch.fields.badges) : []
    }));

    // Sort by last_message_at desc
    formatted.sort((a, b) => new Date(b.last_message_at || 0) - new Date(a.last_message_at || 0));

    res.json({ success: true, channels: formatted });

  } catch (err) {
    console.error('[Inbox]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /chat/channels/:user_email - Get channels for a specific user (client view)
 */
app.get('/chat/channels/:user_email', async (req, res) => {
  try {
    const userEmail = req.params.user_email.toLowerCase().trim();

    // Find channels where this email is the client
    const filter = `{client_email} = "${userEmail}"`;
    const channels = await airtableGet(AT_TABLES.channels, filter);

    if (channels.length === 0) {
      // No channel exists - create one
      const channelId = `ch_${generateId()}`;

      // Try to get client name from GHL
      let clientName = userEmail.split('@')[0];
      const contact = await ghlFindByEmail(userEmail);
      if (contact) {
        clientName = `${contact.firstName || ''} ${contact.lastName || ''}`.trim() || clientName;
      }

      const newChannel = await airtableCreate(AT_TABLES.channels, {
        channel_id: channelId,
        type: 'client',
        name: clientName,
        client_email: userEmail,
        client_tier: 'trial',
        client_status: 'active',
        participant_emails: userEmail,
        created_at: new Date().toISOString()
      });

      if (newChannel) {
        return res.json({
          success: true,
          channels: [{
            id: newChannel.id,
            channel_id: channelId,
            type: 'client',
            name: clientName,
            client_email: userEmail,
            client_tier: 'trial',
            unread_client: 0
          }]
        });
      }
    }

    const formatted = channels.map(ch => ({
      id: ch.id,
      channel_id: ch.fields.channel_id,
      type: ch.fields.type || 'client',
      name: ch.fields.name,
      client_email: ch.fields.client_email,
      client_tier: ch.fields.client_tier || 'trial',
      unread_client: ch.fields.unread_client || 0
    }));

    res.json({ success: true, channels: formatted });

  } catch (err) {
    console.error('[Get Channels]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /chat/channels - Create a new channel
 */
app.post('/chat/channels', async (req, res) => {
  try {
    const { type = 'client', name, client_email, participant_emails, client_tier = 'trial' } = req.body;

    const channelId = `ch_${generateId()}`;

    const channel = await airtableCreate(AT_TABLES.channels, {
      channel_id: channelId,
      type,
      name: name || client_email?.split('@')[0] || 'New Channel',
      client_email: client_email?.toLowerCase(),
      client_tier,
      client_status: 'active',
      participant_emails: participant_emails || client_email,
      created_at: new Date().toISOString()
    });

    if (!channel) {
      return res.status(500).json({ error: 'Failed to create channel' });
    }

    res.json({
      success: true,
      channel: {
        id: channel.id,
        channel_id: channelId,
        type,
        name: channel.fields.name,
        client_email: channel.fields.client_email
      }
    });

  } catch (err) {
    console.error('[Create Channel]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /chat/messages/:channel_id - Get messages for a channel
 */
app.get('/chat/messages/:channel_id', async (req, res) => {
  try {
    const channelId = req.params.channel_id;
    const limit = parseInt(req.query.limit) || 50;
    const before = req.query.before; // For pagination

    let filter = `{channel_id} = "${channelId}"`;

    const messages = await airtableGet(AT_TABLES.messages, filter, limit);

    const formatted = messages.map(msg => ({
      id: msg.id,
      message_id: msg.fields.message_id,
      channel_id: msg.fields.channel_id,
      sender_email: msg.fields.sender_email,
      sender_name: msg.fields.sender_name,
      sender_role: msg.fields.sender_role || 'client',
      sender_avatar: msg.fields.sender_avatar,
      content: msg.fields.content,
      attachments: msg.fields.attachments || [],
      created_at: msg.fields.created_at,
      is_system: msg.fields.is_system || false
    }));

    // Sort by created_at asc
    formatted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    res.json({ success: true, messages: formatted });

  } catch (err) {
    console.error('[Get Messages]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /chat/send - Send a message
 */
app.post('/chat/send', async (req, res) => {
  try {
    const { channel_id, content, sender_email, sender_name, sender_role = 'client', sender_avatar, attachments } = req.body;

    if (!channel_id || !content || !sender_email) {
      return res.status(400).json({ error: 'channel_id, content, and sender_email required' });
    }

    const messageId = `msg_${generateId()}`;
    const now = new Date().toISOString();

    const message = await airtableCreate(AT_TABLES.messages, {
      message_id: messageId,
      channel_id,
      sender_email: sender_email.toLowerCase(),
      sender_name: sender_name || sender_email.split('@')[0],
      sender_role,
      sender_avatar,
      content,
      created_at: now,
      is_system: false
    });

    if (!message) {
      return res.status(500).json({ error: 'Failed to send message' });
    }

    // Update channel's last_message_at and increment unread count
    const channels = await airtableGet(AT_TABLES.channels, `{channel_id} = "${channel_id}"`);
    if (channels.length > 0) {
      const channel = channels[0];
      const updates = { last_message_at: now };

      // Increment unread for the other party
      if (sender_role === 'client') {
        updates.unread_team = (channel.fields.unread_team || 0) + 1;
      } else {
        updates.unread_client = (channel.fields.unread_client || 0) + 1;
      }

      await airtableUpdate(AT_TABLES.channels, channel.id, updates);
    }

    res.json({
      success: true,
      message: {
        id: message.id,
        message_id: messageId,
        channel_id,
        sender_email: sender_email.toLowerCase(),
        sender_name: sender_name || sender_email.split('@')[0],
        sender_role,
        content,
        created_at: now
      }
    });

  } catch (err) {
    console.error('[Send Message]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /chat/poll/:channel_id - Poll for new messages
 */
app.get('/chat/poll/:channel_id', async (req, res) => {
  try {
    const channelId = req.params.channel_id;
    const after = req.query.after; // message_id to get messages after

    let filter = `{channel_id} = "${channelId}"`;

    const messages = await airtableGet(AT_TABLES.messages, filter, 100);

    let formatted = messages.map(msg => ({
      id: msg.id,
      message_id: msg.fields.message_id,
      channel_id: msg.fields.channel_id,
      sender_email: msg.fields.sender_email,
      sender_name: msg.fields.sender_name,
      sender_role: msg.fields.sender_role || 'client',
      sender_avatar: msg.fields.sender_avatar,
      content: msg.fields.content,
      attachments: msg.fields.attachments || [],
      created_at: msg.fields.created_at,
      is_system: msg.fields.is_system || false
    }));

    // Sort by created_at asc
    formatted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    // Filter to only messages after the given message_id
    if (after) {
      const afterIndex = formatted.findIndex(m => m.message_id === after);
      if (afterIndex >= 0) {
        formatted = formatted.slice(afterIndex + 1);
      }
    }

    res.json({ success: true, messages: formatted });

  } catch (err) {
    console.error('[Poll Messages]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /chat/read/:channel_id - Mark messages as read
 */
app.post('/chat/read/:channel_id', async (req, res) => {
  try {
    const channelId = req.params.channel_id;
    const userRole = req.headers['x-user-role'] || req.body.role || 'client';

    const channels = await airtableGet(AT_TABLES.channels, `{channel_id} = "${channelId}"`);
    if (channels.length === 0) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    const channel = channels[0];
    const updates = {};

    if (userRole === 'client') {
      updates.unread_client = 0;
    } else {
      updates.unread_team = 0;
    }

    await airtableUpdate(AT_TABLES.channels, channel.id, updates);

    res.json({ success: true });

  } catch (err) {
    console.error('[Mark Read]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// ZOOM INTEGRATION
// ============================================

let zoomAccessToken = null;
let zoomTokenExpiry = 0;

async function getZoomAccessToken() {
  if (zoomAccessToken && Date.now() < zoomTokenExpiry) {
    return zoomAccessToken;
  }

  if (!ZOOM_CLIENT_ID || !ZOOM_CLIENT_SECRET || !ZOOM_ACCOUNT_ID) {
    console.log('[Zoom] Missing credentials');
    return null;
  }

  try {
    const auth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString('base64');
    const res = await axios.post(
      'https://zoom.us/oauth/token',
      `grant_type=account_credentials&account_id=${ZOOM_ACCOUNT_ID}`,
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    zoomAccessToken = res.data.access_token;
    zoomTokenExpiry = Date.now() + (res.data.expires_in * 1000) - 60000; // Refresh 1 min before expiry
    console.log('[Zoom] Token refreshed');
    return zoomAccessToken;
  } catch (err) {
    console.error('[Zoom Token]', err.response?.data || err.message);
    return null;
  }
}

/**
 * POST /api/zoom/meeting - Create instant Zoom meeting
 */
app.post('/api/zoom/meeting', async (req, res) => {
  try {
    const { topic = 'ContentBug Quick Meeting', channel_id, host_email } = req.body;

    const token = await getZoomAccessToken();
    if (!token) {
      return res.status(500).json({ error: 'Zoom not configured' });
    }

    // Create instant meeting
    const meetingRes = await axios.post(
      'https://api.zoom.us/v2/users/me/meetings',
      {
        topic,
        type: 1, // Instant meeting
        settings: {
          host_video: true,
          participant_video: true,
          join_before_host: true,
          waiting_room: false,
          meeting_authentication: false
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const meeting = meetingRes.data;

    // If channel_id provided, post a system message to the channel
    if (channel_id) {
      const systemMessage = await airtableCreate(AT_TABLES.messages, {
        message_id: `msg_${generateId()}`,
        channel_id,
        sender_email: host_email || 'system@contentbug.io',
        sender_name: 'ContentBug',
        sender_role: 'system',
        content: `🎥 **Zoom Meeting Started**\n\n[Join Meeting](${meeting.join_url})\n\nMeeting ID: ${meeting.id}`,
        created_at: new Date().toISOString(),
        is_system: true
      });
    }

    res.json({
      success: true,
      meeting: {
        id: meeting.id,
        join_url: meeting.join_url,
        start_url: meeting.start_url,
        password: meeting.password,
        topic: meeting.topic
      }
    });

  } catch (err) {
    console.error('[Zoom Meeting]', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to create meeting' });
  }
});

/**
 * POST /api/zoom/webhook - Zoom webhook endpoint
 */
app.post('/api/zoom/webhook', async (req, res) => {
  console.log('[Zoom Webhook]', JSON.stringify(req.body).slice(0, 500));

  // Handle Zoom webhook validation
  if (req.body.event === 'endpoint.url_validation') {
    const hashForValidation = crypto
      .createHmac('sha256', ZOOM_WEBHOOK_SECRET)
      .update(req.body.payload.plainToken)
      .digest('hex');

    return res.json({
      plainToken: req.body.payload.plainToken,
      encryptedToken: hashForValidation
    });
  }

  res.json({ received: true });
});

// ============================================
// CLIENT ENDPOINTS (reads from GHL)
// ============================================

app.get('/api/client/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    const contact = await ghlFindByEmail(email);

    if (!contact) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const data = {
      success: true,
      ghlContactId: contact.id,
      email: contact.email,
      firstName: contact.firstName || '',
      lastName: contact.lastName || '',
      phone: contact.phone || ''
    };

    if (contact.customFields) {
      for (const cf of contact.customFields) {
        if (cf.id === GHL_FIELDS.subscriptionStatus) data.subscriptionStatus = cf.value;
        if (cf.id === GHL_FIELDS.portalAccess) data.portalAccess = cf.value;
        if (cf.id === GHL_FIELDS.userRole) data.userRole = cf.value;
        if (cf.id === GHL_FIELDS.onboardingStatus) data.onboardingStatus = cf.value;
        if (cf.id === GHL_FIELDS.subscriptionName) data.subscriptionName = cf.value;
        if (cf.id === GHL_FIELDS.googleDriveFolderLink) data.googleDriveFolderLink = cf.value;
      }
    }

    res.json(data);

  } catch (err) {
    console.error('[Client Get]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/client/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    const updates = req.body;

    const contact = await ghlFindByEmail(email);
    if (!contact) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const ghlUpdates = {};
    if (updates.firstName) ghlUpdates.firstName = updates.firstName;
    if (updates.lastName) ghlUpdates.lastName = updates.lastName;
    if (updates.phone) ghlUpdates.phone = updates.phone;

    const customFields = [];
    if (updates.subscriptionStatus) customFields.push({ id: GHL_FIELDS.subscriptionStatus, value: updates.subscriptionStatus });
    if (updates.portalAccess) customFields.push({ id: GHL_FIELDS.portalAccess, value: updates.portalAccess });
    if (updates.userRole) customFields.push({ id: GHL_FIELDS.userRole, value: updates.userRole });
    if (updates.onboardingStatus) customFields.push({ id: GHL_FIELDS.onboardingStatus, value: updates.onboardingStatus });

    if (customFields.length > 0) ghlUpdates.customFields = customFields;

    await ghlUpdateContact(contact.id, ghlUpdates);

    res.json({ success: true, ghlContactId: contact.id });

  } catch (err) {
    console.error('[Client Update]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// GHL API PROXY ENDPOINTS
// ============================================

app.get('/ghl/contact/search', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });
  const contact = await ghlFindByEmail(email);
  res.json(contact || { error: 'not found' });
});

app.get('/ghl/contact/:id', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/contacts/${req.params.id}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json(r.data);
  } catch (err) {
    res.status(404).json({ error: 'not found' });
  }
});

app.get('/ghl/custom-fields', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/locations/${GHL_LOCATION_ID}/customFields`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// TEAM ENDPOINTS
// ============================================

/**
 * GET /api/team - Get team members
 */
app.get('/api/team', async (req, res) => {
  try {
    const team = await airtableGet(AT_TABLES.team);

    const formatted = team.map(t => ({
      id: t.id,
      name: t.fields.Name,
      email: t.fields.Email,
      role: t.fields.Role || 'editor',
      status: t.fields.Status || 'active',
      avatar: t.fields.AvatarURL,
      online_status: t.fields.OnlineStatus || 'offline'
    }));

    res.json({ success: true, team: formatted });

  } catch (err) {
    console.error('[Team Get]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// WEBHOOKS
// ============================================

app.post('/webhook', (req, res) => {
  console.log('[Webhook]', JSON.stringify(req.body).slice(0, 500));
  res.json({ received: true });
});

app.post('/webhook/ghl', (req, res) => {
  console.log('[GHL Webhook]', JSON.stringify(req.body).slice(0, 500));
  res.json({ received: true });
});

// Stripe webhook - updates GHL contact
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;

  try {
    if (STRIPE_WEBHOOK_SECRET) {
      const stripe = require('stripe')(STRIPE_SECRET_KEY);
      event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
    } else {
      event = JSON.parse(req.body.toString());
    }

    console.log('[Stripe]', event.type);

    if (event.type === 'invoice.payment_succeeded') {
      const invoice = event.data.object;
      if (invoice.customer_email) {
        const contact = await ghlFindByEmail(invoice.customer_email);
        if (contact) {
          await ghlUpdateContact(contact.id, {
            customFields: [
              { id: GHL_FIELDS.subscriptionStatus, value: 'Active' },
              { id: GHL_FIELDS.portalAccess, value: 'Full Access' },
              { id: GHL_FIELDS.paymentAmount, value: (invoice.amount_paid / 100).toString() }
            ]
          });
        }
      }
    }

    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      if (invoice.customer_email) {
        const contact = await ghlFindByEmail(invoice.customer_email);
        if (contact) {
          await ghlUpdateContact(contact.id, {
            customFields: [
              { id: GHL_FIELDS.subscriptionStatus, value: 'Failed Payment' },
              { id: GHL_FIELDS.portalAccess, value: 'Limited' }
            ]
          });
        }
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      if (sub.customer && STRIPE_SECRET_KEY) {
        const stripe = require('stripe')(STRIPE_SECRET_KEY);
        const customer = await stripe.customers.retrieve(sub.customer);
        if (customer.email) {
          const contact = await ghlFindByEmail(customer.email);
          if (contact) {
            await ghlUpdateContact(contact.id, {
              customFields: [
                { id: GHL_FIELDS.subscriptionStatus, value: 'Canceled' },
                { id: GHL_FIELDS.portalAccess, value: 'Locked' }
              ]
            });
          }
        }
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('[Stripe Error]', err.message);
    res.status(400).json({ error: err.message });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`ContentBug Portal v3.5.0 on port ${PORT}`);
  console.log('Chat stored in Airtable, GHL for contacts');
  console.log('Zoom integration active');
});
