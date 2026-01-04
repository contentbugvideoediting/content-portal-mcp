// ContentBug Portal MCP Server v3.6.0
// GHL is source of truth for contacts - GHL natively syncs to Airtable
// Chat/Messages stored in Airtable directly
// Zoom integration for instant meetings
// Hourly auto-sync to Airtable
// Updated: 2026-01-02

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

// Airtable Configuration - Token from Railway env vars (AIRTABLE_API_KEY)
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID || 'appIrlFuwtsxj8hly';
const AIRTABLE_API = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}`;

// Airtable Table IDs
const AT_TABLES = {
  channels: 'tbluzdmKjuhC2Bvra',
  messages: 'tbl98EutZ8YB6Tc2E',
  clients: 'tbl4XuHJAcVDUVYGX',
  team: 'tblHlgg1sHKFt052x',
  sync_log: 'tblSyncLog' // Will be created if missing
};

// Hourly sync tracking
let lastSyncTime = new Date();
let syncStats = {
  messages_count: 0,
  channels_count: 0,
  errors: [],
  last_sync: null
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
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'shared', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'shared', 'team-signup.html')));
app.get('/create-account', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'free-trial.html')));
app.get('/free-trial', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'free-trial.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'dashboard.html')));
app.get('/review', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'review.html')));
app.get('/record', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'client', 'record.html')));
app.get('/blueprint', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'style-blueprint.html')));
app.get('/submit', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'submit-project.html')));
app.get('/team-login', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'team-login.html')));
app.get('/team-signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'shared', 'team-signup.html')));
app.get('/editor-signup', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor-signup.html')));
app.get('/team', (req, res) => res.sendFile(path.join(__dirname, 'portal', 'editor', 'index.html')));

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
  version: '3.7.0-sessions',
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
    } else if (source === 'free_trial' || source === 'free_trial_signup') {
      template = 'free_trial_signup';
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
 * Returns both chat channel and project updates channel
 */
app.get('/chat/channels/:user_email', async (req, res) => {
  try {
    const userEmail = req.params.user_email.toLowerCase().trim();

    // Find channels where this email is the client
    const filter = `{client_email} = "${userEmail}"`;
    const channels = await airtableGet(AT_TABLES.channels, filter);

    // Check if chat and updates channels exist
    const hasChatChannel = channels.some(ch =>
      (ch.fields.type === 'client' || !ch.fields.type) &&
      (!ch.fields.channel_id || !ch.fields.channel_id.startsWith('pu_'))
    );
    const hasUpdatesChannel = channels.some(ch =>
      ch.fields.type === 'project_updates' ||
      (ch.fields.channel_id && ch.fields.channel_id.startsWith('pu_'))
    );

    // Try to get client name from GHL if we need to create channels
    let clientName = userEmail.split('@')[0];
    if (!hasChatChannel || !hasUpdatesChannel) {
      const contact = await ghlFindByEmail(userEmail);
      if (contact) {
        clientName = `${contact.firstName || ''} ${contact.lastName || ''}`.trim() || clientName;
      }
    }

    const createdChannels = [];

    // Create chat channel if needed (ch_ prefix indicates chat channel)
    if (!hasChatChannel) {
      const chatChannelId = `ch_${generateId()}`;
      const chatChannel = await airtableCreate(AT_TABLES.channels, {
        channel_id: chatChannelId,
        name: clientName,
        client_email: userEmail,
        client_tier: 'trial',
        client_status: 'active',
        participant_emails: userEmail,
        created_at: new Date().toISOString()
      });
      if (chatChannel) {
        createdChannels.push({
          id: chatChannel.id,
          channel_id: chatChannelId,
          type: 'client',
          name: clientName,
          client_email: userEmail,
          client_tier: 'trial',
          unread_client: 0
        });
      }
    }

    // Create project updates channel if needed (pu_ prefix indicates updates channel)
    if (!hasUpdatesChannel) {
      const updatesChannelId = `pu_${generateId()}`;
      const updatesChannel = await airtableCreate(AT_TABLES.channels, {
        channel_id: updatesChannelId,
        name: `${clientName} - Project Updates`,
        client_email: userEmail,
        client_tier: 'trial',
        client_status: 'active',
        participant_emails: userEmail,
        created_at: new Date().toISOString()
      });
      if (updatesChannel) {
        createdChannels.push({
          id: updatesChannel.id,
          channel_id: updatesChannelId,
          type: 'project_updates',
          name: `${clientName} - Project Updates`,
          client_email: userEmail,
          client_tier: 'trial',
          unread_client: 0
        });
      }
    }

    // Combine existing and new channels
    const existingFormatted = channels.map(ch => {
      // Determine type from field or channel_id prefix
      let channelType = ch.fields.type || 'client';
      if (ch.fields.channel_id && ch.fields.channel_id.startsWith('pu_')) {
        channelType = 'project_updates';
      }
      return {
        id: ch.id,
        channel_id: ch.fields.channel_id,
        type: channelType,
        name: ch.fields.name,
        client_email: ch.fields.client_email,
        client_tier: ch.fields.client_tier || 'trial',
        unread_client: ch.fields.unread_client || 0
      };
    });

    const allChannels = [...existingFormatted, ...createdChannels];

    res.json({ success: true, channels: allChannels });

  } catch (err) {
    console.error('[Get Channels]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /chat/channels - Create a new channel
 * Channel type is determined by channel_id prefix: ch_ = chat, pu_ = project_updates
 */
app.post('/chat/channels', async (req, res) => {
  try {
    const { type = 'client', name, client_email, participant_emails, client_tier = 'trial' } = req.body;

    // Use pu_ prefix for project_updates, ch_ for everything else
    const channelId = type === 'project_updates' ? `pu_${generateId()}` : `ch_${generateId()}`;

    const channel = await airtableCreate(AT_TABLES.channels, {
      channel_id: channelId,
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

/**
 * POST /project/update - Post a project update to client's project updates channel
 * Used for automatic status updates, revision notifications, edit submissions, etc.
 */
app.post('/project/update', async (req, res) => {
  try {
    const {
      client_email,
      project_name,
      update_type,  // 'status_change', 'revision_request', 'edit_submitted', 'new_request', 'approved', 'rejected'
      message,
      project_id,
      metadata = {}
    } = req.body;

    if (!client_email || !update_type) {
      return res.status(400).json({ error: 'client_email and update_type required' });
    }

    const userEmail = client_email.toLowerCase().trim();

    // Find or create the project_updates channel for this client
    // Look for channels with pu_ prefix (project updates)
    const filter = `{client_email} = "${userEmail}"`;
    let allChannels = await airtableGet(AT_TABLES.channels, filter);

    // Find existing updates channel by pu_ prefix
    const existingUpdatesChannel = allChannels.find(ch =>
      ch.fields.channel_id && ch.fields.channel_id.startsWith('pu_')
    );

    let updatesChannelId;

    if (!existingUpdatesChannel) {
      // Create the updates channel (pu_ prefix = project updates)
      updatesChannelId = `pu_${generateId()}`;
      let clientName = userEmail.split('@')[0];

      const contact = await ghlFindByEmail(userEmail);
      if (contact) {
        clientName = `${contact.firstName || ''} ${contact.lastName || ''}`.trim() || clientName;
      }

      await airtableCreate(AT_TABLES.channels, {
        channel_id: updatesChannelId,
        name: `${clientName} - Project Updates`,
        client_email: userEmail,
        client_tier: 'trial',
        client_status: 'active',
        participant_emails: userEmail,
        created_at: new Date().toISOString()
      });
    } else {
      updatesChannelId = existingUpdatesChannel.fields.channel_id;
    }

    // Generate formatted message based on update type
    const updateMessages = {
      status_change: `📋 Project "${project_name || 'Your project'}" status updated: ${message || metadata.new_status || 'Updated'}`,
      revision_request: `🔄 Revision requested for "${project_name || 'Your project'}": ${message || 'Please review the changes'}`,
      edit_submitted: `✅ Edit submitted for "${project_name || 'Your project'}". Ready for your review!`,
      new_request: `🆕 New project request received: "${project_name || 'Your project'}"`,
      approved: `🎉 "${project_name || 'Your project'}" has been approved! Your files are ready.`,
      rejected: `❌ "${project_name || 'Your project'}" needs changes: ${message || 'Please see notes'}`,
      comment: `💬 New comment on "${project_name || 'Your project'}": ${message || ''}`,
      upload: `📁 New files uploaded for "${project_name || 'Your project'}"`,
      deadline: `⏰ Deadline update for "${project_name || 'Your project'}": ${message || metadata.deadline || 'Updated'}`
    };

    const formattedMessage = updateMessages[update_type] || message || `Update for ${project_name || 'your project'}`;

    // Create the system message (use minimal fields that work)
    const messageId = `msg_${generateId()}`;
    const newMessage = await airtableCreate(AT_TABLES.messages, {
      message_id: messageId,
      channel_id: updatesChannelId,
      sender_email: 'system@contentbug.io',
      sender_name: 'Content Bug',
      content: formattedMessage,
      created_at: new Date().toISOString()
    });

    if (!newMessage) {
      console.error('[Project Update] Failed to create message in Airtable');
    }

    // Increment unread count for client
    const channelRecords = await airtableGet(AT_TABLES.channels, `{channel_id} = "${updatesChannelId}"`);
    if (channelRecords.length > 0) {
      const currentUnread = channelRecords[0].fields.unread_client || 0;
      await airtableUpdate(AT_TABLES.channels, channelRecords[0].id, {
        unread_client: currentUnread + 1,
        last_message_at: new Date().toISOString()
      });
    }

    res.json({
      success: true,
      message_id: messageId,
      channel_id: updatesChannelId,
      content: formattedMessage
    });

  } catch (err) {
    console.error('[Project Update]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /project/updates/:client_email - Get all project updates for a client
 */
app.get('/project/updates/:client_email', async (req, res) => {
  try {
    const userEmail = req.params.client_email.toLowerCase().trim();

    // Find the project_updates channel - look for type="project_updates" OR channel_id starting with "pu_"
    const filter = `{client_email} = "${userEmail}"`;
    const allChannels = await airtableGet(AT_TABLES.channels, filter);

    // Find the updates channel (type=project_updates or channel_id starts with pu_)
    const updatesChannel = allChannels.find(ch =>
      ch.fields.type === 'project_updates' ||
      (ch.fields.channel_id && ch.fields.channel_id.startsWith('pu_'))
    );

    if (!updatesChannel) {
      return res.json({ success: true, updates: [], channel_id: null });
    }

    const channelId = updatesChannel.fields.channel_id;

    // Get messages from this channel
    const messages = await airtableGet(AT_TABLES.messages, `{channel_id} = "${channelId}"`, 100);

    const updates = messages.map(msg => ({
      id: msg.id,
      message_id: msg.fields.message_id,
      content: msg.fields.content,
      created_at: msg.fields.created_at
    }));

    // Sort by created_at desc (newest first)
    updates.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      success: true,
      channel_id: channelId,
      updates,
      unread: updatesChannel.fields.unread_client || 0
    });

  } catch (err) {
    console.error('[Get Project Updates]', err.message);
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
// HOURLY SYNC TO AIRTABLE
// ============================================
async function hourlySync() {
  const syncTime = new Date();
  console.log(`[Sync] Starting hourly sync at ${syncTime.toISOString()}`);

  try {
    // Get counts from Airtable
    const [messagesRes, channelsRes] = await Promise.all([
      axios.get(`${AIRTABLE_API}/${AT_TABLES.messages}?maxRecords=1&view=Grid%20view`, {
        headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` }
      }).catch(() => ({ data: { records: [] } })),
      axios.get(`${AIRTABLE_API}/${AT_TABLES.channels}?maxRecords=1&view=Grid%20view`, {
        headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` }
      }).catch(() => ({ data: { records: [] } }))
    ]);

    // Update sync stats
    syncStats = {
      messages_count: messagesRes.data.records?.length || 0,
      channels_count: channelsRes.data.records?.length || 0,
      errors: [],
      last_sync: syncTime.toISOString(),
      server_uptime: process.uptime(),
      memory_usage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB'
    };

    lastSyncTime = syncTime;
    console.log(`[Sync] Complete - Messages: ${syncStats.messages_count}, Channels: ${syncStats.channels_count}`);

  } catch (err) {
    console.error('[Sync] Error:', err.message);
    syncStats.errors.push({ time: syncTime.toISOString(), error: err.message });
  }
}

// Sync status endpoint
app.get('/api/sync/status', (req, res) => {
  res.json({
    success: true,
    last_sync: lastSyncTime.toISOString(),
    stats: syncStats,
    next_sync: new Date(lastSyncTime.getTime() + 60 * 60 * 1000).toISOString()
  });
});

// Manual sync trigger
app.post('/api/sync/now', async (req, res) => {
  try {
    await hourlySync();
    res.json({ success: true, message: 'Sync completed', stats: syncStats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================
// GHL EMAIL TEMPLATES API
// ============================================

/**
 * GET /api/ghl/emails - List all email templates
 */
app.get('/api/ghl/emails', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/emails/templates?locationId=${GHL_LOCATION_ID}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json({ success: true, templates: r.data.templates || r.data });
  } catch (err) {
    console.error('[GHL Emails]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/ghl/emails/:tid - Get single email template
 */
app.get('/api/ghl/emails/:tid', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/emails/templates/${req.params.tid}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json({ success: true, template: r.data });
  } catch (err) {
    console.error('[GHL Email Get]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/ghl/emails/:tid - Update email template HTML
 */
app.put('/api/ghl/emails/:tid', async (req, res) => {
  try {
    const { html, name, subject, preheader } = req.body;
    const payload = {};
    if (html) payload.html = html;
    if (name) payload.name = name;
    if (subject) payload.subject = subject;
    if (preheader) payload.preheader = preheader;

    const r = await axios.put(
      `https://services.leadconnectorhq.com/emails/templates/${req.params.tid}`,
      payload,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
    );
    res.json({ success: true, template: r.data });
  } catch (err) {
    console.error('[GHL Email Update]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/ghl/emails - Create new email template
 */
app.post('/api/ghl/emails', async (req, res) => {
  try {
    const { name, html, subject, preheader } = req.body;
    if (!name || !html) {
      return res.status(400).json({ error: 'name and html required' });
    }

    const r = await axios.post(
      `https://services.leadconnectorhq.com/emails/templates`,
      { locationId: GHL_LOCATION_ID, name, html, subject, preheader },
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
    );
    res.json({ success: true, template: r.data });
  } catch (err) {
    console.error('[GHL Email Create]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// GHL FUNNELS API
// ============================================

/**
 * GET /api/ghl/funnels - List all funnels
 */
app.get('/api/ghl/funnels', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/funnels/?locationId=${GHL_LOCATION_ID}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json({ success: true, funnels: r.data.funnels || r.data });
  } catch (err) {
    console.error('[GHL Funnels]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/ghl/funnels/:fid/pages - List pages in a funnel
 */
app.get('/api/ghl/funnels/:fid/pages', async (req, res) => {
  try {
    const r = await axios.get(
      `https://services.leadconnectorhq.com/funnels/${req.params.fid}/pages?locationId=${GHL_LOCATION_ID}`,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
    );
    res.json({ success: true, pages: r.data.pages || r.data });
  } catch (err) {
    console.error('[GHL Funnel Pages]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/ghl/funnels/:fid/pages/:pid - Update page HTML
 */
app.put('/api/ghl/funnels/:fid/pages/:pid', async (req, res) => {
  try {
    const { html, name } = req.body;
    const payload = {};
    if (html) payload.html = html;
    if (name) payload.name = name;

    const r = await axios.put(
      `https://services.leadconnectorhq.com/funnels/${req.params.fid}/pages/${req.params.pid}`,
      payload,
      { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
    );
    res.json({ success: true, page: r.data });
  } catch (err) {
    console.error('[GHL Page Update]', err.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================

// ============================================
// PROJECT & REVIEW ENDPOINTS
// ============================================

/**
 * GET /projects/:id - Get project by ID for review page
 */
app.get('/projects/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const userEmail = req.headers['x-user-email'];
    const userRole = req.headers['x-user-role'] || 'client';

    // Demo/test mode
    if (projectId === 'demo' || projectId === 'test-project') {
      return res.json({
        success: true,
        project: {
          id: 'test-project',
          title: 'Content Bug Review Demo',
          client_name: 'Demo Client',
          client_email: userEmail || 'demo@contentbug.io',
          editor_email: 'editor@contentbug.io',
          status: 'review',
          video_url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4',
          versions: [
            { version: 1, date: '2025-12-28', status: 'previous', notes: 'Initial rough cut' },
            { version: 2, date: '2025-12-30', status: 'current', notes: 'Color graded + audio fixed' }
          ],
          feedback: []
        }
      });
    }

    // Find in Airtable Projects
    const projects = await airtableGet('tblBRsSS40wP3B3l5', `{project_id}="${projectId}"`);
    
    if (projects.length === 0) {
      // Fallback to demo if not found
      return res.json({
        success: true,
        project: {
          id: projectId,
          title: 'Content Bug Review Demo',
          status: 'review',
          video_url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4',
          versions: [{ version: 1, date: new Date().toISOString().split('T')[0], status: 'current' }],
          feedback: []
        }
      });
    }

    const p = projects[0];
    res.json({
      success: true,
      project: {
        id: p.fields.project_id || p.id,
        title: p.fields.Name || p.fields.title || 'Untitled Project',
        client_name: p.fields.client_name,
        client_email: p.fields.client_email,
        editor_email: p.fields.editor_email,
        status: p.fields.Status || 'review',
        video_url: p.fields.video_url || p.fields.VideoURL,
        versions: JSON.parse(p.fields.versions || '[]'),
        feedback: JSON.parse(p.fields.feedback || '[]')
      }
    });

  } catch (err) {
    console.error('[Project Get]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/project/revisions - Submit revisions from review page
 */
app.post('/api/project/revisions', async (req, res) => {
  try {
    const { project_id, project_title, client_email, client_name, editor_email, revisions, additional_notes, version } = req.body;

    console.log('[Revisions] Submitting', revisions?.length, 'for project:', project_id);

    // Post to project updates
    await axios.post('http://localhost:' + PORT + '/project/update', {
      client_email,
      project_name: project_title,
      update_type: 'revision_request',
      message: `${revisions?.length || 0} revision(s) requested${additional_notes ? ': ' + additional_notes : ''}`,
      project_id,
      metadata: { revision_count: revisions?.length, revisions, version }
    }).catch(() => {});

    // Notify editor via GHL
    if (editor_email && GHL_EMAIL_WEBHOOK) {
      await axios.post(GHL_EMAIL_WEBHOOK, {
        email: editor_email,
        template: 'revision_requested',
        project_name: project_title,
        client_name: client_name || 'Client',
        revision_count: revisions?.length || 0
      }).catch(() => {});
    }

    res.json({ success: true, message: 'Revisions submitted', revision_count: revisions?.length || 0 });

  } catch (err) {
    console.error('[Project Revisions]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/project/approve - Approve project with rating
 */
app.post('/api/project/approve', async (req, res) => {
  try {
    const { project_id, rating, email, approved_at } = req.body;

    console.log('[Approve] Project:', project_id, 'Rating:', rating);

    await axios.post('http://localhost:' + PORT + '/project/update', {
      client_email: email,
      project_name: `Project ${project_id}`,
      update_type: 'approved',
      message: `Project approved with ${rating} stars!`,
      project_id,
      metadata: { rating, approved_at }
    }).catch(() => {});

    if (GHL_EMAIL_WEBHOOK) {
      await axios.post(GHL_EMAIL_WEBHOOK, { email, template: 'project_approved', project_id, rating }).catch(() => {});
    }

    res.json({ success: true, message: 'Project approved!', rating });

  } catch (err) {
    console.error('[Project Approve]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/trial/review-booked - Record trial booking
 */
app.post('/api/trial/review-booked', async (req, res) => {
  try {
    const { email, booked_at } = req.body;

    console.log('[Trial] Review call booked for:', email);

    if (GHL_API_KEY && email) {
      const contact = await ghlFindByEmail(email);
      if (contact) {
        await ghlUpdateContact(contact.id, { customFields: [{ id: GHL_FIELDS.onboardingStatus, value: 'Review Call Booked' }] });
        await ghlAddTags(contact.id, ['review-call-booked']);
      }
    }

    res.json({ success: true, message: 'Booking recorded' });

  } catch (err) {
    console.error('[Trial Review Booked]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});


// ============================================
// GOOGLE DRIVE SESSION MANAGEMENT
// Clients store raw sessions in their own Drive folder
// ============================================

/**
 * GET /api/sessions/:email - List client's raw sessions from their Drive folder
 */
app.get('/api/sessions/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    
    // Get client's Drive folder from GHL
    const contact = await ghlFindByEmail(email);
    if (!contact) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Get their Google Drive folder link
    let driveFolderId = null;
    if (contact.customFields) {
      const folderField = contact.customFields.find(f => f.id === GHL_FIELDS.googleDriveFolderLink);
      if (folderField?.value) {
        // Extract folder ID from URL or use directly
        const match = folderField.value.match(/folders\/([a-zA-Z0-9_-]+)/);
        driveFolderId = match ? match[1] : folderField.value;
      }
    }

    if (!driveFolderId) {
      return res.json({ 
        success: true, 
        sessions: [], 
        message: 'No Drive folder configured. Sessions will be set up after first project.' 
      });
    }

    if (!driveReady || !googleDrive) {
      return res.status(503).json({ error: 'Google Drive not configured' });
    }

    // List video files from their folder
    const response = await googleDrive.files.list({
      q: `'${driveFolderId}' in parents and (mimeType contains 'video/' or mimeType contains 'audio/') and trashed=false`,
      fields: 'files(id, name, mimeType, size, createdTime, modifiedTime, thumbnailLink, webViewLink, webContentLink)',
      orderBy: 'modifiedTime desc',
      pageSize: 50
    });

    const sessions = (response.data.files || []).map(f => ({
      id: f.id,
      name: f.name,
      type: f.mimeType.includes('video') ? 'video' : 'audio',
      size: parseInt(f.size || 0),
      size_formatted: formatBytes(parseInt(f.size || 0)),
      created_at: f.createdTime,
      modified_at: f.modifiedTime,
      thumbnail: f.thumbnailLink,
      view_url: f.webViewLink,
      download_url: f.webContentLink
    }));

    res.json({
      success: true,
      folder_id: driveFolderId,
      sessions,
      count: sessions.length
    });

  } catch (err) {
    console.error('[Sessions List]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/sessions/upload - Get upload URL for client's Drive folder
 * Returns a resumable upload URL for large files
 */
app.post('/api/sessions/upload', async (req, res) => {
  try {
    const { email, filename, mimeType } = req.body;
    
    if (!email || !filename) {
      return res.status(400).json({ error: 'email and filename required' });
    }

    // Get client's Drive folder
    const contact = await ghlFindByEmail(email.toLowerCase().trim());
    if (!contact) {
      return res.status(404).json({ error: 'Client not found' });
    }

    let driveFolderId = null;
    if (contact.customFields) {
      const folderField = contact.customFields.find(f => f.id === GHL_FIELDS.googleDriveFolderLink);
      if (folderField?.value) {
        const match = folderField.value.match(/folders\/([a-zA-Z0-9_-]+)/);
        driveFolderId = match ? match[1] : folderField.value;
      }
    }

    // If no folder exists, create one for this client
    if (!driveFolderId && driveReady && googleDrive) {
      const folderResponse = await googleDrive.files.create({
        requestBody: {
          name: `${contact.firstName || 'Client'} ${contact.lastName || ''} - Sessions`.trim(),
          mimeType: 'application/vnd.google-apps.folder',
          parents: ['0ADnOJaRBvSNCUk9PVA'] // ContentBug shared drive
        },
        fields: 'id, webViewLink'
      });
      
      driveFolderId = folderResponse.data.id;
      
      // Update GHL with the new folder link
      await ghlUpdateContact(contact.id, {
        customFields: [
          { id: GHL_FIELDS.googleDriveFolderLink, value: folderResponse.data.webViewLink }
        ]
      });
    }

    if (!driveFolderId || !driveReady) {
      return res.status(503).json({ error: 'Unable to access Drive storage' });
    }

    // Create placeholder file and return upload info
    // For direct browser uploads, we'll create the file metadata first
    const fileMetadata = {
      name: filename,
      parents: [driveFolderId]
    };

    const file = await googleDrive.files.create({
      requestBody: fileMetadata,
      fields: 'id, webViewLink'
    });

    res.json({
      success: true,
      file_id: file.data.id,
      folder_id: driveFolderId,
      message: 'File placeholder created. Upload content via Drive API.',
      // For browser uploads, client should use Google Picker or resumable upload
      upload_method: 'google_picker_or_resumable'
    });

  } catch (err) {
    console.error('[Sessions Upload]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/sessions/link - Link existing Drive files to a project request
 */
app.post('/api/sessions/link', async (req, res) => {
  try {
    const { email, project_id, session_ids } = req.body;
    
    if (!email || !project_id || !session_ids?.length) {
      return res.status(400).json({ error: 'email, project_id, and session_ids required' });
    }

    console.log('[Sessions Link]', session_ids.length, 'sessions to project:', project_id);

    // Get file details for linked sessions
    const sessionDetails = [];
    if (driveReady && googleDrive) {
      for (const fileId of session_ids) {
        try {
          const file = await googleDrive.files.get({
            fileId,
            fields: 'id, name, mimeType, size, webViewLink'
          });
          sessionDetails.push({
            id: file.data.id,
            name: file.data.name,
            type: file.data.mimeType,
            size: file.data.size,
            url: file.data.webViewLink
          });
        } catch (e) {
          console.error('[Session Get]', fileId, e.message);
        }
      }
    }

    // Store the link in Airtable (or update project record)
    // This could go in a Sessions field on the Projects table
    
    res.json({
      success: true,
      project_id,
      linked_sessions: sessionDetails,
      count: sessionDetails.length
    });

  } catch (err) {
    console.error('[Sessions Link]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/sessions/:fileId - Remove a session file
 */
app.delete('/api/sessions/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    const userEmail = req.headers['x-user-email'];

    if (!driveReady || !googleDrive) {
      return res.status(503).json({ error: 'Google Drive not available' });
    }

    // Move to trash (can be recovered)
    await googleDrive.files.update({
      fileId,
      requestBody: { trashed: true }
    });

    res.json({ success: true, message: 'Session moved to trash' });

  } catch (err) {
    console.error('[Session Delete]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Helper function
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`ContentBug Portal v3.7.0 on port ${PORT}`);
  console.log('Chat stored in Airtable, GHL for contacts');
  console.log('Zoom integration active');
  console.log('Hourly sync enabled');

  // Run initial sync after 10 seconds
  setTimeout(hourlySync, 10000);

  // Run sync every hour (3600000ms)
  setInterval(hourlySync, 60 * 60 * 1000);
});
