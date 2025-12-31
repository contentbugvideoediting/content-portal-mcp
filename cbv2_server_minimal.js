// ContentBug Minimal MCP Server v3.0
// Core integrations: Airtable, GHL, Make.com, Google Drive
// Stripped down - no fluff, just what works

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// ENVIRONMENT VARIABLES
// ============================================
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID || 'appIrlFuwtsxj8hly';
const GHL_API_KEY = process.env.GHL_API_KEY || process.env.GHL_PRIVATE_INTEGRATION;
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || 'mCNHhjy593eUueqfuqyU';
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const APIFY_API_TOKEN = process.env.APIFY_API_TOKEN;
const GOOGLE_SERVICE_ACCOUNT_JSON = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
const GOOGLE_SHARED_DRIVE_ID = process.env.GOOGLE_SHARED_DRIVE_ID || '0ADnOJaRBvSNCUk9PVA';

// ============================================
// GOOGLE DRIVE SETUP
// ============================================
let googleDrive = null;
let driveReady = false;

function initGoogleDrive() {
  try {
    if (!GOOGLE_SERVICE_ACCOUNT_JSON) {
      console.log('[Drive] No service account configured');
      return false;
    }
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
    next(); // Raw body for Stripe
  } else {
    express.json({ limit: '10mb' })(req, res, next);
  }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/healthz', (req, res) => res.json({
  ok: true,
  version: '3.0.0-minimal',
  ts: Date.now(),
  services: {
    airtable: !!AIRTABLE_API_KEY,
    ghl: !!GHL_API_KEY,
    claude: !!CLAUDE_API_KEY,
    openai: !!OPENAI_API_KEY,
    stripe: !!STRIPE_SECRET_KEY,
    apify: !!APIFY_API_TOKEN,
    drive: driveReady
  }
}));

// ============================================
// AIRTABLE HELPERS
// ============================================
async function airtableCreate(table, fields) {
  if (!AIRTABLE_API_KEY) return null;
  try {
    const res = await axios.post(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}`,
      { fields },
      { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' } }
    );
    return res.data;
  } catch (err) {
    console.error('[Airtable Create]', err?.response?.data || err.message);
    return null;
  }
}

async function airtableQuery(table, filterFormula = '', options = {}) {
  if (!AIRTABLE_API_KEY) return { records: [] };
  try {
    const params = new URLSearchParams();
    if (filterFormula) params.append('filterByFormula', filterFormula);
    if (options.maxRecords) params.append('maxRecords', options.maxRecords);

    const res = await axios.get(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}?${params}`,
      { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } }
    );
    return res.data;
  } catch (err) {
    console.error('[Airtable Query]', err?.response?.data || err.message);
    return { records: [] };
  }
}

async function airtableUpdate(table, recordId, fields) {
  if (!AIRTABLE_API_KEY) return null;
  try {
    const res = await axios.patch(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(table)}/${recordId}`,
      { fields },
      { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' } }
    );
    return res.data;
  } catch (err) {
    console.error('[Airtable Update]', err?.response?.data || err.message);
    return null;
  }
}

// ============================================
// GHL HELPERS
// ============================================
async function ghlRequest(endpoint, method = 'GET', data = null) {
  if (!GHL_API_KEY) return null;
  try {
    const config = {
      method,
      url: `https://services.leadconnectorhq.com${endpoint}`,
      headers: {
        'Authorization': `Bearer ${GHL_API_KEY}`,
        'Version': '2021-07-28',
        'Content-Type': 'application/json'
      }
    };
    if (data) config.data = data;
    const res = await axios(config);
    return res.data;
  } catch (err) {
    console.error('[GHL]', err?.response?.data || err.message);
    return null;
  }
}

async function ghlCreateContact(contactData) {
  return ghlRequest('/contacts/', 'POST', {
    locationId: GHL_LOCATION_ID,
    ...contactData
  });
}

async function ghlSearchContact(email) {
  return ghlRequest(`/contacts/search/duplicate?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`);
}

// ============================================
// WEBHOOKS
// ============================================

// Make.com webhook - generic handler
app.post('/webhook', async (req, res) => {
  console.log('[Webhook] Received:', JSON.stringify(req.body).slice(0, 500));
  res.json({ received: true, ts: Date.now() });
});

// GHL webhook
app.post('/webhook/ghl', async (req, res) => {
  console.log('[GHL Webhook]', JSON.stringify(req.body).slice(0, 500));
  res.json({ received: true });
});

// Stripe webhook
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    if (STRIPE_WEBHOOK_SECRET) {
      const stripe = require('stripe')(STRIPE_SECRET_KEY);
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } else {
      event = JSON.parse(req.body.toString());
    }

    console.log('[Stripe]', event.type);

    // Handle subscription events
    if (event.type === 'customer.subscription.created' ||
        event.type === 'customer.subscription.updated') {
      const subscription = event.data.object;
      console.log('[Stripe] Subscription:', subscription.id, subscription.status);
    }

    res.json({ received: true });
  } catch (err) {
    console.error('[Stripe Error]', err.message);
    res.status(400).json({ error: err.message });
  }
});

// ============================================
// AIRTABLE API ENDPOINTS
// ============================================

// Create record
app.post('/airtable/create', async (req, res) => {
  const { table, fields } = req.body;
  if (!table || !fields) {
    return res.status(400).json({ error: 'table and fields required' });
  }
  const result = await airtableCreate(table, fields);
  res.json(result || { error: 'create failed' });
});

// Query records
app.post('/airtable/query', async (req, res) => {
  const { table, filter, maxRecords } = req.body;
  if (!table) {
    return res.status(400).json({ error: 'table required' });
  }
  const result = await airtableQuery(table, filter || '', { maxRecords });
  res.json(result);
});

// Update record
app.post('/airtable/update', async (req, res) => {
  const { table, recordId, fields } = req.body;
  if (!table || !recordId || !fields) {
    return res.status(400).json({ error: 'table, recordId, and fields required' });
  }
  const result = await airtableUpdate(table, recordId, fields);
  res.json(result || { error: 'update failed' });
});

// ============================================
// GHL API ENDPOINTS
// ============================================

// Create contact
app.post('/ghl/contact/create', async (req, res) => {
  const result = await ghlCreateContact(req.body);
  res.json(result || { error: 'create failed' });
});

// Search contact
app.get('/ghl/contact/search', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });
  const result = await ghlSearchContact(email);
  res.json(result || { error: 'search failed' });
});

// Get contact
app.get('/ghl/contact/:id', async (req, res) => {
  const result = await ghlRequest(`/contacts/${req.params.id}`);
  res.json(result || { error: 'not found' });
});

// Update contact
app.post('/ghl/contact/:id', async (req, res) => {
  const result = await ghlRequest(`/contacts/${req.params.id}`, 'PUT', req.body);
  res.json(result || { error: 'update failed' });
});

// Delete contact
app.delete('/ghl/contact/:id', async (req, res) => {
  const result = await ghlRequest(`/contacts/${req.params.id}`, 'DELETE');
  res.json(result || { success: true });
});

// Add tags to contact
app.post('/ghl/contact/:id/tags', async (req, res) => {
  const { tags } = req.body;
  const result = await ghlRequest(`/contacts/${req.params.id}/tags`, 'POST', { tags });
  res.json(result || { error: 'failed' });
});

// Remove tag from contact
app.delete('/ghl/contact/:id/tags', async (req, res) => {
  const result = await ghlRequest(`/contacts/${req.params.id}/tags`, 'DELETE', req.body);
  res.json(result || { success: true });
});

// ============================================
// GHL PIPELINES & OPPORTUNITIES
// ============================================

// Get all pipelines
app.get('/ghl/pipelines', async (req, res) => {
  const result = await ghlRequest(`/opportunities/pipelines?locationId=${GHL_LOCATION_ID}`);
  res.json(result || { error: 'failed' });
});

// Get opportunities
app.get('/ghl/opportunities', async (req, res) => {
  const { pipelineId, stageId, contactId } = req.query;
  let url = `/opportunities/search?locationId=${GHL_LOCATION_ID}`;
  if (pipelineId) url += `&pipelineId=${pipelineId}`;
  if (stageId) url += `&stageId=${stageId}`;
  if (contactId) url += `&contactId=${contactId}`;
  const result = await ghlRequest(url);
  res.json(result || { error: 'failed' });
});

// Create opportunity
app.post('/ghl/opportunity', async (req, res) => {
  const result = await ghlRequest('/opportunities/', 'POST', {
    locationId: GHL_LOCATION_ID,
    ...req.body
  });
  res.json(result || { error: 'create failed' });
});

// Update opportunity
app.post('/ghl/opportunity/:id', async (req, res) => {
  const result = await ghlRequest(`/opportunities/${req.params.id}`, 'PUT', req.body);
  res.json(result || { error: 'update failed' });
});

// ============================================
// GHL CALENDARS & APPOINTMENTS
// ============================================

// Get calendars
app.get('/ghl/calendars', async (req, res) => {
  const result = await ghlRequest(`/calendars/?locationId=${GHL_LOCATION_ID}`);
  res.json(result || { error: 'failed' });
});

// Get calendar slots
app.get('/ghl/calendar/:id/slots', async (req, res) => {
  const { startDate, endDate } = req.query;
  const result = await ghlRequest(`/calendars/${req.params.id}/free-slots?startDate=${startDate}&endDate=${endDate}`);
  res.json(result || { error: 'failed' });
});

// Create appointment
app.post('/ghl/appointment', async (req, res) => {
  const result = await ghlRequest('/calendars/events/appointments', 'POST', {
    locationId: GHL_LOCATION_ID,
    ...req.body
  });
  res.json(result || { error: 'create failed' });
});

// Get appointments
app.get('/ghl/appointments', async (req, res) => {
  const { calendarId, startTime, endTime, contactId } = req.query;
  let url = `/calendars/events?locationId=${GHL_LOCATION_ID}`;
  if (calendarId) url += `&calendarId=${calendarId}`;
  if (startTime) url += `&startTime=${startTime}`;
  if (endTime) url += `&endTime=${endTime}`;
  if (contactId) url += `&contactId=${contactId}`;
  const result = await ghlRequest(url);
  res.json(result || { error: 'failed' });
});

// ============================================
// GHL CONVERSATIONS & SMS/EMAIL
// ============================================

// Get conversations
app.get('/ghl/conversations', async (req, res) => {
  const { contactId } = req.query;
  const result = await ghlRequest(`/conversations/search?locationId=${GHL_LOCATION_ID}${contactId ? `&contactId=${contactId}` : ''}`);
  res.json(result || { error: 'failed' });
});

// Send SMS
app.post('/ghl/sms', async (req, res) => {
  const { contactId, message } = req.body;
  const result = await ghlRequest('/conversations/messages', 'POST', {
    type: 'SMS',
    contactId,
    message
  });
  res.json(result || { error: 'send failed' });
});

// Send Email
app.post('/ghl/email', async (req, res) => {
  const { contactId, subject, body, html } = req.body;
  const result = await ghlRequest('/conversations/messages', 'POST', {
    type: 'Email',
    contactId,
    subject,
    body,
    html
  });
  res.json(result || { error: 'send failed' });
});

// ============================================
// GHL WORKFLOWS & AUTOMATIONS
// ============================================

// Get workflows
app.get('/ghl/workflows', async (req, res) => {
  const result = await ghlRequest(`/workflows/?locationId=${GHL_LOCATION_ID}`);
  res.json(result || { error: 'failed' });
});

// ============================================
// GHL FORMS & SURVEYS
// ============================================

// Get forms
app.get('/ghl/forms', async (req, res) => {
  const result = await ghlRequest(`/forms/?locationId=${GHL_LOCATION_ID}`);
  res.json(result || { error: 'failed' });
});

// Get form submissions
app.get('/ghl/forms/:id/submissions', async (req, res) => {
  const result = await ghlRequest(`/forms/submissions?locationId=${GHL_LOCATION_ID}&formId=${req.params.id}`);
  res.json(result || { error: 'failed' });
});

// ============================================
// GHL PAYMENTS & INVOICES
// ============================================

// Get invoices
app.get('/ghl/invoices', async (req, res) => {
  const { contactId, status } = req.query;
  let url = `/invoices?locationId=${GHL_LOCATION_ID}`;
  if (contactId) url += `&contactId=${contactId}`;
  if (status) url += `&status=${status}`;
  const result = await ghlRequest(url);
  res.json(result || { error: 'failed' });
});

// Create invoice
app.post('/ghl/invoice', async (req, res) => {
  const result = await ghlRequest('/invoices', 'POST', {
    locationId: GHL_LOCATION_ID,
    ...req.body
  });
  res.json(result || { error: 'create failed' });
});

// ============================================
// GHL CUSTOM FIELDS & VALUES
// ============================================

// Get custom fields
app.get('/ghl/custom-fields', async (req, res) => {
  const result = await ghlRequest(`/locations/${GHL_LOCATION_ID}/customFields`);
  res.json(result || { error: 'failed' });
});

// Get custom values
app.get('/ghl/custom-values', async (req, res) => {
  const result = await ghlRequest(`/locations/${GHL_LOCATION_ID}/customValues`);
  res.json(result || { error: 'failed' });
});

// ============================================
// LEAD CAPTURE (Free Trial)
// ============================================
app.post('/api/lead/create', async (req, res) => {
  try {
    const { email, firstName, lastName, phone, source } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'email required' });
    }

    // 1. Create/update GHL contact
    const ghlContact = await ghlCreateContact({
      email,
      firstName: firstName || '',
      lastName: lastName || '',
      phone: phone || '',
      source: source || 'Free Trial',
      tags: ['free-trial', 'lead']
    });

    // 2. Create Airtable client record
    const airtableRecord = await airtableCreate('Clients', {
      Email: email,
      'First Name': firstName || '',
      'Last Name': lastName || '',
      Phone: phone || '',
      Source: source || 'Free Trial',
      Status: 'Lead',
      'GHL Contact ID': ghlContact?.contact?.id || ''
    });

    res.json({
      success: true,
      ghl_contact_id: ghlContact?.contact?.id,
      airtable_id: airtableRecord?.id
    });

  } catch (err) {
    console.error('[Lead Create]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// AI ENDPOINTS (Claude & GPT)
// ============================================

// Claude chat
app.post('/ai/claude', async (req, res) => {
  if (!CLAUDE_API_KEY) {
    return res.status(503).json({ error: 'Claude not configured' });
  }

  try {
    const { messages, system, max_tokens = 1000 } = req.body;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens,
      system: system || 'You are a helpful assistant.',
      messages
    }, {
      headers: {
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json'
      }
    });

    res.json(response.data);
  } catch (err) {
    console.error('[Claude]', err?.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

// OpenAI chat
app.post('/ai/gpt', async (req, res) => {
  if (!OPENAI_API_KEY) {
    return res.status(503).json({ error: 'OpenAI not configured' });
  }

  try {
    const { messages, model = 'gpt-4', max_tokens = 1000 } = req.body;

    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model,
      max_tokens,
      messages
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    res.json(response.data);
  } catch (err) {
    console.error('[GPT]', err?.response?.data || err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// APIFY SCRAPING ENDPOINTS
// ============================================

// Apify actor IDs
const APIFY_ACTORS = {
  youtube: 'streamers/youtube-scraper',
  tiktok: 'clockworks/tiktok-scraper',
  instagram: 'apify/instagram-scraper',
  twitter: 'quacker/twitter-scraper',
  facebook: 'apify/facebook-posts-scraper'
};

// Run Apify actor
async function runApifyActor(actorId, input) {
  if (!APIFY_API_TOKEN) return null;
  try {
    const res = await axios.post(
      `https://api.apify.com/v2/acts/${actorId}/runs?token=${APIFY_API_TOKEN}`,
      input,
      { headers: { 'Content-Type': 'application/json' }, timeout: 30000 }
    );
    return res.data;
  } catch (err) {
    console.error('[Apify Run]', err?.response?.data || err.message);
    return null;
  }
}

// Get Apify run status/results
async function getApifyRun(runId) {
  if (!APIFY_API_TOKEN) return null;
  try {
    const res = await axios.get(
      `https://api.apify.com/v2/actor-runs/${runId}?token=${APIFY_API_TOKEN}`
    );
    return res.data;
  } catch (err) {
    console.error('[Apify Status]', err?.response?.data || err.message);
    return null;
  }
}

// Get Apify dataset items
async function getApifyDataset(datasetId, limit = 100) {
  if (!APIFY_API_TOKEN) return null;
  try {
    const res = await axios.get(
      `https://api.apify.com/v2/datasets/${datasetId}/items?token=${APIFY_API_TOKEN}&limit=${limit}`
    );
    return res.data;
  } catch (err) {
    console.error('[Apify Dataset]', err?.response?.data || err.message);
    return null;
  }
}

// Scrape YouTube channel/video
app.post('/apify/youtube', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { channelUrl, videoUrl, maxVideos = 10 } = req.body;
  const input = {};

  if (channelUrl) {
    input.startUrls = [{ url: channelUrl }];
    input.maxResults = maxVideos;
  } else if (videoUrl) {
    input.startUrls = [{ url: videoUrl }];
  } else {
    return res.status(400).json({ error: 'channelUrl or videoUrl required' });
  }

  const result = await runApifyActor(APIFY_ACTORS.youtube, input);
  res.json(result || { error: 'failed' });
});

// Scrape TikTok profile/video
app.post('/apify/tiktok', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { profileUrl, videoUrl, maxVideos = 10 } = req.body;
  const input = { maxProfilesPerQuery: 1, resultsPerPage: maxVideos };

  if (profileUrl) {
    input.profiles = [profileUrl];
  } else if (videoUrl) {
    input.postURLs = [videoUrl];
  } else {
    return res.status(400).json({ error: 'profileUrl or videoUrl required' });
  }

  const result = await runApifyActor(APIFY_ACTORS.tiktok, input);
  res.json(result || { error: 'failed' });
});

// Scrape Instagram profile/reel
app.post('/apify/instagram', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { profileUrl, postUrl, maxPosts = 10 } = req.body;
  const input = { resultsLimit: maxPosts };

  if (profileUrl) {
    input.directUrls = [profileUrl];
  } else if (postUrl) {
    input.directUrls = [postUrl];
  } else {
    return res.status(400).json({ error: 'profileUrl or postUrl required' });
  }

  const result = await runApifyActor(APIFY_ACTORS.instagram, input);
  res.json(result || { error: 'failed' });
});

// Scrape Twitter/X profile
app.post('/apify/twitter', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { handle, maxTweets = 20 } = req.body;
  if (!handle) return res.status(400).json({ error: 'handle required' });

  const input = {
    handles: [handle.replace('@', '')],
    maxTweets
  };

  const result = await runApifyActor(APIFY_ACTORS.twitter, input);
  res.json(result || { error: 'failed' });
});

// Scrape Facebook posts
app.post('/apify/facebook', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { pageUrl, maxPosts = 10 } = req.body;
  if (!pageUrl) return res.status(400).json({ error: 'pageUrl required' });

  const input = {
    startUrls: [{ url: pageUrl }],
    maxPosts
  };

  const result = await runApifyActor(APIFY_ACTORS.facebook, input);
  res.json(result || { error: 'failed' });
});

// Get run status
app.get('/apify/run/:runId', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });
  const result = await getApifyRun(req.params.runId);
  res.json(result || { error: 'not found' });
});

// Get dataset results
app.get('/apify/dataset/:datasetId', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });
  const limit = parseInt(req.query.limit) || 100;
  const result = await getApifyDataset(req.params.datasetId, limit);
  res.json(result || { error: 'not found' });
});

// Generic actor run
app.post('/apify/run', async (req, res) => {
  if (!APIFY_API_TOKEN) return res.status(503).json({ error: 'Apify not configured' });

  const { actorId, input } = req.body;
  if (!actorId) return res.status(400).json({ error: 'actorId required' });

  const result = await runApifyActor(actorId, input || {});
  res.json(result || { error: 'failed' });
});

// ============================================
// GOOGLE DRIVE ENDPOINTS
// ============================================

// List files in folder
app.get('/drive/files', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { folderId, pageSize = 50 } = req.query;
    const query = folderId ? `'${folderId}' in parents and trashed = false` : 'trashed = false';

    const result = await googleDrive.files.list({
      q: query,
      pageSize: parseInt(pageSize),
      fields: 'files(id, name, mimeType, size, createdTime, modifiedTime, webViewLink)',
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
      driveId: GOOGLE_SHARED_DRIVE_ID,
      corpora: 'drive'
    });

    res.json(result.data.files || []);
  } catch (err) {
    console.error('[Drive List]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get file metadata
app.get('/drive/file/:fileId', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const result = await googleDrive.files.get({
      fileId: req.params.fileId,
      fields: 'id, name, mimeType, size, createdTime, modifiedTime, webViewLink, webContentLink',
      supportsAllDrives: true
    });
    res.json(result.data);
  } catch (err) {
    console.error('[Drive Get]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create folder
app.post('/drive/folder', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { name, parentId } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const result = await googleDrive.files.create({
      requestBody: {
        name,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [parentId || GOOGLE_SHARED_DRIVE_ID]
      },
      fields: 'id, name, webViewLink',
      supportsAllDrives: true
    });

    res.json(result.data);
  } catch (err) {
    console.error('[Drive Folder]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create client folder structure
// Format: FIRSTNAME_LASTNAME_SUBSCRIPTIONSTATUS (ALL CAPS)
// Example: SEAN_CONLEY_PRO or JOHN_SMITH_TRIAL
//
// Folder Structure:
// └── FIRSTNAME_LASTNAME_STATUS/
//     ├── BRAND ASSETS/
//     │   ├── LOGOS/
//     │   ├── HEADSHOTS - SMILING/
//     │   └── HEADSHOTS - SHOCKED/
//     ├── SESSIONS/           (recorded virtual studio sessions - not tied to projects)
//     └── PROJECTS/           (auto-deleted after 30 days, clients never see contents)
//
// NOTE: Clients only see finished edits delivered to them, not raw project files

const ACTIVE_CLIENTS_FOLDER_ID = process.env.ACTIVE_CLIENTS_FOLDER_ID || '1iaIa7B9TAysVnHnVW250oGPaiNC0wGYE';
const CANCELED_CLIENTS_FOLDER_ID = process.env.CANCELED_CLIENTS_FOLDER_ID || '1bGb9xY283TRPVYHd-thZET5UJtwCKR1M';
const GHL_SUBSCRIPTION_FIELD_ID = 'IsFHpDJyHPLLCBEv6p7v'; // Subscription Name (MC)

app.post('/drive/client-folder', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { firstName, lastName, subscriptionStatus, parentId, airtableId } = req.body;

    if (!firstName || !lastName) {
      return res.status(400).json({ error: 'firstName and lastName required' });
    }

    // Build folder name: FIRSTNAME_LASTNAME_STATUS (ALL CAPS)
    const status = (subscriptionStatus || 'TRIAL').toUpperCase();
    const folderName = `${firstName.toUpperCase()}_${lastName.toUpperCase()}_${status}`;

    // Create main client folder in ACTIVE_CLIENTS
    const mainFolder = await googleDrive.files.create({
      requestBody: {
        name: folderName,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [parentId || ACTIVE_CLIENTS_FOLDER_ID]
      },
      fields: 'id, name, webViewLink',
      supportsAllDrives: true
    });

    // Create folder structure
    const folderStructure = {
      'BRAND ASSETS': ['LOGOS', 'HEADSHOTS - SMILING', 'HEADSHOTS - SHOCKED'],
      'SESSIONS': [],      // Virtual studio recordings (not tied to projects)
      'PROJECTS': []       // Auto-deleted after 30 days, clients never see contents
    };

    const created = {};

    for (const [folderName, subfolders] of Object.entries(folderStructure)) {
      // Create main subfolder
      const folder = await googleDrive.files.create({
        requestBody: {
          name: folderName,
          mimeType: 'application/vnd.google-apps.folder',
          parents: [mainFolder.data.id]
        },
        fields: 'id, name',
        supportsAllDrives: true
      });

      created[folderName] = { id: folder.data.id, subfolders: [] };

      // Create nested subfolders if any
      for (const subfolder of subfolders) {
        const sub = await googleDrive.files.create({
          requestBody: {
            name: subfolder,
            mimeType: 'application/vnd.google-apps.folder',
            parents: [folder.data.id]
          },
          fields: 'id, name',
          supportsAllDrives: true
        });
        created[folderName].subfolders.push({ name: subfolder, id: sub.data.id });
      }
    }

    // Update Airtable with folder info if airtableId provided
    if (airtableId) {
      await airtableUpdate('Clients', airtableId, {
        'Drive Folder ID': mainFolder.data.id,
        'Drive Folder URL': mainFolder.data.webViewLink
      });
    }

    res.json({
      clientFolder: mainFolder.data,
      structure: created,
      folderName: mainFolder.data.name
    });
  } catch (err) {
    console.error('[Drive Client Folder]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update client folder name (when subscription changes)
app.post('/drive/client-folder/:folderId/rename', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { firstName, lastName, subscriptionStatus } = req.body;

    if (!firstName || !lastName || !subscriptionStatus) {
      return res.status(400).json({ error: 'firstName, lastName, and subscriptionStatus required' });
    }

    // ALL CAPS format
    const newName = `${firstName.toUpperCase()}_${lastName.toUpperCase()}_${subscriptionStatus.toUpperCase()}`;

    const result = await googleDrive.files.update({
      fileId: req.params.folderId,
      requestBody: { name: newName },
      fields: 'id, name, webViewLink',
      supportsAllDrives: true
    });

    res.json(result.data);
  } catch (err) {
    console.error('[Drive Rename]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Move client folder to CANCELED_CLIENTS when subscription ends
app.post('/drive/client-folder/:folderId/cancel', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { firstName, lastName } = req.body;

    // Get current folder info
    const file = await googleDrive.files.get({
      fileId: req.params.folderId,
      fields: 'parents, name',
      supportsAllDrives: true
    });

    // Build new name with CANCELED status
    let newName = file.data.name;
    if (firstName && lastName) {
      newName = `${firstName.toUpperCase()}_${lastName.toUpperCase()}_CANCELED`;
    } else {
      // Just replace the status part of existing name
      newName = file.data.name.replace(/_[A-Z]+$/, '_CANCELED');
    }

    // Move to CANCELED_CLIENTS folder and rename
    const result = await googleDrive.files.update({
      fileId: req.params.folderId,
      addParents: CANCELED_CLIENTS_FOLDER_ID,
      removeParents: file.data.parents.join(','),
      requestBody: { name: newName },
      fields: 'id, name, webViewLink, parents',
      supportsAllDrives: true
    });

    res.json({
      moved: true,
      folder: result.data,
      from: 'ACTIVE_CLIENTS',
      to: 'CANCELED_CLIENTS'
    });
  } catch (err) {
    console.error('[Drive Cancel]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Reactivate client - move back to ACTIVE_CLIENTS
app.post('/drive/client-folder/:folderId/reactivate', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { firstName, lastName, subscriptionStatus } = req.body;

    if (!subscriptionStatus) {
      return res.status(400).json({ error: 'subscriptionStatus required' });
    }

    // Get current folder info
    const file = await googleDrive.files.get({
      fileId: req.params.folderId,
      fields: 'parents, name',
      supportsAllDrives: true
    });

    // Build new name with new status
    let newName;
    if (firstName && lastName) {
      newName = `${firstName.toUpperCase()}_${lastName.toUpperCase()}_${subscriptionStatus.toUpperCase()}`;
    } else {
      // Just replace the status part of existing name
      newName = file.data.name.replace(/_CANCELED$/, `_${subscriptionStatus.toUpperCase()}`);
    }

    // Move back to ACTIVE_CLIENTS folder and rename
    const result = await googleDrive.files.update({
      fileId: req.params.folderId,
      addParents: ACTIVE_CLIENTS_FOLDER_ID,
      removeParents: file.data.parents.join(','),
      requestBody: { name: newName },
      fields: 'id, name, webViewLink, parents',
      supportsAllDrives: true
    });

    res.json({
      reactivated: true,
      folder: result.data,
      from: 'CANCELED_CLIENTS',
      to: 'ACTIVE_CLIENTS'
    });
  } catch (err) {
    console.error('[Drive Reactivate]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete file/folder
app.delete('/drive/file/:fileId', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    await googleDrive.files.delete({
      fileId: req.params.fileId,
      supportsAllDrives: true
    });
    res.json({ deleted: true });
  } catch (err) {
    console.error('[Drive Delete]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// AUTO-DELETE PROJECTS AFTER 30 DAYS
// ============================================
// Finds all PROJECTS folders, checks files older than 30 days, deletes them
// Call this endpoint daily via cron/scheduled task (Make.com, Railway cron, etc.)

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

app.post('/drive/cleanup-old-projects', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const cutoffDate = new Date(Date.now() - THIRTY_DAYS_MS).toISOString();
    let deletedCount = 0;
    let checkedCount = 0;
    const deletedFiles = [];

    // Find all folders named "PROJECTS" in active clients
    const projectFolders = await googleDrive.files.list({
      q: `name = 'PROJECTS' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`,
      fields: 'files(id, name, parents)',
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
      driveId: GOOGLE_SHARED_DRIVE_ID,
      corpora: 'drive'
    });

    // For each PROJECTS folder, find old files
    for (const projectFolder of projectFolders.data.files || []) {
      const oldFiles = await googleDrive.files.list({
        q: `'${projectFolder.id}' in parents and modifiedTime < '${cutoffDate}' and trashed = false`,
        fields: 'files(id, name, modifiedTime)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      checkedCount += (oldFiles.data.files || []).length;

      // Delete each old file/folder
      for (const file of oldFiles.data.files || []) {
        try {
          await googleDrive.files.delete({
            fileId: file.id,
            supportsAllDrives: true
          });
          deletedCount++;
          deletedFiles.push({
            name: file.name,
            modifiedTime: file.modifiedTime,
            parentFolder: projectFolder.id
          });
        } catch (delErr) {
          console.error(`[Cleanup] Failed to delete ${file.name}:`, delErr.message);
        }
      }
    }

    console.log(`[Cleanup] Deleted ${deletedCount} files older than 30 days`);

    res.json({
      success: true,
      projectFoldersChecked: (projectFolders.data.files || []).length,
      filesChecked: checkedCount,
      filesDeleted: deletedCount,
      cutoffDate,
      deletedFiles
    });
  } catch (err) {
    console.error('[Cleanup]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get list of projects that WOULD be deleted (dry run)
app.get('/drive/cleanup-old-projects/preview', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const cutoffDate = new Date(Date.now() - THIRTY_DAYS_MS).toISOString();
    const toDelete = [];

    // Find all PROJECTS folders
    const projectFolders = await googleDrive.files.list({
      q: `name = 'PROJECTS' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`,
      fields: 'files(id, name)',
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
      driveId: GOOGLE_SHARED_DRIVE_ID,
      corpora: 'drive'
    });

    for (const projectFolder of projectFolders.data.files || []) {
      const oldFiles = await googleDrive.files.list({
        q: `'${projectFolder.id}' in parents and modifiedTime < '${cutoffDate}' and trashed = false`,
        fields: 'files(id, name, modifiedTime, size)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      for (const file of oldFiles.data.files || []) {
        toDelete.push({
          name: file.name,
          modifiedTime: file.modifiedTime,
          size: file.size,
          projectFolderId: projectFolder.id
        });
      }
    }

    res.json({
      cutoffDate,
      daysOld: 30,
      wouldDelete: toDelete.length,
      files: toDelete
    });
  } catch (err) {
    console.error('[Cleanup Preview]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Move file
app.post('/drive/file/:fileId/move', async (req, res) => {
  if (!driveReady) return res.status(503).json({ error: 'Drive not configured' });

  try {
    const { newParentId } = req.body;
    if (!newParentId) return res.status(400).json({ error: 'newParentId required' });

    // Get current parents
    const file = await googleDrive.files.get({
      fileId: req.params.fileId,
      fields: 'parents',
      supportsAllDrives: true
    });

    const result = await googleDrive.files.update({
      fileId: req.params.fileId,
      addParents: newParentId,
      removeParents: file.data.parents.join(','),
      fields: 'id, name, parents',
      supportsAllDrives: true
    });

    res.json(result.data);
  } catch (err) {
    console.error('[Drive Move]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// STRIPE PAYMENT ENDPOINTS
// ============================================

// Get Stripe instance
function getStripe() {
  if (!STRIPE_SECRET_KEY) return null;
  return require('stripe')(STRIPE_SECRET_KEY);
}

// Create checkout session
app.post('/stripe/checkout', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { priceId, customerEmail, successUrl, cancelUrl, metadata } = req.body;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer_email: customerEmail,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: successUrl || 'https://go.contentbug.io/dashboard?success=true',
      cancel_url: cancelUrl || 'https://contentbug.io/pricing?canceled=true',
      metadata: metadata || {}
    });

    res.json({ sessionId: session.id, url: session.url });
  } catch (err) {
    console.error('[Stripe Checkout]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create customer
app.post('/stripe/customer', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { email, name, metadata } = req.body;
    const customer = await stripe.customers.create({ email, name, metadata });
    res.json(customer);
  } catch (err) {
    console.error('[Stripe Customer]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get customer by email
app.get('/stripe/customer', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { email } = req.query;
    const customers = await stripe.customers.list({ email, limit: 1 });
    res.json(customers.data[0] || null);
  } catch (err) {
    console.error('[Stripe Customer]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get subscriptions
app.get('/stripe/subscriptions', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { customerId, status } = req.query;
    const params = { limit: 100 };
    if (customerId) params.customer = customerId;
    if (status) params.status = status;
    const subscriptions = await stripe.subscriptions.list(params);
    res.json(subscriptions.data);
  } catch (err) {
    console.error('[Stripe Subscriptions]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Cancel subscription
app.post('/stripe/subscription/:id/cancel', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { immediately } = req.body;
    let result;
    if (immediately) {
      result = await stripe.subscriptions.cancel(req.params.id);
    } else {
      result = await stripe.subscriptions.update(req.params.id, { cancel_at_period_end: true });
    }
    res.json(result);
  } catch (err) {
    console.error('[Stripe Cancel]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get invoices
app.get('/stripe/invoices', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { customerId } = req.query;
    const params = { limit: 100 };
    if (customerId) params.customer = customerId;
    const invoices = await stripe.invoices.list(params);
    res.json(invoices.data);
  } catch (err) {
    console.error('[Stripe Invoices]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create billing portal session
app.post('/stripe/portal', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  try {
    const { customerId, returnUrl } = req.body;
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl || 'https://go.contentbug.io/dashboard'
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[Stripe Portal]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// HTML STORAGE (Airtable-based)
// ============================================
const HTML_TABLE = 'HTML_Files';

// Save/update HTML file
app.post('/html/save', async (req, res) => {
  try {
    const { filename, content, type, version } = req.body;
    if (!filename || !content) {
      return res.status(400).json({ error: 'filename and content required' });
    }

    // Check if file exists
    const existing = await airtableQuery(HTML_TABLE, `{Filename} = "${filename}"`, { maxRecords: 1 });

    if (existing.records.length > 0) {
      // Update existing
      const result = await airtableUpdate(HTML_TABLE, existing.records[0].id, {
        Content: content,
        Type: type || 'html',
        Version: version || (parseInt(existing.records[0].fields.Version || '0') + 1).toString(),
        'Last Updated': new Date().toISOString()
      });
      res.json({ updated: true, id: result?.id, filename });
    } else {
      // Create new
      const result = await airtableCreate(HTML_TABLE, {
        Filename: filename,
        Content: content,
        Type: type || 'html',
        Version: version || '1',
        'Last Updated': new Date().toISOString()
      });
      res.json({ created: true, id: result?.id, filename });
    }
  } catch (err) {
    console.error('[HTML Save]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get HTML file
app.get('/html/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    const result = await airtableQuery(HTML_TABLE, `{Filename} = "${filename}"`, { maxRecords: 1 });

    if (result.records.length === 0) {
      return res.status(404).json({ error: 'not found' });
    }

    const record = result.records[0];
    res.json({
      filename: record.fields.Filename,
      content: record.fields.Content,
      type: record.fields.Type,
      version: record.fields.Version,
      lastUpdated: record.fields['Last Updated']
    });
  } catch (err) {
    console.error('[HTML Get]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// List all HTML files
app.get('/html', async (req, res) => {
  try {
    const result = await airtableQuery(HTML_TABLE, '', { maxRecords: 100 });
    const files = result.records.map(r => ({
      id: r.id,
      filename: r.fields.Filename,
      type: r.fields.Type,
      version: r.fields.Version,
      lastUpdated: r.fields['Last Updated']
    }));
    res.json(files);
  } catch (err) {
    console.error('[HTML List]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// PORTAL STATIC FILES
// ============================================
const PORTAL_DIR = path.join(__dirname, 'portal');
app.use('/portal', express.static(PORTAL_DIR));

// Portal routes
const portalPages = ['login', 'signup', 'dashboard', 'portal', 'review', 'style-blueprint', 'submit-project'];
portalPages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(PORTAL_DIR, `${page}.html`), err => {
      if (err) res.status(404).send('Page not found');
    });
  });
});

app.get('/', (req, res) => res.redirect('/login'));

// ============================================
// INVITE & AFFILIATE SYSTEM
// ============================================

// POST /api/invite/send - Send invite to team member
app.post('/api/invite/send', async (req, res) => {
  try {
    const { type, recipient, inviteLink, inviterEmail, inviterName, channelId, permissions } = req.body;

    if (!recipient || !inviteLink) {
      return res.status(400).json({ error: 'Missing recipient or invite link' });
    }

    // Build message
    const message = `${inviterName || 'Someone'} has invited you to join their Content Bug channel!\n\nClick here to join: ${inviteLink}`;

    if (type === 'email' && recipient.includes('@') && GHL_API_KEY) {
      try {
        // Send via GHL
        await axios.post(GHL_WEBHOOK_URL || 'https://services.leadconnectorhq.com/hooks/mCNHhjy593eUueqfuqyU/webhook-trigger/7a6987de-1839-45f5-97e2-0f0af01048c9', {
          type: 'invite',
          email: recipient,
          subject: `${inviterName || 'Someone'} invited you to Content Bug`,
          message: message,
          inviteLink: inviteLink
        });
      } catch (ghlErr) {
        console.log('[Invite] GHL webhook error:', ghlErr.message);
      }
    }

    // Store in Airtable
    if (AIRTABLE_API_KEY) {
      try {
        await axios.post(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Client%20Team%20Members`,
          {
            fields: {
              'Contact': recipient,
              'Invite Type': type,
              'Inviter Email': inviterEmail,
              'Inviter Name': inviterName,
              'Channel ID': channelId,
              'Can Chat': permissions?.canChat !== false,
              'Can View Projects': permissions?.canViewProjects !== false,
              'Can Submit': permissions?.canSubmit || false,
              'Status': 'Invited',
              'Invite Sent': new Date().toISOString()
            }
          },
          {
            headers: {
              'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
              'Content-Type': 'application/json'
            }
          }
        );
      } catch (atErr) {
        console.log('[Invite] Airtable storage:', atErr.message);
      }
    }

    console.log(`[Invite] Sent ${type} invite to ${recipient} from ${inviterEmail}`);
    res.json({ success: true });

  } catch (err) {
    console.error('[Invite] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/affiliate/send - Send affiliate link
app.post('/api/affiliate/send', async (req, res) => {
  try {
    const { type, recipient, affiliateLink, referrerEmail, referrerName } = req.body;

    if (!recipient || !affiliateLink) {
      return res.status(400).json({ error: 'Missing recipient or affiliate link' });
    }

    const message = `Hey! ${referrerName || 'Your friend'} thinks you'd love Content Bug - professional video editing for content creators.\n\nCheck it out: ${affiliateLink}`;

    if (type === 'email' && recipient.includes('@') && GHL_API_KEY) {
      try {
        await axios.post(GHL_WEBHOOK_URL || 'https://services.leadconnectorhq.com/hooks/mCNHhjy593eUueqfuqyU/webhook-trigger/7a6987de-1839-45f5-97e2-0f0af01048c9', {
          type: 'affiliate',
          email: recipient,
          subject: `${referrerName || 'A friend'} recommends Content Bug`,
          message: message,
          affiliateLink: affiliateLink
        });
      } catch (ghlErr) {
        console.log('[Affiliate] GHL webhook error:', ghlErr.message);
      }
    }

    // Track referral in Airtable
    if (AIRTABLE_API_KEY) {
      try {
        await axios.post(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Affiliate%20Referrals`,
          {
            fields: {
              'Referred Contact': recipient,
              'Referrer Email': referrerEmail,
              'Referrer Name': referrerName,
              'Send Type': type,
              'Status': 'Sent',
              'Date Sent': new Date().toISOString()
            }
          },
          {
            headers: {
              'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
              'Content-Type': 'application/json'
            }
          }
        );
      } catch (atErr) {
        console.log('[Affiliate] Airtable storage:', atErr.message);
      }
    }

    console.log(`[Affiliate] Sent ${type} referral to ${recipient} from ${referrerEmail}`);
    res.json({ success: true });

  } catch (err) {
    console.error('[Affiliate] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/affiliate/stats - Get affiliate stats for a user
app.get('/api/affiliate/stats', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.json({ signups: 0, pending: 0 });

    let signups = 0, pending = 0;

    if (AIRTABLE_API_KEY) {
      try {
        const response = await axios.get(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Affiliate%20Referrals`,
          {
            params: { filterByFormula: `{Referrer Email}='${email}'` },
            headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
          }
        );
        const records = response.data?.records || [];
        signups = records.filter(r => r.fields?.Status === 'Converted').length;
        pending = records.filter(r => r.fields?.Status === 'Sent' || r.fields?.Status === 'Clicked').length;
      } catch (atErr) {
        console.log('[Affiliate Stats]:', atErr.message);
      }
    }

    res.json({ signups, pending });
  } catch (err) {
    res.json({ signups: 0, pending: 0 });
  }
});

// GET /api/client/team-members - Get team members for a channel
app.get('/api/client/team-members', async (req, res) => {
  try {
    const channelId = req.query.channelId;
    if (!channelId) return res.json({ members: [] });

    let members = [];

    if (AIRTABLE_API_KEY) {
      try {
        const response = await axios.get(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Client%20Team%20Members`,
          {
            params: { filterByFormula: `{Channel ID}='${channelId}'` },
            headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
          }
        );
        members = (response.data?.records || []).map(r => ({
          id: r.id,
          name: r.fields?.Name || 'Pending',
          email: r.fields?.Email || r.fields?.Contact,
          status: r.fields?.Status || 'Invited',
          canChat: r.fields?.['Can Chat'] || false,
          canViewProjects: r.fields?.['Can View Projects'] || false,
          canSubmit: r.fields?.['Can Submit'] || false
        }));
      } catch (atErr) {
        console.log('[Team Members]:', atErr.message);
      }
    }

    res.json({ members });
  } catch (err) {
    res.json({ members: [] });
  }
});

// ============================================
// PRESENCE TRACKING - Online Users
// ============================================

// In-memory store for online users (in production, use Redis)
const onlineUsers = new Map();
const PRESENCE_TIMEOUT = 60000; // 60 seconds - user considered offline after this

// Clean up stale users every 30 seconds
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of onlineUsers.entries()) {
    if (now - data.timestamp > PRESENCE_TIMEOUT) {
      onlineUsers.delete(email);
      console.log(`[Presence] User offline (timeout): ${email}`);
    }
  }
}, 30000);

// Heartbeat - update user presence
app.post('/api/presence/heartbeat', (req, res) => {
  try {
    const { email, name, role, avatar, currentPage, timestamp } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Update user presence
    onlineUsers.set(email.toLowerCase(), {
      email: email.toLowerCase(),
      name: name || 'User',
      role: role || 'client',
      avatar: avatar || null,
      currentPage: currentPage || 'Unknown',
      timestamp: timestamp || Date.now()
    });

    // Return all online users
    const users = Array.from(onlineUsers.values());
    res.json({ success: true, onlineUsers: users });
  } catch (err) {
    console.error('[Presence] Heartbeat error:', err.message);
    res.status(500).json({ error: 'Heartbeat failed' });
  }
});

// Get online users
app.get('/api/presence/online', (req, res) => {
  try {
    const users = Array.from(onlineUsers.values());
    res.json({ success: true, onlineUsers: users, count: users.length });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get online users' });
  }
});

// Mark user offline
app.post('/api/presence/offline', express.text({ type: '*/*' }), (req, res) => {
  try {
    let email;
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      email = body.email;
    } catch (e) {
      email = req.body;
    }

    if (email) {
      onlineUsers.delete(email.toLowerCase());
      console.log(`[Presence] User offline: ${email}`);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to mark offline' });
  }
});

// ============================================
// AUTHENTICATION - Email Verification
// ============================================

// In-memory store for verification codes (in production, use Redis)
const verificationCodes = new Map();

// Generate 6-digit code
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Clean up expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of verificationCodes.entries()) {
    if (now - data.createdAt > 600000) { // 10 minutes expiry
      verificationCodes.delete(email);
    }
  }
}, 300000);

// Send verification code
app.post('/api/auth/send-code', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const code = generateCode();
    verificationCodes.set(email.toLowerCase(), {
      code,
      createdAt: Date.now(),
      attempts: 0
    });

    // Send code via GHL email
    if (GHL_API_KEY) {
      try {
        // First, find or create the contact
        let contactId = null;

        // Search for existing contact
        const searchRes = await axios.get(
          `https://services.leadconnectorhq.com/contacts/?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`,
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
        );

        if (searchRes.data?.contacts?.length > 0) {
          contactId = searchRes.data.contacts[0].id;
        } else {
          // Create new contact
          const createRes = await axios.post(
            'https://services.leadconnectorhq.com/contacts/',
            {
              locationId: GHL_LOCATION_ID,
              email: email,
              source: 'Free Trial Verification',
              tags: ['trial-signup']
            },
            { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
          );
          contactId = createRes.data?.contact?.id;
        }

        // Send verification code via GHL webhook trigger (workflow sends email)
        // This is more reliable than API email sending
        try {
          const webhookRes = await axios.post(
            'https://services.leadconnectorhq.com/hooks/mCNHhjy593eUueqfuqyU/webhook-trigger/7a6987de-1839-45f5-97e2-0f0af01048c9',
            {
              email: email,
              verification_code: code,
              contact_id: contactId,
              type: 'verification_code',
              timestamp: new Date().toISOString()
            },
            { headers: { 'Content-Type': 'application/json' } }
          );
          console.log(`[Auth] Webhook triggered for ${email}, code: ${code}`);
        } catch (webhookErr) {
          console.log('[Auth] Webhook error:', webhookErr.message);
          // Code is still stored, user can use it if they already have an email setup
        }
      } catch (emailErr) {
        console.log('[Auth] GHL error:', emailErr.message);
      }
    }

    console.log(`[Auth] Code sent to ${email}: ${code}`);
    res.json({ success: true, message: 'Verification code sent' });
  } catch (err) {
    console.error('[Auth] Send code error:', err.message);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

// Verify code
app.post('/api/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    const stored = verificationCodes.get(email.toLowerCase());
    if (!stored) {
      return res.status(400).json({ error: 'No code found. Please request a new one.' });
    }

    // Check expiry (10 minutes)
    if (Date.now() - stored.createdAt > 600000) {
      verificationCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });
    }

    // Check attempts (max 5)
    if (stored.attempts >= 5) {
      verificationCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: 'Too many attempts. Please request a new code.' });
    }

    // Verify code
    if (stored.code !== code) {
      stored.attempts++;
      return res.status(400).json({ error: 'Invalid code' });
    }

    // Success - clean up and return token
    verificationCodes.delete(email.toLowerCase());

    // Generate simple session token
    const token = Buffer.from(`${email}:${Date.now()}`).toString('base64');

    // Update contact in GHL with verified tag
    if (GHL_API_KEY) {
      try {
        const searchRes = await axios.get(
          `https://services.leadconnectorhq.com/contacts/?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`,
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
        );

        if (searchRes.data?.contacts?.length > 0) {
          const contactId = searchRes.data.contacts[0].id;
          await axios.post(
            `https://services.leadconnectorhq.com/contacts/${contactId}/tags`,
            { tags: ['email-verified', 'trial-started'] },
            { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
          );
        }
      } catch (tagErr) {
        console.log('[Auth] Tag update error:', tagErr.message);
      }
    }

    console.log(`[Auth] Email verified: ${email}`);
    res.json({ success: true, token, verified: true });
  } catch (err) {
    console.error('[Auth] Verify error:', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============================================
// TRIAL CONTACT CREATION
// ============================================

// Create/update GHL contact with full info after name capture
app.post('/api/trial/create-contact', async (req, res) => {
  try {
    const { email, firstName, lastName, source, onboardingStatus } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    let contactId = null;
    let isExisting = false;

    if (GHL_API_KEY) {
      // Check if contact exists
      const searchRes = await axios.get(
        `https://services.leadconnectorhq.com/contacts/?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`,
        { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
      );

      if (searchRes.data?.contacts?.length > 0) {
        // Update existing contact
        contactId = searchRes.data.contacts[0].id;
        isExisting = true;

        await axios.put(
          `https://services.leadconnectorhq.com/contacts/${contactId}`,
          {
            firstName: firstName || undefined,
            lastName: lastName || undefined,
            customFields: [
              { key: 'onboarding_status', field_value: onboardingStatus || 'Started' }
            ]
          },
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
        );

        // Add tags
        await axios.post(
          `https://services.leadconnectorhq.com/contacts/${contactId}/tags`,
          { tags: ['trial-started', 'email-verified', 'portal-onboarding'] },
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
        );

      } else {
        // Create new contact
        const createRes = await axios.post(
          'https://services.leadconnectorhq.com/contacts/',
          {
            locationId: GHL_LOCATION_ID,
            email: email,
            firstName: firstName || '',
            lastName: lastName || '',
            source: source || 'Free Trial',
            tags: ['trial-started', 'email-verified', 'portal-onboarding'],
            customFields: [
              { key: 'onboarding_status', field_value: onboardingStatus || 'Started' }
            ]
          },
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
        );
        contactId = createRes.data?.contact?.id;
      }
    }

    console.log(`[Trial] Contact ${isExisting ? 'updated' : 'created'}: ${email} (${contactId})`);
    res.json({
      success: true,
      contactId,
      isExisting,
      message: isExisting ? 'Contact updated' : 'Contact created'
    });

  } catch (err) {
    console.error('[Trial] Contact creation error:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

// Check if email exists in system (for routing existing vs new users)
app.post('/api/trial/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    let exists = false;
    let contactData = null;
    let isCustomer = false;

    if (GHL_API_KEY) {
      const searchRes = await axios.get(
        `https://services.leadconnectorhq.com/contacts/?locationId=${GHL_LOCATION_ID}&email=${encodeURIComponent(email)}`,
        { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28' } }
      );

      if (searchRes.data?.contacts?.length > 0) {
        exists = true;
        contactData = searchRes.data.contacts[0];
        // Check if they're already a customer (has customer tag or subscription)
        const tags = contactData.tags || [];
        isCustomer = tags.includes('customer') || tags.includes('active-subscription');
      }
    }

    res.json({
      exists,
      isCustomer,
      firstName: contactData?.firstName,
      lastName: contactData?.lastName
    });

  } catch (err) {
    console.error('[Trial] Email check error:', err.message);
    res.json({ exists: false, isCustomer: false });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`ContentBug MCP Server v3.0 (Minimal)`);
  console.log(`${'='.repeat(50)}`);
  console.log(`Port: ${PORT}`);
  console.log(`\nServices:`);
  console.log(`  Airtable: ${AIRTABLE_API_KEY ? 'YES' : 'NO'}`);
  console.log(`  GHL:      ${GHL_API_KEY ? 'YES' : 'NO'}`);
  console.log(`  Claude:   ${CLAUDE_API_KEY ? 'YES' : 'NO'}`);
  console.log(`  OpenAI:   ${OPENAI_API_KEY ? 'YES' : 'NO'}`);
  console.log(`  Stripe:   ${STRIPE_SECRET_KEY ? 'YES' : 'NO'}`);
  console.log(`${'='.repeat(50)}\n`);
});
