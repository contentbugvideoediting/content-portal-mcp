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
    stripe: !!STRIPE_SECRET_KEY
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
