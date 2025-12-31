// ContentBug Portal MCP Server v3.3.0
// GHL is source of truth - GHL natively syncs to Airtable
// Portal just sends webhooks to GHL, GHL handles everything
// Updated: 2024-12-31

const express = require('express');
const axios = require('axios');
const cors = require('cors');
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
// HEALTH CHECK
// ============================================
app.get('/healthz', (req, res) => res.json({
  ok: true,
  version: '3.3.0-ghl-native',
  ts: Date.now(),
  services: {
    ghl: !!GHL_API_KEY,
    claude: !!CLAUDE_API_KEY,
    openai: !!OPENAI_API_KEY,
    stripe: !!STRIPE_SECRET_KEY,
    apify: !!APIFY_API_TOKEN,
    drive: driveReady
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
// Memory backup for codes (GHL is primary storage)
const verificationCodes = new Map();

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ============================================
// AUTH ENDPOINTS
// ============================================

/**
 * SEND VERIFICATION CODE
 * 1. Generate 6-digit code
 * 2. Store in memory (backup)
 * 3. Send webhook to GHL with: email, code, template, first_name
 * 4. GHL workflow: creates/updates contact, stores code in contact field, sends email
 * 5. GHL native sync mirrors to Airtable automatically
 */
app.post('/api/auth/send-code', async (req, res) => {
  try {
    const { email, source = 'portal_login', firstName = '' } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const code = generateCode();

    // Store in memory (backup for verify)
    verificationCodes.set(normalizedEmail, {
      code,
      createdAt: Date.now(),
      attempts: 0
    });

    // Determine template
    let template = 'portal_login_trial';

    if (source === 'pricing_unlock' || source === 'pricing_page') {
      template = 'pricing_unlock';
    } else {
      // Check existing contact status
      const contact = await ghlFindByEmail(normalizedEmail);
      if (contact?.customFields) {
        const subStatus = contact.customFields.find(f => f.id === GHL_FIELDS.subscriptionStatus)?.value;
        if (subStatus === 'Active') template = 'portal_login_active';
        else if (subStatus === 'Failed Payment') template = 'portal_login_failed';
        else if (subStatus === 'Canceled') template = 'portal_login_canceled';
      }
    }

    // Send to GHL webhook
    // GHL workflow will: create/update contact, save code to contact.verification_code, send email
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

/**
 * VERIFY CODE
 * 1. Check memory first
 * 2. Fallback: check GHL contact's verification_code field
 * 3. On success: clear code in GHL, update last_login, return contact data
 */
app.post('/api/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check memory first
    let stored = verificationCodes.get(normalizedEmail);
    let storedCode = stored?.code;

    // Fallback: check GHL contact
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

    // Expiry check (10 min)
    if (stored && Date.now() - stored.createdAt > 600000) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });
    }

    // Attempt limit
    if (stored && stored.attempts >= 5) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Too many attempts. Request a new code.' });
    }

    // Verify
    if (storedCode !== code) {
      if (stored) stored.attempts++;
      return res.status(400).json({ error: 'Invalid code' });
    }

    // SUCCESS
    verificationCodes.delete(normalizedEmail);

    // Get contact data from GHL
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

      // Parse custom fields
      if (contact.customFields) {
        for (const cf of contact.customFields) {
          if (cf.id === GHL_FIELDS.subscriptionStatus) contactData.subscriptionStatus = cf.value || '';
          if (cf.id === GHL_FIELDS.portalAccess) contactData.portalAccess = cf.value || 'Limited';
          if (cf.id === GHL_FIELDS.userRole) contactData.userRole = cf.value || 'Lead';
          if (cf.id === GHL_FIELDS.onboardingStatus) contactData.onboardingStatus = cf.value || '';
          if (cf.id === GHL_FIELDS.subscriptionName) contactData.subscriptionName = cf.value || '';
        }
      }

      // Clear code and update last login in GHL
      await ghlUpdateContact(contact.id, {
        customFields: [
          { id: GHL_FIELDS.verificationCode, value: '' },
          { id: GHL_FIELDS.lastLogin, value: new Date().toISOString() }
        ]
      });

      // Add verified tag
      await ghlAddTags(contact.id, ['email-verified']);
    }

    // Session token
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
  console.log(`ContentBug Portal v3.3.0 on port ${PORT}`);
  console.log('GHL is source of truth (native Airtable sync)');
});
