// ContentBug Minimal MCP Server v3.1
// Core integrations: Airtable, GHL, Make.com, Google Drive
// Updated: Unified email webhook, Airtable field sync

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

// UNIFIED EMAIL WEBHOOK - One webhook routes to all email templates
const GHL_EMAIL_WEBHOOK = process.env.GHL_EMAIL_WEBHOOK || 'https://services.leadconnectorhq.com/hooks/mCNHhjy593eUueqfuqyU/webhook-trigger/7a6987de-1839-45f5-97e2-0f0af01048c9';

// ============================================
// AIRTABLE FIELD MAPPING (Clients Table)
// ============================================
const AIRTABLE_FIELDS = {
  // Core fields
  firstName: 'First Name',
  lastName: 'Last Name',
  email: 'Email',
  phone: 'Phone',

  // Status fields
  contactStatus: 'Contact Status',          // New Lead, Hot Lead, Trial - Active, Won - Active, Lost - Canceled
  freeTrialStatus: 'Free Trial Status',     // Account Created, Blueprint Created, Edit Submitted, etc.
  portalAccess: 'Portal Access',            // Limited, Full Access, Locked
  qualificationStatus: 'Qualification Status',

  // Subscription fields
  subscriptionStatus: 'Subscription Status', // Active, Failed Payment, Canceled
  subscriptionName: 'Subscription Name',
  billingFrequency: 'Subscription Billing Frequency', // 1 Month, 3 Months, 6 Months, 12 Months
  subscriptionTerm: 'Subscription Term',     // Monthly, Annual
  subscriptionStartDate: 'Subscription Start Date',
  subscriptionEndDate: 'Subscription End Date',
  nextPaymentDate: 'Next Scheduled Payment Date',

  // Payment fields
  paymentStatus: 'Payment Status',           // Succeeded, Failed, Refunded
  paymentAmount: 'Payment Amount',
  lastPaymentDate: 'Last Successful Payment Date',
  paymentHistory: 'Payment History',
  paymentUpdateLink: 'Payment Update Link',

  // Onboarding fields
  appointmentName: 'Appointment Name',
  appointmentDate: 'Appointment Date',
  appointmentTime: 'Appointment Time',
  appointmentLocation: 'Appointment Location',
  appointmentNotes: 'Appointment Notes',

  // Project fields
  videoType: 'Video Type',
  videoOutput: 'Video Output',
  startTimeline: 'Start Timeline',
  footageReady: 'Footage Ready',

  // Integration fields
  ghlContactId: 'GHL Contact ID',
  driveFolderId: 'Drive Folder ID',
  driveFolderUrl: 'Drive Folder URL',
  googleDriveFolderLink: 'Google Drive Folder Link',

  // Auth fields
  verificationCode: 'Verification Code',
  lastLogin: 'Last Login',
  lastLogout: 'Last Logout',

  // Scores
  avgQualityScore: 'Average Quality Score',
  avgTurnaroundScore: 'Average Turnaround Time Score',
  avgRevisionScore: 'Average Revision Count Score'
};

// GHL Custom Field Keys (contact.field_key format)
const GHL_CUSTOM_FIELDS = {
  verificationCode: 'contact.verification_code',
  lastLogin: 'contact.last_login',
  subscriptionStatus: 'contact.subscription_status',
  billingFrequency: 'contact.billing_frequency',
  paymentAmount: 'contact.payment_amount',
  paymentUpdateLink: 'contact.payment_update_link',
  googleDriveFolderLink: 'contact.google_drive_folder_link',
  qualificationStatus: 'contact.qualification_status_txt',
  appointmentDate: 'contact.appointment_date'
};

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
  version: '3.1.0-unified',
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

// Find client by email in Airtable
async function findClientByEmail(email) {
  const result = await airtableQuery('Clients', `{Email}='${email}'`, { maxRecords: 1 });
  return result.records?.[0] || null;
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

async function ghlUpdateContact(contactId, data) {
  return ghlRequest(`/contacts/${contactId}`, 'PUT', data);
}

async function ghlFindByEmail(email) {
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

// ============================================
// UNIFIED EMAIL WEBHOOK
// ============================================
// This sends emails through GHL workflow that routes based on 'template' field
// Available templates:
//   - pricing_unlock: 6-digit code for pricing page unlock
//   - portal_login_active: Login code for active subscribers
//   - portal_login_trial: Login code for trial users
//   - portal_login_failed: Login code for failed payment users
//   - portal_login_canceled: Login code for canceled users
//   - welcome_trial: Welcome email after trial signup
//   - welcome_paid: Welcome email after payment
//   - payment_failed: Payment failed notification
//   - payment_success: Payment success confirmation

async function sendEmailViaWebhook(payload) {
  try {
    const webhookData = {
      email: payload.email,
      template: payload.template,
      verification_code: payload.code || '',
      first_name: payload.firstName || '',
      contact_id: payload.contactId || '',
      subscription_status: payload.subscriptionStatus || '',
      portal_access: payload.portalAccess || '',
      timestamp: new Date().toISOString(),
      ...payload.customData
    };

    console.log(`[Email Webhook] Sending template "${payload.template}" to ${payload.email}`);

    await axios.post(GHL_EMAIL_WEBHOOK, webhookData, {
      headers: { 'Content-Type': 'application/json' }
    });

    return { success: true };
  } catch (err) {
    console.error('[Email Webhook]', err.message);
    return { success: false, error: err.message };
  }
}

// ============================================
// VERIFICATION CODE SYSTEM
// ============================================
// In-memory store for codes (backup - primary storage is Airtable)
const verificationCodes = new Map();

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Determine email template based on contact status
function getEmailTemplate(source, contact) {
  // If source is pricing page, always use pricing_unlock
  if (source === 'pricing_unlock' || source === 'pricing_page') {
    return 'pricing_unlock';
  }

  // For portal login, check subscription status
  const subStatus = contact?.subscriptionStatus || contact?.['Subscription Status'] || '';
  const portalAccess = contact?.portalAccess || contact?.['Portal Access'] || '';
  const contactStatus = contact?.contactStatus || contact?.['Contact Status'] || '';

  if (subStatus === 'Active') {
    return 'portal_login_active';
  } else if (subStatus === 'Failed Payment') {
    return 'portal_login_failed';
  } else if (subStatus === 'Canceled') {
    return 'portal_login_canceled';
  } else if (contactStatus?.includes('Trial')) {
    return 'portal_login_trial';
  }

  // Default to trial template for new leads
  return 'portal_login_trial';
}

// ============================================
// AUTH ENDPOINTS
// ============================================

// Send verification code
app.post('/api/auth/send-code', async (req, res) => {
  try {
    const { email, source = 'portal_login' } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const code = generateCode();

    // Store in memory (backup)
    verificationCodes.set(normalizedEmail, {
      code,
      createdAt: Date.now(),
      attempts: 0,
      source
    });

    let contactId = null;
    let airtableId = null;
    let contactData = null;
    let isNewContact = false;

    // 1. Find or create GHL contact
    if (GHL_API_KEY) {
      const existingContact = await ghlFindByEmail(normalizedEmail);

      if (existingContact) {
        contactId = existingContact.id;
        contactData = existingContact;

        // Update verification code in GHL
        await ghlUpdateContact(contactId, {
          customFields: [
            { key: GHL_CUSTOM_FIELDS.verificationCode, field_value: code }
          ]
        });
      } else {
        // Create new contact
        isNewContact = true;
        const newContact = await ghlCreateContact({
          email: normalizedEmail,
          source: source === 'pricing_unlock' ? 'Pricing Page' : 'Portal Login',
          tags: ['verification-requested'],
          customFields: [
            { key: GHL_CUSTOM_FIELDS.verificationCode, field_value: code }
          ]
        });
        contactId = newContact?.contact?.id;
      }
    }

    // 2. Find or create Airtable client
    if (AIRTABLE_API_KEY) {
      const existingClient = await findClientByEmail(normalizedEmail);

      if (existingClient) {
        airtableId = existingClient.id;
        contactData = { ...contactData, ...existingClient.fields };

        // Update verification code
        await airtableUpdate('Clients', airtableId, {
          [AIRTABLE_FIELDS.verificationCode]: code,
          [AIRTABLE_FIELDS.ghlContactId]: contactId || existingClient.fields[AIRTABLE_FIELDS.ghlContactId]
        });
      } else {
        // Create new client
        const newClient = await airtableCreate('Clients', {
          [AIRTABLE_FIELDS.email]: normalizedEmail,
          [AIRTABLE_FIELDS.verificationCode]: code,
          [AIRTABLE_FIELDS.contactStatus]: 'New Lead',
          [AIRTABLE_FIELDS.portalAccess]: 'Limited',
          [AIRTABLE_FIELDS.ghlContactId]: contactId || ''
        });
        airtableId = newClient?.id;
      }
    }

    // 3. Determine email template and send via unified webhook
    const template = getEmailTemplate(source, contactData);

    await sendEmailViaWebhook({
      email: normalizedEmail,
      template,
      code,
      firstName: contactData?.firstName || contactData?.['First Name'] || '',
      contactId,
      subscriptionStatus: contactData?.subscriptionStatus || contactData?.['Subscription Status'] || '',
      portalAccess: contactData?.portalAccess || contactData?.['Portal Access'] || ''
    });

    console.log(`[Auth] Code ${code} sent to ${normalizedEmail} via template "${template}"`);

    res.json({
      success: true,
      message: 'Verification code sent',
      isNewContact
    });

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

    const normalizedEmail = email.toLowerCase().trim();

    // Try to get code from memory first
    let stored = verificationCodes.get(normalizedEmail);
    let storedCode = stored?.code;

    // If not in memory, check Airtable
    if (!storedCode && AIRTABLE_API_KEY) {
      const client = await findClientByEmail(normalizedEmail);
      if (client) {
        storedCode = client.fields[AIRTABLE_FIELDS.verificationCode];
        stored = { code: storedCode, createdAt: Date.now() - 300000, attempts: 0 }; // Assume 5 min old
      }
    }

    if (!storedCode) {
      return res.status(400).json({ error: 'No code found. Please request a new one.' });
    }

    // Check expiry (10 minutes for memory-stored codes)
    if (stored && Date.now() - stored.createdAt > 600000) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });
    }

    // Check attempts (max 5)
    if (stored && stored.attempts >= 5) {
      verificationCodes.delete(normalizedEmail);
      return res.status(400).json({ error: 'Too many attempts. Please request a new code.' });
    }

    // Verify code
    if (storedCode !== code) {
      if (stored) stored.attempts++;
      return res.status(400).json({ error: 'Invalid code' });
    }

    // Success - clean up
    verificationCodes.delete(normalizedEmail);

    // Clear code in Airtable and update last login
    let clientData = null;
    if (AIRTABLE_API_KEY) {
      const client = await findClientByEmail(normalizedEmail);
      if (client) {
        clientData = client.fields;
        await airtableUpdate('Clients', client.id, {
          [AIRTABLE_FIELDS.verificationCode]: '', // Clear the code
          [AIRTABLE_FIELDS.lastLogin]: new Date().toISOString()
        });
      }
    }

    // Update GHL with verified tag and clear code
    let ghlContactId = null;
    if (GHL_API_KEY) {
      const ghlContact = await ghlFindByEmail(normalizedEmail);
      if (ghlContact) {
        ghlContactId = ghlContact.id;

        // Clear verification code
        await ghlUpdateContact(ghlContactId, {
          customFields: [
            { key: GHL_CUSTOM_FIELDS.verificationCode, field_value: '' },
            { key: GHL_CUSTOM_FIELDS.lastLogin, field_value: new Date().toISOString() }
          ]
        });

        // Add verified tag
        await axios.post(
          `https://services.leadconnectorhq.com/contacts/${ghlContactId}/tags`,
          { tags: ['email-verified'] },
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
        );
      }
    }

    // Generate session token
    const token = Buffer.from(`${normalizedEmail}:${Date.now()}`).toString('base64');

    console.log(`[Auth] Email verified: ${normalizedEmail}`);

    res.json({
      success: true,
      token,
      verified: true,
      email: normalizedEmail,
      firstName: clientData?.[AIRTABLE_FIELDS.firstName] || '',
      lastName: clientData?.[AIRTABLE_FIELDS.lastName] || '',
      subscriptionStatus: clientData?.[AIRTABLE_FIELDS.subscriptionStatus] || '',
      portalAccess: clientData?.[AIRTABLE_FIELDS.portalAccess] || 'Limited',
      contactStatus: clientData?.[AIRTABLE_FIELDS.contactStatus] || 'New Lead',
      ghlContactId
    });

  } catch (err) {
    console.error('[Auth] Verify error:', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

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

    // Handle subscription events - sync to Airtable
    if (event.type === 'customer.subscription.created' ||
        event.type === 'customer.subscription.updated') {
      const subscription = event.data.object;
      const customerEmail = subscription.customer_email || event.data.object.customer_details?.email;

      if (customerEmail && AIRTABLE_API_KEY) {
        const client = await findClientByEmail(customerEmail);
        if (client) {
          const status = subscription.status === 'active' ? 'Active' :
                        subscription.status === 'past_due' ? 'Failed Payment' :
                        subscription.status === 'canceled' ? 'Canceled' : 'Active';

          await airtableUpdate('Clients', client.id, {
            [AIRTABLE_FIELDS.subscriptionStatus]: status,
            [AIRTABLE_FIELDS.portalAccess]: status === 'Active' ? 'Full Access' : 'Limited'
          });
        }
      }

      console.log('[Stripe] Subscription:', subscription.id, subscription.status);
    }

    if (event.type === 'invoice.payment_succeeded') {
      const invoice = event.data.object;
      const customerEmail = invoice.customer_email;

      if (customerEmail && AIRTABLE_API_KEY) {
        const client = await findClientByEmail(customerEmail);
        if (client) {
          await airtableUpdate('Clients', client.id, {
            [AIRTABLE_FIELDS.paymentStatus]: 'Succeeded',
            [AIRTABLE_FIELDS.paymentAmount]: invoice.amount_paid / 100,
            [AIRTABLE_FIELDS.lastPaymentDate]: new Date().toISOString().split('T')[0],
            [AIRTABLE_FIELDS.subscriptionStatus]: 'Active',
            [AIRTABLE_FIELDS.portalAccess]: 'Full Access'
          });

          // Send success email
          await sendEmailViaWebhook({
            email: customerEmail,
            template: 'payment_success',
            firstName: client.fields[AIRTABLE_FIELDS.firstName] || '',
            customData: { amount: invoice.amount_paid / 100 }
          });
        }
      }
    }

    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      const customerEmail = invoice.customer_email;

      if (customerEmail && AIRTABLE_API_KEY) {
        const client = await findClientByEmail(customerEmail);
        if (client) {
          await airtableUpdate('Clients', client.id, {
            [AIRTABLE_FIELDS.paymentStatus]: 'Failed',
            [AIRTABLE_FIELDS.subscriptionStatus]: 'Failed Payment',
            [AIRTABLE_FIELDS.portalAccess]: 'Limited'
          });

          // Send failed payment email
          await sendEmailViaWebhook({
            email: customerEmail,
            template: 'payment_failed',
            firstName: client.fields[AIRTABLE_FIELDS.firstName] || '',
            customData: {
              paymentUpdateLink: client.fields[AIRTABLE_FIELDS.paymentUpdateLink] || ''
            }
          });
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

// Get custom fields
app.get('/ghl/custom-fields', async (req, res) => {
  const result = await ghlRequest(`/locations/${GHL_LOCATION_ID}/customFields`);
  res.json(result || { error: 'failed' });
});

// ============================================
// SYNC ENDPOINTS
// ============================================

// Sync contact from GHL to Airtable
app.post('/sync/ghl-to-airtable', async (req, res) => {
  try {
    const { email, contactId } = req.body;

    if (!email && !contactId) {
      return res.status(400).json({ error: 'email or contactId required' });
    }

    // Get GHL contact
    let ghlContact = null;
    if (contactId) {
      ghlContact = await ghlRequest(`/contacts/${contactId}`);
    } else {
      ghlContact = await ghlFindByEmail(email);
    }

    if (!ghlContact) {
      return res.status(404).json({ error: 'GHL contact not found' });
    }

    const contactEmail = ghlContact.email || email;

    // Find or create Airtable record
    let airtableClient = await findClientByEmail(contactEmail);

    const airtableFields = {
      [AIRTABLE_FIELDS.email]: contactEmail,
      [AIRTABLE_FIELDS.firstName]: ghlContact.firstName || '',
      [AIRTABLE_FIELDS.lastName]: ghlContact.lastName || '',
      [AIRTABLE_FIELDS.phone]: ghlContact.phone || '',
      [AIRTABLE_FIELDS.ghlContactId]: ghlContact.id
    };

    // Map custom fields
    if (ghlContact.customFields) {
      for (const cf of ghlContact.customFields) {
        if (cf.key === GHL_CUSTOM_FIELDS.subscriptionStatus) {
          airtableFields[AIRTABLE_FIELDS.subscriptionStatus] = cf.value;
        }
        if (cf.key === GHL_CUSTOM_FIELDS.paymentAmount) {
          airtableFields[AIRTABLE_FIELDS.paymentAmount] = parseFloat(cf.value) || 0;
        }
        if (cf.key === GHL_CUSTOM_FIELDS.googleDriveFolderLink) {
          airtableFields[AIRTABLE_FIELDS.googleDriveFolderLink] = cf.value;
        }
      }
    }

    let result;
    if (airtableClient) {
      result = await airtableUpdate('Clients', airtableClient.id, airtableFields);
    } else {
      airtableFields[AIRTABLE_FIELDS.contactStatus] = 'New Lead';
      airtableFields[AIRTABLE_FIELDS.portalAccess] = 'Limited';
      result = await airtableCreate('Clients', airtableFields);
    }

    res.json({
      success: true,
      synced: true,
      airtableId: result?.id,
      ghlContactId: ghlContact.id
    });

  } catch (err) {
    console.error('[Sync GHL->Airtable]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Sync contact from Airtable to GHL
app.post('/sync/airtable-to-ghl', async (req, res) => {
  try {
    const { email, recordId } = req.body;

    if (!email && !recordId) {
      return res.status(400).json({ error: 'email or recordId required' });
    }

    // Get Airtable record
    let airtableClient = null;
    if (recordId) {
      const result = await axios.get(
        `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Clients/${recordId}`,
        { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } }
      );
      airtableClient = result.data;
    } else {
      airtableClient = await findClientByEmail(email);
    }

    if (!airtableClient) {
      return res.status(404).json({ error: 'Airtable client not found' });
    }

    const fields = airtableClient.fields;
    const contactEmail = fields[AIRTABLE_FIELDS.email];

    // Find or create GHL contact
    let ghlContact = await ghlFindByEmail(contactEmail);

    const ghlData = {
      email: contactEmail,
      firstName: fields[AIRTABLE_FIELDS.firstName] || '',
      lastName: fields[AIRTABLE_FIELDS.lastName] || '',
      phone: fields[AIRTABLE_FIELDS.phone] || '',
      customFields: []
    };

    // Map Airtable fields to GHL custom fields
    if (fields[AIRTABLE_FIELDS.subscriptionStatus]) {
      ghlData.customFields.push({
        key: GHL_CUSTOM_FIELDS.subscriptionStatus,
        field_value: fields[AIRTABLE_FIELDS.subscriptionStatus]
      });
    }
    if (fields[AIRTABLE_FIELDS.paymentAmount]) {
      ghlData.customFields.push({
        key: GHL_CUSTOM_FIELDS.paymentAmount,
        field_value: fields[AIRTABLE_FIELDS.paymentAmount].toString()
      });
    }
    if (fields[AIRTABLE_FIELDS.googleDriveFolderLink]) {
      ghlData.customFields.push({
        key: GHL_CUSTOM_FIELDS.googleDriveFolderLink,
        field_value: fields[AIRTABLE_FIELDS.googleDriveFolderLink]
      });
    }

    let result;
    if (ghlContact) {
      result = await ghlUpdateContact(ghlContact.id, ghlData);
    } else {
      ghlData.locationId = GHL_LOCATION_ID;
      ghlData.source = 'Airtable Sync';
      result = await ghlCreateContact(ghlData);
    }

    // Update Airtable with GHL ID if new
    if (!ghlContact && result?.contact?.id) {
      await airtableUpdate('Clients', airtableClient.id, {
        [AIRTABLE_FIELDS.ghlContactId]: result.contact.id
      });
    }

    res.json({
      success: true,
      synced: true,
      airtableId: airtableClient.id,
      ghlContactId: ghlContact?.id || result?.contact?.id
    });

  } catch (err) {
    console.error('[Sync Airtable->GHL]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// TRIAL & ONBOARDING ENDPOINTS
// ============================================

// Create trial contact (called after email verification + name capture)
app.post('/api/trial/create-contact', async (req, res) => {
  try {
    const { email, firstName, lastName, phone, source } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let ghlContactId = null;
    let airtableId = null;

    // 1. Create/update GHL contact
    if (GHL_API_KEY) {
      const existing = await ghlFindByEmail(normalizedEmail);

      if (existing) {
        ghlContactId = existing.id;
        await ghlUpdateContact(ghlContactId, {
          firstName: firstName || existing.firstName,
          lastName: lastName || existing.lastName,
          phone: phone || existing.phone
        });

        await axios.post(
          `https://services.leadconnectorhq.com/contacts/${ghlContactId}/tags`,
          { tags: ['trial-started', 'portal-onboarding'] },
          { headers: { Authorization: `Bearer ${GHL_API_KEY}`, Version: '2021-07-28', 'Content-Type': 'application/json' } }
        );
      } else {
        const newContact = await ghlCreateContact({
          email: normalizedEmail,
          firstName: firstName || '',
          lastName: lastName || '',
          phone: phone || '',
          source: source || 'Free Trial',
          tags: ['trial-started', 'portal-onboarding']
        });
        ghlContactId = newContact?.contact?.id;
      }
    }

    // 2. Create/update Airtable client
    if (AIRTABLE_API_KEY) {
      const existing = await findClientByEmail(normalizedEmail);

      if (existing) {
        airtableId = existing.id;
        await airtableUpdate('Clients', airtableId, {
          [AIRTABLE_FIELDS.firstName]: firstName || existing.fields[AIRTABLE_FIELDS.firstName],
          [AIRTABLE_FIELDS.lastName]: lastName || existing.fields[AIRTABLE_FIELDS.lastName],
          [AIRTABLE_FIELDS.phone]: phone || existing.fields[AIRTABLE_FIELDS.phone],
          [AIRTABLE_FIELDS.freeTrialStatus]: 'Account Created',
          [AIRTABLE_FIELDS.ghlContactId]: ghlContactId || existing.fields[AIRTABLE_FIELDS.ghlContactId]
        });
      } else {
        const newClient = await airtableCreate('Clients', {
          [AIRTABLE_FIELDS.email]: normalizedEmail,
          [AIRTABLE_FIELDS.firstName]: firstName || '',
          [AIRTABLE_FIELDS.lastName]: lastName || '',
          [AIRTABLE_FIELDS.phone]: phone || '',
          [AIRTABLE_FIELDS.contactStatus]: 'Trial - Active',
          [AIRTABLE_FIELDS.freeTrialStatus]: 'Account Created',
          [AIRTABLE_FIELDS.portalAccess]: 'Limited',
          [AIRTABLE_FIELDS.ghlContactId]: ghlContactId || ''
        });
        airtableId = newClient?.id;
      }
    }

    // 3. Send welcome email
    await sendEmailViaWebhook({
      email: normalizedEmail,
      template: 'welcome_trial',
      firstName: firstName || '',
      contactId: ghlContactId
    });

    res.json({
      success: true,
      ghlContactId,
      airtableId,
      email: normalizedEmail
    });

  } catch (err) {
    console.error('[Trial Create]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update onboarding status
app.post('/api/trial/update-status', async (req, res) => {
  try {
    const { email, status } = req.body;
    if (!email || !status) {
      return res.status(400).json({ error: 'email and status required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Update Airtable
    if (AIRTABLE_API_KEY) {
      const client = await findClientByEmail(normalizedEmail);
      if (client) {
        await airtableUpdate('Clients', client.id, {
          [AIRTABLE_FIELDS.freeTrialStatus]: status
        });
      }
    }

    res.json({ success: true, status });

  } catch (err) {
    console.error('[Trial Status Update]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// CLIENT PROFILE ENDPOINTS
// ============================================

// Get client profile
app.get('/api/client/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();

    const client = await findClientByEmail(email);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const fields = client.fields;

    res.json({
      success: true,
      id: client.id,
      email: fields[AIRTABLE_FIELDS.email],
      firstName: fields[AIRTABLE_FIELDS.firstName] || '',
      lastName: fields[AIRTABLE_FIELDS.lastName] || '',
      phone: fields[AIRTABLE_FIELDS.phone] || '',
      contactStatus: fields[AIRTABLE_FIELDS.contactStatus] || '',
      freeTrialStatus: fields[AIRTABLE_FIELDS.freeTrialStatus] || '',
      portalAccess: fields[AIRTABLE_FIELDS.portalAccess] || 'Limited',
      subscriptionStatus: fields[AIRTABLE_FIELDS.subscriptionStatus] || '',
      subscriptionName: fields[AIRTABLE_FIELDS.subscriptionName] || '',
      ghlContactId: fields[AIRTABLE_FIELDS.ghlContactId] || ''
    });

  } catch (err) {
    console.error('[Client Profile]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update client profile
app.post('/api/client/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    const updates = req.body;

    const client = await findClientByEmail(email);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Map request fields to Airtable fields
    const airtableUpdates = {};
    if (updates.firstName) airtableUpdates[AIRTABLE_FIELDS.firstName] = updates.firstName;
    if (updates.lastName) airtableUpdates[AIRTABLE_FIELDS.lastName] = updates.lastName;
    if (updates.phone) airtableUpdates[AIRTABLE_FIELDS.phone] = updates.phone;

    const result = await airtableUpdate('Clients', client.id, airtableUpdates);

    res.json({ success: true, updated: result });

  } catch (err) {
    console.error('[Client Update]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`ContentBug MCP Server v3.1 running on port ${PORT}`);
  console.log('Services:', {
    airtable: !!AIRTABLE_API_KEY,
    ghl: !!GHL_API_KEY,
    drive: driveReady
  });
});
