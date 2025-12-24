// server.js
// MCP middleware to connect Make, Claude (Anthropic), OpenAI (optional), Airtable and forward to GHL/Zapier.
// Store secrets in environment variables or your host's secret manager (do NOT commit them).
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const CLAUDE_API_URL = process.env.CLAUDE_API_URL || 'https://api.anthropic.com/v1/complete';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;
const AIRTABLE_TABLE = process.env.AIRTABLE_TABLE || 'Conversations';
const GHL_WEBHOOK_URL = process.env.GHL_WEBHOOK_URL; // optional: outgoing notification
const MAKE_SHARED_SECRET = process.env.MAKE_SHARED_SECRET || '';
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET || '';
const HMAC_HEADER = process.env.HMAC_HEADER || 'x-mcp-signature';
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS || '800', 10);

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

app.get('/healthz', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Basic shared-secret or HMAC verification middleware
function verifySecret(headerName, expectedSecret) {
  return (req, res, next) => {
    if (!expectedSecret) return next();
    const incoming = req.get(headerName) || req.get(headerName.toLowerCase());
    if (!incoming) return res.status(401).json({ error: 'missing signature header' });
    // If incoming equals the secret, accept (simple token)
    if (incoming === expectedSecret) return next();
    // If incoming is hmac format algo=hex
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

async function saveToAirtable(fields) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return null;
  try {
    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(AIRTABLE_TABLE)}`;
    const res = await axios.post(url, { fields }, {
      headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}`, 'Content-Type': 'application/json' }
    });
    return res.data;
  } catch (err) {
    console.warn('Airtable save error:', err?.response?.data || err.message);
    return null;
  }
}

async function callClaude(prompt, opts = {}) {
  if (!CLAUDE_API_KEY) throw new Error('No CLAUDE_API_KEY configured');
  const payload = {
    model: opts.model || (process.env.CLAUDE_MODEL || 'claude-2'),
    prompt,
    max_tokens_to_sample: opts.max_tokens || MAX_TOKENS,
    temperature: typeof opts.temperature === 'number' ? opts.temperature : 0.2
  };
  const res = await axios.post(CLAUDE_API_URL, payload, {
    headers: { Authorization: `Bearer ${CLAUDE_API_KEY}`, 'Content-Type': 'application/json' }
  });
  const raw = res.data;
  let text = '';
  if (raw?.completion) text = raw.completion;
  else if (raw?.output) text = raw.output;
  else if (Array.isArray(raw.choices) && raw.choices[0]) text = raw.choices[0].text || raw.choices[0].message || '';
  else text = JSON.stringify(raw);
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

// Main endpoint for Make -> MCP
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
      const prompt = `Human: ${input}\n\nAssistant:`;
      aiResult = await callClaude(prompt, { model: body.model, max_tokens: body.max_tokens, temperature: body.temperature });
    }

    // Save to Airtable (best-effort)
    await saveToAirtable({
      ConversationID: convoId,
      Source: body.source || 'make',
      Input: input,
      Response: aiResult.text,
      Provider: provider,
      Raw: JSON.stringify(aiResult.raw).slice(0, 30000)
    });

    // Optionally forward to GHL/Zapier
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

// GHL specific endpoint (normalize and forward internally)
app.post('/webhook/ghl', verifySecret('x-ghl-secret', GHL_SHARED_SECRET), async (req, res, next) => {
  const payload = req.body || {};
  const normalized = {
    input: payload?.message || payload?.text || payload?.lead_message,
    provider: payload?.provider || 'claude',
    conversation_id: payload?.conversation_id
  };
  // Reuse /webhook handler by calling its logic directly
  req.body = normalized;
  return app._router.handle(req, res, next);
});

app.get('/conversation/:id', async (req, res) => {
  const id = req.params.id;
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return res.status(501).json({ error: 'persistence not configured' });
  try {
    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(AIRTABLE_TABLE)}?filterByFormula={ConversationID}='${id}'&maxRecords=1`;
    const r = await axios.get(url, { headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` } });
    return res.json(r.data);
  } catch (err) {
    return res.status(500).json({ error: 'airtable_error', details: err?.response?.data || err.message });
  }
});

app.listen(PORT, () => {
  console.log(`MCP server listening on ${PORT}`);
});