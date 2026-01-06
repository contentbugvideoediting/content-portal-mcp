// ============================================
// CONTENTBUG FINANCIAL API - Plaid + Wise Integration
// Add this to your cbv2_server_minimal.js or require as module
// Routes: /api/finance/*
// Deployed to: portalv2.contentbug.io
// ============================================

const express = require('express');
const axios = require('axios');
const router = express.Router();

// ============================================
// PLAID CONFIGURATION
// ============================================
const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID || ''; // Get from Plaid Dashboard
const PLAID_SECRET = process.env.PLAID_SECRET || '7RR54OCNJ3B62YVKWOVE3KD5LI'; // Production
const PLAID_SECRET_SANDBOX = process.env.PLAID_SECRET_SANDBOX || '722cb643e4b941b8f6bbcd9bbe3dda';
const PLAID_ENV = process.env.PLAID_ENV || 'sandbox'; // 'sandbox' or 'production'

const PLAID_BASE_URL = PLAID_ENV === 'production' 
  ? 'https://production.plaid.com'
  : 'https://sandbox.plaid.com';

const getPlaidSecret = () => PLAID_ENV === 'production' ? PLAID_SECRET : PLAID_SECRET_SANDBOX;

// ============================================
// WISE CONFIGURATION  
// ============================================
const WISE_API_TOKEN = process.env.WISE_API_TOKEN || '23edfb11-a74f-4f5e-b524-a4cb37757a3d';
const WISE_ENV = process.env.WISE_ENV || 'production';
const WISE_BASE_URL = WISE_ENV === 'production'
  ? 'https://api.transferwise.com'
  : 'https://api.sandbox.transferwise.tech';

// ContentBug Wise Profile IDs (from API)
const WISE_PROFILES = {
  personal: 42607363,
  business: 42607341 // Content Bug Video Editing
};

// ============================================
// STRIPE (already configured in main server)
// ============================================
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// ============================================
// IN-MEMORY STORAGE (Use Redis/DB in production)
// ============================================
const linkedAccounts = new Map(); // userId -> { accessToken, itemId, accounts }
const transactions = new Map();   // userId -> transactions[]

// ============================================
// PLAID ROUTES
// ============================================

/**
 * POST /api/finance/plaid/create-link-token
 * Creates a Plaid Link token for frontend initialization
 */
router.post('/plaid/create-link-token', async (req, res) => {
  try {
    const { userId = 'contentbug-admin', clientUserId } = req.body;
    
    const response = await axios.post(`${PLAID_BASE_URL}/link/token/create`, {
      client_id: PLAID_CLIENT_ID,
      secret: getPlaidSecret(),
      client_name: 'ContentBug',
      user: {
        client_user_id: clientUserId || userId
      },
      products: ['transactions', 'auth'],
      country_codes: ['US'],
      language: 'en',
      // Optional: Webhook for transaction updates
      // webhook: 'https://portalv2.contentbug.io/api/finance/plaid/webhook'
    });

    console.log('[Plaid] Link token created for:', userId);
    
    res.json({
      success: true,
      link_token: response.data.link_token,
      expiration: response.data.expiration
    });
  } catch (error) {
    console.error('[Plaid] Create link token error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: error.response?.data?.error_message || 'Failed to create link token'
    });
  }
});

/**
 * POST /api/finance/plaid/exchange-token
 * Exchanges public_token for access_token after user links account
 */
router.post('/plaid/exchange-token', async (req, res) => {
  try {
    const { public_token, metadata, userId = 'contentbug-admin' } = req.body;

    if (!public_token) {
      return res.status(400).json({ success: false, error: 'Missing public_token' });
    }

    // Exchange for access token
    const exchangeResponse = await axios.post(`${PLAID_BASE_URL}/item/public_token/exchange`, {
      client_id: PLAID_CLIENT_ID,
      secret: getPlaidSecret(),
      public_token
    });

    const { access_token, item_id } = exchangeResponse.data;

    // Get account details
    const accountsResponse = await axios.post(`${PLAID_BASE_URL}/accounts/get`, {
      client_id: PLAID_CLIENT_ID,
      secret: getPlaidSecret(),
      access_token
    });

    // Store linked account
    const accountData = {
      accessToken: access_token,
      itemId: item_id,
      institution: metadata?.institution,
      accounts: accountsResponse.data.accounts,
      linkedAt: new Date().toISOString()
    };

    // Get existing accounts for user or create new array
    const userAccounts = linkedAccounts.get(userId) || [];
    userAccounts.push(accountData);
    linkedAccounts.set(userId, userAccounts);

    console.log('[Plaid] Account linked:', metadata?.institution?.name, '- Accounts:', accountsResponse.data.accounts.length);

    res.json({
      success: true,
      item_id,
      accounts: accountsResponse.data.accounts.map(acc => ({
        id: acc.account_id,
        name: acc.name,
        type: acc.type,
        subtype: acc.subtype,
        mask: acc.mask,
        balances: acc.balances
      }))
    });
  } catch (error) {
    console.error('[Plaid] Exchange token error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: error.response?.data?.error_message || 'Failed to exchange token'
    });
  }
});

/**
 * POST /api/finance/plaid/get-accounts
 * Get all linked accounts for a user
 */
router.post('/plaid/get-accounts', async (req, res) => {
  try {
    const { userId = 'contentbug-admin' } = req.body;
    const userAccounts = linkedAccounts.get(userId) || [];

    if (userAccounts.length === 0) {
      return res.json({ success: true, accounts: [] });
    }

    // Fetch fresh account data for each linked item
    const allAccounts = [];
    
    for (const linked of userAccounts) {
      try {
        const response = await axios.post(`${PLAID_BASE_URL}/accounts/get`, {
          client_id: PLAID_CLIENT_ID,
          secret: getPlaidSecret(),
          access_token: linked.accessToken
        });

        for (const acc of response.data.accounts) {
          allAccounts.push({
            id: acc.account_id,
            itemId: linked.itemId,
            institution: linked.institution?.name || 'Unknown Bank',
            name: acc.name,
            officialName: acc.official_name,
            type: acc.type,
            subtype: acc.subtype,
            mask: acc.mask,
            balances: {
              current: acc.balances.current,
              available: acc.balances.available,
              limit: acc.balances.limit,
              currency: acc.balances.iso_currency_code
            }
          });
        }
      } catch (err) {
        console.error('[Plaid] Error fetching accounts for item:', linked.itemId);
      }
    }

    res.json({ success: true, accounts: allAccounts });
  } catch (error) {
    console.error('[Plaid] Get accounts error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get accounts' });
  }
});

/**
 * POST /api/finance/plaid/get-transactions
 * Get transactions for a specific account or all accounts
 */
router.post('/plaid/get-transactions', async (req, res) => {
  try {
    const { 
      userId = 'contentbug-admin',
      startDate,
      endDate,
      accountId 
    } = req.body;

    const userAccounts = linkedAccounts.get(userId) || [];
    
    if (userAccounts.length === 0) {
      return res.json({ success: true, transactions: [] });
    }

    // Default to last 30 days
    const end = endDate || new Date().toISOString().split('T')[0];
    const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const allTransactions = [];

    for (const linked of userAccounts) {
      try {
        const response = await axios.post(`${PLAID_BASE_URL}/transactions/get`, {
          client_id: PLAID_CLIENT_ID,
          secret: getPlaidSecret(),
          access_token: linked.accessToken,
          start_date: start,
          end_date: end,
          options: {
            count: 500,
            offset: 0
          }
        });

        for (const tx of response.data.transactions) {
          // Filter by account if specified
          if (accountId && tx.account_id !== accountId) continue;

          allTransactions.push({
            id: tx.transaction_id,
            accountId: tx.account_id,
            institution: linked.institution?.name,
            name: tx.name,
            merchantName: tx.merchant_name,
            amount: tx.amount,
            date: tx.date,
            category: tx.category,
            primaryCategory: tx.personal_finance_category?.primary,
            pending: tx.pending,
            paymentChannel: tx.payment_channel,
            logo: tx.logo_url,
            // Categorize for dashboard
            type: tx.amount < 0 ? 'income' : 'expense'
          });
        }
      } catch (err) {
        console.error('[Plaid] Error fetching transactions:', err.response?.data?.error_message || err.message);
      }
    }

    // Sort by date descending
    allTransactions.sort((a, b) => new Date(b.date) - new Date(a.date));

    // Cache transactions
    transactions.set(userId, allTransactions);

    res.json({ 
      success: true, 
      transactions: allTransactions,
      count: allTransactions.length,
      dateRange: { start, end }
    });
  } catch (error) {
    console.error('[Plaid] Get transactions error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get transactions' });
  }
});

/**
 * POST /api/finance/plaid/get-balance
 * Get real-time balance for all accounts
 */
router.post('/plaid/get-balance', async (req, res) => {
  try {
    const { userId = 'contentbug-admin' } = req.body;
    const userAccounts = linkedAccounts.get(userId) || [];

    if (userAccounts.length === 0) {
      return res.json({ success: true, balances: [] });
    }

    const balances = [];

    for (const linked of userAccounts) {
      try {
        const response = await axios.post(`${PLAID_BASE_URL}/accounts/balance/get`, {
          client_id: PLAID_CLIENT_ID,
          secret: getPlaidSecret(),
          access_token: linked.accessToken
        });

        for (const acc of response.data.accounts) {
          balances.push({
            accountId: acc.account_id,
            institution: linked.institution?.name,
            name: acc.name,
            type: acc.type,
            current: acc.balances.current,
            available: acc.balances.available,
            limit: acc.balances.limit,
            currency: acc.balances.iso_currency_code || 'USD'
          });
        }
      } catch (err) {
        console.error('[Plaid] Balance fetch error:', err.message);
      }
    }

    // Calculate totals
    const totals = {
      totalCurrent: balances.reduce((sum, b) => sum + (b.current || 0), 0),
      totalAvailable: balances.reduce((sum, b) => sum + (b.available || 0), 0),
      byType: {}
    };

    balances.forEach(b => {
      if (!totals.byType[b.type]) totals.byType[b.type] = 0;
      totals.byType[b.type] += b.current || 0;
    });

    res.json({ success: true, balances, totals });
  } catch (error) {
    console.error('[Plaid] Get balance error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get balance' });
  }
});

/**
 * POST /api/finance/plaid/webhook
 * Handle Plaid webhooks for transaction updates
 */
router.post('/plaid/webhook', async (req, res) => {
  try {
    const { webhook_type, webhook_code, item_id } = req.body;
    
    console.log('[Plaid Webhook]', webhook_type, webhook_code, item_id);

    if (webhook_type === 'TRANSACTIONS') {
      if (webhook_code === 'DEFAULT_UPDATE' || webhook_code === 'HISTORICAL_UPDATE') {
        // New transactions available - could trigger a sync here
        console.log('[Plaid] New transactions available for item:', item_id);
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('[Plaid Webhook Error]', error.message);
    res.status(500).json({ success: false });
  }
});

// ============================================
// WISE ROUTES
// ============================================

/**
 * GET /api/finance/wise/profiles
 * Get Wise profiles (personal & business)
 */
router.get('/wise/profiles', async (req, res) => {
  try {
    const response = await axios.get(`${WISE_BASE_URL}/v1/profiles`, {
      headers: { Authorization: `Bearer ${WISE_API_TOKEN}` }
    });

    res.json({ 
      success: true, 
      profiles: response.data 
    });
  } catch (error) {
    console.error('[Wise] Get profiles error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: error.response?.data?.message || 'Failed to get Wise profiles' 
    });
  }
});

/**
 * GET /api/finance/wise/balances/:profileId
 * Get multi-currency balances for a profile
 */
router.get('/wise/balances/:profileId', async (req, res) => {
  try {
    const { profileId } = req.params;

    const response = await axios.get(
      `${WISE_BASE_URL}/v4/profiles/${profileId}/balances?types=STANDARD`,
      { headers: { Authorization: `Bearer ${WISE_API_TOKEN}` } }
    );

    // Format balances
    const balances = response.data.map(b => ({
      id: b.id,
      currency: b.currency,
      amount: b.amount.value,
      type: b.type,
      primary: b.primary
    }));

    // Calculate total in USD
    const usdBalance = balances.find(b => b.currency === 'USD');
    const totalUSD = usdBalance ? usdBalance.amount : 0;

    res.json({ 
      success: true, 
      balances,
      totalUSD
    });
  } catch (error) {
    console.error('[Wise] Get balances error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get Wise balances' 
    });
  }
});

/**
 * GET /api/finance/wise/statement/:profileId/:balanceId
 * Get account statement/transactions
 */
router.get('/wise/statement/:profileId/:balanceId', async (req, res) => {
  try {
    const { profileId, balanceId } = req.params;
    const { startDate, endDate } = req.query;

    if (!WISE_API_TOKEN) {
      return res.status(400).json({ success: false, error: 'Wise API token not configured' });
    }

    const end = endDate || new Date().toISOString();
    const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const response = await axios.get(
      `${WISE_BASE_URL}/v1/profiles/${profileId}/balance-statements/${balanceId}/statement.json`,
      {
        params: {
          intervalStart: start,
          intervalEnd: end,
          type: 'COMPACT'
        },
        headers: { Authorization: `Bearer ${WISE_API_TOKEN}` }
      }
    );

    res.json({
      success: true,
      statement: response.data
    });
  } catch (error) {
    console.error('[Wise] Get statement error:', error.response?.data || error.message);
    res.status(500).json({ success: false, error: 'Failed to get statement' });
  }
});

/**
 * GET /api/finance/wise/exchange-rate
 * Get current exchange rate
 */
router.get('/wise/exchange-rate', async (req, res) => {
  try {
    const { source = 'USD', target = 'EUR' } = req.query;

    // This endpoint is public - no auth needed
    const response = await axios.get(
      `${WISE_BASE_URL}/v1/rates?source=${source}&target=${target}`
    );

    res.json({
      success: true,
      rate: response.data[0]
    });
  } catch (error) {
    console.error('[Wise] Get rate error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get exchange rate' });
  }
});

// ============================================
// AGGREGATED FINANCIAL DATA
// ============================================

/**
 * GET /api/finance/summary
 * Get complete financial summary across all sources
 */
router.get('/summary', async (req, res) => {
  try {
    const userId = req.query.userId || 'contentbug-admin';
    const summary = {
      plaid: { accounts: [], totalBalance: 0 },
      wise: { balances: [] },
      stripe: { revenue: 0, refunds: 0 },
      totals: {
        revenue: 0,
        expenses: 0,
        refunds: 0,
        netBalance: 0
      },
      lastUpdated: new Date().toISOString()
    };

    // Get Plaid data
    const userAccounts = linkedAccounts.get(userId) || [];
    for (const linked of userAccounts) {
      try {
        const response = await axios.post(`${PLAID_BASE_URL}/accounts/balance/get`, {
          client_id: PLAID_CLIENT_ID,
          secret: getPlaidSecret(),
          access_token: linked.accessToken
        });
        
        for (const acc of response.data.accounts) {
          summary.plaid.accounts.push({
            name: acc.name,
            institution: linked.institution?.name,
            balance: acc.balances.current,
            type: acc.type
          });
          summary.plaid.totalBalance += acc.balances.current || 0;
        }
      } catch (err) {
        console.error('[Summary] Plaid error:', err.message);
      }
    }

    // Get cached transactions for totals
    const userTransactions = transactions.get(userId) || [];
    userTransactions.forEach(tx => {
      if (tx.amount < 0) {
        summary.totals.revenue += Math.abs(tx.amount);
      } else {
        summary.totals.expenses += tx.amount;
      }
    });

    summary.totals.netBalance = summary.totals.revenue - summary.totals.expenses - summary.totals.refunds;

    res.json({ success: true, summary });
  } catch (error) {
    console.error('[Summary] Error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get financial summary' });
  }
});

/**
 * GET /api/finance/health
 * Check financial API connections
 */
router.get('/health', async (req, res) => {
  const status = {
    plaid: {
      configured: !!PLAID_CLIENT_ID,
      environment: PLAID_ENV,
      url: PLAID_BASE_URL
    },
    wise: {
      configured: !!WISE_API_TOKEN,
      environment: WISE_ENV,
      url: WISE_BASE_URL
    },
    stripe: {
      configured: !!STRIPE_SECRET_KEY
    },
    linkedAccountsCount: linkedAccounts.size,
    timestamp: new Date().toISOString()
  };

  res.json({ success: true, status });
});

// ============================================
// EXPORT ROUTER
// ============================================
module.exports = router;

// ============================================
// USAGE: Add to main server file
// ============================================
/*
const financeRoutes = require('./finance-routes');
app.use('/api/finance', financeRoutes);

Required ENV variables in Railway:
- PLAID_CLIENT_ID
- PLAID_SECRET (production)
- PLAID_SECRET_SANDBOX
- PLAID_ENV (sandbox or production)
- WISE_API_TOKEN
- WISE_ENV
- STRIPE_SECRET_KEY (already configured)
*/
