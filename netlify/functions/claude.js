// netlify/functions/accounts.js
// Server-side account management using Netlify Blobs
const { getStore } = require('@netlify/blobs');

const ADMIN_SECRET = process.env.WTS_ADMIN_SECRET || 'wts-admin-2024';
const STORE_KEY = 'wts_accounts';

const headers = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Secret',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  const store = getStore('wts');
  const action = event.queryStringParameters && event.queryStringParameters.action;

  // ── GET accounts (login check — public) ──
  if (event.httpMethod === 'GET' && action === 'list') {
    try {
      const raw = await store.get(STORE_KEY);
      const accounts = raw ? JSON.parse(raw) : [];
      // Return accounts without passwords for login check
      return { statusCode: 200, headers, body: JSON.stringify(accounts) };
    } catch(e) {
      return { statusCode: 200, headers, body: JSON.stringify([]) };
    }
  }

  // ── POST actions ──
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body); } catch(e) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
    }

    // LOGIN — check credentials, return account if valid
    if (action === 'login') {
      try {
        const raw = await store.get(STORE_KEY);
        const accounts = raw ? JSON.parse(raw) : [];
        const acc = accounts.find(a => a.email === body.email && a.pwd === body.pwd && a.active);
        if (!acc) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Identifiants incorrects.' }) };

        // Update device token on first login from this device
        if (!acc.deviceToken && body.deviceToken) {
          acc.deviceToken = body.deviceToken;
          acc.lastLogin = new Date().toISOString();
          acc.loginCount = (acc.loginCount || 0) + 1;
          await store.set(STORE_KEY, JSON.stringify(accounts));
        } else if (acc.deviceToken && acc.deviceToken !== body.deviceToken) {
          return { statusCode: 403, headers, body: JSON.stringify({ error: 'Appareil non autorisé. Contacte WTS.' }) };
        } else {
          acc.lastLogin = new Date().toISOString();
          acc.loginCount = (acc.loginCount || 0) + 1;
          await store.set(STORE_KEY, JSON.stringify(accounts));
        }

        return { statusCode: 200, headers, body: JSON.stringify({ ok: true, firstname: acc.firstname, lastname: acc.lastname, email: acc.email }) };
      } catch(e) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
      }
    }

    // All actions below require admin secret
    if (body.secret !== ADMIN_SECRET) {
      return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès refusé.' }) };
    }

    // SAVE — replace all accounts
    if (action === 'save') {
      try {
        await store.set(STORE_KEY, JSON.stringify(body.accounts || []));
        return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
      } catch(e) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
      }
    }

    // RESET DEVICE — clear device token for one account
    if (action === 'reset_device') {
      try {
        const raw = await store.get(STORE_KEY);
        const accounts = raw ? JSON.parse(raw) : [];
        const acc = accounts.find(a => a.id === body.accountId);
        if (acc) { acc.deviceToken = null; }
        await store.set(STORE_KEY, JSON.stringify(accounts));
        return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
      } catch(e) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
      }
    }
  }

  return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found' }) };
};
