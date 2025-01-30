const express = require('express');
const oauthServer = require('oauth2-server');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();

const URI_SERVER = "http://localhost:3000" | "https://d737-2409-40e4-104c-4945-3dc3-85c9-d095-83da.ngrok-free.app";

// adding body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', JSON.stringify(req.body, null, 2));
  }
  
  if (req.query && Object.keys(req.query).length > 0) {
    console.log('Query Params:', JSON.stringify(req.query, null, 2));
  }
  
  next();
});

// In memory storage
const clients = [
  {
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUris: ['http://localhost:3000/cb'],
    grants: ['authorization_code', 'password', 'refresh_token']
  }
];
const tokens = {};
const authorizationCodes = {};

// OAuth server configuration
const oauth = new oauthServer({
  model: require('./model'),
  grants: ['authorization_code', 'password', 'refresh_token'],
  debug: true
});

app.get('/test', (req, res) => {
  res.json({ message: 'OAuth server is running' });
});

// auth endpoint
app.get('/signin/chrome/0/o/oauth2/v2/auth', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;
  
  const client = clients.find(c => c.clientId === client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }
  
  const authorizationCode = crypto.randomBytes(16).toString('hex');
  authorizationCodes[authorizationCode] = {
    code: authorizationCode,
    // 10 minute expiry
    expiresAt: new Date(Date.now() + 600000),
    client,
    scope,
    state,
    // in practice this would be the authenticated user
    user: { id: 1 }
  };
  
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', authorizationCode);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }
  
  res.redirect(redirectUrl.toString());
});

// token endpoint
app.post('/oauth2/v4/token', async (req, res) => {
  try {
    const request = new oauthServer.Request(req);
    const response = new oauthServer.Response(res);
    
    const token = await oauth.token(request, response);
    
    tokens[token.accessToken] = {
      ...token,
      expiresAt: new Date(Date.now() + token.accessTokenExpiresAt)
    };
    
    res.json({
      access_token: token.accessToken,
      token_type: 'Bearer',
      expires_in: Math.floor((token.accessTokenExpiresAt - Date.now()) / 1000),
      refresh_token: token.refreshToken,
      scope: token.scope
    });
  } catch (err) {
    res.status(err.code || 500).json({
      error: err.name,
      error_description: err.message
    });
  }
});

// token info endpoint
app.get('/oauth2/v2/tokeninfo', (req, res) => {
  const accessToken = req.query.access_token;
  const token = tokens[accessToken];
  
  if (!token || token.expiresAt < new Date()) {
    return res.status(400).json({ error: 'invalid_token' });
  }
  
  res.json({
    azp: token.client.clientId,
    aud: token.client.clientId,
    scope: token.scope,
    exp: Math.floor(token.expiresAt.getTime() / 1000),
    expires_in: Math.floor((token.expiresAt - new Date()) / 1000)
  });
});

// reverse engineered sync req and response
app.get('/signin/chrome/sync', (req, res) => {
  res.set({
    'Content-Type': 'text/html; charset=UTF-8',
    'Set-Cookie': 'Host-GAPS=1:DcCQElkewD1WSNm4CWy2tidWlu35mA:DoYw4UXBxkS_i93a; Path=/; Expires=Sat, 30-Jan-2027 16:54:13 GMT; Secure; HttpOnly; Priority=HIGH',
    'X-Frame-Options': 'DENY',
    'Vary': 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site',
    'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': 'Mon, 01 Jan 1990 00:00:00 GMT',
    'Date': new Date().toUTCString(),
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "script-src 'report-sample' 'nonce-x_iEXrXGvVgbrP9bVZBbfg' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; report-uri /cspreport",
    'Cross-Origin-Opener-Policy-Report-Only': 'same-origin; report-to="coop_gse_qebhlk"',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Content-Length': '463',
    'Server': 'GSE',
    'Alt-Svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'
  });

  const redirectUrl = `${URI_SERVER}/o/oauth2/v2/auth?client_id=my-client-id&redirect_uri=${URI_SERVER}/cb&response_type=code&scope=email&state=${req.query.state || ''}`;

  res.redirect(redirectUrl);
});

// issue token endpoint
app.post('/v1/issuetoken', async (req, res) => {
  try {
    const { client_id, client_secret, scope } = req.body;
    
    const client = clients.find(
      c => c.clientId === client_id && c.clientSecret === client_secret
    );
    
    if (!client) {
      return res.status(401).json({ error: 'invalid_client' });
    }
    
    const accessToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour
    
    tokens[accessToken] = {
      accessToken,
      client,
      scope,
      expiresAt
    };
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error' });
  }
});

// revoke token endpoint
app.post('/o/oauth2/revoke', (req, res) => {
  const { token } = req.body;
  
  if (tokens[token]) {
    delete tokens[token];
    res.status(200).end();
  } else {
    res.status(400).json({ error: 'invalid_token' });
  }
});

// user info endpoint
app.get('/oauth2/v1/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  const accessToken = authHeader.split(' ')[1];
  const token = tokens[accessToken];
  
  if (!token || token.expiresAt < new Date()) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  res.json({
    id: '12345',
    email: 'user@example.com',
    verified_email: true,
    name: 'Test User',
    given_name: 'Test',
    family_name: 'User',
    picture: 'https://example.com/photo.jpg'
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`OAuth2 server running on port ${PORT}`);
});