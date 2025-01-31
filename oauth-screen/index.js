const express = require('express');
const OAuth2Server = require('oauth2-server');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

// view engine
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'chromium-secret',
  resave: false,
  saveUninitialized: true
}));

const oauth = new OAuth2Server({
  model: {
    getClient: (clientId, clientSecret) => ({
      clientId: 'chromium-client',
      clientSecret: 'client-secret',
      grants: ['authorization_code', 'refresh_token'],
      redirectUris: [
        'chrome://chrome-signin',
        'https://6ce8-2409-40e4-131e-b94b-22d2-ccf3-1e4d-1eb7.ngrok-free.app/callback'
      ]
    }),

    saveAuthorizationCode: (code, client, user) => ({
      authorizationCode: 'mock-auth-code-12345', // Mock auth code
      expiresAt: new Date(Date.now() + 300000), // 5 minutes
      user,
      client
    }),

    getAuthorizationCode: (code) => ({
      code: code,
      expiresAt: new Date(Date.now() + 300000),
      user: { id: 1, email: 'testuser@gmail.com' },
      client: { id: 'chromium-client' }
    }),

    revokeAuthorizationCode: (code) => true,

    saveToken: (token, client, user) => ({
      accessToken: 'mock-access-token-67890', // Mock access token
      accessTokenExpiresAt: new Date(Date.now() + 3600000), // 1 hour
      refreshToken: 'mock-refresh-token-abcde', // Mock refresh token
      refreshTokenExpiresAt: new Date(Date.now() + 86400000), // 24 hours
      client,
      user
    })
  }
});

// authentication middleware
const chromiumAuth = (req, res, next) => {
  res.set({
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "script-src 'self'",
    'Set-Cookie': `Host-GAPS=1:${crypto.randomBytes(16).toString('hex')}; Secure; HttpOnly`
  });
  next();
};

// chromium entry point
app.get('/o/oauth2/v2/auth', chromiumAuth, async (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  try {
    const options = {
      authenticateHandler: {
        handle: (req) => ({ id: 1, email: req.session.email })
      }
    };

    const code = await oauth.authorize(new OAuth2Server.Request(req), options);
    
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code.authorizationCode);
    if (state) redirectUrl.searchParams.set('state', state);

    res.redirect(redirectUrl.toString());
  } catch (error) {
    res.render('login', {
      client_id,
      redirect_uri,
      state,
      error: 'Authentication required'
    });
  }
});

// login page
app.get('/login', chromiumAuth, (req, res) => {
  res.render('login', {
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    state: req.query.state,
    error: null
  });
});

// login handler
app.post('/login', async (req, res) => {
  const { email, password, client_id, redirect_uri, state } = req.body;

  // mock validation
  if (email === 'testuser@gmail.com' && password === 'testpassword123') {
    req.session.email = email;
    res.redirect(`/o/oauth2/v2/auth?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&response_type=code`);
  } else {
    res.render('login', {
      client_id,
      redirect_uri,
      state,
      error: 'Invalid credentials'
    });
  }
});

// chromium token exchange
app.post('/oauth2/v4/token', async (req, res) => {
  const request = new OAuth2Server.Request(req);
  const response = new OAuth2Server.Response(res);

  try {
    const token = await oauth.token(request, response);
    res.json({
      access_token: token.accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: token.refreshToken,
      id_token: 'mock-id-token'
    });
  } catch (error) {
    res.status(error.code).json(error);
  }
});

app.get('/oauth2/v1/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  res.json({
    id: '12345',
    email: 'testuser@gmail.com',
    verified_email: true,
    name: 'Chromium User'
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Chromium OAuth server running on http://localhost:${PORT}`);
});