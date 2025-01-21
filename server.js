const express = require('express');
const oauthServer = require('oauth2-server');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();

//logging requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (Object.keys(req.body).length) {
    console.log('Body:', JSON.stringify(req.body, null, 2));
  }
  if (Object.keys(req.query).length) {
    console.log('Query Params:', JSON.stringify(req.query, null, 2));
  }
  next();
});

// In-memory storage for clients, tokens, and authorization codes
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

const oauth = new oauthServer({
  model: require('./model'),
  grants: ['authorization_code', 'password', 'refresh_token'],
  debug: true
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;

  const client = clients.find(c => c.clientId === client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid client or redirect URI' });
  }

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'Unsupported response type' });
  }

  const authorizationCode = crypto.randomBytes(16).toString('hex');

  authorizationCodes[authorizationCode] = {
    code: authorizationCode,
    expiresAt: new Date(Date.now() + 3600000), // 1 hour expiry
    client,
    user: { id: 1 }
  };

  const redirectUrl = `${redirect_uri}?code=${authorizationCode}`;
  res.redirect(redirectUrl);
});

app.post('/token', (req, res) => {
  const request = new oauthServer.Request(req); 
  const response = new oauthServer.Response(res);  

  oauth.token(request, response)
    .then((token) => {
      res.json(token);
    })
    .catch((err) => {
      res.status(err.code || 500).json(err);
    });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`OAuth2 server running on port ${PORT}`);
});
