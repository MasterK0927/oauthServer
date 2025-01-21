const crypto = require('crypto');

// In-memory storage for tokens, clients, and authorization codes
const tokens = {};
const authorizationCodes = {};
const clients = [
  {
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUris: ['http://localhost:3000/cb'],
    grants: ['authorization_code', 'password', 'refresh_token']
  }
];

const model = {
  getClient: function(clientId, clientSecret) {
    return clients.find(c => c.clientId === clientId && (!clientSecret || c.clientSecret === clientSecret)) || null;
  },

  saveAuthorizationCode: function(code, client, user) {
    authorizationCodes[code] = {
      authorizationCode: code,
      expiresAt: new Date(Date.now() + 3600000), // 1 hour
      client,
      user
    };
    return authorizationCodes[code];
  },

  getAuthorizationCode: function(authorizationCode) {
    return authorizationCodes[authorizationCode] || null;
  },

  saveAccessToken: function(token, client, user) {
    tokens[token.accessToken] = {
      accessToken: token.accessToken,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      refreshToken: token.refreshToken,
      refreshTokenExpiresAt: token.refreshTokenExpiresAt,
      client,
      user
    };
    return tokens[token.accessToken];
  },

  getAccessToken: function(bearerToken) {
    return tokens[bearerToken] || null;
  },

  saveRefreshToken: function(refreshToken, client, user) {
    tokens[refreshToken] = {
      refreshToken: refreshToken,
      refreshTokenExpiresAt: new Date(Date.now() + 3600000), // 1 hour expiry
      client,
      user
    };
    return tokens[refreshToken];
  },

  getRefreshToken: function(refreshToken) {
    return tokens[refreshToken] || null;
  }
};

module.exports = model;
