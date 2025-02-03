require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const OAuth2Server = require('oauth2-server');
const crypto = require('crypto');

const app = express();

// View Engine
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret',
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
                'http://localhost:3000/callback'
            ]
        }),
        saveAuthorizationCode: (code, client, user) => ({
            authorizationCode: 'mock-auth-code-12345',
            expiresAt: new Date(Date.now() + 300000),
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
            accessToken: 'mock-access-token-67890',
            accessTokenExpiresAt: new Date(Date.now() + 3600000),
            refreshToken: 'mock-refresh-token-abcde',
            refreshTokenExpiresAt: new Date(Date.now() + 86400000),
            client,
            user
        })
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

const chromiumAuth = (req, res, next) => {
    res.set({
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "script-src 'self'",
        'Set-Cookie': `Host-GAPS=1:${crypto.randomBytes(16).toString('hex')}; Secure; HttpOnly`
    });
    next();
};

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
        res.render('login', { client_id, redirect_uri, state, error: 'Authentication required' });
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'No authorization code provided' });
  }

  try {
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', qs.stringify({
      code,
      client_id: 'y385787851048-fk8u1939hdo5gtb0r0vji84rm5sb445b.apps.googleusercontent.com',
      client_secret: 'yGOCSPX-u49qwln_DJSdC729QmKy4jVNhILa',
      redirect_uri: 'http://localhost:3000/auth/google/callback',
      grant_type: 'authorization_code'
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const { access_token, id_token } = tokenResponse.data;

    const userResponse = await axios.get(`https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`);
    const userInfo = userResponse.data;

    res.json({
      message: 'Google login successful!',
      user: userInfo,
      access_token,
      id_token
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to exchange code for token', details: error.response?.data });
  }
});

app.get('/login', chromiumAuth, (req, res) => {
    res.render('login', { client_id: req.query.client_id, redirect_uri: req.query.redirect_uri, state: req.query.state, error: null });
});

app.post('/login', async (req, res) => {
    const { email, password, client_id, redirect_uri, state } = req.body;

    if (email === 'testuser@gmail.com' && password === 'testpassword123') {
        req.session.email = email;
        res.redirect(`/o/oauth2/v2/auth?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&response_type=code`);
    } else {
        res.render('login', { client_id, redirect_uri, state, error: 'Invalid credentials' });
    }
});

app.post('/oauth2/v4/token', async (req, res) => {
    try {
        const token = await oauth.token(new OAuth2Server.Request(req), new OAuth2Server.Response(res));
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

app.get('/oauth2/v1/userinfo', (req, res) => {
    if (!req.session.email) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ id: '12345', email: req.session.email, verified_email: true, name: 'Chromium User' });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
