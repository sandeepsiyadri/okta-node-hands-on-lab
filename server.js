require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');

const app = express();
const port = process.env.PORT || 3000;

const requiredEnv = ['OKTA_ISSUER', 'OKTA_CLIENT_ID', 'OKTA_CLIENT_SECRET', 'APP_BASE_URL', 'SESSION_SECRET'];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false // local HTTP lab only; set true behind HTTPS in real environments
    }
  })
);

let oidcClient;

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  const groups = req.session.user?.groups || [];
  if (!groups.includes('Admin')) {
    return res.status(403).render('forbidden', { user: req.session.user });
  }
  next();
}

app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  const state = generators.state();
  const nonce = generators.nonce();

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;
  req.session.nonce = nonce;

  const authorizationUrl = oidcClient.authorizationUrl({
    scope: 'openid profile email groups',
    response_type: 'code',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    nonce
  });

  res.redirect(authorizationUrl);
});

app.get('/authorization-code/callback', async (req, res, next) => {
  try {
    const params = oidcClient.callbackParams(req);
    const tokenSet = await oidcClient.callback(
      `${process.env.APP_BASE_URL}/authorization-code/callback`,
      params,
      {
        code_verifier: req.session.codeVerifier,
        state: req.session.state,
        nonce: req.session.nonce
      }
    );

    const claims = tokenSet.claims();
    req.session.user = {
      sub: claims.sub,
      name: claims.name,
      email: claims.email,
      groups: claims.groups || [],
      idTokenClaims: claims,
      accessToken: tokenSet.access_token
    };

    delete req.session.codeVerifier;
    delete req.session.state;
    delete req.session.nonce;

    res.redirect('/profile');
  } catch (err) {
    next(err);
  }
});

app.get('/profile', requireLogin, (req, res) => {
  res.render('profile', { user: req.session.user });
});

app.get('/admin', requireLogin, requireAdmin, (req, res) => {
  res.render('admin', { user: req.session.user });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(`<h2>Error</h2><pre>${err.message}</pre>`);
});

async function start() {
  const oktaIssuer = await Issuer.discover(process.env.OKTA_ISSUER);
  oidcClient = new oktaIssuer.Client({
    client_id: process.env.OKTA_CLIENT_ID,
    client_secret: process.env.OKTA_CLIENT_SECRET,
    redirect_uris: [`${process.env.APP_BASE_URL}/authorization-code/callback`],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic'
  });

  app.listen(port, () => {
    console.log(`Okta lab app running at ${process.env.APP_BASE_URL}`);
  });
}

start().catch((err) => {
  console.error('Failed to start app:', err);
  process.exit(1);
});
