var express = require('express');
var router = express.Router();
var passport = require('passport');
var dotenv = require('dotenv');
var util = require('util');
const axios = require('axios').default;
var flash = require('connect-flash');
var url = require('url');
var querystring = require('querystring');

dotenv.config();

// Perform the login, after login Auth0 will redirect to callback
router.get('/login', passport.authenticate('auth0', {
  scope: 'openid email profile'
}), function (req, res) {
  res.redirect('/');
});

// Perform the final stage of authentication and redirect to previously requested URL or '/user'
router.get('/callback', function (req, res, next) {
  console.log(`[callback] query: ${JSON.stringify(req.query, null, 2)}`);
  console.log(`[callback] cookies: ${JSON.stringify(req.cookies, null, 2)}`);
  console.log(`[callback] signedCookies: ${JSON.stringify(req.signedCookies, null, 2)}`);
  console.log(`[callback] headers: ${JSON.stringify(req.headers, null, 2)}`);
  console.log(`[callback] body: ${JSON.stringify(req.body, null, 2)}`);
  passport.authenticate('auth0', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login'); }
    req.session.user_id = user._json['https://www.cloudbees.com/user/metadata'].user_id;
    console.log(`[callback] user id_token: ${JSON.stringify(user._json, null, 2)}`);
    req.logIn(user, function (err) {
      if (err) { return next(err); }
      const returnTo = req.session.returnTo;
      delete req.session.returnTo;
      res.redirect(returnTo || '/user');
    });
  })(req, res, next);
});

// Perform session logout and redirect to homepage
router.get('/logout', (req, res) => {
  req.logout();

  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port;
  }

  var logoutURL = new url.URL(
    util.format('https://%s/v2/logout', process.env.AUTH0_DOMAIN)
  );
  var searchString = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    returnTo: returnTo
  });
  logoutURL.search = searchString;

  res.redirect(logoutURL);
});

router.get(/\/(setup|disable)_mfa/, (req, res) => {
  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port + '/mfa_callback';
  }
  let authorizeURL = new url.URL(util.format('https://%s/authorize', process.env.AUTH0_DOMAIN));
  let queryStr = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    audience: 'https://' + process.env.AUTH0_DOMAIN + '/mfa/',
    scope: 'openid enroll read:authenticators remove:authenticators',
    response_type: 'code',
    redirect_uri: returnTo,
    state: req.path
  })
  authorizeURL.search = queryStr;
  console.log('Sending MFA request: ' + authorizeURL.toJSON());
  res.redirect(authorizeURL);
});

router.get('/mfa_callback', async (req, res) => {
  console.log(`[mfa_callback] req.query: ${JSON.stringify(req.query)}`);
  console.log(`[mfa_callback] code: ${req.query.code}`);
  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port + '/mfa_callback';
  }
  let mfa_token;
  let uds_access_token;
  try {
    const response = await axios.post('https://' + process.env.AUTH0_DOMAIN + '/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      code: req.query.code,
      redirect_uri: returnTo
    });
    console.log(`[mfa_callback] mfa oauth token response: ${JSON.stringify(response.data, null, 2)}`);
    mfa_token = response.data.access_token;
    req.session.mfa_token = mfa_token;
    const response_uds_token = await axios.post('https://' + process.env.AUTH0_DOMAIN + '/oauth/token', {
      grant_type: 'client_credentials',
      audience: 'https://c12s-dataservices-api',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET
    });
    console.log(`[mfa_callback] uds oauth token response: ${JSON.stringify(response_uds_token.data, null, 2)}`);
    uds_access_token = response_uds_token.data.access_token;
    req.session.uds_access_token = uds_access_token;
  } catch (err) {
    const message = `Error getting oauth token: ${JSON.stringify(err)}`;
    console.log(`[mfa_callback] ${message}`);
    req.flash('error', message);
    res.redirect('/user');
    return;
  }

  if (req.query.state === '/setup_mfa') {
    try {
      const response_uds = await axios.post(process.env.UDS_URL + '/api/v1/utils/initiate_mfa', {
        mfaToken: mfa_token,
        userId: req.session.user_id
      }, {
        headers: {
          Authorization: `Bearer ${uds_access_token}`
        }
      });
      console.log(`[mfa_callback] initiate_mfa response ${JSON.stringify(response_uds.data, null, 2)}`);
      req.session.barcode_uri = response_uds.data.barcodeUri;
    } catch (err) {
      const message = `Error calling initiate mfa: ${JSON.stringify(err)}`;
      console.log(`[mfa_callback] ${message}`);
      req.flash('error', message);
      res.redirect('/user');
      return;
    }
    res.redirect('/mfa');
    return;
  }
  try {
    await axios.post(process.env.UDS_URL + '/api/v1/utils/disable_mfa', {
      mfaToken: mfa_token,
      userId: req.session.user_id
    }, {
      headers: {
        Authorization: `Bearer ${uds_access_token}`
      }
    });
    console.log(`[mfa_callback] disable_mfa successful`);
  } catch (err) {
    const message = `Error calling disable mfa: ${JSON.stringify(err)}`;
    console.log(`[mfa_callback] ${message}`);
    flash('error', message);
    res.redirect('/user');
    return;
  }
});

module.exports = router;
