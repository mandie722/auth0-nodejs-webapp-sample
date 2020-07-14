var express = require('express');
var router = express.Router();
var passport = require('passport');
var dotenv = require('dotenv');
var util = require('util');
var bent = require('bent');
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
  console.log(`[callback] code: ${req.query.code}`);
  passport.authenticate('auth0', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login'); }
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

router.get('/mfa', (req, res) => {
  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port + '/mfa_callback';
  }
  let authorizeURL = new url.URL(util.format('https://%s/authorize', process.env.AUTH0_DOMAIN));
  let queryStr = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    audience: 'https://' + process.env.AUTH0_DOMAIN + '/mfa/',
    scope: 'enroll+read:authenticators+remove:authenticators',
    response_type: 'code',
    redirect_uri: returnTo
  })
  authorizeURL.search = queryStr;
  console.log('Sending MFA request: ' + authorizeURL.toJSON());
  res.redirect(authorizeURL);
});

router.get('/mfa_callback', async (req, res) => {
  console.log(`[mfa_callback] code: ${req.query.code}`);
  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port + '/mfa_callback';
  }
  try {
    const post = bent('https://' + process.env.AUTH0_DOMAIN, 'POST', 'json', 200);
    const response = await post('/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      code: req.query.code,
      redirect_uri: returnTo
    });
    console.log(`[mfa_callback] oauth token response: ${JSON.stringify(response)}`);
  } catch (error) {
    console.log(`[mfa_callback] Error getting oauth token: ${JSON.stringify(error)}`);
  }
  res.redirect('/user');
});

module.exports = router;
