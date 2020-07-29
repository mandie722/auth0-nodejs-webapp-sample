var express = require('express');
var QRCode = require('qrcode');
var secured = require('../lib/middleware/secured');
var flash = require('connect-flash');
const axios = require('axios').default;
var router = express.Router();

/* GET user profile. */
router.get('/mfa', secured(), async (req, res) => {
  console.log(`[mfa] barcodeUri: ${req.session.barcode_uri}`);
  const qr = await QRCode.toDataURL(req.session.barcode_uri)
  res.render('mfa', {
    qr: qr,
    title: 'MFA page'
  });
});

router.post('/mfa_code_submit', secured(), async (req, res) => {
  console.log(`[mfa_code_submit] body: ${JSON.stringify(req.body)}`);
  const code = req.body.code;
  const mfa_token = req.session.mfa_token;
  const uds_access_token = req.session.uds_access_token;
  const user_id = req.session.user_id;

  try {
    const response_uds = await axios.post(process.env.UDS_URL + '/api/v1/utils/enable_mfa', {
      mfaToken: mfa_token,
      userId: user_id,
      otpCode: code
    }, {
      headers: {
        Authorization: `Bearer ${uds_access_token}`
      }
    });
    console.log(`[mfa_code_submit] enable_mfa response ${JSON.stringify(response_uds.data, null, 2)}`);
    const recovery_codes = response_uds.data.recoveryCodes;
    flash('info', `Recovery Codes: ${recovery_codes}`)
  } catch (err) {
    const message = `Error calling enable mfa: ${JSON.stringify(err)}`;
    console.log(`[mfa_code_submit] ${message}`);
    console.trace(err);
    flash('error', message);
    res.redirect('/mfa');
    return;
  }
  res.redirect('/user');
});

module.exports = router;
