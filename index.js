var debug = require('debug')('raven');
var passport = require('passport');
var querystring = require('querystring');
var util = require('util');
var crypto = require('crypto');
var fs = require('fs');
var join = require('path').join;

var RAVEN_URL = 'https://raven.cam.ac.uk/auth/authenticate.html';
var RESPONSE_PARTS = [
  'ver',
  'status',
  'msg',
  'issue',
  'id',
  'url',
  'principal',
  'auth',
  'sso',
  'life',
  'params',
  'kid',
  'sig'
];

var ERROR_CODES = {
  410: 'Raven authentication was cancelled by the user.',
  510: 'No mutually acceptable authentication types available.',
  520: 'Unsupported Raven WAA2WLS protocol version.',
  530: 'Raven authentication failed due to error in request.',
  560: 'WAA not authorised to authenticate with Raven.',
  570: 'Raven authentication was declined on this occassion.'
};

//cache keys
var keys = {};

exports = module.exports = Strategy;
exports.Strategy = Strategy;

function Strategy(options, verify) {
  if (typeof options.audience !== 'string') throw new Error('You must provide an audience option');
  if (typeof verify !== 'function') throw new Error('You must provide a verify function');
  this.name = 'raven';
  this._verify = verify;
  this._audience = options.audience;
  this.clockOffset = options.clockOffset || 0;
  this.clockMargin = options.clockMargin || 60000;
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  if (req.query['WLS-Response']) {
    return this.processResponse(req);
  } else {
    return this.redirectToAuthenticate(req);
  }
};

Strategy.prototype.redirectToAuthenticate = function (req) {
  var params = querystring.stringify({
    ver: 2,
    url: this._audience + req.url,
    desc: this.siteName,
    params: ''
  });
  this.redirect(RAVEN_URL + '?' + params);
};

Strategy.prototype.processResponse = function (req) {
  var self = this;
  var response = {};
  var extraneous = [];
  req.query['WLS-Response']
    .split('!')
    .forEach(function (item, i) {
      if (!RESPONSE_PARTS[i]) {
        extraneous.push([i, item]);
      } else {
        response[RESPONSE_PARTS[i]] = item;
      }
    });
  if (extraneous.length) {
    debug('Incorrect lenght of WLS-Response');
    return this.error(new Error('Incorrect lenght of WLS-Response'));
  }
  if (response.status != '200') {
    var message = ERROR_CODES[response.status] ||
      ('Raven authentication failed with unknown status ' + response.status);
    debug(message);
    if (response.status = '410') return this.fail();
    else return this.error(new Error(message));
  } else if (response.status === '200') {
    var interval = (now() + this.clockOffset) - parseDate(response.issue);
    if (interval < 0) interval = -interval;

    if (interval < this.clockMargin) {
      debug('Checking certificate');
      //data = parameters - (sig + kid)
      var data = req.query['WLS-Response']
        .split('!')
        .slice(0, -2)
        .join('!');
      if (checkSignature(data, response.sig, response.kid)) {
        debug('Raven response signature check passed.');
        return self._verify(response.principal, function (err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        });
      } else {
        debug('Raven response signature check failed.');
        return this.error(new Error('Raven response signature check failed.'));
      }
    } else {
        debug('Timestamp out of date.');
        return this.error(new Error('Timestamp out of date.'));
    }
  }
};

function checkSignature(data, sig, kid) {
  data = decodeURI(data);
  sig = wlsDecode(decodeURI(sig));
  var keyPath = join(__dirname, 'pubkey' + kid + '.crt');
  var key = keys[keyPath] || (keys[keyPath] = fs.readFileSync(keyPath));
  var verifier = crypto.createVerify('SHA1');
  verifier.update(data);
  var res = verifier.verify(key, sig, 'base64');
  if (res) {
    debug('verification passed');
    return true;
  } else {
    debug('verification failed');
    return false;
  }
}

function wlsDecode(str) {
  return str.replace(/-/g, '+').replace(/\./g, '/').replace(/_/g, '=');
}

function parseDate(str) {
  var match = /^(\d\d\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/.exec(str);
  return Date.UTC(match[1], (+match[2]) - 1, match[3], match[4], match[5], match[6]);
}
function now() {
  return Date.now();
}