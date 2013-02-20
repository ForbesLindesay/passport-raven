var express = require('express');
var app = express();

var passport = require('passport');
var Raven = require('../');

passport.use(new Raven({
    audience: 'http://localhost:3000'
  }, function (crsid, cb) {
    return process.nextTick(function () {
      console.log('login with crsid: ' + crsid);
      cb(null, crsid);
    });
  }));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(express.logger('dev'));
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.session({ secret: 'keyboard cat' })); 

app.use(passport.initialize());
app.use(passport.session());


app.get('/', passport.authenticate('raven'), function (req, res) {
  res.send('looged in as ' + req.user);
});

app.listen(3000);