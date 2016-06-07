/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2016 Mailvelope GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

const co = require('co');
const app = require('koa')();
const log = require('npmlog');
const config = require('config');
const router = require('koa-router')();
const openpgp = require('openpgp');
const nodemailer = require('nodemailer');
const openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;
const Mongo = require('./dao/mongo');
const Email = require('./email/email');
const UserId = require('./service/user-id');
const PublicKey = require('./service/public-key');
const HKP = require('./route/hkp');
const REST = require('./route/rest');

let mongo, email, userId, publicKey, hkp, rest;

//
// Configure koa HTTP server
//

// HKP routes
router.post('/pks/add', function *() { // no query params
  yield hkp.add(this);
});
router.get('/pks/lookup', function *() { // ?op=get&search=0x1234567890123456
  yield hkp.lookup(this);
});

// REST api routes
router.post('/api/v1/key', function *() { // { publicKeyArmored, primaryEmail } hint the primary email address
  yield rest.create(this);
});
router.get('/api/v1/key', function *() { // ?keyid=keyid OR ?email=email
  yield rest.read(this);
});
router.del('/api/v1/key', function *() { // ?keyid=keyid OR ?email=email
  yield rest.remove(this);
});

// links for verification and sharing
router.get('/api/v1/verify', function *() { // ?keyid=keyid&nonce=nonce
  yield rest.verify(this);
});
router.get('/api/v1/verifyRemove', function *() { // ?keyid=keyid&nonce=nonce
  yield rest.verifyRemove(this);
});
router.get('/user/:email', function *() { // shorthand link for sharing
  yield rest.share(this);
});

// Set HTTP response headers
app.use(function *(next) {
  this.set('Strict-Transport-Security', 'max-age=16070400');
  this.set('Access-Control-Allow-Origin', '*');
  this.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  this.set('Access-Control-Allow-Headers', 'Content-Type');
  this.set('Cache-Control', 'no-cache');
  this.set('Pragma', 'no-cache');
  this.set('Connection', 'keep-alive');
  yield next;
});

// Redirect all http traffic to https
app.use(function *(next) {
  if (process.env.NODE_ENV === 'production' && !this.secure && this.get('X-Forwarded-Proto') === 'http') {
    this.redirect('https://' + this.hostname + this.url);
  } else {
    yield next;
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

app.on('error', (error, ctx) => {
  if (error.status) {
    log.verbose('app', 'Request faild: %s, %s', error.status, error.message);
  } else {
    log.error('app', 'Unknown error', error, ctx);
  }
});

//
// Module initialization
//

function injectDependencies() {
  mongo = new Mongo(config.mongo);
  email = new Email(nodemailer, openpgpEncrypt);
  email.init(config.email);
  userId = new UserId(mongo);
  publicKey = new PublicKey(openpgp, mongo, email, userId);
  hkp = new HKP(publicKey);
  rest = new REST(publicKey, userId);
}

//
// Start app ... connect to the database and start listening
//

if (!global.testing) { // don't automatically start server in tests
  co(function *() {
    let app = yield init();
    app.listen(config.server.port);
    log.info('app', 'Ready to rock! Listening on http://localhost:' + config.server.port);
  }).catch(err => log.error('app', 'Initialization failed!', err));
}

function *init() {
  log.level = config.log.level; // set log level depending on process.env.NODE_ENV
  injectDependencies();
  log.info('app', 'Connecting to MongoDB ...');
  yield mongo.connect();
  return app;
}

module.exports = init;