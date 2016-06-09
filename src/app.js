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
const Mongo = require('./dao/mongo');
const Email = require('./email/email');
const PGP = require('./service/pgp');
const PublicKey = require('./service/public-key');
const HKP = require('./route/hkp');
const REST = require('./route/rest');
const home = require('./route/home');

let mongo, email, pgp, publicKey, hkp, rest;

//
// Configure koa HTTP server
//

// HKP routes
router.post('/pks/add', function *() {
  yield hkp.add(this);
});
router.get('/pks/lookup', function *() {
  yield hkp.lookup(this);
});

// REST api routes
router.post('/api/v1/key', function *() {
  yield rest.create(this);
});
router.get('/api/v1/key', function *() {
  yield rest.read(this);
});
router.del('/api/v1/key', function *() {
  yield rest.remove(this);
});

// links for verification, removal and sharing
router.get('/api/v1/verify', function *() {
  yield rest.verify(this);
});
router.get('/api/v1/removeKey', function *() {
  yield rest.remove(this);
});
router.get('/api/v1/verifyRemove', function *() {
  yield rest.verifyRemove(this);
});
router.get('/user/:email', function *() {
  yield rest.share(this);
});

// display homepage
router.get('/', home);

// Set HTTP response headers
app.use(function *(next) {
  this.set('Strict-Transport-Security', 'max-age=16070400');
  this.set('Access-Control-Allow-Origin', '*');
  this.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  this.set('Access-Control-Allow-Headers', 'Content-Type');
  this.set('Cache-Control', 'no-cache');
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
  mongo = new Mongo();
  email = new Email();
  pgp = new PGP();
  publicKey = new PublicKey(pgp, mongo, email);
  hkp = new HKP(publicKey);
  rest = new REST(publicKey);
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
  email.init(config.email);
  log.info('app', 'Connecting to MongoDB ...');
  yield mongo.init(config.mongo);
  return app;
}

module.exports = init;