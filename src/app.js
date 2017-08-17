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

const Koa = require('koa');
const koaBody = require('koa-body');
const log = require('npmlog');
const config = require('config');
const serve = require('koa-static');
const router = require('koa-router')();
const util = require('./service/util');
const Mongo = require('./dao/mongo');
const Email = require('./email/email');
const PGP = require('./service/pgp');
const PublicKey = require('./service/public-key');
const HKP = require('./route/hkp');
const REST = require('./route/rest');

const app = new Koa();

let mongo;
let email;
let pgp;
let publicKey;
let hkp;
let rest;

//
// Configure koa HTTP server
//

// HKP routes
router.post('/pks/add', ctx => hkp.add(ctx));
router.get('/pks/lookup', ctx => hkp.lookup(ctx));

// REST api routes
router.post('/api/v1/key', ctx => rest.create(ctx));
router.get('/api/v1/key', ctx => rest.query(ctx));
router.del('/api/v1/key', ctx => rest.remove(ctx));

// Redirect all http traffic to https
app.use(async(ctx, next) => {
  if (util.isTrue(config.server.httpsUpgrade) && util.checkHTTP(ctx)) {
    ctx.redirect(`https://${ctx.hostname}${ctx.url}`);
  } else {
    await next();
  }
});

// Set HTTP response headers
app.use(async(ctx, next) => {
  // HSTS
  if (util.isTrue(config.server.httpsUpgrade)) {
    ctx.set('Strict-Transport-Security', 'max-age=16070400');
  }
  // HPKP
  if (config.server.httpsKeyPin && config.server.httpsKeyPinBackup) {
    ctx.set('Public-Key-Pins', `pin-sha256="${config.server.httpsKeyPin}"; pin-sha256="${config.server.httpsKeyPinBackup}"; max-age=16070400`);
  }
  // CSP
  ctx.set('Content-Security-Policy', "default-src 'self'; object-src 'none'; script-src 'self' code.jquery.com; style-src 'self' maxcdn.bootstrapcdn.com; font-src 'self' maxcdn.bootstrapcdn.com");
  // Prevent rendering website in foreign iframe (Clickjacking)
  ctx.set('X-Frame-Options', 'DENY');
  // CORS
  ctx.set('Access-Control-Allow-Origin', '*');
  ctx.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  ctx.set('Access-Control-Allow-Headers', 'Content-Type');
  ctx.set('Connection', 'keep-alive');
  await next();
});

app.use(koaBody({
  multipart: true,
  formLimit: '1mb'
}));

app.use(router.routes());
app.use(router.allowedMethods());

// serve static files
app.use(serve(`${__dirname}/static`));

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
  (async() => {
    try {
      const app = await init();
      app.listen(config.server.port);
      log.info('app', `Ready to rock! Listening on http://localhost:${config.server.port}`);
    } catch (err) {
      log.error('app', 'Initialization failed!', err);
    }
  })();
}

async function init() {
  log.level = config.log.level; // set log level depending on process.env.NODE_ENV
  injectDependencies();
  email.init(config.email);
  log.info('app', 'Connecting to MongoDB ...');
  await mongo.init(config.mongo);
  return app;
}

module.exports = init;
