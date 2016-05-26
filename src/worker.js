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
const fs = require('fs');
const app = require('koa')();
const log = require('npmlog');
const router = require('koa-router')();
const Mongo = require('./dao/mongo');
const PublicKey = require('./ctrl/public-key');
const HKP = require('./routes/hkp');

let mongo, publicKey, hkp;

//
// Configure koa router
//

router.get('/pks/lookup', function *() {
  yield hkp.lookup(this);
});
router.post('/pks/add', function *() {
  yield hkp.add(this);
});

app.use(router.routes());
app.use(router.allowedMethods());
app.on('error', (err, ctx) => log.error('worker', 'Unknown server error', err, ctx));

//
// Module initialization
//

function injectDependencies() {
  let credentials = readCredentials();
  mongo = new Mongo({
    uri: process.env.MONGO_URI || credentials.mongoUri,
    user: process.env.MONGO_USER || credentials.mongoUser,
    password: process.env.MONGO_PASS || credentials.mongoPass
  });
  publicKey = new PublicKey(mongo);
  hkp = new HKP(publicKey);
}

function readCredentials() {
  try {
    return JSON.parse(fs.readFileSync(__dirname + '/../credentials.json'));
  } catch(e) {
    log.info('worker', 'No credentials.json found ... using environment vars.');
  }
}

//
// Start app ... connect to the database and start listening
//

co(function *() {

  injectDependencies();
  yield mongo.connect();
  app.listen(process.env.PORT || 8888);

}).catch(err => log.error('worker', 'Initialization failed!', err));