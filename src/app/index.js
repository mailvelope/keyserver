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
const serve = require('koa-static');
const router = require('koa-router')();
const render = require('koa-ejs');
const locales = require('koa-locales');
const config = require('config');
const path = require('path');
const middleware = require('./middleware');
const Mongo = require('../dao/mongo');
const Email = require('../email/email');
const HKP = require('../route/hkp');
const REST = require('../route/rest');
const PGP = require('../service/pgp');
const PublicKey = require('../service/public-key');

const app = new Koa();

render(app, {
  root: path.join(__dirname, '../view')
});

locales(app, {
  dirs: [path.join(__dirname, '../../locales')],
  writeCookie: false
});

let hkp;
let rest;

app.use(async (ctx, next) => {
  ctx.state = ctx.state || {};
  ctx.state.__ = ctx.__.bind(ctx);
  await next();
});

// UI views
router.get('/', ctx => ctx.render('index'));
router.redirect('/index.html', '/');
router.get('/manage.html', ctx => ctx.render('manage'));

// HKP and REST api routes
router.post('/pks/add', ctx => hkp.add(ctx));
router.get('/pks/lookup', ctx => hkp.lookup(ctx));
router.post('/api/v1/key', ctx => rest.create(ctx));
router.get('/api/v1/key', ctx => rest.query(ctx));
router.del('/api/v1/key', ctx => rest.remove(ctx));

// setup koa middlewares
app.on('error', middleware.logUnknownError);
app.use(middleware.upgradeToHTTPS);
app.use(middleware.setHTTPResponseHeaders);
app.use(router.routes());
app.use(router.allowedMethods());
app.use(serve(path.join(__dirname, '../static')));

async function init() {
  // inject dependencies
  const mongo = new Mongo();
  const email = new Email();
  const pgp = new PGP();
  const publicKey = new PublicKey(pgp, mongo, email);
  hkp = new HKP(publicKey);
  rest = new REST(publicKey);
  // init DAOs
  email.init(config.email);
  await mongo.init(config.mongo);
  return app;
}

module.exports = init;
