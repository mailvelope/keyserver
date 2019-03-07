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

const log = require('winston');
const config = require('config');
const util = require('../service/util');

exports.upgradeToHTTPS = async function(ctx, next) {
  if (util.isTrue(config.server.httpsUpgrade) && util.checkHTTP(ctx)) {
    ctx.redirect(`https://${ctx.hostname}${ctx.url}`);
  } else {
    await next();
  }
};

exports.setHTTPResponseHeaders = async function(ctx, next) {
  // HSTS
  if (util.isTrue(config.server.httpsUpgrade)) {
    ctx.set('Strict-Transport-Security', 'max-age=16070400');
  }
  // HPKP
  if (config.server.httpsKeyPin && config.server.httpsKeyPinBackup) {
    ctx.set('Public-Key-Pins', `pin-sha256="${config.server.httpsKeyPin}"; pin-sha256="${config.server.httpsKeyPinBackup}"; max-age=16070400`);
  }
  // CSP
  ctx.set('Content-Security-Policy', "default-src 'self'; object-src 'none'; script-src 'self' code.jquery.com; style-src 'self' stackpath.bootstrapcdn.com 'unsafe-inline'; font-src 'self' stackpath.bootstrapcdn.com");
  // Prevent rendering website in foreign iframe (Clickjacking)
  ctx.set('X-Frame-Options', 'DENY');
  // CORS
  ctx.set('Access-Control-Allow-Origin', '*');
  ctx.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  ctx.set('Access-Control-Allow-Headers', 'Content-Type');
  ctx.set('Connection', 'keep-alive');
  await next();
};

exports.logUnknownError = function(error, ctx) {
  if (error.status) {
    log.verbose('middleware', `Request failed: ${error.status} ${error.message}`);
  } else {
    log.error('middleware', 'Unknown error', error, ctx);
  }
};
