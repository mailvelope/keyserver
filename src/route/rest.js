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

const parse = require('co-body');
const util = require('../ctrl/util');

/**
 * The REST api to provide additional functionality on top of HKP
 */
class REST {

  /**
   * Create an instance of the REST server
   * @param  {Object} publicKey   An instance of the public key controller
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  /**
   * Public key upload via http POST
   * @param  {Object} ctx   The koa request/response context
   */
  *create(ctx) {
    let pk = yield parse.json(ctx, { limit: '1mb' });
    if ((pk.primaryEmail && !util.validateAddress(pk.primaryEmail)) ||
      !util.validatePublicKey(pk.publicKeyArmored)) {
      ctx.throw(400, 'Invalid request!');
    }
    yield this._publicKey(pk);
  }

  *verify(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  /**
   * Public key fetch via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  *read(ctx) {
    let q = { keyid:ctx.query.keyid, email:ctx.query.email };
    if (!util.validateKeyId(q.keyid) && !util.validateAddress(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    ctx.body = yield this._publicKey.get(q);
  }

  /**
   * Public key fetch via http GET (shorthand link for sharing)
   * @param  {Object} ctx   The koa request/response context
   */
  *share(ctx) {
    let q = { email:ctx.params.email };
    if (!util.validateAddress(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    ctx.body = (yield this._publicKey.get(q)).publicKeyArmored;
  }

  *remove(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  *verifyRemove(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

}

module.exports = REST;