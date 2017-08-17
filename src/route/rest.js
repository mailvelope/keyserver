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

const util = require('../service/util');

/**
 * The REST api to provide additional functionality on top of HKP
 */
class REST {
  /**
   * Create an instance of the REST server
   * @param  {Object} publicKey   An instance of the public key service
   * @param  {Object} userId      An instance of the user id service
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  /**
   * Public key upload via http POST
   * @param  {Object} ctx   The koa request/response context
   */
  async create(ctx) {
    const {publicKeyArmored, primaryEmail} = ctx.request.body;
    if (!publicKeyArmored || (primaryEmail && !util.isEmail(primaryEmail))) {
      ctx.throw(400, 'Invalid request!');
    }
    const origin = util.origin(ctx);
    await this._publicKey.put({publicKeyArmored, primaryEmail, origin});
    ctx.body = 'Upload successful. Check your inbox to verify your email address.';
    ctx.status = 201;
  }

  /**
   * Public key query via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async query(ctx) {
    const op = ctx.query.op;
    if (op === 'verify' || op ===  'verifyRemove') {
      return this[op](ctx); // delegate operation
    }
    // do READ if no 'op' provided
    const q = {keyId: ctx.query.keyId, fingerprint: ctx.query.fingerprint, email: ctx.query.email};
    if (!util.isKeyId(q.keyId) && !util.isFingerPrint(q.fingerprint) && !util.isEmail(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    ctx.body = await this._publicKey.get(q);
  }

  /**
   * Verify a public key's user id via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async verify(ctx) {
    const q = {keyId: ctx.query.keyId, nonce: ctx.query.nonce};
    if (!util.isKeyId(q.keyId) || !util.isString(q.nonce)) {
      ctx.throw(400, 'Invalid request!');
    }
    await this._publicKey.verify(q);
    // create link for sharing
    const link = util.url(util.origin(ctx), `/pks/lookup?op=get&search=0x${q.keyId.toUpperCase()}`);
    ctx.body = `<p>Email address successfully verified!</p><p>Link to share your key: <a href="${link}" target="_blank">${link}</a></p>`;
    ctx.set('Content-Type', 'text/html; charset=utf-8');
  }

  /**
   * Request public key removal via http DELETE
   * @param  {Object} ctx   The koa request/response context
   */
  async remove(ctx) {
    const q = {keyId: ctx.query.keyId, email: ctx.query.email, origin: util.origin(ctx)};
    if (!util.isKeyId(q.keyId) && !util.isEmail(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    await this._publicKey.requestRemove(q);
    ctx.body = 'Check your inbox to verify the removal of your key.';
    ctx.status = 202;
  }

  /**
   * Verify public key removal via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async verifyRemove(ctx) {
    const q = {keyId: ctx.query.keyId, nonce: ctx.query.nonce};
    if (!util.isKeyId(q.keyId) || !util.isString(q.nonce)) {
      ctx.throw(400, 'Invalid request!');
    }
    await this._publicKey.verifyRemove(q);
    ctx.body = 'Key successfully removed!';
  }
}

module.exports = REST;
