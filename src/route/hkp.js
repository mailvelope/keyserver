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
 * An implementation of the OpenPGP HTTP Keyserver Protocol (HKP)
 * See https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
 */
class HKP {
  /**
   * Create an instance of the HKP server
   * @param  {Object} publicKey   An instance of the public key service
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  /**
   * Public key upload via http POST
   * @param  {Object} ctx   The koa request/response context
   */
  async add(ctx) {
    const publicKeyArmored = ctx.request.body.keytext;
    if (!publicKeyArmored) {
      ctx.throw(400, 'Invalid request!');
    }
    const origin = util.origin(ctx);
    await this._publicKey.put({publicKeyArmored, origin});
    ctx.body = 'Upload successful. Check your inbox to verify your email address.';
    ctx.status = 201;
  }

  /**
   * Public key lookup via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async lookup(ctx) {
    const params = this.parseQueryString(ctx);
    const key = await this._publicKey.get(params);
    this.setGetHeaders(ctx, params);
    this.setGetBody(ctx, params, key);
  }

  /**
   * Parse the query string for a lookup request and set a corresponding
   * error code if the requests is not supported or invalid.
   * @param  {Object} ctx   The koa request/response context
   * @return {Object}       The query parameters or undefined for an invalid request
   */
  parseQueryString(ctx) {
    const params = {
      op: ctx.query.op, // operation ... only 'get' is supported
      mr: ctx.query.options === 'mr' // machine readable
    };
    if (this.checkId(ctx.query.search)) {
      const id = ctx.query.search.replace(/^0x/, '');
      params.keyId = util.isKeyId(id) ? id : undefined;
      params.fingerprint = util.isFingerPrint(id) ? id : undefined;
    } else if (util.isEmail(ctx.query.search)) {
      params.email = ctx.query.search;
    }

    if (['get', 'index', 'vindex'].indexOf(params.op) === -1) {
      ctx.throw(501, 'Not implemented!');
    } else if (!params.keyId && !params.fingerprint && !params.email) {
      ctx.throw(501, 'Not implemented!');
    }

    return params;
  }

  /**
   * Checks for a valid key id in the query string. A key must be prepended
   * with '0x' and can be between 16 and 40 hex characters long.
   * @param  {String} id   The key id
   * @return {Boolean}     If the key id is valid
   */
  checkId(id) {
    if (!util.isString(id)) {
      return false;
    }
    return /^0x[a-fA-F0-9]{16,40}$/.test(id);
  }

  /**
   * Set HTTP headers for a GET requests with 'mr' (machine readable) options.
   * @param  {Object} ctx      The koa request/response context
   * @param  {Object} params   The parsed query string parameters
   */
  setGetHeaders(ctx, params) {
    if (params.op === 'get' && params.mr) {
      ctx.set('Content-Type', 'application/pgp-keys; charset=utf-8');
      ctx.set('Content-Disposition', 'attachment; filename=openpgpkey.asc');
    }
  }

  /**
   * Format the body accordingly.
   * See https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-5
   * @param {Object} ctx      The koa request/response context
   * @param {Object} params   The parsed query string parameters
   * @param {Object} key      The public key document
   */
  setGetBody(ctx, params, key) {
    if (params.op === 'get') {
      ctx.body = key.publicKeyArmored;
    } else if (['index', 'vindex'].indexOf(params.op) !== -1) {
      const VERSION = 1;
      const COUNT = 1; // number of keys
      const fp = key.fingerprint.toUpperCase();
      const algo = (key.algorithm.indexOf('rsa') !== -1) ? 1 : '';
      const created = key.created ? (key.created.getTime() / 1000) : '';

      ctx.body = `info:${VERSION}:${COUNT}\npub:${fp}:${algo}:${key.keySize}:${created}::\n`;

      for (const uid of key.userIds) {
        ctx.body += `uid:${encodeURIComponent(`${uid.name} <${uid.email}>`)}:::\n`;
      }
    }
  }
}

module.exports = HKP;
