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
 * An implementation of the OpenPGP HTTP Keyserver Protocol (HKP)
 * See https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
 */
class HKP {

  /**
   * Create an instance of the HKP server
   * @param  {Object} publicKey   An instance of the public key controller
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  /**
   * Public key upload via http POST
   * @param  {Object} ctx   The koa request/response context
   */
  *add(ctx) {
    let body = yield parse.form(ctx, { limit: '1mb' });
    if (!util.validatePublicKey(body.keytext)) {
      ctx.throw(400, 'Invalid request!');
    }
    yield this._publicKey.put({ publicKeyArmored:body.keytext });
  }

  /**
   * Public key lookup via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  *lookup(ctx) {
    let params = this.parseQueryString(ctx);
    let key = yield this._publicKey.get(params);
    this.setGetHeaders(ctx, params);
    ctx.body = key.publicKeyArmored;
  }

  /**
   * Parse the query string for a lookup request and set a corresponding
   * error code if the requests is not supported or invalid.
   * @param  {Object} ctx   The koa request/response context
   * @return {Object}       The query parameters or undefined for an invalid request
   */
  parseQueryString(ctx) {
    let params = {
      op: ctx.query.op, // operation ... only 'get' is supported
      mr: ctx.query.options === 'mr' // machine readable
    };
    if (this.checkId(ctx.query.search)) {
      params.keyid = ctx.query.search.replace(/^0x/, '');
    } else if(util.validateAddress(ctx.query.search)) {
      params.email = ctx.query.search;
    }

    if (params.op !== 'get') {
      ctx.throw(501, 'Not implemented!');
    } else if (!params.keyid && !params.email) {
      ctx.throw(400, 'Invalid request!');
    }

    return params;
  }

  /**
   * Checks for a valid key id in the query string. A key must be prepended
   * with '0x' and can be between 8 and 40 hex characters long.
   * @param  {String} keyid   The key id
   * @return {Boolean}        If the key id is valid
   */
  checkId(keyid) {
    if (!util.isString(keyid)) {
      return false;
    }
    return /^0x[a-fA-F0-9]{8,40}$/.test(keyid);
  }

  /**
   * Set HTTP headers for a GET requests with 'mr' (machine readable) options.
   * @param  {Object} ctx      The koa request/response context
   * @param  {Object} params   The parsed query string parameters
   */
  setGetHeaders(ctx, params) {
    if (params.mr) {
      ctx.set('Content-Type', 'application/pgp-keys; charset=UTF-8');
      ctx.set('Content-Disposition', 'attachment; filename=openpgpkey.asc');
    }
  }

}

module.exports = HKP;