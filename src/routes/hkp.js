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
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  /**
   * Public key lookup via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  *lookup(ctx) {
    let params = this.parseQueryString(ctx);
    if (!params) {
      return; // invalid request
    }

    let key = yield this._publicKey.get(params);
    if (key) {
      ctx.body = key.publicKeyArmored;
      if (params.mr) {
        this.setGetMRHEaders(ctx);
      }
    } else {
      ctx.status = 404;
      ctx.body = 'Not found!';
    }
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
      params._id = ctx.query.search.replace(/^0x/, '');
    } else if(this.checkEmail(ctx.query.search)) {
      params.email = ctx.query.search;
    }

    if (params.op !== 'get') {
      ctx.status = 501;
      ctx.body = 'Not implemented!';
      return;
    } else if (!params._id && !params.email) {
      ctx.status = 400;
      ctx.body = 'Invalid request!';
      return;
    }

    return params;
  }

  /**
   * Checks for a valid email address.
   * @param  {String} address   The email address
   * @return {Boolean}          If the email address if valid
   */
  checkEmail(address) {
    return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$/.test(address);
  }

  /**
   * Checks for a valid key id in the query string. A key must be prepended
   * with '0x' and can be between 8 and 40 hex characters long.
   * @param  {String} keyid   The key id
   * @return {Boolean}        If the key id is valid
   */
  checkId(keyid) {
    return /^0x[a-fA-F0-9]{8,40}$/.test(keyid);
  }

  /**
   * Set HTTP headers for a GET requests with 'mr' (machine readable) options.
   * @param  {Object} ctx   The koa request/response context
   */
  setGetMRHEaders(ctx) {
    ctx.set('Content-Type', 'application/pgp-keys; charset=UTF-8');
    ctx.set('Content-Disposition', 'attachment; filename=openpgpkey.asc');
  }

}

module.exports = HKP;