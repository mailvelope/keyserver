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
   * Public key lookup via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  *lookup(ctx) {
    var params = this.parseQueryString(ctx);
    if (!params) {
      return; // invalid request
    }

    this.setHeaders(ctx);
    if (params.mr) {
      this.setGetMRHEaders(ctx);
    }
    ctx.body = yield Promise.resolve('----- BEGIN PUBLIC PGP KEY -----');
  }

  /**
   * Public key upload via http POST
   * @param  {Object} ctx   The koa request/response context
   */
  *add(ctx) {
    ctx.throw(501, 'Not implemented!');
    return yield Promise.resolve();
  }

  /**
   * Parse the query string for a lookup request and set a corresponding
   * error code if the requests is not supported or invalid.
   * @param  {Object} ctx   The koa request/response context
   * @return {Object}       The query parameters or undefined for an invalid request
   */
  parseQueryString(ctx) {
    let q = ctx.query;
    let params = {
      op: q.op, // operation ... only 'get' is supported
      mr: q.options === 'mr', // machine readable
      keyid: this.checkId(q.search) ? q.search.replace('0x', '') : null,
      email: this.checkEmail(q.search) ? q.search : null,
    };

    if (params.op !== 'get') {
      ctx.status = 501;
      ctx.body = 'Not implemented!';
      return;
    } else if (!params.keyid && !params.email) {
      ctx.status = 404;
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
   * with '0x' and can be between 8 and 40 characters long.
   * @param  {String} keyid   The key id
   * @return {Boolean}        If the key id is valid
   */
  checkId(keyid) {
    return /^0x[a-fA-Z0-9]{8,40}/.test(keyid);
  }

  /**
   * Set HTTP headers for the HKP requests.
   * @param  {Object} ctx   The koa request/response context
   */
  setHeaders(ctx) {
    ctx.set('Access-Control-Allow-Origin', '*');
    ctx.set('Cache-Control', 'no-cache');
    ctx.set('Pragma', 'no-cache');
    ctx.set('Connection', 'keep-alive');
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