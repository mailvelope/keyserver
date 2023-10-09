/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const util = require('../lib/util');

/**
 * An implementation of the OpenPGP HTTP Keyserver Protocol (HKP)
 * See https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
 */
class HKP {
  /**
   * Create an instance of the HKP server
   * @param  {Object} publicKey - an instance of the public key service
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  /**
   * Public key upload via http POST
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async add(request, h) {
    const {keytext: publicKeyArmored} = request.payload;
    if (!publicKeyArmored) {
      return Boom.badRequest('No key found');
    }
    const origin = util.origin(request);
    await this._publicKey.put({publicKeyArmored, origin, i18n: request.i18n});
    return h.response('Upload successful. Check your inbox to verify your email address.').code(201);
  }

  /**
   * Public key lookup via http GET
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async lookup(request, h) {
    const params = this.parseQueryString(request);
    const key = await this._publicKey.get({...params, i18n: request.i18n});
    if (params.op === 'get') {
      if (params.mr) {
        return h.response(key.publicKeyArmored)
        .header('Content-Type', 'application/pgp-keys; charset=utf-8')
        .header('Content-Disposition', 'attachment; filename=openpgpkey.asc');
      } else {
        return h.view('key-armored', {query: params, key});
      }
    } else if (['index', 'vindex'].includes(params.op)) {
      const VERSION = 1;
      const COUNT = 1; // number of keys
      const fp = key.fingerprint.toUpperCase();
      const algo = key.algorithm.includes('rsa') ? 1 : '';
      const created = key.created ? (key.created.getTime() / 1000) : '';
      let body = `info:${VERSION}:${COUNT}\npub:${fp}:${algo}:${key.keySize}:${created}::\n`;
      for (const uid of key.userIds) {
        body += `uid:${encodeURIComponent(`${uid.name} <${uid.email}>`)}:::\n`;
      }
      if (params.mr) {
        return h.response(body)
        .header('Content-Type', 'text/plain; charset=utf-8');
      } else {
        return h.response(body);
      }
    }
  }

  /**
   * Parse the query string for a lookup request and set a corresponding
   * error code if the requests is not supported or invalid.
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   * @return {Object} - query parameters or undefined for an invalid request
   */
  parseQueryString(request) {
    const params = {
      op: request.query.op, // operation ... only 'get' is supported
      mr: request.query.options === 'mr' // machine readable
    };
    if (this.checkId(request.query.search)) {
      const id = request.query.search.replace(/^0x/, '');
      params.keyId = util.isKeyId(id) ? id : undefined;
      params.fingerprint = util.isFingerPrint(id) ? id : undefined;
    } else if (util.isEmail(request.query.search)) {
      params.email = request.query.search;
    }
    if (!['get', 'index', 'vindex'].includes(params.op)) {
      throw Boom.notImplemented('Method not implemented');
    } else if (!params.keyId && !params.fingerprint && !params.email) {
      throw Boom.badRequest('Invalid search parameter');
    }
    return params;
  }

  /**
   * Checks for a valid key id in the query string. A key must be prepended
   * with '0x' and can be between 16 and 40 hex characters long.
   * @param {String} id - key id
   * @return {Boolean} - if the key id is valid
   */
  checkId(id) {
    if (!util.isString(id)) {
      return false;
    }
    return /^0x[a-fA-F0-9]{16,40}$/.test(id);
  }
}

exports.plugin = {
  name: 'HKP',
  async register(server, options) {
    const hkp = new HKP(server.app.publicKey);

    const routeOptions = {
      bind: hkp,
      cors: Boolean(options.server.cors === 'true'),
      security: Boolean(options.server.security === 'true'),
      ext: {
        onPreResponse: {
          method({response}, h) {
            if (!response.isBoom) {
              return h.continue;
            }
            return h.response(response.message).code(response.output.statusCode);
          }
        }
      }
    };

    server.route({
      method: 'POST',
      path: '/pks/add',
      handler: hkp.add,
      options: routeOptions
    });

    server.route({
      method: 'GET',
      path: '/pks/lookup',
      handler: hkp.lookup,
      options: routeOptions
    });
  }
};
