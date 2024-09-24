/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const util = require('../lib/util');
const openpgp = require('openpgp');

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
    return h.response('Upload successful. Check your inbox to verify your email address.').code(200);
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
        .header('Content-Disposition', 'attachment; filename=openpgp-key.asc');
      } else {
        return h.view('key-armored', {query: params, key});
      }
    } else if (['index', 'vindex'].includes(params.op)) {
      const VERSION = 1;
      const COUNT = 1; // number of keys
      const fp = key.fingerprint.toUpperCase();
      let algo;
      try {
        algo = openpgp.enums.write(openpgp.enums.publicKey, key.algorithm);
      } catch (e) {
        algo = key.algorithm.includes('rsa') ? 1 : '';
      }
      const created = key.created ? (key.created.getTime() / 1000) : '';
      const keySize = key.keySize ? key.keySize : '';
      let body = `info:${VERSION}:${COUNT}\npub:${fp}:${algo}:${keySize}:${created}::\n`;
      for (const uid of key.userIds) {
        if (uid.verified) {
          body += `uid:${encodeURIComponent(`${uid.name} <${uid.email}>`)}:::\n`;
        }
      }
      return h.response(body).type('text/plain');
    }
  }

  /**
   * Parse the query string for a lookup request and set a corresponding
   * error code if the requests is not supported or invalid.
   * @param {Object} query - hapi request query object
   * @return {Object} - query parameters or undefined for an invalid request
   */
  parseQueryString({query}) {
    const params = {
      op: query.op, // operation ... only 'get' is supported
      mr: query.options === 'mr' // machine readable
    };
    if (!['get', 'index', 'vindex'].includes(params.op)) {
      throw Boom.notImplemented('Method not implemented');
    }
    this.parseSearch(query.search, params);
    if (!params.keyId && !params.fingerprint && !params.email) {
      throw Boom.badRequest('Invalid search parameter');
    }
    return params;
  }

  /**
   * Parse the search parameter
   * @param  {String} search Query parameter search
   * @param  {Object} params Map with results
   */
  parseSearch(search, params) {
    if (!search || !util.isString(search)) {
      return;
    }
    search = search.replaceAll(/\s/g, '');
    if (this.checkId(search)) {
      const id = search.replace(/^0x/, '');
      params.keyId = util.isKeyId(id) ? id : undefined;
      params.fingerprint = util.isFingerPrint(id) ? id : undefined;
      return;
    }
    if (search.startsWith('<') && search.endsWith('>')) {
      search = search.slice(1, -1);
    }
    if (util.isEmail(search)) {
      params.email = search;
    }
  }

  /**
   * Checks for a valid key id in the query string. A key must be prepended
   * with '0x' and can be between 16 and 40 hex characters long.
   * @param {String} id - key id
   * @return {Boolean} - if the key id is valid
   */
  checkId(id) {
    return /^(?:0x)?[a-fA-F0-9]{16,40}$/.test(id);
  }
}

exports.plugin = {
  name: 'HKP',
  async register(server, options) {
    const hkp = new HKP(server.app.publicKey);

    const routeOptions = {
      bind: hkp,
      cors: options.server.cors,
      security: options.server.security,
      ext: {
        onPreResponse: {
          method({response}, h) {
            if (!response.isBoom) {
              return h.continue;
            }
            return h.response(response.message).code(response.output.statusCode).type('text/plain');
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
