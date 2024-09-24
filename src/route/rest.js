/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const util = require('../lib/util');

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
   * Public key / user ID upload via http POST
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async create(request, h) {
    const {emails, publicKeyArmored} = request.payload;
    if (!publicKeyArmored) {
      return Boom.badRequest('No public armored key found');
    }
    const origin = util.origin(request);
    await this._publicKey.put({emails, publicKeyArmored, origin, i18n: request.i18n});
    return h.response('Upload successful. Check your inbox to verify your email address.').code(200);
  }

  /**
   * Public key query via http GET
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async query(request, h) {
    const {op} = request.query;
    if (op === 'verify') {
      return this.verify(request, h);
    } else if (op === 'verifyRemove') {
      return this.verifyRemove(request, h);
    }
    // do READ if no 'op' provided
    const {keyId, fingerprint, email} = request.query;
    if (!keyId && !fingerprint && ! email ||
        keyId && !util.isKeyId(keyId) || fingerprint && !util.isFingerPrint(fingerprint) || email && !util.isEmail(email)) {
      return Boom.badRequest('Missing parameter: keyId, fingerprint or email.');
    }
    return h.response(await this._publicKey.get({keyId, fingerprint, email, i18n: request.i18n}));
  }

  /**
   * Verify a public key's user id via http GET
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async verify(request, h) {
    const {keyId, nonce} = request.query;
    if (!util.isKeyId(keyId) || !util.isNonce(nonce)) {
      throw Boom.badRequest('Invalid parameter keyId or nonce');
    }
    const {email} = await this._publicKey.verify({keyId, nonce});
    // create link for sharing
    const link = util.url(util.origin(request), `/pks/lookup?op=get&search=${email}`);
    return h.view('verify-success', {email, link});
  }

  /**
   * Request public key removal via http DELETE
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async remove(request, h) {
    const {keyId, email} = request.query;
    const origin  = util.origin(request);
    if (!util.isKeyId(keyId) && !util.isEmail(email)) {
      throw Boom.badRequest('Invalid parameter keyId or email');
    }
    await this._publicKey.requestRemove({keyId, email, origin, i18n: request.i18n});
    return h.response('Check your inbox to verify the removal of your email address.').code(200);
  }

  /**
   * Verify public key removal via http GET
   * @param {Object} request - hapi request object
   * @param {Object} h - hapi response toolkit
   */
  async verifyRemove(request, h) {
    const {keyId, nonce} = request.query;
    if (!util.isKeyId(keyId) || !util.isNonce(nonce)) {
      throw Boom.badRequest('Invalid parameter keyId or nonce');
    }
    const {email} = await this._publicKey.verifyRemove({keyId, nonce});
    return h.view('removal-success', {email});
  }
}

exports.plugin = {
  name: 'REST',
  async register(server, options) {
    const rest = new REST(server.app.publicKey);

    const routeOptions = {
      bind: rest,
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
      path: '/api/v1/key',
      handler: rest.create,
      options: routeOptions
    });

    server.route({
      method: 'GET',
      path: '/api/v1/key',
      handler: rest.query,
      options: routeOptions
    });

    server.route({
      method: 'DELETE',
      path: '/api/v1/key',
      handler: rest.remove,
      options: routeOptions
    });
  }
};
