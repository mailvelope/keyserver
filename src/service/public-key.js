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

const log = require('npmlog');
const util = require('./util');
const tpl = require('../email/templates.json');

/**
 * Database documents have the format:
 * {
 *   _id: "02C134D079701934", // the 16 byte key id in uppercase hex
 *   publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----"
 * }
 */
const DB_TYPE = 'publickey';

/**
 * A service that handlers PGP public keys queries to the database
 */
class PublicKey {

  /**
   * Create an instance of the service
   * @param {Object} openpgp   An instance of OpenPGP.js
   * @param {Object} mongo     An instance of the MongoDB client
   * @param {Object} email     An instance of the Email Sender
   * @param {Object} userId    An instance of the UserId service
   */
  constructor(openpgp, mongo, email, userId) {
    this._openpgp = openpgp;
    this._mongo = mongo;
    this._email = email;
    this._userId = userId;
  }

  /**
   * Persist a new public key
   * @param {String} publicKeyArmored   The ascii armored pgp key block
   * @param {String} primaryEmail       (optional) The key's primary email address
   * @param {Object} origin             Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @yield {undefined}
   */
  *put(options) {
    // parse key block
    let publicKeyArmored = options.publicKeyArmored, primaryEmail = options.primaryEmail, origin = options.origin;
    publicKeyArmored = publicKeyArmored.trim(); // remove whitespace
    let params = this._parseKey(publicKeyArmored);
    // check for existing verfied key by id or email addresses
    let verified = yield this._userId.getVerfied(params);
    if (verified) {
      util.throw(304, 'Key for this user already exists');
    }
    // store key in database
    let userIds = yield this._persisKey(publicKeyArmored, params);
    // send mails to verify user ids (send only one if primary email is provided)
    yield this._sendVerifyEmail(userIds, primaryEmail, origin, publicKeyArmored);
  }

  /**
   * Parse an ascii armored pgp key block and get its parameters.
   * @param  {String} publicKeyArmored   ascii armored pgp key block
   * @return {Object}                    key's id and user ids
   */
  _parseKey(publicKeyArmored) {
    let keys, userIds = [];
    try {
      keys = this._openpgp.key.readArmored(publicKeyArmored).keys;
    } catch(e) {
      log.error('public-key', 'Failed to parse PGP key:\n%s', publicKeyArmored, e);
      util.throw(500, 'Failed to parse PGP key');
    }
    if (!keys || !keys.length || !keys[0].primaryKey) {
      util.throw(400, 'Invalid PGP key');
    }
    // get key user ids
    keys.forEach(key => userIds = userIds.concat(key.getUserIds()));
    userIds = util.deDup(userIds);
    // get key id
    let primKey = keys[0].primaryKey;
    return {
      keyid: primKey.getKeyId().toHex().toUpperCase(),
      userIds: util.parseUserIds(userIds),
      fingerprint: primKey.fingerprint.toUpperCase(),
      created: primKey.created,
      algorithm: primKey.algorithm,
      keylen: primKey.getBitSize()
    };
  }

  /**
   * Persist the public key and its user ids in the database.
   * @param {String} publicKeyArmored   ascii armored pgp key block
   * @param {Object} params             public key parameters
   * @yield {Array}                     The persisted user id documents
   */
  *_persisKey(publicKeyArmored, params) {
    // delete old/unverified key and user ids with the same key id
    yield this.remove({ keyid:params.keyid });
    // persist new user ids
    let userIds = yield this._userId.batch(params);
    // persist new key
    let r = yield this._mongo.create({ _id:params.keyid, publicKeyArmored }, DB_TYPE);
    if (r.insertedCount !== 1) {
      // rollback user ids
      yield this.remove({ keyid:params.keyid });
      util.throw(500, 'Failed to persist key');
    }
    return userIds;
  }

  /**
   * Send verification emails to the public keys user ids for verification.
   * If a primary email address is provided only one email will be sent.
   * @param {Array}  userIds            user id documents containg the verification nonces
   * @param {string} primaryEmail       the public key's primary email address
   * @param {Object} origin             the server's origin (required for email links)
   * @param {String} publicKeyArmored   The ascii armored pgp key block
   * @yield {undefined}
   */
  *_sendVerifyEmail(userIds, primaryEmail, origin, publicKeyArmored) {
    let primaryUserId = userIds.find(uid => uid.email === primaryEmail);
    if (primaryUserId) {
      userIds = [primaryUserId];
    }
    for (let userId of userIds) {
      userId.publicKeyArmored = publicKeyArmored; // set key for encryption
      yield this._email.send({ template:tpl.verifyKey, userId, origin });
    }
  }

  /**
   * Fetch a verified public key from the database. Either the key id or the
   * email address muss be provided.
   * @param {String} keyid   (optional) The public key id
   * @param {String} email   (optional) The user's email address
   * @yield {Object}         The public key document
   */
  *get(options) {
    let keyid = options.keyid, email = options.email;
    let verified = yield this._userId.getVerfied({
      keyid: keyid ? keyid.toUpperCase() : undefined,
      userIds: email ? [{ email:email.toLowerCase() }] : undefined
    });
    if (!verified) {
      util.throw(404, 'Key not found');
    }
    let key = yield this._mongo.get({ _id:verified.keyid }, DB_TYPE);
    let params = this._parseKey(key.publicKeyArmored);
    params.publicKeyArmored = key.publicKeyArmored;
    return params;
  }

  /**
   * Request removal of the public key by flagging all user ids and sending
   * a verification email to the primary email address. Only one email
   * needs to sent to a single user id to authenticate removal of all user ids
   * that belong the a certain key id.
   * @param {String} keyid    (optional) The public key id
   * @param {String} email    (optional) The user's email address
   * @param {Object} origin   Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @yield {undefined}
   */
  *requestRemove(options) {
    let keyid = options.keyid, email = options.email, origin = options.origin;
    let userIds = yield this._userId.flagForRemove({ keyid, email }, DB_TYPE);
    if (!userIds.length) {
      util.throw(404, 'User id not found');
    }
    for (let userId of userIds) {
      yield this._email.send({ template:tpl.verifyRemove, userId, origin });
    }
  }

  /**
   * Verify the removal of the user's key id by proving knowledge of the nonce.
   * Also deletes all user id documents of that key id.
   * @param {string} keyid   public key id
   * @param {string} nonce   The verification nonce proving email address ownership
   * @yield {undefined}
   */
  *verifyRemove(options) {
    let keyid = options.keyid, nonce = options.nonce;
    let flagged = yield this._userId.getFlaggedForRemove({ keyid, nonce });
    if (!flagged) {
      util.throw(404, 'User id not found');
    }
    yield this.remove({ keyid });
  }

  /**
   * Delete a public key document and its corresponding user id documents.
   * @param {String} keyid   The key id
   * @yield {undefined}
   */
  *remove(options) {
    let keyid = options.keyid;
    // remove key document
    yield this._mongo.remove({ _id:keyid }, DB_TYPE);
    // remove matching user id documents
    yield this._userId.remove({ keyid });
  }

}

module.exports = PublicKey;