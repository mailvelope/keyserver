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

const util = require('./util');
const tpl = require('../email/templates.json');

/**
 * Database documents have the format:
 * {
 *   _id: ObjectId, // a randomly generated MongoDB document ID
 *   keyId: 'b8e4105cc9dedc77', // the 16 char key id in lowercase hex
 *   fingerprint: 'e3317db04d3958fd5f662c37b8e4105cc9dedc77', // the 40 char key fingerprint in lowercase hex
 *   userIds: [
 *     {
 *       name:'Jon Smith',
 *       email:'jon@smith.com',
 *       nonce: "6a314915c09368224b11df0feedbc53c", // random 32 char verifier used to prove ownership
 *       verified: true // if the user ID has been verified
 *     }
 *   ],
 *   created: Sat Oct 17 2015 12:17:03 GMT+0200 (CEST), // key creation time as JavaScript Date
 *   algorithm: 'rsa_encrypt_sign', // primary key alogrithm
 *   keySize: 4096, // key length in bits
 *   publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----'
 * }
 */
const DB_TYPE = 'publickey';

/**
 * A service that handlers PGP public keys queries to the database
 */
class PublicKey {

  /**
   * Create an instance of the service
   * @param {Object} pgp       An instance of the OpenPGP.js wrapper
   * @param {Object} mongo     An instance of the MongoDB client
   * @param {Object} email     An instance of the Email Sender
   */
  constructor(pgp, mongo, email) {
    this._pgp = pgp;
    this._mongo = mongo;
    this._email = email;
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
    let key = this._pgp.parseKey(publicKeyArmored);
    // check for existing verfied key by id or email addresses
    let verified = yield this.getVerified(key);
    if (verified) {
      util.throw(304, 'Key for this user already exists');
    }
    // store key in database
    yield this._persisKey(key);
    // send mails to verify user ids (send only one if primary email is provided)
    yield this._sendVerifyEmail(key, primaryEmail, origin);
  }

  /**
   * Persist the public key and its user ids in the database.
   * @param {Object} key   public key parameters
   * @yield {undefined}    The persisted user id documents
   */
  *_persisKey(key) {
    // delete old/unverified key
    yield this._mongo.remove({ fingerprint:key.fingerprint }, DB_TYPE);
    // generate nonces for verification
    for (let uid of key.userIds) {
      uid.nonce = util.random();
    }
    // persist new key
    let r = yield this._mongo.create(key, DB_TYPE);
    if (r.insertedCount !== 1) {
      util.throw(500, 'Failed to persist key');
    }
  }

  /**
   * Send verification emails to the public keys user ids for verification.
   * If a primary email address is provided only one email will be sent.
   * @param {Array}  userIds            user id documents containg the verification nonces
   * @param {string} primaryEmail       the public key's primary email address
   * @param {Object} origin             the server's origin (required for email links)
   * @yield {undefined}
   */
  *_sendVerifyEmail(key, primaryEmail, origin) {
    let userIds = key.userIds, keyId = key.keyId;
    // check for primary email (send only one email)
    let primaryUserId = userIds.find(uid => uid.email === primaryEmail);
    if (primaryUserId) {
      userIds = [primaryUserId];
    }
    // send emails
    for (let userId of userIds) {
      userId.publicKeyArmored = key.publicKeyArmored; // set key for encryption
      yield this._email.send({ template:tpl.verifyKey, userId, keyId, origin });
    }
  }

  /**
   * Verify a user id by proving knowledge of the nonce.
   * @param {string} keyId   Correspronding public key id
   * @param {string} nonce   The verification nonce proving email address ownership
   * @yield {undefined}
   */
  *verify(options) {
    let keyId = options.keyId, nonce = options.nonce;
    // look for verification nonce in database
    let query = { keyId, 'userIds.nonce':nonce };
    let key = yield this._mongo.get(query, DB_TYPE);
    if (!key) {
      util.throw(404, 'User id not found');
    }
    // flag the user id as verified
    yield this._mongo.update(query, {
      'userIds.$.verified': true,
      'userIds.$.nonce': null
    }, DB_TYPE);
  }

  /**
   * Check if a verified key already exists either by fingerprint, 16 char key id,
   * or email address. There can only be one verified user ID for an email address
   * at any given time.
   * @param {Array}  userIds       A list of user ids to check
   * @param {string} fingerprint   The public key fingerprint
   * @param {string} keyId         (optional) The public key id
   * @yield {Object}               The verified key document
   */
  *getVerified(options) {
    let fingerprint = options.fingerprint, userIds = options.userIds, keyId = options.keyId;
    let queries = [];
    // query by fingerprint
    if (fingerprint) {
      queries.push({
        fingerprint: fingerprint.toLowerCase(),
        'userIds.verified': true
      });
    }
    // query by key id (to prevent key id collision)
    if (keyId) {
      queries.push({
        keyId: keyId.toLowerCase(),
        'userIds.verified': true
      });
    }
    // query by user id
    if (userIds) {
      queries = queries.concat(userIds.map(uid => ({
        userIds: {
          $elemMatch: {
            'email': uid.email.toLowerCase(),
            'verified': true
          }
        }
      })));
    }
    return yield this._mongo.get({ $or:queries }, DB_TYPE);
  }

  /**
   * Fetch a verified public key from the database. Either the key id or the
   * email address muss be provided.
   * @param {string} fingerprint   (optional) The public key fingerprint
   * @param {string} keyId         (optional) The public key id
   * @param {String} email         (optional) The user's email address
   * @yield {Object}               The public key document
   */
  *get(options) {
    let fingerprint = options.fingerprint, keyId = options.keyId, email = options.email;
    // look for verified key
    let userIds = email ? [{ email:email }] : undefined;
    let key = yield this.getVerified({ keyId, fingerprint, userIds });
    if (!key) {
      util.throw(404, 'Key not found');
    }
    // clean json return value (_id, nonce)
    delete key._id;
    key.userIds = key.userIds.map(uid => ({
      name: uid.name,
      email: uid.email,
      verified: uid.verified
    }));
    return key;
  }

  /**
   * Request removal of the public key by flagging all user ids and sending
   * a verification email to the primary email address. Only one email
   * needs to sent to a single user id to authenticate removal of all user ids
   * that belong the a certain key id.
   * @param {String} keyId    (optional) The public key id
   * @param {String} email    (optional) The user's email address
   * @param {Object} origin   Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @yield {undefined}
   */
  *requestRemove(options) {
    let keyId = options.keyId, email = options.email, origin = options.origin;
    let userIds = yield this._flagForRemove(keyId, email);
    if (!userIds.length) {
      util.throw(404, 'User id not found');
    }
    for (let userId of userIds) {
      yield this._email.send({ template:tpl.verifyRemove, userId, keyId, origin });
    }
  }

  /**
   * Flag all user IDs of a key for removal by generating a new nonce and
   * saving it. Either a key id or email address must be provided
   * @param {String} keyId   (optional) The public key id
   * @param {String} email   (optional) The user's email address
   * @yield {Array}          A list of user ids with nonces
   */
  *_flagForRemove(keyId, email) {
    let query = email ? { 'userIds.email':email } : { keyId };
    let key = yield this._mongo.get(query, DB_TYPE);
    if (!key) {
      return [];
    }
    if (email) {
      let nonce = util.random();
      yield this._mongo.update(query, { 'userIds.$.nonce':nonce }, DB_TYPE);
      let uid = key.userIds.find(u => u.email === email);
      uid.nonce = nonce;
      return [uid];
    }
    if (keyId) {
      for (let uid of key.userIds) {
        let nonce = util.random();
        yield this._mongo.update({ 'userIds.email':uid.email }, { 'userIds.$.nonce':nonce }, DB_TYPE);
        uid.nonce = nonce;
      }
      return key.userIds;
    }
  }

  /**
   * Verify the removal of the user's key id by proving knowledge of the nonce.
   * Also deletes all user id documents of that key id.
   * @param {string} keyId   public key id
   * @param {string} nonce   The verification nonce proving email address ownership
   * @yield {undefined}
   */
  *verifyRemove(options) {
    let keyId = options.keyId, nonce = options.nonce;
    let flagged = yield this._mongo.get({ keyId, 'userIds.nonce':nonce }, DB_TYPE);
    if (!flagged) {
      util.throw(404, 'User id not found');
    }
    yield this._mongo.remove({ keyId }, DB_TYPE);
  }

}

module.exports = PublicKey;