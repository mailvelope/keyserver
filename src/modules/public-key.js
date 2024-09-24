/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const config = require('../../config/config');
const util = require('../lib/util');
const tpl = require('../lib/templates');
const log = require('../lib/log');

/**
 * Database documents have the format:
 * {
 *   _id: ObjectId, // a randomly generated MongoDB document ID
 *   keyId: 'b8e4105cc9dedc77', // the 16 char key ID in lowercase hex
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
 *   uploaded: Sat Oct 17 2015 12:17:03 GMT+0200 (CEST), // time of key upload as JavaScript Date
 *   algorithm: 'rsa_encrypt_sign', // primary key alogrithm
 *   keySize: 4096, // key length in bits
 *   publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----',
 *   verifyUntil: Mon Nov 16 2015 12:17:03 GMT+0200 (CEST) // verification deadline
 * }
 */
const DB_TYPE = 'publickey';
const {KEY_STATUS} = util;

/**
 * A service that handlers PGP public keys queries to the database
 */
class PublicKey {
  /**
   * Create an instance of the service
   * @param {Object} pgp    An instance of the OpenPGP.js wrapper
   * @param {Object} mongo  An instance of the MongoDB client
   * @param {Object} email  An instance of the Email Sender
   */
  constructor(pgp, mongo, email) {
    this._pgp = pgp;
    this._mongo = mongo;
    this._email = email;
  }

  async init() {
    // create time to live (TTL) index to purge unverified keys
    await this._mongo.createIndexes([{key: {verifyUntil: 1}, expireAfterSeconds: 1}], DB_TYPE);
  }

  /**
   * Persist a new public key
   * @param  {Array} emails             (optional) The emails to upload/update
   * @param  {String} publicKeyArmored  The ascii armored pgp key block
   * @param  {Object} origin            Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @param  {Object} i18n              i18n object
   * @return {Promise<undefined>}
   */
  async put({emails = [], publicKeyArmored, origin, i18n}) {
    emails = emails.map(util.normalizeEmail);
    // parse key block
    const key = await this._pgp.parseKey(publicKeyArmored);
    // if emails array is empty, all userIds of the key will be submitted
    if (emails.length) {
      // keep submitted user IDs only
      key.userIds = key.userIds.filter(({email}) => emails.includes(email));
      if (key.userIds.length !== emails.length) {
        throw Boom.badRequest('Provided email address does not match a valid user ID of the key');
      }
    }
    await this.enforceRateLimit(key);
    await this.checkCollision(key);
    // check for existing verified key with same ID
    const verified = await this.getVerified({keyId: key.keyId});
    if (verified) {
      key.userIds = await this._mergeUsers(verified.userIds, key.userIds, key.publicKeyArmored);
      // reduce new key to verified user IDs
      const filteredPublicKeyArmored = await this._pgp.filterKeyByUserIds(key.userIds.filter(({verified}) => verified), key.publicKeyArmored);
      // update verified key with new key
      key.publicKeyArmored = await this._pgp.updateKey(verified.publicKeyArmored, filteredPublicKeyArmored);
    } else {
      key.userIds = key.userIds.filter(userId => userId.status === KEY_STATUS.valid);
      if (!key.userIds.length) {
        throw Boom.badRequest('Invalid PGP key: no valid user IDs found');
      }
      await this._addKeyArmored(key.userIds, key.publicKeyArmored);
      // new key, set armored to null
      key.publicKeyArmored = null;
      this.setVerifyUntil(key);
    }
    // send mails to verify user IDs
    await this._sendVerifyEmail(key, origin, i18n);
    // store key in database
    await this._persistKey(key);
  }

  /**
   * Merge existing and new user IDs
   * @param  {Array} existingUsers      source user IDs
   * @param  {Array} newUsers           new user IDs
   * @param  {String} publicKeyArmored  armored key block of new user IDs
   * @return {Promise<Array>}           merged user IDs
   */
  async _mergeUsers(existingUsers, newUsers, publicKeyArmored) {
    const result = [];
    // existing verified valid or revoked users
    const verifiedUsers = existingUsers.filter(userId => userId.verified);
    // valid new users which are not yet verified
    const validUsers = newUsers.filter(userId => userId.status === KEY_STATUS.valid && !this._includeEmail(verifiedUsers, userId));
    // pending users are not verified, not newly submitted
    const pendingUsers = existingUsers.filter(userId => !userId.verified && !this._includeEmail(validUsers, userId));
    await this._addKeyArmored(validUsers, publicKeyArmored);
    result.push(...validUsers, ...pendingUsers, ...verifiedUsers);
    return result;
  }

  /**
   * Create amored key block which contains the corresponding user ID only and add it to the user ID object
   * @param  {Array} userIds            user IDs to be extended
   * @param  {String} publicKeyArmored  armored key block to be filtered
   * @return {Promise<undefined>}
   */
  async _addKeyArmored(userIds, publicKeyArmored) {
    for (const userId of userIds) {
      userId.publicKeyArmored = await this._pgp.filterKeyByUserIds([userId], publicKeyArmored, config.email.pgp);
      userId.notify = true;
    }
  }

  _includeEmail(users, user) {
    return users.find(({email}) => email === user.email);
  }

  /**
   * Set verifyUntil date to purgeTimeInDays in the future
   * @param {Object} key  public key parameters
   */
  setVerifyUntil(key) {
    const verifyUntil = new Date(key.uploaded);
    verifyUntil.setDate(key.uploaded.getDate() + config.publicKey.purgeTimeInDays);
    key.verifyUntil = verifyUntil;
  }

  /**
   * Send verification emails to the public keys user IDs for verification.
   * If a primary email address is provided only one email will be sent.
   * @param  {Array} userIds      user ID documents containg the verification nonces
   * @param  {Object} origin      the server's origin (required for email links)
   * @param  {Object} i18n        i18n object
   * @return {Promise<undefined}
   */
  async _sendVerifyEmail({userIds, keyId}, origin, i18n) {
    for (const userId of userIds) {
      if (userId.notify === true) {
        // generate nonce for verification
        userId.nonce = util.random();
        await this._email.send({template: tpl.verifyKey, userId, keyId, origin, publicKeyArmored: userId.publicKeyArmored, i18n});
      }
    }
  }

  /**
   * Persist the public key and its user IDs in the database.
   * @param  {Object} key          public key parameters
   * @return {Promise<undefined>}
   */
  async _persistKey(key) {
    // delete old/unverified key
    await this._mongo.remove({keyId: key.keyId}, DB_TYPE);
    // generate nonces for verification
    for (const userId of key.userIds) {
      // remove status from user
      delete userId.status;
      // remove notify flag from user
      delete userId.notify;
    }
    // persist new key
    const r = await this._mongo.create(key, DB_TYPE);
    if (!r.acknowledged) {
      throw Boom.badImplementation('Failed to persist key');
    }
  }

  /**
   * Verify a user ID by proving knowledge of the nonce.
   * @param  {String} keyId     Correspronding public key ID
   * @param  {String} nonce     The verification nonce proving email address ownership
   * @return {Promise<Object>}  The email that has been verified
   */
  async verify({keyId, nonce}) {
    // look for verification nonce in database
    const query = {keyId, 'userIds.nonce': nonce};
    const key = await this._mongo.get(query, DB_TYPE);
    if (!key) {
      throw Boom.notFound('User ID not found');
    }
    await this._removeKeysWithSameEmail(key, nonce);
    let {publicKeyArmored, email} = key.userIds.find(userId => userId.nonce === nonce);
    // update armored key
    if (key.publicKeyArmored) {
      publicKeyArmored = await this._pgp.updateKey(key.publicKeyArmored, publicKeyArmored);
    }
    // flag the user ID as verified
    await this._mongo.update(query, {
      publicKeyArmored,
      'userIds.$.verified': true,
      'userIds.$.nonce': null,
      'userIds.$.publicKeyArmored': null,
      verifyUntil: null
    }, DB_TYPE);
    return {email};
  }

  /**
   * Removes keys with the same email address
   * @param  {String} options.keyId   source key ID
   * @param  {Array} options.userIds  user IDs of source key
   * @param  {Array} nonce            relevant nonce
   * @return {Promise<undefined>}
   */
  async _removeKeysWithSameEmail({keyId, userIds}, nonce) {
    return this._mongo.remove({
      keyId: {$ne: keyId},
      'userIds.email': userIds.find(u => u.nonce === nonce).email
    }, DB_TYPE);
  }

  /**
   * Check if a verified key already exists either by fingerprint, 16 char key ID,
   * or email address. There can only be one verified user ID for an email address
   * at any given time.
   * @param  {Array} userIds       A list of user IDs to check
   * @param  {String} fingerprint  The public key fingerprint
   * @param  {String} keyId        (optional) The public key ID
   * @return {Promise<Object>}     The verified key document
   */
  async getVerified({userIds, fingerprint, keyId}) {
    let queries = [];
    // query by fingerprint
    if (fingerprint) {
      queries.push({
        fingerprint: fingerprint.toLowerCase(),
        'userIds.verified': true
      });
    }
    // query by key ID (to prevent key ID collision)
    if (keyId) {
      queries.push({
        keyId: keyId.toLowerCase(),
        'userIds.verified': true
      });
    }
    // query by user ID
    if (userIds) {
      queries = queries.concat(userIds.map(uid => ({
        userIds: {
          $elemMatch: {
            'email': util.normalizeEmail(uid.email),
            'verified': true
          }
        }
      })));
    }
    return this._mongo.get({$or: queries}, DB_TYPE);
  }

  /**
   * Fetch a verified public key from the database. Either the key ID or the
   * email address muss be provided.
   * @param  {String} fingerprint  (optional) The public key fingerprint
   * @param  {String} keyId        (optional) The public key ID
   * @param  {String} email        (optional) The user's email address
   * @param  {Object} i18n         i18n object
   * @return {Promise<Object>}     The public key document
   */
  async get({fingerprint, keyId, email, i18n}) {
    // look for verified key
    const userIds = email ? [{email}] : undefined;
    const key = await this.getVerified({keyId, fingerprint, userIds});
    if (!key) {
      throw Boom.notFound(i18n.__('key_not_found'));
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
   * Request removal of the public key by flagging all user IDs and sending
   * a verification email to the primary email address. Only one email
   * needs to sent to a single user ID to authenticate removal of all user IDs
   * that belong the a certain key ID.
   * @param  {String} keyId        (optional) The public key ID
   * @param  {String} email        (optional) The user's email address
   * @param  {Object} origin       Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @param  {Object} i18n         i18n object
   * @return {Promise<undefined>}
   */
  async requestRemove({keyId, email, origin, i18n}) {
    // flag user IDs for removal
    const key = await this._flagForRemove(keyId, email);
    if (!key) {
      throw Boom.notFound('User ID not found');
    }
    // send verification mails
    keyId = key.keyId; // get keyId in case request was by email
    for (const userId of key.userIds) {
      await this._email.send({template: tpl.verifyRemove, userId, keyId, origin, i18n});
    }
  }

  /**
   * Flag all user IDs of a key for removal by generating a new nonce and
   * saving it. Either a key ID or email address must be provided
   * @param  {String} keyId    (optional) The public key ID
   * @param  {String} email    (optional) The user's email address
   * @return {Promise<Array>}  A list of user IDs with nonces
   */
  async _flagForRemove(keyId, email) {
    email = util.normalizeEmail(email);
    const query = email ? {'userIds.email': email} : {keyId};
    const key = await this._mongo.get(query, DB_TYPE);
    if (!key) {
      return;
    }
    // flag only the provided user ID
    if (email) {
      const nonce = util.random();
      await this._mongo.update(query, {'userIds.$.nonce': nonce}, DB_TYPE);
      const uid = key.userIds.find(u => u.email === email);
      uid.nonce = nonce;
      return {userIds: [uid], keyId: key.keyId};
    }
    // flag all key user IDs
    if (keyId) {
      for (const uid of key.userIds) {
        const nonce = util.random();
        await this._mongo.update({'userIds.email': uid.email}, {'userIds.$.nonce': nonce}, DB_TYPE);
        uid.nonce = nonce;
      }
      return key;
    }
  }

  /**
   * Verify the removal of the user's key ID by proving knowledge of the nonce.
   * Also deletes all user ID documents of that key ID.
   * @param  {String} keyId        public key ID
   * @param  {String} nonce        The verification nonce proving email address ownership
   * @return {Promise<undefined>}
   */
  async verifyRemove({keyId, nonce}) {
    // check if key exists in database
    const flagged = await this._mongo.get({keyId, 'userIds.nonce': nonce}, DB_TYPE);
    if (!flagged) {
      throw Boom.notFound('User ID not found');
    }
    if (flagged.userIds.length === 1) {
      // delete the key
      await this._mongo.remove({keyId}, DB_TYPE);
      return flagged.userIds[0];
    }
    // update the key
    const rmIdx = flagged.userIds.findIndex(userId => userId.nonce === nonce);
    const rmUserId = flagged.userIds[rmIdx];
    if (rmUserId.verified) {
      if (flagged.userIds.filter(({verified}) => verified).length > 1) {
        flagged.publicKeyArmored = await this._pgp.removeUserId(rmUserId.email, flagged.publicKeyArmored);
      } else {
        flagged.publicKeyArmored = null;
        this.setVerifyUntil(flagged);
      }
    }
    flagged.userIds.splice(rmIdx, 1);
    await this._mongo.update({keyId}, flagged, DB_TYPE);
    return rmUserId;
  }

  /**
   * Check collision of key ID with existing keys on the server
   * @param  {Object} key  Public key parameters
   * @throws {Error}       The key failed the collision check
   */
  async checkCollision(key) {
    const queries = [];
    queries.push({keyId: key.keyId, fingerprint: {$ne: key.fingerprint}});
    const newKey = await this._pgp.readKey(key.publicKeyArmored);
    for (const subkey of newKey.subkeys) {
      queries.push({fingerprint: subkey.getFingerprint()});
      queries.push({keyId: subkey.getKeyID().toHex()});
    }
    const found = await this._mongo.count({$or: queries}, DB_TYPE);
    if (found) {
      log.error('Key ID collision: \n%s\n%s', key.fingerprint, key.publicKeyArmored);
      throw Boom.badRequest('Key ID collision error: a key ID of this key already exists on the server.');
    }
  }

  /**
   * Enforce a rate limit on how many upload operation are allowed per user ID
   * @param  {Object} key  Public key parameters
   * @throws {Error}       The key exceeds the rate limit
   */
  async enforceRateLimit(key) {
    const queries = [];
    if (!config.publicKey.uploadRateLimit) {
      return;
    }
    for (const userId of key.userIds) {
      queries.push({'userIds.email': userId.email});
    }
    const found = await this._mongo.count({$or: queries}, DB_TYPE);
    if (found > config.publicKey.uploadRateLimit) {
      log.error('Too many requests: \n%s\n%s', key.userIds.map(userId => userId.email), key.publicKeyArmored);
      throw Boom.tooManyRequests('Too many requests for this email address. Upload temporarily blocked.');
    }
  }
}

module.exports = PublicKey;
