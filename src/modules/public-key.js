/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const config = require('../../config/config');
const util = require('../lib/util');
const tpl = require('../lib/templates');

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
 *   uploaded: Sat Oct 17 2015 12:17:03 GMT+0200 (CEST), // time of key upload as JavaScript Date
 *   algorithm: 'rsa_encrypt_sign', // primary key alogrithm
 *   keySize: 4096, // key length in bits
 *   publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----'
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
   * @param {Array} emails              (optional) The emails to upload/update
   * @param {String} publicKeyArmored   The ascii armored pgp key block
   * @param {Object} origin             Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @param {Object} i18n               i18n object
   * @return {Promise}
   */
  async put({emails = [], publicKeyArmored, origin, i18n}) {
    emails = emails.map(util.normalizeEmail);
    // lazily purge old/unverified keys on every key upload
    await this._purgeOldUnverified();
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
    // check for existing verified key with same id
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
    }
    // send mails to verify user ids
    await this._sendVerifyEmail(key, origin, i18n);
    // store key in database
    await this._persistKey(key);
  }

  /**
   * Delete all keys where no user id has been verified after x days.
   * @return {Promise}
   */
  async _purgeOldUnverified() {
    // create date in the past to compare with
    const xDaysAgo = new Date();
    xDaysAgo.setDate(xDaysAgo.getDate() - config.publicKey.purgeTimeInDays);
    // remove unverified keys older than x days (or no 'uploaded' attribute)
    return this._mongo.remove({
      'userIds.verified': {$ne: true},
      uploaded: {$lt: xDaysAgo}
    }, DB_TYPE);
  }

  /**
   * Merge existing and new user IDs
   * @param  {Array} existingUsers     source user IDs
   * @param  {Array} newUsers          new user IDs
   * @param  {String} publicKeyArmored armored key block of new user IDs
   * @return {Array}                   merged user IDs
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
   * @param {Array} userIds           user IDs to be extended
   * @param {String} PublicKeyArmored armored key block to be filtered
   * @return {Promise}
   */
  async _addKeyArmored(userIds, publicKeyArmored) {
    for (const userId of userIds) {
      userId.publicKeyArmored = await this._pgp.filterKeyByUserIds([userId], publicKeyArmored);
      userId.notify = true;
    }
  }

  _includeEmail(users, user) {
    return users.find(({email}) => email === user.email);
  }

  /**
   * Send verification emails to the public keys user ids for verification.
   * If a primary email address is provided only one email will be sent.
   * @param {Array}  userIds            user id documents containg the verification nonces
   * @param {Object} origin             the server's origin (required for email links)
   * @param {Object} i18n               i18n object
   * @return {Promise}
   */
  async _sendVerifyEmail({userIds, keyId}, origin, i18n) {
    for (const userId of userIds) {
      if (userId.notify && userId.notify === true) {
        // generate nonce for verification
        userId.nonce = util.random();
        await this._email.send({template: tpl.verifyKey, userId, keyId, origin, publicKeyArmored: userId.publicKeyArmored, i18n});
      }
    }
  }

  /**
   * Persist the public key and its user ids in the database.
   * @param {Object} key   public key parameters
   * @return {Promise}
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
   * Verify a user id by proving knowledge of the nonce.
   * @param {string} keyId   Correspronding public key id
   * @param {string} nonce   The verification nonce proving email address ownership
   * @return {Promise}       The email that has been verified
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
    // flag the user id as verified
    const updatedUserIds = key.userIds.map(uid => {
      if (uid.nonce === nonce) {
        return {
          verified: true,
          nonce: null,
          publicKeyArmored: null,
          name: uid.name,
          email: uid.email
        };
      }
      return uid;
    });
    await this._mongo.update({'_id': key['_id']}, {
      publicKeyArmored,
      userIds: updatedUserIds
    }, DB_TYPE);
    return {email};
  }

  /**
   * Removes keys with the same email address
   * @param  {String} options.keyId   source key ID
   * @param  {Array} options.userIds  user IDs of source key
   * @param  {Array} nonce            relevant nonce
   * @return {Promise}
   */
  async _removeKeysWithSameEmail({keyId, userIds}, nonce) {
    return this._mongo.remove({
      keyId: {$ne: keyId},
      'userIds.email': userIds.find(u => u.nonce === nonce).email
    }, DB_TYPE);
  }

  /**
   * Check if a verified key already exists either by fingerprint, 16 char key id,
   * or email address. There can only be one verified user ID for an email address
   * at any given time.
   * @param {Array}  userIds       A list of user ids to check
   * @param {string} fingerprint   The public key fingerprint
   * @param {string} keyId         (optional) The public key id
   * @return {Object}               The verified key document
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
        'userIds.email': {
            $eq: util.normalizeEmail(uid.email)},
        'userIds.verified': {
            $eq: true
        }
      })));
    }
    return this._mongo.get({$or: queries}, DB_TYPE);
  }

  /**
   * Fetch a verified public key from the database. Either the key id or the
   * email address muss be provided.
   * @param {string} fingerprint   (optional) The public key fingerprint
   * @param {string} keyId         (optional) The public key id
   * @param {String} email         (optional) The user's email address
   * @param {Object} i18n          i18n object
   * @return {Object}               The public key document
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
   * Request removal of the public key by flagging all user ids and sending
   * a verification email to the primary email address. Only one email
   * needs to sent to a single user id to authenticate removal of all user ids
   * that belong the a certain key id.
   * @param {String} keyId    (optional) The public key id
   * @param {String} email    (optional) The user's email address
   * @param {Object} origin   Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @param {Object} i18n     i18n object
   * @return {Promise}
   */
  async requestRemove({keyId, email, origin, i18n}) {
    // flag user ids for removal
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
   * saving it. Either a key id or email address must be provided
   * @param {String} keyId   (optional) The public key id
   * @param {String} email   (optional) The user's email address
   * @return {Array}          A list of user ids with nonces
   */
  async _flagForRemove(keyId, email) {
    email = util.normalizeEmail(email);
    const query = email ? {'userIds.email': email} : {keyId};
    const key = await this._mongo.get(query, DB_TYPE);
    if (!key) {
      return;
    }
    // flag only the provided user id
    if (email) {
      const nonce = util.random();
      const flaggedUserIds = key.userIds.map(uid => {
        if (uid.email === email) {
          return {
            nonce: nonce,
            verified: uid.verified,
            publicKeyArmored: uid.publicKeyArmored,
            name: uid.name,
            email: uid.email
          }
        }
        return uid;
      });
      await this._mongo.update({'_id':key['_id']}, {userIds: flaggedUserIds}, DB_TYPE);
      const uid = key.userIds.find(u => u.email === email);
      uid.nonce = nonce;
      return {userIds: [uid], keyId: key.keyId};
    }
    // flag all key user ids
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
   * Verify the removal of the user's key id by proving knowledge of the nonce.
   * Also deletes all user id documents of that key id.
   * @param {string} keyId   public key id
   * @param {string} nonce   The verification nonce proving email address ownership
   * @return {Promise}
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
      }
    }
    flagged.userIds.splice(rmIdx, 1);
    await this._mongo.update({keyId}, flagged, DB_TYPE);
    return rmUserId;
  }
}

module.exports = PublicKey;
