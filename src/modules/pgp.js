/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const log = require('../lib/log');
const util = require('../lib/util');
const openpgp = require('openpgp');

const {KEY_STATUS} = util;

/**
 * A simple wrapper around OpenPGP.js
 */
class PGP {
  constructor() {
    openpgp.config.showVersion = false;
    openpgp.config.showComment = false;
  }

  /**
   * Parse an ascii armored pgp key block and get its parameters.
   * @param  {String} publicKeyArmored   ascii armored pgp key block
   * @return {Object}                    public key document to persist
   */
  async parseKey(publicKeyArmored) {
    let key;
    try {
      key = await openpgp.readKey({armoredKey: publicKeyArmored});
    } catch (e) {
      log.error('Error reading PGP key\n%s\n%s', e, publicKeyArmored);
      throw Boom.badRequest(`Error reading PGP key. ${e.message}`);
    }
    if (key.isPrivate()) {
      log.error('Attempted private key upload');
      throw Boom.badRequest('Error uploading private key. Please keep your private key secret and never upload it to key servers. Only public keys accepted.');
    }
    // verify key
    const verifyDate = new Date();
    // accept keys valid 24h in the future
    verifyDate.setUTCDate(verifyDate.getUTCDate() + 1);
    await this.verifyKey(key, verifyDate);
    // check for at least one valid user id
    const userIds = await this.parseUserIds(key, verifyDate);
    if (!userIds.length) {
      log.error('Invalid PGP key: no valid user IDs with email address found\n%s', publicKeyArmored);
      throw Boom.badRequest('Invalid PGP key: no valid user ID with email address found');
    }
    // get algorithm details from primary key
    const keyInfo = key.getAlgorithmInfo();
    // public key document that is stored in the database
    return {
      keyId: key.getKeyID().toHex(),
      fingerprint: key.getFingerprint(),
      userIds,
      created: key.getCreationTime(),
      uploaded: new Date(),
      algorithm: keyInfo.algorithm,
      keySize: keyInfo.bits,
      publicKeyArmored: key.armor()
    };
  }

  /**
   * Verify key. At least one valid user ID and signing or encryption key is required.
   * @param  {openpgp.PublicKey} key
   * @param  {Date} date The verification date
   * @throws {Error} If key verification failed
   * @async
   */
  async verifyKey(key, verifyDate = new Date()) {
    try {
      await key.verifyPrimaryKey(verifyDate);
    } catch (e) {
      log.error('Invalid PGP key: primary key verification failed\n%s\n%s', e, key.armor());
      throw Boom.badRequest(`Invalid PGP key. Key verification failed: ${e.message}`);
    }
    let signingKeyError;
    let encryptionKeyError;
    try {
      await key.getSigningKey(null, verifyDate);
    } catch (e) {
      signingKeyError = e;
    }
    try {
      await key.getEncryptionKey(null, verifyDate);
    } catch (e) {
      encryptionKeyError = e;
    }
    if (signingKeyError && encryptionKeyError) {
      log.error('Invalid PGP key: no valid encryption or signing key found\n%s\n%s\n%s', encryptionKeyError, signingKeyError, key.armor());
      throw Boom.badRequest(`Invalid PGP key. No valid encryption or signing key found: ${signingKeyError.message}`);
    }
  }

  /**
   * Parse user IDs and return the ones that are valid or revoked and contain an email address
   * @param  {openpgp.PublicKey} key
   * @param {Date} verifyDate Verify user IDs at this point in time
   * @return {Array}         An array of user ID objects
   */
  async parseUserIds(key, verifyDate = new Date()) {
    const result = [];
    for (const user of key.users) {
      const userStatus = await this.verifyUser(user, verifyDate);
      const email = user.userID?.email;
      if (userStatus !== KEY_STATUS.invalid && email) {
        result.push({
          status: userStatus,
          name: user.userID.name,
          email: util.normalizeEmail(email),
          verified: false
        });
      }
    }
    return result;
  }

  async verifyUser(user, verifyDate = new Date()) {
    try {
      await user.verify(verifyDate);
      return KEY_STATUS.valid;
    } catch (e) {
      switch (e.message) {
        case 'Self-certification is revoked':
          return KEY_STATUS.revoked;
        default:
          return KEY_STATUS.invalid;
      }
    }
  }

  /**
   * Remove user IDs from armored key block which are not in array of user IDs
   * @param  {Array} userIds  user IDs to be kept
   * @param  {String} armoredKey armored key block to be filtered
   * @return {String}         filtered amored key block
   */
  async filterKeyByUserIds(userIds, armoredKey) {
    const emails = userIds.map(({email}) => email);
    let key;
    try {
      key = await openpgp.readKey({armoredKey});
    } catch (e) {
      log.error('Failed to parse PGP key in filterKeyByUserIds\n%s\n%s', e, armoredKey);
      throw Boom.badImplementation('Failed to parse PGP key');
    }
    key.users = key.users.filter(({userID}) => userID && emails.includes(util.normalizeEmail(userID.email)));
    return key.armor();
  }

  /**
   * Merge (update) armored key blocks
   * @param  {String} srcArmored source amored key block
   * @param  {String} dstArmored destination armored key block
   * @return {String}            merged armored key block
   */
  async updateKey(srcArmored, dstArmored) {
    let srcKey;
    try {
      srcKey = await openpgp.readKey({armoredKey: srcArmored});
    } catch (e) {
      log.error('Failed to parse source PGP key for update\n%s\n%s', e, srcArmored);
      throw Boom.badImplementation('Failed to parse PGP key');
    }
    let dstKey;
    try {
      dstKey = await openpgp.readKey({armoredKey: dstArmored});
    } catch (e) {
      log.error('Failed to parse destination PGP key for update\n%s\n%s', e, dstArmored);
      throw Boom.badImplementation('Failed to parse PGP key');
    }
    const updatedKey = await dstKey.update(srcKey);
    return updatedKey.armor();
  }

  /**
   * Remove user ID from armored key block
   * @param  {String} email            email of user ID to be removed
   * @param  {String} armoredKey amored key block to be filtered
   * @return {String}                  filtered armored key block
   */
  async removeUserId(email, armoredKey) {
    let key;
    try {
      key = await openpgp.readKey({armoredKey});
    } catch (e) {
      log.error('Failed to parse PGP key in removeUserId\n%s\n%s', e, armoredKey);
      throw Boom.badImplementation('Failed to parse PGP key');
    }
    key.users = key.users.filter(({userID}) => userID && util.normalizeEmail(userID.email) !== email);
    return key.armor();
  }
}

module.exports = PGP;
