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

const log = require('winston');
const util = require('./util');
const openpgp = require('openpgp');

const KEY_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const KEY_END = '-----END PGP PUBLIC KEY BLOCK-----';

/**
 * A simple wrapper around OpenPGP.js
 */
class PGP {
  constructor() {
    openpgp.config.show_version = false;
    openpgp.config.show_comment = false;
  }

  /**
   * Parse an ascii armored pgp key block and get its parameters.
   * @param  {String} publicKeyArmored   ascii armored pgp key block
   * @return {Object}                    public key document to persist
   */
  async parseKey(publicKeyArmored) {
    publicKeyArmored = this.trimKey(publicKeyArmored);

    const r = await openpgp.readKeys({armoredKeys: publicKeyArmored});
    //const r = await openpgp.key.readArmored(publicKeyArmored);
    if (r.err) {
      const error = r.err[0];
      log.error('pgp', 'Failed to parse PGP key:\n%s', publicKeyArmored, error);
      util.throw(500, 'Failed to parse PGP key');
    } else if (!r || r.length !== 1 || !r[0].keyPacket) {
      util.throw(400, 'Invalid PGP key: only one key can be uploaded');
    }

    // verify primary key
    const key = r[0];
    //const primaryKey = key;
    const now = new Date();
    const verifyDate = key.created > now ? key.created : now;
    try {
      await key.verifyPrimaryKey(verifyDate)
    } catch (myerror) {
      util.throw(400, 'Invalid PGP key: primary key verification failed');
    }

    // accept version 4 keys only
    const keyId = key.keyPacket.keyID.toHex();
    const fingerprint = key.getFingerprint();
    if (!util.isKeyId(keyId) || !util.isFingerPrint(fingerprint)) {
      util.throw(400, 'Invalid PGP key: only v4 keys are accepted');
    }

    // check for at least one valid user id
    const userIds = await this.parseUserIds(key.users, key.keyPacket, verifyDate);
    if (!userIds.length) {
      util.throw(400, 'Invalid PGP key: invalid user IDs');
    }

    // get algorithm details from primary key
    const keyInfo = key.getAlgorithmInfo();

    // public key document that is stored in the database
    return {
      keyId,
      fingerprint,
      userIds,
      created: key.created,
      uploaded: new Date(),
      algorithm: keyInfo.algorithm,
      keySize: keyInfo.bits,
      publicKeyArmored
    };
  }

  /**
   * Remove all characters before and after the ascii armored key block
   * @param  {string} data   The ascii armored key
   * @return {string}        The trimmed key block
   */
  trimKey(data) {
    if (!this.validateKeyBlock(data)) {
      util.throw(400, 'Invalid PGP key: key block not found');
    }
    return KEY_BEGIN + data.split(KEY_BEGIN)[1].split(KEY_END)[0] + KEY_END;
  }

  /**
   * Validate an ascii armored public PGP key block.
   * @param  {string} data   The armored key block
   * @return {boolean}       If the key is valid
   */
  validateKeyBlock(data) {
    if (!util.isString(data)) {
      return false;
    }
    const begin = data.indexOf(KEY_BEGIN);
    const end =  data.indexOf(KEY_END);
    return begin >= 0 && end > begin;
  }

  /**
   * Parse an array of user ids and verify signatures
   * @param  {Array} users   A list of openpgp.js user objects
   * @param {Object} primaryKey The primary key packet of the key
   * @param {Date} verifyDate Verify user IDs at this point in time
   * @return {Array}         An array of user id objects
   */
  async parseUserIds(users, primaryKey, verifyDate = new Date()) {
    if (!users || !users.length) {
      util.throw(400, 'Invalid PGP key: no user ID found');
    }
    // at least one user id must be valid, revoked or expired
    const result = [];
    for (const user of users) {
      const userStatus = await user.verify(verifyDate, openpgp.config);
      if (userStatus !== 0 && user.userID && user.userID.userID) {
        try {
          const uid = user.userID;
          if (util.isEmail(uid.email)) {
            // map to local user id object format
            result.push({
              status: userStatus,
              name: uid.name,
              email: util.normalizeEmail(uid.email),
              verified: false
            });
          }
        } catch (e) { console.log(e); }
      }
    }
    return result;
  }

  /**
   * Remove user IDs from armored key block which are not in array of user IDs
   * @param  {Array} userIds  user IDs to be kept
   * @param  {String} armored armored key block to be filtered
   * @return {String}         filtered amored key block
   */
  async filterKeyByUserIds(userIds, armored) {
    const emails = userIds.map(({email}) => email);
    const key = await openpgp.readKey({armoredKey: armored});
    //const {keys: [key]} = r;
    key.users = key.users.filter(({userId}) => !userId || emails.includes(util.normalizeEmail(userId.email)));
    return key.armor();
  }

  /**
   * Merge (update) armored key blocks
   * @param  {String} srcArmored source amored key block
   * @param  {String} dstArmored destination armored key block
   * @return {String}            merged armored key block
   */
  async updateKey(srcArmored, dstArmored) {
    const {keys: [srcKey], err: srcErr} = await openpgp.key.readArmored(srcArmored);
    if (srcErr) {
      log.error('pgp', 'Failed to parse source PGP key for update:\n%s', srcArmored, srcErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    const {keys: [dstKey], err: dstErr} = await openpgp.key.readArmored(dstArmored);
    if (dstErr) {
      log.error('pgp', 'Failed to parse destination PGP key for update:\n%s', dstArmored, dstErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    await dstKey.update(srcKey);
    return dstKey.armor();
  }

  /**
   * Remove user ID from armored key block
   * @param  {String} email            email of user ID to be removed
   * @param  {String} publicKeyArmored amored key block to be filtered
   * @return {String}                  filtered armored key block
   */
  async removeUserId(email, publicKeyArmored) {
    const {keys: [key]} = await openpgp.key.readArmored(publicKeyArmored);
    key.users = key.users.filter(({userId}) => !userId || util.normalizeEmail(userId.email) !== email);
    return key.armor();
  }
}

module.exports = PGP;
