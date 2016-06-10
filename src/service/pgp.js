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
const openpgp = require('openpgp');
const addressparser = require('addressparser');

const KEY_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const KEY_END = '-----END PGP PUBLIC KEY BLOCK-----';

/**
 * A simple wrapper around OpenPGP.js
 */
class PGP {

  /**
   * Parse an ascii armored pgp key block and get its parameters.
   * @param  {String} publicKeyArmored   ascii armored pgp key block
   * @return {Object}                    public key document to persist
   */
  parseKey(publicKeyArmored) {
    publicKeyArmored = this.trimKey(publicKeyArmored);

    let r = openpgp.key.readArmored(publicKeyArmored);
    if (r.err) {
      let error = r.err[0];
      log.error('pgp', 'Failed to parse PGP key:\n%s', publicKeyArmored, error);
      util.throw(500, 'Failed to parse PGP key');
    } else if (!r.keys || r.keys.length !== 1 || !r.keys[0].primaryKey) {
      util.throw(400, 'Invalid PGP key: only one key can be uploaded');
    }

    // verify primary key
    let key = r.keys[0];
    let primaryKey = key.primaryKey;
    if (key.verifyPrimaryKey() !== openpgp.enums.keyStatus.valid) {
      util.throw(400, 'Invalid PGP key: primary key verification failed');
    }

    // accept version 4 keys only
    let keyId = primaryKey.getKeyId().toHex();
    let fingerprint = primaryKey.fingerprint;
    if (!util.isKeyId(keyId) || !util.isFingerPrint(fingerprint)) {
      util.throw(400, 'Invalid PGP key: only v4 keys are accepted');
    }

    // check for at least one valid user id
    let userIds = this.parseUserIds(key.users, primaryKey);
    if (!userIds.length) {
      util.throw(400, 'Invalid PGP key: invalid user ids');
    }

    // public key document that is stored in the database
    return {
      keyId,
      fingerprint,
      userIds,
      created: primaryKey.created,
      algorithm: primaryKey.algorithm,
      keySize: primaryKey.getBitSize(),
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
   * @return {Array}         An array of user id objects
   */
  parseUserIds(users, primaryKey) {
    if (!users || !users.length) {
      util.throw(400, 'Invalid PGP key: no user id found');
    }
    // at least one user id signature must be valid
    let result = [];
    for (let user of users) {
      let oneValid = false;
      for (let cert of user.selfCertifications) {
        if (user.isValidSelfCertificate(primaryKey, cert)) {
          oneValid = true;
        }
      }
      if (oneValid) {
        result = result.concat(addressparser(user.userId.userid));
      }
    }
    // map to local user id object format
    return result.map(uid => {
      if (!util.isEmail(uid.address)) {
        util.throw(400, 'Invalid PGP key: invalid email address');
      }
      return {
        name: uid.name,
        email: uid.address.toLowerCase(),
        verified: false
      };
    });
  }
}

module.exports = PGP;