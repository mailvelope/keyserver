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

/**
 * Database documents have the format:
 * {
 *   _id: "02C134D079701934",   // the 16 byte key id
 *   email: "jon@example.com",  // the primary and verified email address
 *   publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----"
 * }
 */
const DB_TYPE = 'publickey';

/**
 * A controller that handlers PGP public keys queries to the database
 */
class PublicKey {

  /**
   * Create an instance of the controller
   * @param  {Object} mongo   An instance of the MongoDB client
   */
  constructor(mongo) {
    this._mongo = mongo;
  }

  //
  // Create/Update
  //

  put(options) {

  }

  verify(options) {

  }

  //
  // Read
  //

  get(options) {

  }

  //
  // Delete
  //

  remove(options) {

  }

  verifyRemove(options) {

  }

}

module.exports = PublicKey;