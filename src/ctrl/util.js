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

const addressparser = require('addressparser');

/**
 * Checks for a valid string
 * @param  {} data     The input to be checked
 * @return {boolean}   If data is a string
 */
exports.isString = function(data) {
  return typeof data === 'string' || String.prototype.isPrototypeOf(data);
};

/**
 * Checks for a valid key id which is between 8 and 40 hex chars.
 * @param  {string} data   The key id
 * @return {boolean}       If the key id if valid
 */
exports.validateKeyId = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  return /^[a-fA-F0-9]{8,40}$/.test(data);
};

/**
 * Checks for a valid email address.
 * @param  {string} data   The email address
 * @return {boolean}       If the email address if valid
 */
exports.validateAddress = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(data);
};

/**
 * Validate an ascii armored public PGP key block.
 * @param  {string} data   The armored key block
 * @return {boolean}      If the key is valid
 */
exports.validatePublicKey = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  const begin = /-----BEGIN PGP PUBLIC KEY BLOCK-----/;
  const end = /-----END PGP PUBLIC KEY BLOCK-----/;
  return begin.test(data) && end.test(data);
};

/**
 * Parse an array of user id string to objects
 * @param  {Array} userIds   A list of user ids strings
 * @return {Array}           An array of user id objects
 */
exports.parseUserIds = function(userIds) {
  let result = [];
  userIds.forEach(uid => result = result.concat(addressparser(uid)));
  return result.map(u => ({
    email: u.address ? u.address.toLowerCase() : undefined,
    name: u.name
  }));
};

/**
 * Deduplicates items in an array
 * @param  {Array} list   The list of items with duplicates
 * @return {Array}        The list of items without duplicates
 */
exports.deDup = function(list) {
  var result = [];
  (list || []).forEach(function(i) {
    if (result.indexOf(i) === -1) {
      result.push(i);
    }
  });
  return result;
};

/**
 * Create an error with a custom status attribute e.g. for http codes.
 * @param  {number} status    The error's http status code
 * @param  {string} message   The error message
 * @return {Error}            The resulting error object
 */
exports.error = function(status, message) {
  let err = new Error(message);
  err.status = status;
  return err;
};