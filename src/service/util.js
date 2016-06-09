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
 * Checks for a valid string
 * @param  {} data     The input to be checked
 * @return {boolean}   If data is a string
 */
exports.isString = function(data) {
  return typeof data === 'string' || String.prototype.isPrototypeOf(data);
};

/**
 * Cast string to a boolean value
 * @param  {}  data    The input to be checked
 * @return {boolean}   If data is true
 */
exports.isTrue = function(data) {
  if (this.isString(data)) {
    return data === 'true';
  } else {
    return !!data;
  }
};

/**
 * Checks for a valid long key id which is 16 hex chars long.
 * @param  {string} data   The key id
 * @return {boolean}       If the key id is valid
 */
exports.isKeyId = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  return /^[a-fA-F0-9]{16}$/.test(data);
};

/**
 * Checks for a valid version 4 fingerprint which is 40 hex chars long.
 * @param  {string} data   The key id
 * @return {boolean}       If the fingerprint is valid
 */
exports.isFingerPrint = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  return /^[a-fA-F0-9]{40}$/.test(data);
};

/**
 * Checks for a valid email address.
 * @param  {string} data   The email address
 * @return {boolean}       If the email address if valid
 */
exports.isEmail = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(data);
};

/**
 * Create an error with a custom status attribute e.g. for http codes.
 * @param  {number} status    The error's http status code
 * @param  {string} message   The error message
 * @return {Error}            The resulting error object
 */
exports.throw = function(status, message) {
  let err = new Error(message);
  err.status = status;
  err.expose = true; // display message to the client
  throw err;
};

/**
 * Get the server's own origin host and protocol. Required for sending
 * verification links via email. If the PORT environmane variable
 * is set, we assume the protocol to be 'https', since the AWS loadbalancer
 * speaks 'https' externally but 'http' between the LB and the server.
 * @param  {Object} ctx   The koa request/repsonse context
 * @return {Object}       The server origin
 */
exports.getOrigin = function(ctx) {
  return {
    protocol: process.env.PORT ? 'https' : ctx.protocol,
    host: ctx.host
  };
};