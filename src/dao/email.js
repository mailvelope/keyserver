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
 * A simple wrapper around Nodemailer to send verification emails
 */
class Email {

  /**
   * Create an instance of the email object.
   * @param  {Object} mailer   An instance of nodemailer
   */
  constructor(mailer) {
    this._mailer = mailer;
  }

  /**
   * Send the verification email to the user to verify email address
   * ownership. If the primary email address is provided, only one email
   * will be sent out. Otherwise all of the PGP key's user IDs will be
   * verified, resulting in an email sent per user ID.
   * @param {Array} options.userIds        The user id documents containing the nonces
   * @param {Array} options.primaryEmail   (optional) The user's primary email address
   * @yield {undefined}
   */
  sendVerification() {
    return Promise.resolve();
  }

  send() {

  }

}

module.exports = Email;