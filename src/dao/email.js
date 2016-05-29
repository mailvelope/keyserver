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
const util = require('../service/util');

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
   * Create an instance of the reusable nodemailer SMTP transport.
   * @param {string} host          The SMTP server's hostname e.g. 'smtp.gmail.com'
   * @param {Object} auth          Auth credential e.g. { user:'user@gmail.com', pass:'pass' }
   * @param {Object} sender        The message 'FROM' field e.g. { name:'Your Support', email:'noreply@exmple.com' }
   * @param {string} port          (optional) The SMTP server's SMTP port. Defaults to 465.
   * @param {boolean} secure       (optional) If TSL should be used. Defaults to true.
   * @param {boolean} requireTLS   (optional) If TSL is mandatory. Defaults to true.
   */
  init(options) {
    this._transport = this._mailer.createTransport({
      host: options.host,
      port: options.port || 465,
      auth: options.auth,
      secure: options.secure || true,
      requireTLS: options.requireTLS || true
    });
    this._sender = options.sender;
  }

  /**
   * A generic method to send an email message via nodemail.
   * @param {Object} from      The sender user id object e.g. { name:'Jon Smith', email:'j@smith.com' }
   * @param {Object} to        The recipient user id object e.g. { name:'Jon Smith', email:'j@smith.com' }
   * @param {string} subject   The message subject
   * @param {string} text      The message plaintext body
   * @param {string} html      The message html body
   * @yield {Object}           The reponse object containing SMTP info
   */
  *send(options) {
    let mailOptions = {
      from: {
        name: options.from.name,
        address: options.from.email
      },
      to: {
        name: options.to.name,
        address: options.to.email
      },
      subject: options.subject,
      text: options.text,
      html: options.html
    };

    try {
      let info = yield this._transport.sendMail(mailOptions);
      log.silly('email', 'Email sent.', info);
      return info;
    } catch(error) {
      log.error('email', 'Sending email failed.', error, options);
      throw error;
    }
  }

  /**
   * Send the verification email to the user to verify email address
   * ownership. If the primary email address is provided, only one email
   * will be sent out. Otherwise all of the PGP key's user IDs will be
   * verified, resulting in an email sent per user ID.
   * @param {Array}  userIds        The user id documents containing the nonces
   * @param {Array}  primaryEmail   (optional) The user's primary email address
   * @param {Object} origin         Required for links to the keyserver e.g. { protocol:'https', host:'openpgpkeys@example.com' }
   * @yield {undefined}
   */
  *sendVerification(options) {
    let primaryEmail = options.primaryEmail, userIds = options.userIds, origin = options.origin;
    let primaryUserId = userIds.find(uid => uid.email === primaryEmail);
    if (primaryUserId) { // send only one email to the primary user id
      return yield this._sendVerificationHelper(primaryUserId, origin);
    }
    for (let uid of userIds) {
      yield this._sendVerificationHelper(uid, origin);
    }
  }

  /**
   * Help method to send a verification message
   * @param {Object} userId   The user id document
   * @param {Object} origin   The origin of the server
   * @yield {Object}          The send response from the SMTP server
   */
  *_sendVerificationHelper(userId, origin) {
    let message = this._createVerifyMessage(userId, origin);
    try {
      let info = yield this.send(message);
      if (!this._checkResponse(info)) {
        log.warn('email', 'Verification mail may not have been received.', info);
      }
      return info;
    } catch(e) {
      util.throw(500, 'Sending verification email failed');
    }
  }

  /**
   * Helper function to create a verification message object.
   * @param  {Object} userId   The user id document
   * @param  {Object} origin   The origin of the server
   * @return {Object}          The message object
   */
  _createVerifyMessage(userId, origin) {
    let verifyLink = origin.protocol + '://' + origin.host +
      '/api/v1/verify/?keyid=' + encodeURIComponent(userId.keyid) +
      '&nonce=' + encodeURIComponent(userId.nonce);
    let text = `Hey${userId.name ? ' ' + userId.name : ''},

please click here to verify your key: ${verifyLink}
`;

    return {
      from: this._sender,
      to: userId,
      subject: 'Verify Your Key',
      text: text
    };
  }

  /**
   * Check if the message was sent successfully according to SMTP
   * reply codes: http://www.supermailer.de/smtp_reply_codes.htm
   * @param  {Object} info   The info object return from nodemailer
   * @return {boolean}       If the message was received by the user
   */
  _checkResponse(info) {
    return /^2/.test(info.response);
  }

}

module.exports = Email;