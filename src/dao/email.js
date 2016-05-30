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
const message = require('./message.json');

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
   * @param {string} host          SMTP server's hostname: 'smtp.gmail.com'
   * @param {Object} auth          Auth credential: { user:'user@gmail.com', pass:'pass' }
   * @param {Object} sender        message 'FROM' field: { name:'Your Support', email:'noreply@exmple.com' }
   * @param {string} port          (optional) SMTP server's SMTP port. Defaults to 465.
   * @param {boolean} secure       (optional) if TSL should be used. Defaults to true.
   * @param {boolean} requireTLS   (optional) if TSL is mandatory. Defaults to true.
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
   * Send the verification email to the user to verify email address
   * ownership. If the primary email address is provided, only one email
   * will be sent out. Otherwise all of the PGP key's user IDs will be
   * verified, resulting in an email sent per user ID.
   * @param {Array}  userIds        user id documents containing the nonces
   * @param {Array}  primaryEmail   (optional) user's primary email address
   * @param {Object} origin         Required for links to the keyserver: { protocol:'https', host:'openpgpkeys@example.com' }
   * @yield {undefined}
   */
  *sendVerifyKey(options) {
    let primaryEmail = options.primaryEmail, userIds = options.userIds, origin = options.origin;
    let primaryUserId = userIds.find(uid => uid.email === primaryEmail);
    if (primaryUserId) { // send only one email to the primary user id
      return yield this._sendVerifyKeyHelper(primaryUserId, origin);
    }
    for (let uid of userIds) {
      yield this._sendVerifyKeyHelper(uid, origin);
    }
  }

  /**
   * Helper function to send a verification message
   * @param {Object} userId   user id document
   * @param {Object} origin   origin of the server
   * @yield {Object}          send response from the SMTP server
   */
  *_sendVerifyKeyHelper(userId, origin) {
    let msg = {
      from: this._sender,
      to: userId,
      subject: message.verifyKey.subject,
      text: message.verifyKey.text,
      html: message.verifyKey.html,
      params: {
        name: userId.name,
        baseUrl: origin.protocol + '://' + origin.host,
        keyid: encodeURIComponent(userId.keyid),
        nonce: encodeURIComponent(userId.nonce)
      }
    };
    return yield this.send(msg);
  }

  /**
   * A generic method to send an email message via nodemailer.
   * @param {Object} from      sender user id object: { name:'Jon Smith', email:'j@smith.com' }
   * @param {Object} to        recipient user id object: { name:'Jon Smith', email:'j@smith.com' }
   * @param {string} subject   message subject
   * @param {string} text      message plaintext body template
   * @param {string} html      message html body template
   * @param {Object} params    (optional) nodermailer template parameters
   * @yield {Object}           reponse object containing SMTP info
   */
  *send(options) {
    let template = {
      subject: options.subject,
      text: options.text,
      html: options.html
    };
    let sender = {
      from: {
        name: options.from.name,
        address: options.from.email
      }
    };
    let recipient = {
      to: {
        name: options.to.name,
        address: options.to.email
      }
    };
    let params = options.params || {};

    try {
      let sendFn = this._transport.templateSender(template, sender);
      let info = yield sendFn(recipient, params);
      if (!this._checkResponse(info)) {
        log.warn('email', 'Message may not have been received.', info);
      }
      return info;
    } catch(error) {
      log.error('email', 'Sending message failed.', error, options);
      util.throw(500, 'Sending email to user failed');
    }
  }

  /**
   * Check if the message was sent successfully according to SMTP
   * reply codes: http://www.supermailer.de/smtp_reply_codes.htm
   * @param  {Object} info   info object return from nodemailer
   * @return {boolean}       if the message was received by the user
   */
  _checkResponse(info) {
    return /^2/.test(info.response);
  }

}

module.exports = Email;