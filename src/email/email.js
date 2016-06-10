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
const nodemailer = require('nodemailer');
const openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;

/**
 * A simple wrapper around Nodemailer to send verification emails
 */
class Email {

  /**
   * Create an instance of the reusable nodemailer SMTP transport.
   * @param {string}  host       SMTP server's hostname: 'smtp.gmail.com'
   * @param {Object}  auth       Auth credential: { user:'user@gmail.com', pass:'pass' }
   * @param {Object}  sender     message 'FROM' field: { name:'Your Support', email:'noreply@exmple.com' }
   * @param {string}  port       (optional) SMTP server's SMTP port. Defaults to 465.
   * @param {boolean} tls        (optional) if TSL should be used. Defaults to true.
   * @param {boolean} starttls   (optional) force STARTTLS to prevent downgrade attack. Defaults to true.
   * @param {boolean} pgp        (optional) if outgoing emails are encrypted to the user's public key.
   */
  init(options) {
    this._transport = nodemailer.createTransport({
      host: options.host,
      port: options.port || 465,
      auth: options.auth,
      secure: (options.tls !== undefined) ? util.isTrue(options.tls) : true,
      requireTLS: (options.starttls !== undefined) ? util.isTrue(options.starttls) : true,
    });
    if (util.isTrue(options.pgp)) {
      this._transport.use('stream', openpgpEncrypt());
    }
    this._sender = options.sender;
  }

  /**
   * Send the verification email to the user using a template.
   * @param {Object} template   the email template to use
   * @param {Object} userId     user id document
   * @param {string} keyId      key id of public key
   * @param {Object} origin     origin of the server
   * @yield {Object}            send response from the SMTP server
   */
  *send(options) {
    let template = options.template, userId = options.userId, keyId = options.keyId, origin = options.origin;
    let message = {
      from: this._sender,
      to: userId,
      subject: template.subject,
      text: template.text,
      html: template.html,
      params: {
        name: userId.name,
        baseUrl: util.url(origin),
        keyId: keyId,
        nonce: userId.nonce
      }
    };
    return yield this._sendHelper(message);
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
  *_sendHelper(options) {
    let template = {
      subject: options.subject,
      text: options.text,
      html: options.html,
      encryptionKeys: [options.to.publicKeyArmored]
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