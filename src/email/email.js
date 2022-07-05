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
const util = require('../service/util');
const openpgp = require('openpgp');
const nodemailer = require('nodemailer');

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
  init({host, port = 465, auth, tls, starttls, pgp, sender}) {
    this._transporter = nodemailer.createTransport({
      host,
      port,
      auth,
      secure: (tls !== undefined) ? util.isTrue(tls) : true,
      requireTLS: (starttls !== undefined) ? util.isTrue(starttls) : true,
    });
    this._usePGPEncryption = util.isTrue(pgp);
    this._sender = sender;
  }

  /**
   * Send the verification email to the user using a template.
   * @param {Object} template   the email template function to use
   * @param {Object} userId     recipient user id object: { name:'Jon Smith', email:'j@smith.com', publicKeyArmored:'...' }
   * @param {string} keyId      key id of public key
   * @param {Object} origin     origin of the server
   * @yield {Object}            reponse object containing SMTP info
   */
  async send({template, userId, keyId, origin, publicKeyArmored}) {
    const compiled = template({
      ...userId,
      origin,
      keyId
    });
    if (this._usePGPEncryption && publicKeyArmored) {
      compiled.text = await this._pgpEncrypt(compiled.text, publicKeyArmored);
    }
    const sendOptions = {
      from: {name: this._sender.name, address: this._sender.email},
      to: {name: userId.name, address: userId.email},
      subject: compiled.subject,
      text: compiled.text
    };
    return this._sendHelper(sendOptions);
  }

  /**
   * Encrypt the message body using OpenPGP.js
   * @param  {string} plaintext          the plaintext message body
   * @param  {string} publicKeyArmored   the recipient's public key
   * @return {string}                    the encrypted PGP message block
   */
  async _pgpEncrypt(plaintext, publicKeyArmored) {
    //const {keys: [key], err} = 
	  let key;
	  try {
    key = await openpgp.readKey({armoredKey: publicKeyArmored});
	  }	  catch (err) {
      log.error('email', 'Reading armored key failed.', err, publicKeyArmored);
    }
    const now = new Date();
    // set message creation date if key has been created with future creation date
    const msgCreationDate = key.created > now ? key.created : now;
    const crypttext = await openpgp.createMessage({text: plaintext})
    try {
      const ciphertext = await openpgp.encrypt({
        message: crypttext,
        encryptionKeys: key,
        date: msgCreationDate
      });
      return ciphertext;
    } catch (error) {
      console.log(error);
      log.error('email', 'Encrypting message failed.', error, publicKeyArmored);
      util.throw(400, 'Encrypting message for verification email failed.', error);
    }
  }

  /**
   * A generic method to send an email message via nodemailer.
   * @param {Object} sendoptions object: { from: ..., to: ..., subject: ..., text: ... }
   * @yield {Object}           reponse object containing SMTP info
   */
  async _sendHelper(sendOptions) {
    try {
      const info = await this._transporter.sendMail(sendOptions);
      if (!this._checkResponse(info)) {
        log.warn('email', 'Message may not have been received.', info);
      }
      return info;
    } catch (error) {
      log.error('email', 'Sending message failed.', error);
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
