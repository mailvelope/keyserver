/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const log = require('../lib/log');
const util = require('../lib/util');
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
   * @param {Object} template         the email template function to use
   * @param {Object} userId           recipient user id object: { name:'Jon Smith', email:'j@smith.com' }
   * @param {string} keyId            key id of public key
   * @param {string} publicKeyArmored public key of recipient
   * @param {Object} origin           origin of the server
   * @yield {Object}            reponse object containing SMTP info
   */
  async send({template, userId, keyId, origin, publicKeyArmored, i18n}) {
    const compiled = template({
      ...userId,
      origin,
      keyId,
      i18n
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
    const {keys: [key], err} = await openpgp.key.readArmored(publicKeyArmored);
    if (err) {
      log.warning('Reading armored key for message encryption returned error\n%s\n%s', err, publicKeyArmored);
    }
    const now = new Date();
    // set message creation date if key has been created with future creation date
    const msgCreationDate = key.primaryKey.created > now ? key.primaryKey.created : now;
    try {
      const ciphertext = await openpgp.encrypt({
        message: openpgp.message.fromText(plaintext),
        publicKeys: key,
        date: msgCreationDate
      });
      return ciphertext.data;
    } catch (error) {
      log.error('Encrypting message for verification email failed\n%s\n%s', error, publicKeyArmored);
      throw Boom.boomify(error, {statusCode: 400, message: 'Encrypting message for verification email failed.'});
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
        log.warning('Message may not have been received: %s', info.response);
      }
      return info;
    } catch (error) {
      log.error('Sending message failed\n%s', error);
      throw Boom.badImplementation('Sending email to user failed');
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
