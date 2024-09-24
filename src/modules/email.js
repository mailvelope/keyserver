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
   * @param {String} host       SMTP server's hostname: 'smtp.gmail.com'
   * @param {Object} auth       Auth credential: { user:'user@gmail.com', pass:'pass' }
   * @param {Object} sender     message 'FROM' field: { name:'Your Support', email:'noreply@exmple.com' }
   * @param {String} port       (optional) SMTP server's SMTP port. Defaults to 465.
   * @param {Boolean} tls       (optional) if TSL should be used. Defaults to true.
   * @param {Boolean} starttls  (optional) force STARTTLS to prevent downgrade attack. Defaults to true.
   * @param {Boolean} pgp       (optional) if outgoing emails are encrypted to the user's public key.
   */
  init({host, port = 465, auth, tls, starttls, pgp, sender}) {
    this._transporter = nodemailer.createTransport({
      host,
      port,
      auth,
      secure: tls,
      requireTLS: starttls
    });
    this._usePGPEncryption = util.isTrue(pgp);
    this._sender = sender;
  }

  /**
   * Send the verification email to the user using a template.
   * @param  {Object} template          the email template function to use
   * @param  {Object} userId            recipient user ID object: { name:'Jon Smith', email:'j@smith.com' }
   * @param  {String} keyId             key ID of public key
   * @param  {String} publicKeyArmored  public key of recipient
   * @param  {Object} origin            origin of the server
   * @return {Promise<Object>}          reponse object containing SMTP info
   */
  async send({template, userId, keyId, origin, publicKeyArmored, i18n}) {
    const compiled = template({
      ...userId,
      origin,
      keyId,
      i18n
    });
    if (this._usePGPEncryption && publicKeyArmored) {
      compiled.text = await this._pgpEncrypt(compiled.text, publicKeyArmored, i18n);
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
   * @param  {String} plaintext         the plaintext message body
   * @param  {String} publicKeyArmored  the recipient's public key
   * @return {Promise<String>}          the encrypted PGP message block
   */
  async _pgpEncrypt(plaintext, publicKeyArmored, i18n) {
    let key;
    try {
      key = await openpgp.readKey({armoredKey: publicKeyArmored});
    } catch (e) {
      log.error('Failed to parse PGP key in _pgpEncrypt\n%s\n%s', e, publicKeyArmored);
      throw Boom.badImplementation('Failed to parse PGP key');
    }
    try {
      const message = await openpgp.createMessage({text: plaintext});
      const ciphertext = await openpgp.encrypt({
        message,
        encryptionKeys: key,
        date: util.getTomorrow(),
        config: {showComment: true, commentString: `*** ${i18n.__('verify_key_comment')} ***`}
      });
      return ciphertext;
    } catch (error) {
      log.error('Encrypting message for verification email failed\n%s\n%s', error, publicKeyArmored);
      throw Boom.boomify(error, {statusCode: 400, message: 'Encrypting message for verification email failed.'});
    }
  }

  /**
   * A generic method to send an email message via nodemailer.
   * @param  {Object} sendoptions  object: { from: ..., to: ..., subject: ..., text: ... }
   * @return {Promise<Object>}     reponse object containing SMTP info
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
   * @param  {Object} info  info object return from nodemailer
   * @return {Boolean}      if the message was received by the user
   */
  _checkResponse(info) {
    return /^2/.test(info.response);
  }
}

module.exports = Email;
