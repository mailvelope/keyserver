'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const expect = require('chai').expect;
const log = require('npmlog');
const config = require('config');
const Email = require('../../src/email/email');
const nodemailer = require('nodemailer');
const openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;
const tpl = require('../../src/email/templates.json');

log.level = config.log.level;

describe('Email Integration Tests', function() {
  this.timeout(20000);

  let email, credentials, userId, origin, publicKeyArmored;

  before(function() {
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.info('email-test', 'No credentials.json found ... using environment vars.');
    }
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    origin = {
      protocol: 'http',
      host: 'localhost:' + config.server.port
    };
    email = new Email(nodemailer, openpgpEncrypt);
    email.init({
      host: process.env.SMTP_HOST || credentials.smtp.host,
      port: process.env.SMTP_PORT || credentials.smtp.port,
      tls: (process.env.SMTP_TLS || credentials.smtp.tls) === 'true',
      starttls: (process.env.SMTP_STARTTLS || credentials.smtp.starttls) === 'true',
      pgp: (process.env.SMTP_PGP || credentials.smtp.pgp) === 'true',
      auth: {
        user: process.env.SMTP_USER || credentials.smtp.user,
        pass: process.env.SMTP_PASS || credentials.smtp.pass
      },
      sender: {
        name: process.env.SENDER_NAME || credentials.sender.name,
        email: process.env.SENDER_EMAIL || credentials.sender.email
      }
    });
  });

  beforeEach(() => {
    userId = {
      name: credentials.sender.name,
      email: credentials.sender.email,
      keyid: '0123456789ABCDF0',
      nonce: 'qwertzuioasdfghjkqwertzuio',
      publicKeyArmored
    };
  });

  describe("_sendHelper", () => {
    it('should work', function *() {
      let mailOptions = {
        from: credentials.sender,
        to: credentials.sender,
        subject: 'Hello ✔', // Subject line
        text: 'Hello world 🐴', // plaintext body
        html: '<b>Hello world 🐴</b>' // html body
      };
      let info = yield email._sendHelper(mailOptions);
      expect(info).to.exist;
    });
  });

  describe("send verifyKey template", () => {
    it('should send plaintext email', function *() {
      delete userId.publicKeyArmored;
      yield email.send({ template:tpl.verifyKey, userId, origin });
    });

    it('should send pgp encrypted email', function *() {
      yield email.send({ template:tpl.verifyKey, userId, origin });
    });
  });

  describe("send verifyRemove template", () => {
    it('should send plaintext email', function *() {
      delete userId.publicKeyArmored;
      yield email.send({ template:tpl.verifyRemove, userId, origin });
    });

    it('should send pgp encrypted email', function *() {
      yield email.send({ template:tpl.verifyRemove, userId, origin });
    });
  });

});