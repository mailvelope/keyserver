'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const expect = require('chai').expect;
const config = require('config');
const Email = require('../../src/email/email');
const nodemailer = require('nodemailer');
const openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;
const tpl = require('../../src/email/templates.json');

describe('Email Integration Tests', function() {
  this.timeout(20000);

  let email, userId, origin, publicKeyArmored;

  const recipient = { name:'Test User', email:'safewithme.testuser@gmail.com' };

  before(function() {
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    origin = {
      protocol: 'http',
      host: 'localhost:' + config.server.port
    };
    email = new Email(nodemailer, openpgpEncrypt);
    email.init(config.email);
  });

  beforeEach(() => {
    userId = {
      name: recipient.name,
      email: recipient.email,
      keyid: '0123456789ABCDF0',
      nonce: 'qwertzuioasdfghjkqwertzuio',
      publicKeyArmored
    };
  });

  describe("_sendHelper", () => {
    it('should work', function *() {
      let mailOptions = {
        from: email._sender,
        to: recipient,
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