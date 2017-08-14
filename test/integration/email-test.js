'use strict';

const config = require('config');
const Email = require('../../src/email/email');
const tpl = require('../../src/email/templates.json');

describe('Email Integration Tests', function() {
  this.timeout(20000);

  let email, keyId, userId, origin, publicKeyArmored;

  const recipient = { name:'Test User', email:'safewithme.testuser@gmail.com' };

  before(function() {
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    origin = {
      protocol: 'http',
      host: 'localhost:' + config.server.port
    };
    email = new Email();
    email.init(config.email);
  });

  beforeEach(() => {
    keyId = '0123456789ABCDF0';
    userId = {
      name: recipient.name,
      email: recipient.email,
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
      yield email.send({ template:tpl.verifyKey, userId, keyId, origin });
    });

    it('should send pgp encrypted email', function *() {
      yield email.send({ template:tpl.verifyKey, userId, keyId, origin });
    });
  });

  describe("send verifyRemove template", () => {
    it('should send plaintext email', function *() {
      delete userId.publicKeyArmored;
      yield email.send({ template:tpl.verifyRemove, userId, keyId, origin });
    });

    it('should send pgp encrypted email', function *() {
      yield email.send({ template:tpl.verifyRemove, userId, keyId, origin });
    });
  });

});