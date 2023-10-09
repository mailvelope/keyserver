'use strict';

const config = require('../../config/config');
const Email = require('../../src/modules/email');
const tpl = require('../../src/lib/templates');

describe('Email Integration Tests', function() {
  this.timeout(20000);

  let email;
  let keyId;
  let userId;
  let origin;
  let publicKeyArmored;

  const recipient = {name: 'Mailvelope Demo', email: 'demo@mailvelope.com'};
  const i18n = {
    __: key => key,
    __mf: key => key
  };

  before(() => {
    publicKeyArmored = require('fs').readFileSync(`${__dirname}/../fixtures/key2.asc`, 'utf8');
    origin = {
      protocol: 'http',
      host: `localhost:${config.server.port}`
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

  describe('_sendHelper', () => {
    it('should work', async () => {
      const mailOptions = {
        from: {name: email._sender.name, address: email._sender.email},
        to: {name: recipient.name, address: recipient.email},
        subject: 'Hello ✔', // Subject line
        text: 'Hello world 🐴', // plaintext body
        html: '<b>Hello world 🐴</b>' // html body
      };
      const info = await email._sendHelper(mailOptions);
      expect(info).to.exist;
    });
  });

  describe('send verifyKey template', () => {
    it('should send plaintext email', async () => {
      await email.send({template: tpl.verifyKey, userId, keyId, origin, i18n});
    });

    it('should send pgp encrypted email', async () => {
      await email.send({template: tpl.verifyKey, userId, keyId, publicKeyArmored: userId.publicKeyArmored, origin, i18n});
    });
  });

  describe('send verifyRemove template', () => {
    it('should send plaintext email', async () => {
      await email.send({template: tpl.verifyRemove, userId, keyId, origin, i18n});
    });
  });
});
