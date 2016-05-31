'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const expect = require('chai').expect;
const log = require('npmlog');
const config = require('config');
const Email = require('../../src/dao/email');
const nodemailer = require('nodemailer');

log.level = config.log.level;

describe('Email Integration Tests', function() {
  this.timeout(20000);

  let email, credentials;

  before(() => {
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.warn('email-test', 'No credentials.json found ... skipping tests.');
      this.skip();
      return;
    }
    email = new Email(nodemailer);
    email.init({
      host: process.env.SMTP_HOST || credentials.smtp.host,
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

  describe("send", () => {
    it('should work', function *() {
      let mailOptions = {
        from: credentials.sender,
        to: credentials.sender,
        subject: 'Hello ✔', // Subject line
        text: 'Hello world 🐴', // plaintext body
        html: '<b>Hello world 🐴</b>' // html body
      };
      let info = yield email.send(mailOptions);
      expect(info).to.exist;
    });
  });

  describe("sendVerifyKey", () => {
    it('should work', function *() {
      let options = {
        userIds: [{
          name: credentials.sender.name,
          email: credentials.sender.email,
          keyid: '0123456789ABCDF0',
          nonce: 'qwertzuioasdfghjkqwertzuio'
        }],
        primaryEmail: credentials.sender.email,
        origin: {
          protocol: 'http',
          host: 'localhost:' + config.server.port
        }
      };
      yield email.sendVerifyKey(options);
    });
  });

});