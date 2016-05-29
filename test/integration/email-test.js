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

  before(function() {
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.warn('email-test', 'No credentials.json found ... skipping tests.');
      this.skip();
      return;
    }
    email = new Email(nodemailer);
    email.init({
      host: credentials.smtp.host,
      auth: {
        user: credentials.smtp.user,
        pass: credentials.smtp.pass
      },
      sender: credentials.sender
    });
  });

  describe("send", function() {
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

  describe("sendVerification", function() {
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
      yield email.sendVerification(options);
    });
  });

});