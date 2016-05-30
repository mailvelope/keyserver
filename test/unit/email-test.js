'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const expect = require('chai').expect;
const log = require('npmlog');
const Email = require('../../src/dao/email');
const nodemailer = require('nodemailer');
const sinon = require('sinon');


describe('Email Unit Tests', function() {
  let email, sendFnStub;

  let sender = {
    name: 'Foo Bar',
    email: 'foo@bar.com'
  };
  let userId1 = {
    name: 'name1',
    email: 'email1',
    keyid: '0123456789ABCDF0',
    nonce: 'qwertzuioasdfghjkqwertzuio'
  };
  let userId2 = {
    name: 'name2',
    email: 'email2',
    keyid: '0123456789ABCDF0',
    nonce: 'qwertzuioasdfghjkqwertzuio'
  };
  let origin = {
    protocol: 'http',
    host: 'localhost:8888'
  };
  let mailOptions = {
    from: sender,
    to: sender,
    subject: 'Hello ✔', // Subject line
    text: 'Hello world 🐴', // plaintext body
    html: '<b>Hello world 🐴</b>' // html body
  };

  beforeEach(function() {
    sendFnStub = sinon.stub();
    sinon.stub(nodemailer, 'createTransport').returns({
      templateSender: function() { return sendFnStub; }
    });

    sinon.stub(log, 'warn');
    sinon.stub(log, 'error');

    email = new Email(nodemailer);
    email.init({
      host: 'host',
      auth: { user:'user', pass:'pass' },
      sender: sender
    });
    expect(email._sender).to.equal(sender);
  });

  afterEach(function() {
    nodemailer.createTransport.restore();
    log.warn.restore();
    log.error.restore();
  });

  describe("sendVerifyKey", function() {

    beforeEach(function() {
      sinon.stub(email, '_sendVerifyKeyHelper').returns(Promise.resolve({ response:'250' }));
    });

    afterEach(function() {
      email._sendVerifyKeyHelper.restore();
    });

    it('should send one email if primary email is given', function *() {
      let options = {
        userIds: [userId1, userId2],
        primaryEmail: userId1.email,
        origin: origin
      };
      yield email.sendVerifyKey(options);

      expect(email._sendVerifyKeyHelper.withArgs(userId1, origin).calledOnce).to.be.true;
    });

    it('should send two emails if primary email is not given', function *() {
      let options = {
        userIds: [userId1, userId2],
        origin: origin
      };
      yield email.sendVerifyKey(options);

      expect(email._sendVerifyKeyHelper.calledTwice).to.be.true;
    });

    it('should send two emails if primary email does not match', function *() {
      let options = {
        userIds: [userId1, userId2],
        primaryEmail: 'other',
        origin: origin
      };
      yield email.sendVerifyKey(options);

      expect(email._sendVerifyKeyHelper.calledTwice).to.be.true;
    });
  });

  describe("_sendVerifyKeyHelper", function() {
    beforeEach(function() {
      sinon.stub(email, 'send').returns(Promise.resolve({ response:'250' }));
    });

    afterEach(function() {
      email.send.restore();
    });

    it('should work', function *() {
      let info = yield email._sendVerifyKeyHelper(userId1, origin);

      expect(info.response).to.match(/^250/);
    });
  });

  describe("sendVerifyRemove", function() {
    beforeEach(function() {
      sinon.stub(email, 'send').returns(Promise.resolve({ response:'250' }));
    });

    afterEach(function() {
      email.send.restore();
    });

    it('should work', function *() {
      let info = yield email.sendVerifyRemove({userId:userId1, origin});

      expect(info.response).to.match(/^250/);
    });
  });

  describe("send", function() {
    it('should work', function *() {
      sendFnStub.returns(Promise.resolve({ response:'250' }));

      let info = yield email.send(mailOptions);

      expect(info.response).to.match(/^250/);
    });

    it('should log warning for reponse error', function *() {
      sendFnStub.returns(Promise.resolve({ response:'554' }));

      let info = yield email.send(mailOptions);

      expect(info.response).to.match(/^554/);
      expect(log.warn.calledOnce).to.be.true;
    });

    it('should fail', function *() {
      sendFnStub.returns(Promise.reject(new Error('boom')));

      try {
        yield email.send(mailOptions);
      } catch(e) {
        expect(log.error.calledOnce).to.be.true;
        expect(e.status).to.equal(500);
        expect(e.message).to.match(/failed/);
      }
    });
  });

});