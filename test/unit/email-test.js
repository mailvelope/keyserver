'use strict';

const log = require('npmlog');
const Email = require('../../src/email/email');
const nodemailer = require('nodemailer');

describe('Email Unit Tests', () => {
  let email;
  let sendFnStub;

  const template = {
    subject: 'foo',
    text: 'bar',
    html: '<strong>bar</strong>'
  };
  const sender = {
    name: 'Foo Bar',
    email: 'foo@bar.com'
  };
  const userId1 = {
    name: 'name1',
    email: 'email1',
    nonce: 'qwertzuioasdfghjkqwertzuio'
  };
  const keyId = '0123456789ABCDF0';
  const origin = {
    protocol: 'http',
    host: 'localhost:8888'
  };
  const mailOptions = {
    from: sender,
    to: sender,
    subject: 'Hello ✔', // Subject line
    text: 'Hello world 🐴', // plaintext body
    html: '<b>Hello world 🐴</b>' // html body
  };

  beforeEach(() => {
    sendFnStub = sinon.stub();
    sinon.stub(nodemailer, 'createTransport').returns({
      templateSender: () => sendFnStub
    });

    sinon.stub(log, 'warn');
    sinon.stub(log, 'error');

    email = new Email(nodemailer);
    email.init({
      host: 'host',
      auth: {user: 'user', pass: 'pass'},
      sender
    });
    expect(email._sender).to.equal(sender);
  });

  afterEach(() => {
    nodemailer.createTransport.restore();
    log.warn.restore();
    log.error.restore();
  });

  describe("send", () => {
    beforeEach(() => {
      sinon.stub(email, '_sendHelper').returns(Promise.resolve({response: '250'}));
    });

    afterEach(() => {
      email._sendHelper.restore();
    });

    it('should work', function *() {
      const info = yield email.send({template, userId: userId1, keyId, origin});

      expect(info.response).to.match(/^250/);
    });
  });

  describe("_sendHelper", () => {
    it('should work', function *() {
      sendFnStub.returns(Promise.resolve({response: '250'}));

      const info = yield email._sendHelper(mailOptions);

      expect(info.response).to.match(/^250/);
    });

    it('should log warning for reponse error', function *() {
      sendFnStub.returns(Promise.resolve({response: '554'}));

      const info = yield email._sendHelper(mailOptions);

      expect(info.response).to.match(/^554/);
      expect(log.warn.calledOnce).to.be.true;
    });

    it('should fail', function *() {
      sendFnStub.returns(Promise.reject(new Error('boom')));

      try {
        yield email._sendHelper(mailOptions);
      } catch (e) {
        expect(log.error.calledOnce).to.be.true;
        expect(e.status).to.equal(500);
        expect(e.message).to.match(/failed/);
      }
    });
  });
});
