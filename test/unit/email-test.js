'use strict';

const log = require('winston');
const Email = require('../../src/email/email');
const nodemailer = require('nodemailer');

describe('Email Unit Tests', () => {
  let sandbox;
  let email;
  let sendFnStub;

  const template = () => ({
    subject: 'foo',
    text: 'bar',
    html: '<strong>bar</strong>'
  });
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
    sandbox = sinon.sandbox.create();

    sendFnStub = sinon.stub();
    sandbox.stub(nodemailer, 'createTransport').returns({
      sendMail: sendFnStub
    });

    sandbox.stub(log);

    email = new Email(nodemailer);
    email.init({
      host: 'host',
      auth: {user: 'user', pass: 'pass'},
      sender
    });
    expect(email._sender).to.equal(sender);
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe("send", () => {
    beforeEach(() => {
      sandbox.stub(email, '_sendHelper').returns(Promise.resolve({response: '250'}));
    });

    it('should work', async () => {
      const info = await email.send({template, userId: userId1, keyId, origin});

      expect(info.response).to.match(/^250/);
    });
  });

  describe("_sendHelper", () => {
    it('should work', async () => {
      sendFnStub.returns(Promise.resolve({response: '250'}));

      const info = await email._sendHelper(mailOptions);

      expect(info.response).to.match(/^250/);
    });

    it('should log warning for reponse error', async () => {
      sendFnStub.returns(Promise.resolve({response: '554'}));

      const info = await email._sendHelper(mailOptions);

      expect(info.response).to.match(/^554/);
      expect(log.warn.calledOnce).to.be.true;
    });

    it('should fail', async () => {
      sendFnStub.returns(Promise.reject(new Error('boom')));

      try {
        await email._sendHelper(mailOptions);
      } catch (e) {
        expect(log.error.calledOnce).to.be.true;
        expect(e.status).to.equal(500);
        expect(e.message).to.match(/failed/);
      }
    });
  });
});
