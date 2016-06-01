'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const log = require('npmlog');
const openpgp = require('openpgp');
const nodemailer = require('nodemailer');
const Email = require('../../src/email/email');
const Mongo = require('../../src/dao/mongo');
const UserId = require('../../src/service/user-id');
const PublicKey = require('../../src/service/public-key');
const expect = require('chai').expect;
const sinon = require('sinon');

describe('Public Key Integration Tests', function() {
  this.timeout(20000);

  let publicKey, email, mongo, userId,
    sendEmailStub, publicKeyArmored, emailParams;

  const DB_TYPE_PUB_KEY = 'publickey';
  const DB_TYPE_USER_ID = 'userid';
  const primaryEmail = 'safewithme.testuser@gmail.com';
  const origin = { host:'localhost', protocol:'http' };

  before(function *() {
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    let credentials;
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.info('mongo-test', 'No credentials.json found ... using environment vars.');
    }
    mongo = new Mongo({
      uri: process.env.MONGO_URI || credentials.mongo.uri,
      user: process.env.MONGO_USER || credentials.mongo.user,
      password: process.env.MONGO_PASS || credentials.mongo.pass
    });
    yield mongo.connect();
  });

  beforeEach(function *() {
    yield mongo.clear(DB_TYPE_PUB_KEY);
    yield mongo.clear(DB_TYPE_USER_ID);
    emailParams = null;
    sendEmailStub = sinon.stub().returns(Promise.resolve({ response:'250' }));
    sendEmailStub.withArgs(sinon.match(recipient => {
      return recipient.to.address === primaryEmail;
    }), sinon.match(params => {
      emailParams = params;
      return !!params.nonce;
    }));
    sinon.stub(nodemailer, 'createTransport').returns({
      templateSender: () => { return sendEmailStub; }
    });
    email = new Email(nodemailer);
    email.init({
      host: 'localhost',
      auth: { user:'user', pass:'pass' },
      sender: { name:'Foo Bar', email:'foo@bar.com' }
    });
    userId = new UserId(mongo);
    publicKey = new PublicKey(openpgp, mongo, email, userId);
  });

  afterEach(() => {
    nodemailer.createTransport.restore();
  });

  after(function *() {
    yield mongo.clear(DB_TYPE_PUB_KEY);
    yield mongo.clear(DB_TYPE_USER_ID);
    yield mongo.disconnect();
  });

  describe('put', () => {
    it('should persist key and send verification email', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(emailParams.nonce).to.exist;
    });

    it('should work twice if not yet verified', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(emailParams.nonce).to.exist;
      emailParams = null;
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(emailParams.nonce).to.exist;
    });

    it('should throw 304 if key already exists', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      yield userId.verify(emailParams);
      try {
        yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(304);
      }
    });
  });

  describe('get', () => {
    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
    });

    it('should return verified key by key id', function *() {
      yield userId.verify(emailParams);
      let key = yield publicKey.get({ keyid:emailParams.keyid });
      expect(key.publicKeyArmored).to.equal(publicKeyArmored);
    });

    it('should return verified key by email address', function *() {
      yield userId.verify(emailParams);
      let key = yield publicKey.get({ email:primaryEmail });
      expect(key.publicKeyArmored).to.equal(publicKeyArmored);
    });

    it('should throw 404 for unverified key', function *() {
      try {
        yield publicKey.get({ keyid:emailParams.keyid });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('requestRemove', () => {
    let keyid;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      keyid = emailParams.keyid;
    });

    it('should work for verified key', function *() {
      yield userId.verify(emailParams);
      emailParams = null;
      yield publicKey.requestRemove({ keyid, origin });
      expect(emailParams.nonce).to.exist;
    });

    it('should work for unverified key', function *() {
      emailParams = null;
      yield publicKey.requestRemove({ keyid, origin });
      expect(emailParams.nonce).to.exist;
    });

    it('should work by email address', function *() {
      emailParams = null;
      yield publicKey.requestRemove({ email:primaryEmail, origin });
      expect(emailParams.nonce).to.exist;
    });

    it('should throw 404 for no key', function *() {
      yield publicKey.remove({ keyid });
      try {
        yield publicKey.requestRemove({ keyid, origin });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('verifyRemove', () => {
    let keyid;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      keyid = emailParams.keyid;
      emailParams = null;
      yield publicKey.requestRemove({ keyid, origin });
    });

    it('should remove key', function *() {
      yield publicKey.verifyRemove(emailParams);
      let uid = yield mongo.get({ keyid }, DB_TYPE_USER_ID);
      expect(uid).to.not.exist;
      let key = yield mongo.get({ _id:keyid }, DB_TYPE_PUB_KEY);
      expect(key).to.not.exist;
    });

    it('should throw 404 for no key', function *() {
      yield publicKey.remove({ keyid });
      try {
        yield publicKey.verifyRemove(emailParams);
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('remove', () => {
    let keyid;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      keyid = emailParams.keyid;
    });

    it('should remove key', function *() {
      yield publicKey.remove({ keyid });
      let uid = yield mongo.get({ keyid }, DB_TYPE_USER_ID);
      expect(uid).to.not.exist;
      let key = yield mongo.get({ _id:keyid }, DB_TYPE_PUB_KEY);
      expect(key).to.not.exist;
    });
  });

});