'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const config = require('config');
const nodemailer = require('nodemailer');
const Email = require('../../src/email/email');
const Mongo = require('../../src/dao/mongo');
const PGP = require('../../src/service/pgp');
const PublicKey = require('../../src/service/public-key');
const expect = require('chai').expect;
const sinon = require('sinon');

describe('Public Key Integration Tests', function() {
  this.timeout(20000);

  let publicKey, email, mongo, pgp,
    sendEmailStub, publicKeyArmored, emailParams;

  const DB_TYPE = 'publickey';
  const primaryEmail = 'test1@example.com';
  const origin = { host:'localhost', protocol:'http' };

  before(function *() {
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key3.asc', 'utf8');
    mongo = new Mongo();
    yield mongo.init(config.mongo);
  });

  beforeEach(function *() {
    yield mongo.clear(DB_TYPE);
    emailParams = null;
    sendEmailStub = sinon.stub().returns(Promise.resolve({ response:'250' }));
    sendEmailStub.withArgs(sinon.match(recipient => {
      return recipient.to.address === primaryEmail;
    }), sinon.match(params => {
      emailParams = params;
      return params.nonce !== undefined && params.keyId !== undefined;
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
    pgp = new PGP();
    publicKey = new PublicKey(pgp, mongo, email);
  });

  afterEach(() => {
    nodemailer.createTransport.restore();
  });

  after(function *() {
    yield mongo.clear(DB_TYPE);
    yield mongo.disconnect();
  });

  describe('put', () => {
    it('should persist key and send verification email with primaryEmail', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(emailParams.nonce).to.exist;
    });
    it('should persist key and send verification email without primaryEmail', function *() {
      yield publicKey.put({ publicKeyArmored, origin });
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
      yield publicKey.verify(emailParams);
      try {
        yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(304);
      }
    });
  });

  describe('verify', () => {
    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
    });

    it('should update the document', function *() {
      yield publicKey.verify(emailParams);
      let gotten = yield mongo.get({ keyId:emailParams.keyId }, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[0].nonce).to.be.null;
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should not find the document', function *() {
      try {
        yield publicKey.verify({ keyId:emailParams.keyId, nonce:'fake_nonce' });
        expect(true).to.be.false;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
      let gotten = yield mongo.get({ keyId:emailParams.keyId }, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.false;
      expect(gotten.userIds[0].nonce).to.equal(emailParams.nonce);
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });
  });

  describe('getVerified', () => {
    let key;

    describe('should find a verified key', () => {
      beforeEach(function *() {
        key = pgp.parseKey(publicKeyArmored);
        yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
        yield publicKey.verify(emailParams);
      });

      it('by fingerprint', function *() {
        let verified = yield publicKey.getVerified({ fingerprint:key.fingerprint });
        expect(verified).to.exist;
      });

      it('by all userIds', function *() {
        let verified = yield publicKey.getVerified({ userIds:key.userIds });
        expect(verified).to.exist;
      });

      it('by verified userId', function *() {
        let verified = yield publicKey.getVerified({ userIds:[key.userIds[0]] });
        expect(verified).to.exist;
      });

      it('by unverified userId', function *() {
        let verified = yield publicKey.getVerified({ userIds:[key.userIds[1]] });
        expect(verified).to.not.exist;
      });

      it('by keyId', function *() {
        let verified = yield publicKey.getVerified({ keyId:key.keyId });
        expect(verified).to.exist;
      });

      it('by all params', function *() {
        let verified = yield publicKey.getVerified(key);
        expect(verified).to.exist;
      });
    });

    describe('should not find an unverified key', () => {
      beforeEach(function *() {
        key = pgp.parseKey(publicKeyArmored);
        key.userIds[0].verified = false;
        yield mongo.create(key, DB_TYPE);
      });

      it('by fingerprint', function *() {
        let verified = yield publicKey.getVerified({ fingerprint:key.fingerprint });
        expect(verified).to.not.exist;
      });

      it('by userIds', function *() {
        let verified = yield publicKey.getVerified({ userIds:key.userIds });
        expect(verified).to.not.exist;
      });

      it('by keyId', function *() {
        let verified = yield publicKey.getVerified({ keyId:key.keyId });
        expect(verified).to.not.exist;
      });

      it('by all params', function *() {
        let verified = yield publicKey.getVerified(key);
        expect(verified).to.not.exist;
      });
    });
  });

  describe('get', () => {
    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
    });

    it('should return verified key by key id', function *() {
      yield publicKey.verify(emailParams);
      let key = yield publicKey.get({ keyId:emailParams.keyId });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by key id (uppercase)', function *() {
      yield publicKey.verify(emailParams);
      let key = yield publicKey.get({ keyId:emailParams.keyId.toUpperCase() });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint', function *() {
      yield publicKey.verify(emailParams);
      let fingerprint = pgp.parseKey(publicKeyArmored).fingerprint;
      let key = yield publicKey.get({ fingerprint });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint (uppercase)', function *() {
      yield publicKey.verify(emailParams);
      let fingerprint = pgp.parseKey(publicKeyArmored).fingerprint.toUpperCase();
      let key = yield publicKey.get({ fingerprint });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address', function *() {
      yield publicKey.verify(emailParams);
      let key = yield publicKey.get({ email:primaryEmail });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address (uppercase)', function *() {
      yield publicKey.verify(emailParams);
      let key = yield publicKey.get({ email:primaryEmail.toUpperCase() });
      expect(key.publicKeyArmored).to.exist;
    });

    it('should throw 404 for unverified key', function *() {
      try {
        yield publicKey.get({ keyId:emailParams.keyId });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('requestRemove', () => {
    let keyId;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      keyId = emailParams.keyId;
    });

    it('should work for verified key', function *() {
      yield publicKey.verify(emailParams);
      emailParams = null;
      yield publicKey.requestRemove({ keyId, origin });
      expect(emailParams.keyId).to.exist;
      expect(emailParams.nonce).to.exist;
    });

    it('should work for unverified key', function *() {
      emailParams = null;
      yield publicKey.requestRemove({ keyId, origin });
      expect(emailParams.keyId).to.exist;
      expect(emailParams.nonce).to.exist;
    });

    it('should work by email address', function *() {
      emailParams = null;
      yield publicKey.requestRemove({ email:primaryEmail, origin });
      expect(emailParams.keyId).to.exist;
      expect(emailParams.nonce).to.exist;
    });

    it('should throw 404 for no key', function *() {
      yield mongo.remove({ keyId }, DB_TYPE);
      try {
        yield publicKey.requestRemove({ keyId, origin });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('verifyRemove', () => {
    let keyId;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      keyId = emailParams.keyId;
      emailParams = null;
      yield publicKey.requestRemove({ keyId, origin });
    });

    it('should remove key', function *() {
      yield publicKey.verifyRemove(emailParams);
      let key = yield mongo.get({ keyId }, DB_TYPE);
      expect(key).to.not.exist;
    });

    it('should throw 404 for no key', function *() {
      yield mongo.remove({ keyId }, DB_TYPE);
      try {
        yield publicKey.verifyRemove(emailParams);
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

});