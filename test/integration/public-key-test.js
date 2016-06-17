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
    sendEmailStub, publicKeyArmored, publicKeyArmored2, mailsSent;

  const DB_TYPE = 'publickey';
  const primaryEmail = 'test1@example.com';
  const primaryEmail2 = 'test2@example.com';
  const origin = { host:'localhost', protocol:'http' };

  before(function *() {
    publicKeyArmored = require('fs').readFileSync(__dirname + '/../key3.asc', 'utf8');
    publicKeyArmored2 = require('fs').readFileSync(__dirname + '/../key4.asc', 'utf8');
    mongo = new Mongo();
    yield mongo.init(config.mongo);
  });

  beforeEach(function *() {
    yield mongo.clear(DB_TYPE);
    mailsSent = [];
    sendEmailStub = sinon.stub().returns(Promise.resolve({ response:'250' }));
    sendEmailStub.withArgs(sinon.match(recipient => {
      mailsSent[mailsSent.length] = {to:recipient.to.address};
      return true;
    }), sinon.match(params => {
      mailsSent[mailsSent.length - 1].params = params;
      expect(params.nonce).to.exist;
      expect(params.keyId).to.exist;
      return true;
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
      expect(mailsSent.length).to.equal(1);
      expect(mailsSent[0].to).to.equal(primaryEmail);
      expect(mailsSent[0].params.keyId).to.exist;
      expect(mailsSent[0].params.nonce).to.exist;
    });
    it('should persist key and send verification email without primaryEmail', function *() {
      yield publicKey.put({ publicKeyArmored, origin });
      expect(mailsSent.length).to.equal(4);
    });

    it('should work twice if not yet verified', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(mailsSent.length).to.equal(1);
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      expect(mailsSent.length).to.equal(2);
    });

    it('should throw 304 if key already exists', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      yield publicKey.verify(mailsSent[0].params);
      try {
        yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(304);
      }
    });
  });

  describe('verify', () => {
    it('should update the document', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      let emailParams = mailsSent[0].params;
      yield publicKey.verify(emailParams);
      let gotten = yield mongo.get({ keyId:emailParams.keyId }, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[0].nonce).to.be.null;
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should not find the document', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      let emailParams = mailsSent[0].params;
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

    it('should not verify a second key for already verified user id of another key', function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail:primaryEmail2, origin });
      expect(mailsSent.length).to.equal(1);
      yield publicKey.put({ publicKeyArmored:publicKeyArmored2, primaryEmail:primaryEmail2, origin });
      expect(mailsSent.length).to.equal(2);
      yield publicKey.verify(mailsSent[1].params);

      try {
        yield publicKey.verify(mailsSent[0].params);
        expect(true).to.be.false;
      } catch(e) {
        expect(e.status).to.equal(304);
      }
      let gotten = yield mongo.get({ keyId:mailsSent[0].params.keyId }, DB_TYPE);
      expect(gotten.userIds[1].email).to.equal(primaryEmail2);
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.equal(mailsSent[0].params.nonce);
    });

    it('should be able to verify multiple user ids', function *() {
      yield publicKey.put({ publicKeyArmored, origin });
      expect(mailsSent.length).to.equal(4);
      yield publicKey.verify(mailsSent[0].params);
      yield publicKey.verify(mailsSent[1].params);
      yield publicKey.verify(mailsSent[2].params);
      yield publicKey.verify(mailsSent[3].params);
      let gotten = yield mongo.get({ keyId:mailsSent[0].params.keyId }, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[1].verified).to.be.true;
      expect(gotten.userIds[2].verified).to.be.true;
      expect(gotten.userIds[3].verified).to.be.true;
    });

  });

  describe('getVerified', () => {
    let key;

    describe('should find a verified key', () => {
      beforeEach(function *() {
        key = pgp.parseKey(publicKeyArmored);
        yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
        yield publicKey.verify(mailsSent[0].params);
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
    let emailParams;

    beforeEach(function *() {
      yield publicKey.put({ publicKeyArmored, primaryEmail, origin });
      emailParams = mailsSent[0].params;
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
      keyId = mailsSent[0].params.keyId;
    });

    it('should work for verified key', function *() {
      yield publicKey.verify(mailsSent[0].params);
      yield publicKey.requestRemove({ keyId, origin });
      expect(mailsSent.length).to.equal(5);
    });

    it('should work for unverified key', function *() {
      yield publicKey.requestRemove({ keyId, origin });
      expect(mailsSent.length).to.equal(5);
    });

    it('should work by email address', function *() {
      yield publicKey.requestRemove({ email:primaryEmail, origin });
      expect(mailsSent.length).to.equal(2);
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
      keyId = mailsSent[0].params.keyId;
      yield publicKey.requestRemove({ keyId, origin });
    });

    it('should remove key', function *() {
      yield publicKey.verifyRemove(mailsSent[1].params);
      let key = yield mongo.get({ keyId }, DB_TYPE);
      expect(key).to.not.exist;
    });

    it('should throw 404 for no key', function *() {
      yield mongo.remove({ keyId }, DB_TYPE);
      try {
        yield publicKey.verifyRemove(mailsSent[1].params);
        expect(false).to.be.true;
      } catch(e) {
        expect(e.status).to.equal(404);
      }
    });
  });

});