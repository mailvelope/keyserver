'use strict';

const log = require('winston');
const config = require('config');
const nodemailer = require('nodemailer');
const Email = require('../../src/email/email');
const Mongo = require('../../src/dao/mongo');
const PGP = require('../../src/service/pgp');
const PublicKey = require('../../src/service/public-key');
const templates = require('../../src/email/templates');

describe('Public Key Integration Tests', function() {
  this.timeout(20000);

  const sandbox = sinon.createSandbox();
  let publicKey;
  let email;
  let mongo;
  let pgp;
  let sendEmailStub;
  let publicKeyArmored;
  let publicKeyArmored2;
  let mailsSent;
  const ctx = {__: key => key};

  const DB_TYPE = 'publickey';
  const primaryEmail = 'test1@example.com';
  const origin = {host: 'localhost', protocol: 'http'};

  before(async () => {
    publicKeyArmored = require('fs').readFileSync(`${__dirname}/../fixtures/key3.asc`, 'utf8');
    publicKeyArmored2 = require('fs').readFileSync(`${__dirname}/../fixtures/key4.asc`, 'utf8');
    sinon.stub(log, 'info');
    mongo = new Mongo();
    await mongo.init(config.mongo);
  });

  beforeEach(async () => {
    await mongo.clear(DB_TYPE);

    mailsSent = [];
    const paramMatcher = sinon.match(params => {
      mailsSent[mailsSent.length] = {params};
      expect(params.nonce).to.exist;
      expect(params.keyId).to.exist;
      return true;
    });
    const ctxMatcher = sinon.match(context => Boolean(context));
    sandbox.spy(templates, 'verifyKey').withArgs(ctxMatcher, paramMatcher);
    sandbox.spy(templates, 'verifyRemove').withArgs(ctxMatcher, paramMatcher);

    sendEmailStub = sinon.stub().returns(Promise.resolve({response: '250'}));
    sendEmailStub.withArgs(sinon.match(sendOptions => {
      mailsSent[mailsSent.length - 1].to = sendOptions.to.address;
      return true;
    }));
    sandbox.stub(nodemailer, 'createTransport').returns({
      sendMail: sendEmailStub
    });
    email = new Email(nodemailer);
    email.init({
      host: 'localhost',
      auth: {user: 'user', pass: 'pass'},
      sender: {name: 'Foo Bar', emails: 'foo@bar.com'}
    });
    pgp = new PGP();
    publicKey = new PublicKey(pgp, mongo, email);
  });

  afterEach(() => {
    sandbox.restore();
  });

  after(async () => {
    await mongo.clear(DB_TYPE);
    await mongo.disconnect();
    log.info.restore();
  });

  describe('put', () => {
    it('should persist key and send verification email', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      expect(mailsSent.length).to.equal(4);
    });

    it('should work twice if not yet verified', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      expect(mailsSent.length).to.equal(4);
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      expect(mailsSent.length).to.equal(8);
    });

    it.skip('should throw 304 if key already exists', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      await publicKey.verify(mailsSent[0].params);
      try {
        await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
        expect(false).to.be.true;
      } catch (e) {
        expect(e.status).to.equal(304);
      }
    });

    it('should work for a key with an existing/verified email address to allow key update without an extra delete step in between', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      await publicKey.verify(mailsSent[1].params);
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin}, ctx);
      expect(mailsSent.length).to.equal(5);
    });
  });

  describe('_purgeOldUnverified', () => {
    let key;

    beforeEach(async () => {
      key = await pgp.parseKey(publicKeyArmored);
    });

    it('should work for no keys', async () => {
      const r = await publicKey._purgeOldUnverified();
      expect(r.deletedCount).to.equal(0);
    });

    it('should not remove a current unverified key', async () => {
      await publicKey._persistKey(key);
      const r = await publicKey._purgeOldUnverified();
      expect(r.deletedCount).to.equal(0);
    });

    it('should not remove a current verified key', async () => {
      key.userIds[0].verified = true;
      await publicKey._persistKey(key);
      const r = await publicKey._purgeOldUnverified();
      expect(r.deletedCount).to.equal(0);
    });

    it('should not remove an old verified key', async () => {
      key.uploaded.setDate(key.uploaded.getDate() - 31);
      key.userIds[0].verified = true;
      await publicKey._persistKey(key);
      const r = await publicKey._purgeOldUnverified();
      expect(r.deletedCount).to.equal(0);
    });

    it('should remove an old unverified key', async () => {
      key.uploaded.setDate(key.uploaded.getDate() - 31);
      await publicKey._persistKey(key);
      const r = await publicKey._purgeOldUnverified();
      expect(r.deletedCount).to.equal(1);
    });
  });

  describe('verify', () => {
    it('should update the document', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      const emailParams = mailsSent[0].params;
      await publicKey.verify(emailParams);
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[0].nonce).to.be.null;
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should not find the document', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      const emailParams = mailsSent[0].params;
      try {
        await publicKey.verify({keyId: emailParams.keyId, nonce: 'fake_nonce'});
        expect(true).to.be.false;
      } catch (e) {
        expect(e.status).to.equal(404);
      }
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.false;
      expect(gotten.userIds[0].nonce).to.equal(emailParams.nonce);
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should verify a second key for an already verified user id and delete the old key', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      await publicKey.verify(mailsSent[1].params);
      let firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.exist;
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin}, ctx);
      await publicKey.verify(mailsSent[4].params);
      firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.not.exist;
      const secondKey = await publicKey.getVerified({keyId: mailsSent[4].params.keyId});
      expect(secondKey).to.exist;
    });

    it('should delete other keys with the same user id when verifying', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin}, ctx);
      expect(mailsSent[1].to).to.equal(mailsSent[4].to);
      await publicKey.verify(mailsSent[1].params);
      const firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.exist;
      const secondKey = await mongo.get({keyId: mailsSent[4].params.keyId}, DB_TYPE);
      expect(secondKey).to.not.exist;
    });

    it('should be able to verify multiple user ids', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      expect(mailsSent.length).to.equal(4);
      await publicKey.verify(mailsSent[0].params);
      await publicKey.verify(mailsSent[1].params);
      await publicKey.verify(mailsSent[2].params);
      await publicKey.verify(mailsSent[3].params);
      const gotten = await mongo.get({keyId: mailsSent[0].params.keyId}, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[1].verified).to.be.true;
      expect(gotten.userIds[2].verified).to.be.true;
      expect(gotten.userIds[3].verified).to.be.true;
    });
  });

  describe('getVerified', () => {
    let key;

    describe('should find a verified key', () => {
      beforeEach(async () => {
        key = await pgp.parseKey(publicKeyArmored);
        await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
        await publicKey.verify(mailsSent[0].params);
      });

      it('by fingerprint', async () => {
        const verified = await publicKey.getVerified({fingerprint: key.fingerprint});
        expect(verified).to.exist;
      });

      it('by all userIds', async () => {
        const verified = await publicKey.getVerified({userIds: key.userIds});
        expect(verified).to.exist;
      });

      it('by verified userId', async () => {
        const verified = await publicKey.getVerified({userIds: [key.userIds[0]]});
        expect(verified).to.exist;
      });

      it('by unverified userId', async () => {
        const verified = await publicKey.getVerified({userIds: [key.userIds[1]]});
        expect(verified).to.not.exist;
      });

      it('by keyId', async () => {
        const verified = await publicKey.getVerified({keyId: key.keyId});
        expect(verified).to.exist;
      });

      it('by all params', async () => {
        const verified = await publicKey.getVerified(key);
        expect(verified).to.exist;
      });
    });

    describe('should not find an unverified key', () => {
      beforeEach(async () => {
        key = await pgp.parseKey(publicKeyArmored);
        key.userIds[0].verified = false;
        await mongo.create(key, DB_TYPE);
      });

      it('by fingerprint', async () => {
        const verified = await publicKey.getVerified({fingerprint: key.fingerprint});
        expect(verified).to.not.exist;
      });

      it('by userIds', async () => {
        const verified = await publicKey.getVerified({userIds: key.userIds});
        expect(verified).to.not.exist;
      });

      it('by keyId', async () => {
        const verified = await publicKey.getVerified({keyId: key.keyId});
        expect(verified).to.not.exist;
      });

      it('by all params', async () => {
        const verified = await publicKey.getVerified(key);
        expect(verified).to.not.exist;
      });
    });
  });

  describe('get', () => {
    let emailParams;

    beforeEach(async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      emailParams = mailsSent[0].params;
    });

    it('should return verified key by key id', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({keyId: emailParams.keyId}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by key id (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({keyId: emailParams.keyId.toUpperCase()}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint', async () => {
      await publicKey.verify(emailParams);
      const fingerprint = (await pgp.parseKey(publicKeyArmored)).fingerprint;
      const key = await publicKey.get({fingerprint}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const fingerprint = (await pgp.parseKey(publicKeyArmored)).fingerprint.toUpperCase();
      const key = await publicKey.get({fingerprint}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({email: primaryEmail}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({email: primaryEmail.toUpperCase()}, ctx);
      expect(key.publicKeyArmored).to.exist;
    });

    it('should throw 404 for unverified key', async () => {
      try {
        await publicKey.get({keyId: emailParams.keyId}, ctx);
        expect(false).to.be.true;
      } catch (e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('requestRemove', () => {
    let keyId;

    beforeEach(async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      keyId = mailsSent[0].params.keyId;
    });

    it('should work for verified key', async () => {
      await publicKey.verify(mailsSent[0].params);
      await publicKey.requestRemove({keyId, origin}, ctx);
      expect(mailsSent.length).to.equal(8);
    });

    it('should work for unverified key', async () => {
      await publicKey.requestRemove({keyId, origin}, ctx);
      expect(mailsSent.length).to.equal(8);
    });

    it('should work by email address', async () => {
      await publicKey.requestRemove({email: primaryEmail, origin}, ctx);
      expect(mailsSent.length).to.equal(5);
    });

    it('should throw 404 for no key', async () => {
      await mongo.remove({keyId}, DB_TYPE);
      try {
        await publicKey.requestRemove({keyId, origin}, ctx);
        expect(false).to.be.true;
      } catch (e) {
        expect(e.status).to.equal(404);
      }
    });
  });

  describe('verifyRemove', () => {
    let keyId;

    beforeEach(async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin}, ctx);
      keyId = mailsSent[0].params.keyId;
    });

    afterEach(() => {
      mailsSent = [];
    });

    it('should remove unverified user ID', async () => {
      await publicKey.requestRemove({keyId, origin}, ctx);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key.userIds[0].verified).to.be.false;
      expect(key.userIds[0].email).to.equal(primaryEmail);
      await publicKey.verifyRemove(mailsSent[4].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds[0].email).to.not.equal(primaryEmail);
    });

    it('should remove single verfied user ID', async () => {
      await publicKey.verify(mailsSent[0].params);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key.userIds[0].verified).to.be.true;
      expect(key.userIds[0].email).to.equal(primaryEmail);
      const keyFromArmored = await pgp.parseKey(key.publicKeyArmored);
      expect(keyFromArmored.userIds.find(userId => userId.email === primaryEmail)).not.to.be.undefined;
      await publicKey.requestRemove({keyId, origin}, ctx);
      await publicKey.verifyRemove(mailsSent[4].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds[0].email).to.not.equal(primaryEmail);
      expect(modifiedKey.publicKeyArmored).to.be.null;
    });

    it('should remove verfied user ID', async () => {
      await publicKey.verify(mailsSent[0].params);
      await publicKey.verify(mailsSent[1].params);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key.userIds[0].verified).to.be.true;
      expect(key.userIds[1].verified).to.be.true;
      const emails = [key.userIds[0].email, key.userIds[1].email];
      const keyFromArmored = await pgp.parseKey(key.publicKeyArmored);
      expect(keyFromArmored.userIds.filter(userId => emails.includes(userId.email)).length).to.equal(2);
      await publicKey.requestRemove({keyId, origin}, ctx);
      await publicKey.verifyRemove(mailsSent[5].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds[0].email).to.equal(emails[0]);
      expect(modifiedKey.userIds[1].email).to.not.equal(emails[1]);
      expect(modifiedKey.publicKeyArmored).not.to.be.null;
      const keyFromModifiedArmored = await pgp.parseKey(modifiedKey.publicKeyArmored);
      expect(keyFromModifiedArmored.userIds.filter(userId => emails.includes(userId.email)).length).to.equal(1);
    });

    it('should remove key', async () => {
      await publicKey.requestRemove({keyId, origin}, ctx);
      await publicKey.verifyRemove(mailsSent[4].params);
      await publicKey.verifyRemove(mailsSent[5].params);
      await publicKey.verifyRemove(mailsSent[6].params);
      await publicKey.verifyRemove(mailsSent[7].params);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key).to.not.exist;
    });

    it('should throw 404 for no key', async () => {
      await mongo.remove({keyId}, DB_TYPE);
      try {
        await publicKey.verifyRemove(mailsSent[1].params);
        expect(false).to.be.true;
      } catch (e) {
        expect(e.status).to.equal(404);
      }
    });
  });
});
