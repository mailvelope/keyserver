'use strict';

const config = require('../../config/config');
const Email = require('../../src/modules/email');
const log = require('../../src/lib/log');
const Mongo = require('../../src/modules/mongo');
const nodemailer = require('nodemailer');
const openpgp = require('openpgp');
const util = require('../../src/lib/util');
const PGP = require('../../src/modules/pgp');
const PublicKey = require('../../src/modules/public-key');
const PurifyKey = require('../../src/modules/purify-key');
const templates = require('../../src/lib/templates');

describe('Public Key Integration Tests', function() {
  this.timeout(20000);

  let publicKey;
  let email;
  let mongo;
  let pgp;
  let purify;
  let sendEmailStub;
  let publicKeyArmored;
  let publicKeyArmored2;
  let mailsSent;
  const i18n = {
    __: key => key,
    __mf: key => key
  };

  const DB_TYPE = 'publickey';
  const primaryEmail = 'test1@example.com';
  const origin = {host: 'localhost', protocol: 'http'};
  const conf = structuredClone(config);

  before(async () => {
    publicKeyArmored = require('fs').readFileSync(`${__dirname}/../fixtures/key3.asc`, 'utf8');
    publicKeyArmored2 = require('fs').readFileSync(`${__dirname}/../fixtures/key4.asc`, 'utf8');
    mongo = new Mongo();
    conf.mongo.uri = `${config.mongo.uri}-int`;
    await mongo.init(conf.mongo);
  });

  beforeEach(async () => {
    await mongo.clear(DB_TYPE);
    sinon.stub(log);
    mailsSent = [];
    const paramMatcher = sinon.match(params => {
      mailsSent[mailsSent.length] = {params};
      expect(params.nonce).to.exist;
      expect(params.keyId).to.exist;
      return true;
    });
    sinon.spy(templates, 'verifyKey').withArgs(paramMatcher);
    sinon.spy(templates, 'verifyRemove').withArgs(paramMatcher);
    sendEmailStub = sinon.stub().returns(Promise.resolve({response: '250'}));
    sendEmailStub.withArgs(sinon.match(sendOptions => {
      mailsSent[mailsSent.length - 1].to = sendOptions.to.address;
      return true;
    }));
    sinon.stub(nodemailer, 'createTransport').returns({
      sendMail: sendEmailStub
    });
    email = new Email(nodemailer);
    email.init({
      host: 'localhost',
      auth: {user: 'user', pass: 'pass'},
      sender: {name: 'Foo Bar', emails: 'foo@bar.com'}
    });
    purify = new PurifyKey(conf.purify);
    pgp = new PGP(purify);
    publicKey = new PublicKey(pgp, mongo, email);
    await publicKey.init();
  });

  afterEach(() => {
    sinon.restore();
  });

  after(async () => {
    await mongo.clear(DB_TYPE);
    await mongo.disconnect();
  });

  describe('put', () => {
    it('should persist key and send verification email', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      expect(mailsSent.length).to.equal(4);
    });

    it('should work twice if not yet verified', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      expect(mailsSent.length).to.equal(4);
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      expect(mailsSent.length).to.equal(8);
    });

    it('should work for a key with an existing/verified email address to allow key update without an extra delete step in between', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      await publicKey.verify(mailsSent[1].params);
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin, i18n});
      expect(mailsSent.length).to.equal(5);
    });

    it('should work for key generated 1d in the future', async () => {
      const tomorrow = util.getTomorrow();
      const {publicKey: pubKey} = await openpgp.generateKey({
        userIDs: [{name: 'Demo', email: 'demo@mailvelope.com'}],
        passphrase: '1234',
        date: tomorrow
      });
      await publicKey.put({emails: [], publicKeyArmored: pubKey, origin, i18n});
      expect(mailsSent.length).to.equal(1);
    });
  });

  describe('Set verifyUntil date', () => {
    it('should set verifyUntil date for new unverified key', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const gotten = await mongo.get({keyId: mailsSent[0].params.keyId}, DB_TYPE);
      const verifyUntil = new Date(gotten.uploaded);
      verifyUntil.setDate(gotten.uploaded.getDate() + config.publicKey.purgeTimeInDays);
      expect(gotten.verifyUntil).to.eql(verifyUntil);
    });

    it('Update of unverified key should replace key and set new verifyUntil date', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      // update entry with same key
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const gotten = await mongo.get({keyId: mailsSent[0].params.keyId}, DB_TYPE);
      const verifyUntil = new Date(gotten.uploaded);
      verifyUntil.setDate(gotten.uploaded.getDate() + config.publicKey.purgeTimeInDays);
      expect(gotten.verifyUntil).to.eql(verifyUntil);
    });

    it('Verify should set the verifyUntil date to null', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const emailParams = mailsSent[0].params;
      await publicKey.verify(emailParams);
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.verifyUntil).to.be.null;
    });

    it('Reupload of verified key should delete the verifyUntil field', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const emailParams = mailsSent[0].params;
      await publicKey.verify(emailParams);
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.verifyUntil).to.be.undefined;
    });
  });

  describe('verify', () => {
    it('should update the document', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const emailParams = mailsSent[0].params;
      await publicKey.verify(emailParams);
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.true;
      expect(gotten.userIds[0].nonce).to.be.null;
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should not find the document', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      const emailParams = mailsSent[0].params;
      try {
        await publicKey.verify({keyId: emailParams.keyId, nonce: 'fake_nonce'});
        expect(true).to.be.false;
      } catch (e) {
        expect(e.isBoom).to.be.true;
        expect(e.output.statusCode).to.equal(404);
      }
      const gotten = await mongo.get({keyId: emailParams.keyId}, DB_TYPE);
      expect(gotten.userIds[0].verified).to.be.false;
      expect(gotten.userIds[0].nonce).to.equal(emailParams.nonce);
      expect(gotten.userIds[1].verified).to.be.false;
      expect(gotten.userIds[1].nonce).to.exist;
    });

    it('should verify a second key for an already verified user id and delete the old key', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      await publicKey.verify(mailsSent[1].params);
      let firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.exist;
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin, i18n});
      await publicKey.verify(mailsSent[4].params);
      firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.not.exist;
      const secondKey = await publicKey.getVerified({keyId: mailsSent[4].params.keyId});
      expect(secondKey).to.exist;
    });

    it('should delete other keys with the same user id when verifying', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin, i18n});
      expect(mailsSent[1].to).to.equal(mailsSent[4].to);
      await publicKey.verify(mailsSent[1].params);
      const firstKey = await publicKey.getVerified({keyId: mailsSent[1].params.keyId});
      expect(firstKey).to.exist;
      const secondKey = await mongo.get({keyId: mailsSent[4].params.keyId}, DB_TYPE);
      expect(secondKey).to.not.exist;
    });

    it('should be able to verify multiple user ids', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
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
        await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
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
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      emailParams = mailsSent[0].params;
    });

    it('should return verified key by key id', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({keyId: emailParams.keyId, i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by key id (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({keyId: emailParams.keyId.toUpperCase(), i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint', async () => {
      await publicKey.verify(emailParams);
      const fingerprint = (await pgp.parseKey(publicKeyArmored)).fingerprint;
      const key = await publicKey.get({fingerprint, i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by fingerprint (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const fingerprint = (await pgp.parseKey(publicKeyArmored)).fingerprint.toUpperCase();
      const key = await publicKey.get({fingerprint, i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({email: primaryEmail, i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should return verified key by email address (uppercase)', async () => {
      await publicKey.verify(emailParams);
      const key = await publicKey.get({email: primaryEmail.toUpperCase(), i18n});
      expect(key.publicKeyArmored).to.exist;
    });

    it('should throw 404 for unverified key', async () => {
      try {
        await publicKey.get({keyId: emailParams.keyId, i18n});
        expect(false).to.be.true;
      } catch (e) {
        expect(e.isBoom).to.be.true;
        expect(e.output.statusCode).to.equal(404);
      }
    });
  });

  describe('requestRemove', () => {
    let keyId;

    beforeEach(async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      keyId = mailsSent[0].params.keyId;
    });

    it('should work for verified key', async () => {
      await publicKey.verify(mailsSent[0].params);
      await publicKey.requestRemove({keyId, origin, i18n});
      expect(mailsSent.length).to.equal(8);
    });

    it('should work for unverified key', async () => {
      await publicKey.requestRemove({keyId, origin, i18n});
      expect(mailsSent.length).to.equal(8);
    });

    it('should work by email address', async () => {
      await publicKey.requestRemove({email: primaryEmail, origin, i18n});
      expect(mailsSent.length).to.equal(5);
    });

    it('should throw 404 for no key', async () => {
      await mongo.remove({keyId}, DB_TYPE);
      try {
        await publicKey.requestRemove({keyId, origin, i18n});
        expect(false).to.be.true;
      } catch (e) {
        expect(e.isBoom).to.be.true;
        expect(e.output.statusCode).to.equal(404);
      }
    });
  });

  describe('verifyRemove', () => {
    let keyId;

    beforeEach(async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      keyId = mailsSent[0].params.keyId;
    });

    afterEach(() => {
      mailsSent = [];
    });

    it('should remove unverified user ID', async () => {
      await publicKey.requestRemove({keyId, origin, i18n});
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
      await publicKey.requestRemove({keyId, origin, i18n});
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
      await publicKey.requestRemove({keyId, origin, i18n});
      await publicKey.verifyRemove(mailsSent[5].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds[0].email).to.equal(emails[0]);
      expect(modifiedKey.userIds[1].email).to.not.equal(emails[1]);
      expect(modifiedKey.publicKeyArmored).not.to.be.null;
      const keyFromModifiedArmored = await pgp.parseKey(modifiedKey.publicKeyArmored);
      expect(keyFromModifiedArmored.userIds.filter(userId => emails.includes(userId.email)).length).to.equal(1);
    });

    it('should remove key', async () => {
      await publicKey.requestRemove({keyId, origin, i18n});
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
        expect(e.isBoom).to.be.true;
        expect(e.output.statusCode).to.equal(404);
      }
    });

    it('should reset verifyUntil date if only verified user ID removed', async () => {
      await publicKey.verify(mailsSent[0].params);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key.userIds[0].verified).to.be.true;
      expect(key.userIds).to.have.lengthOf(4);
      expect(key.verifyUntil).to.be.null;
      expect(key.publicKeyArmored).to.exist;
      await publicKey.requestRemove({keyId, email: key.userIds[0].email, origin, i18n});
      await publicKey.verifyRemove(mailsSent[4].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds).to.have.lengthOf(3);
      const verifyUntil = new Date(key.uploaded);
      verifyUntil.setDate(key.uploaded.getDate() + config.publicKey.purgeTimeInDays);
      expect(modifiedKey.verifyUntil).to.eql(verifyUntil);
      expect(modifiedKey.publicKeyArmored).to.be.null;
    });

    it('should not reset verifyUntil date if at least one verified user ID remain', async () => {
      await publicKey.verify(mailsSent[0].params);
      await publicKey.verify(mailsSent[1].params);
      const key = await mongo.get({keyId}, DB_TYPE);
      expect(key.userIds[0].verified).to.be.true;
      expect(key.userIds[1].verified).to.be.true;
      expect(key.userIds).to.have.lengthOf(4);
      expect(key.verifyUntil).to.be.null;
      expect(key.publicKeyArmored).to.exist;
      await publicKey.requestRemove({keyId, email: key.userIds[0].email, origin, i18n});
      await publicKey.verifyRemove(mailsSent[4].params);
      const modifiedKey = await mongo.get({keyId}, DB_TYPE);
      expect(modifiedKey.userIds).to.have.lengthOf(3);
      expect(modifiedKey.verifyUntil).to.be.null;
      expect(modifiedKey.publicKeyArmored).to.exist;
    });
  });

  describe('checkCollision', () => {
    it('should throw error if key exists with same key ID but different fingerprint', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      sinon.stub(pgp, 'parseKey').returns(Promise.resolve({keyId: mailsSent[0].params.keyId, fingerprint: '123', publicKeyArmored, userIds: [{email: mailsSent[0].params.email}]}));
      await expect(publicKey.put({emails: [], publicKeyArmored, origin, i18n})).to.eventually.be.rejectedWith('Key ID collision error: a key ID of this key already exists on the server.');
    });

    it('should throw error if key exists that has same primary key fingerprint as a subkey fingerprint of a new key', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      sinon.stub(pgp, 'readKey').returns(Promise.resolve({
        subkeys: [{
          getFingerprint: () => '04062c70b446e33016e219a74001a127a90de8e1',
          getKeyID: () => ({
            toHex: () => '123'
          })
        }]
      }));
      await expect(publicKey.checkCollision({})).to.eventually.be.rejectedWith('Key ID collision error: a key ID of this key already exists on the server.');
    });

    it('should throw error if key exists that has same primary key ID as a subkey ID of a new key', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      sinon.stub(pgp, 'readKey').returns(Promise.resolve({
        subkeys: [{
          getFingerprint: () => '123',
          getKeyID: () => ({
            toHex: () => '4001a127a90de8e1'
          })
        }]
      }));
      await expect(publicKey.checkCollision({})).to.eventually.be.rejectedWith('Key ID collision error: a key ID of this key already exists on the server.');
    });
  });

  describe('enforceRateLimit', () => {
    it('should throw error if more than uploadRateLimit keys exist on the server', async () => {
      await publicKey.put({emails: [], publicKeyArmored, origin, i18n});
      await publicKey.put({emails: [], publicKeyArmored: publicKeyArmored2, origin, i18n});
      config.publicKey.uploadRateLimit = 1;
      await expect(publicKey.enforceRateLimit({userIds: [{email: 'test1@example.com'}, {email: 'test2@example.com'}]})).to.eventually.be.rejectedWith('Too many requests for this email address. Upload temporarily blocked.');
    });
  });
});
