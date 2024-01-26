'use strict';

const fs = require('fs');
const log = require('../../src/lib/log');
const config = require('../../config/config');
const openpgp = require('openpgp');
const PGP = require('../../src/modules/pgp');
const PurifyKey = require('../../src/modules/purify-key');
const {KEY_STATUS} = require('../../src/lib/util');

describe('PGP Unit Tests', () => {
  const sandbox = sinon.createSandbox();
  let pgp;
  let purify;
  let key1Armored;
  let key2Armored;
  let key3Armored;
  let key5Armored;
  let key6Armored;

  before(() => {
    key1Armored = fs.readFileSync(`${__dirname}/../fixtures/key1.asc`, 'utf8');
    key2Armored = fs.readFileSync(`${__dirname}/../fixtures/key2.asc`, 'utf8');
    key3Armored = fs.readFileSync(`${__dirname}/../fixtures/key3.asc`, 'utf8');
    key5Armored = fs.readFileSync(`${__dirname}/../fixtures/key5.asc`, 'utf8');
    key6Armored = fs.readFileSync(`${__dirname}/../fixtures/key6.asc`, 'utf8');
  });

  beforeEach(() => {
    sandbox.stub(log);
    purify = new PurifyKey(config.purify);
    pgp = new PGP(purify);
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('parseKey', () => {
    it('should throw error on failed key parsing', async () => {
      sandbox.stub(openpgp, 'readKey').throws(new Error('test error'));
      await expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith(/Failed to read PGP key: test error/);
      expect(log.error.calledOnce).to.be.true;
    });

    it('should throw error when verifyPrimaryKey throws', () => {
      sandbox.stub(openpgp, 'readKey').returns({
        isPrivate() { return false; },
        armor() { return 'ABC'; },
        verifyPrimaryKey() { throw new Error('Invalid primary key'); }
      });
      pgp.purify.conf.purifyKey = false;
      return expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith('Invalid PGP key. Verification of the primary key failed.');
    });

    it('should not throw if key is revoked', async () => {
      const key = await pgp.parseKey(key6Armored);
      expect(key).to.exist;
    });

    it('should refuse private keys', () => {
      sandbox.stub(openpgp, 'readKey').returns({
        isPrivate() { return true; },
        armor() { return 'ABC'; }
      });
      return expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith(/Error uploading private key/);
    });

    it('should only accept valid user ids', () => {
      sandbox.stub(pgp, 'parseUserIds').returns([]);
      return expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith(/Invalid PGP key: no valid user ID with email address found/);
    });

    it('should be able to parse RSA key', async () => {
      const params = await pgp.parseKey(key1Armored);
      expect(params.keyId).to.equal('dbc0b3d92b1b86e9');
      expect(params.fingerprint).to.equal('4277257930867231ce393fb8dbc0b3d92b1b86e9');
      expect(params.userIds[0].name).to.equal('safewithme testuser');
      expect(params.userIds[0].email).to.equal('safewithme.testuser@gmail.com');
      expect(params.created.getTime()).to.exist;
      expect(params.uploaded.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsaEncryptSign');
      expect(params.keySize).to.equal(2048);
      expect(params.publicKeyArmored).to.include('PGP PUBLIC KEY');
    });

    it('should be able to parse ECC key', async () => {
      const params = await pgp.parseKey(key2Armored);
      expect(params.keyId).to.equal('4c03a47362c5b4cc');
      expect(params.fingerprint).to.equal('90507fb229658f71f3de96a84c03a47362c5b4cc');
      expect(params.userIds.length).to.equal(1);
      expect(params.created.getTime()).to.exist;
      expect(params.uploaded.getTime()).to.exist;
      expect(params.algorithm).to.equal('eddsa');
      expect(params.publicKeyArmored).to.include('PGP PUBLIC KEY');
    });

    it('should be able to parse komplex key', async () => {
      const params = await pgp.parseKey(key3Armored);
      expect(params.keyId).to.equal('4001a127a90de8e1');
      expect(params.fingerprint).to.equal('04062c70b446e33016e219a74001a127a90de8e1');
      expect(params.userIds.length).to.equal(4);
      expect(params.created.getTime()).to.exist;
      expect(params.uploaded.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsaEncryptSign');
      expect(params.keySize).to.equal(4096);
      expect(params.publicKeyArmored).to.include('PGP PUBLIC KEY');
    });

    it('should be able to parse key with user ID with ,', async () => {
      const {publicKey} = await openpgp.generateKey({
        userIDs: [{name: 'Demo, Mailvelope', email: 'demo@mailvelope.com'}],
        passphrase: '1234'
      });
      const params = await pgp.parseKey(publicKey);
      expect(params.userIds).to.have.lengthOf(1);
      expect(params.userIds[0].name).to.equal('Demo, Mailvelope');
      expect(params.userIds[0].email).to.equal('demo@mailvelope.com');
    });
  });

  describe('verifyKey', () => {
    it('should verify valid key', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.valid);
    });

    it('should verify invalid key', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users[0].selfCertifications[0].signedHashValue[0] = 1;
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.invalid);
    });

    it('should verify revoked key', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.revoked);
    });

    it('should verify expired key', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users[0].selfCertifications[0].keyExpirationTime = 1;
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.expired);
    });

    it('should verify key without user self certification but with key revocation', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      key.users.length = 1;
      key.users[0].selfCertifications = [];
      expect(key.revocationSignatures).to.have.lengthOf(1);
      expect(key.users[0].revocationSignatures).to.have.lengthOf(0);
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.revoked);
    });

    it('should verify key without users but with key revocation', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      key.users.length = 0;
      expect(key.revocationSignatures).to.have.lengthOf(1);
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.revoked);
    });

    it('should verify unrevoked key without users', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users.length = 0;
      expect(key.revocationSignatures).to.have.lengthOf(0);
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.invalid);
    });

    it('should verify unrevoked key with user self certification and with user revocation', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      const user = key.users[4];
      key.users = [user];
      key.revocationSignatures = [];
      expect(key.users[0].selfCertifications).to.have.lengthOf(1);
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.revoked);
    });

    it.skip('should verify unrevoked key without user self certification but with user revocation', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      const user = key.users[4];
      key.users = [user];
      key.users[0].selfCertifications = [];
      key.revocationSignatures = [];
      expect(key.users[0].revocationSignatures).to.have.lengthOf(4);
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.revoked);
    });

    it('should verify unrevoked key with user but without any user certificates', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      const user = key.users[4];
      key.users = [user];
      key.users[0].selfCertifications = [];
      key.users[0].revocationSignatures = [];
      key.revocationSignatures = [];
      const status = await pgp.verifyKey(key);
      expect(status).to.equal(KEY_STATUS.invalid);
    });
  });

  describe('parseUserIds', () => {
    let key;

    beforeEach(async () => {
      key = await openpgp.readKey({armoredKey: key1Armored});
    });

    it('should parse a valid user id', async () => {
      const parsed = await pgp.parseUserIds(key);
      expect(parsed[0].name).to.equal('safewithme testuser');
      expect(parsed[0].email).to.equal('safewithme.testuser@gmail.com');
    });

    it('should return no user id for an invalid signature', async () => {
      key.users[0].userID.userID = 'fake@example.com';
      const parsed = await pgp.parseUserIds(key);
      expect(parsed.length).to.equal(0);
    });

    it('should return no user id if no email address', async () => {
      key.users[0].userID.email = '';
      expect(key.users[0].userID.name).to.exist;
      const parsed = await pgp.parseUserIds(key);
      expect(parsed.length).to.equal(0);
    });

    it('should re-parse user ID if no email address and no name', async () => {
      key.users[0].userID.email = '';
      key.users[0].userID.name = '';
      const parsed = await pgp.parseUserIds(key);
      expect(parsed[0].name).to.equal('safewithme testuser');
      expect(parsed[0].email).to.equal('safewithme.testuser@gmail.com');
    });
  });

  describe('verifyUser', () => {
    it('should verify valid user', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      const keyStatus = await pgp.verifyUser(key.users[0]);
      expect(keyStatus).to.equal(KEY_STATUS.valid);
    });

    it('should verify invalid user', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users[0].selfCertifications[0].signedHashValue[0] = 1;
      const keyStatus = await pgp.verifyUser(key.users[0]);
      expect(keyStatus).to.equal(KEY_STATUS.invalid);
    });

    it('should verify revoked user', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      const keyStatus = await pgp.verifyUser(key.users[4]);
      expect(keyStatus).to.equal(KEY_STATUS.revoked);
    });

    it('should verify revoked user without self certification', async () => {
      const key = await openpgp.readKey({armoredKey: key6Armored});
      key.users[4].selfCertifications = [];
      const keyStatus = await pgp.verifyUser(key.users[4]);
      expect(keyStatus).to.equal(KEY_STATUS.revoked);
    });

    it('should verify user without self certification', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users[0].selfCertifications = [];
      const keyStatus = await pgp.verifyUser(key.users[0]);
      expect(keyStatus).to.equal(KEY_STATUS.no_self_cert);
    });

    it('should verify expired user', async () => {
      const key = await openpgp.readKey({armoredKey: key2Armored});
      key.users[0].selfCertifications[0].signatureNeverExpires = null;
      key.users[0].selfCertifications[0].signatureExpirationTime = 1;
      const keyStatus = await pgp.verifyUser(key.users[0]);
      expect(keyStatus).to.equal(KEY_STATUS.expired);
    });
  });

  describe('filterKeyByUserIds', () => {
    it('should filter user IDs', async () => {
      const email = 'test1@example.com';
      const key = await openpgp.readKey({armoredKey: key3Armored});
      expect(key.users.length).to.equal(4);
      const filtered = await pgp.filterKeyByUserIds([{email}], key3Armored);
      const filteredKey = await openpgp.readKey({armoredKey: filtered});
      expect(filteredKey.users.length).to.equal(1);
      expect(filteredKey.users[0].userID.email).to.equal(email);
    });

    it('should filter user attributes', async () => {
      const email = 'test@example.com';
      const key = await openpgp.readKey({armoredKey: key5Armored});
      expect(key.users.length).to.equal(2);
      const filtered = await pgp.filterKeyByUserIds([{email}], key5Armored);
      const filteredKey = await openpgp.readKey({armoredKey: filtered});
      expect(filteredKey.users.length).to.equal(1);
      expect(filteredKey.users[0].userID).to.exist;
    });

    it('should throw if no valid encryption key', () => expect(pgp.filterKeyByUserIds([{email: 'demo@mailvelope.com'}], key6Armored, true)).to.eventually.be.rejectedWith('Invalid PGP key. No valid encryption key found'));
  });

  describe('removeUserId', () => {
    it('should remove user IDs', async () => {
      const email = 'test1@example.com';
      const key = await openpgp.readKey({armoredKey: key3Armored});
      expect(key.users.length).to.equal(4);
      const reduced = await pgp.removeUserId(email, key3Armored);
      const reducedKey = await openpgp.readKey({armoredKey: reduced});
      expect(reducedKey.users.length).to.equal(3);
      expect(reducedKey.users.find(({userID}) => userID.email === email)).to.be.undefined;
    });

    it('should not remove user attributes', async () => {
      const email = 'test@example.com';
      const key = await openpgp.readKey({armoredKey: key5Armored});
      expect(key.users.length).to.equal(2);
      const reduced = await pgp.removeUserId(email, key5Armored);
      const reducedKey = await openpgp.readKey({armoredKey: reduced});
      expect(reducedKey.users.length).to.equal(1);
      expect(reducedKey.users[0].userAttribute).to.exist;
    });
  });
});
