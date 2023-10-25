'use strict';

const fs = require('fs');
const log = require('../../src/lib/log');
const openpgp = require('openpgp');
const PGP = require('../../src/modules/pgp');

describe('PGP Unit Tests', () => {
  const sandbox = sinon.createSandbox();
  let pgp;
  let key1Armored;
  let key2Armored;
  let key3Armored;
  let key5Armored;

  before(() => {
    key1Armored = fs.readFileSync(`${__dirname}/../fixtures/key1.asc`, 'utf8');
    key2Armored = fs.readFileSync(`${__dirname}/../fixtures/key2.asc`, 'utf8');
    key3Armored = fs.readFileSync(`${__dirname}/../fixtures/key3.asc`, 'utf8');
    key5Armored = fs.readFileSync(`${__dirname}/../fixtures/key5.asc`, 'utf8');
  });

  beforeEach(() => {
    sandbox.stub(log);
    pgp = new PGP();
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('parseKey', () => {
    it('should should throw error on key parsing', async () => {
      sandbox.stub(openpgp, 'readKey').throws(new Error('readKey: test error'));
      await expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith(/Error reading PGP key. readKey: test error/);
      expect(log.error.calledOnce).to.be.true;
    });

    it('should should throw error when primaryKey not verfied', () => {
      sandbox.stub(openpgp, 'readKey').returns({
        isPrivate() { return false; },
        armor() { return 'ABC'; },
        verifyPrimaryKey() { throw new Error('Invalid primary key'); }
      });
      return expect(pgp.parseKey(key3Armored)).to.eventually.be.rejectedWith(/Invalid PGP key. Key verification failed: Invalid primary key/);
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
      const parsed = await pgp.parseUserIds(key);
      expect(parsed.length).to.equal(0);
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
  });

  describe('removeUserId', () => {
    it('should remove user IDs', async () => {
      const email = 'test1@example.com';
      const key = await openpgp.readKey({armoredKey: key3Armored});
      expect(key.users.length).to.equal(4);
      const reduced = await pgp.removeUserId(email, key3Armored);
      const reducedKey = await openpgp.readKey({armoredKey: reduced});
      expect(reducedKey.users.length).to.equal(3);
      expect(reducedKey.users.includes(({userId}) => userId.email === email)).to.be.false;
    });

    it('should not remove user attributes', async () => {
      const email = 'test@example.com';
      const key = await openpgp.readKey({armoredKey: key5Armored});
      expect(key.users.length).to.equal(2);
      const reduced = await pgp.removeUserId(email, key5Armored);
      const reducedKey = await openpgp.readKey({armoredKey: reduced});
      expect(reducedKey.users.length).to.equal(0);
    });
  });
});
