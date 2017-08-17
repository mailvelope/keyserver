'use strict';

const fs = require('fs');
const log = require('npmlog');
const openpgp = require('openpgp');
const PGP = require('../../src/service/pgp');

describe('PGP Unit Tests', () => {
  let sandbox;
  let pgp;
  let key1Armored;
  let key2Armored;
  let key3Armored;

  beforeEach(() => {
    sandbox = sinon.sandbox.create();
    sandbox.stub(log);

    key1Armored = fs.readFileSync(`${__dirname}/../key1.asc`, 'utf8');
    key2Armored = fs.readFileSync(`${__dirname}/../key2.asc`, 'utf8');
    key3Armored = fs.readFileSync(`${__dirname}/../key3.asc`, 'utf8');
    pgp = new PGP();
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('parseKey', () => {
    it('should should throw error on key parsing', () => {
      sandbox.stub(openpgp.key, 'readArmored').returns({err: [new Error()]});
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/Failed to parse/);
      expect(log.error.calledOnce).to.be.true;
    });

    it('should should throw error when more than one key', () => {
      sandbox.stub(openpgp.key, 'readArmored').returns({keys: [{}, {}]});
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only one key/);
    });

    it('should should throw error when more than one key', () => {
      sandbox.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {},
          verifyPrimaryKey() { return false; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/primary key verification/);
    });

    it('should only accept 16 char key id', () => {
      sandbox.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {
            fingerprint: '4277257930867231ce393fb8dbc0b3d92b1b86e9',
            getKeyId() {
              return {
                toHex() { return 'asdf'; }
              };
            }
          },
          verifyPrimaryKey() { return openpgp.enums.keyStatus.valid; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only v4 keys/);
    });

    it('should only accept version 4 fingerprint', () => {
      sandbox.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {
            fingerprint: '4277257930867231ce393fb8dbc0b3d92b1b86e',
            getKeyId() {
              return {
                toHex() { return 'dbc0b3d92b1b86e9'; }
              };
            }
          },
          verifyPrimaryKey() { return openpgp.enums.keyStatus.valid; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only v4 keys/);
    });

    it('should only accept valid user ids', () => {
      sandbox.stub(pgp, 'parseUserIds').returns([]);
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/invalid user ids/);
    });

    it('should be able to parse RSA key', () => {
      const params = pgp.parseKey(key1Armored);
      expect(params.keyId).to.equal('dbc0b3d92b1b86e9');
      expect(params.fingerprint).to.equal('4277257930867231ce393fb8dbc0b3d92b1b86e9');
      expect(params.userIds[0].name).to.equal('safewithme testuser');
      expect(params.userIds[0].email).to.equal('safewithme.testuser@gmail.com');
      expect(params.created.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsa_encrypt_sign');
      expect(params.keySize).to.equal(2048);
      expect(params.publicKeyArmored).to.equal(key1Armored);
    });

    it('should be able to parse RSA/ECC key', () => {
      const params = pgp.parseKey(key2Armored);
      expect(params.keyId).to.equal('b8e4105cc9dedc77');
      expect(params.fingerprint).to.equal('e3317db04d3958fd5f662c37b8e4105cc9dedc77');
      expect(params.userIds.length).to.equal(1);
      expect(params.created.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsa_encrypt_sign');
      expect(params.keySize).to.equal(4096);
      expect(params.publicKeyArmored).to.equal(pgp.trimKey(key2Armored));
    });

    it('should be able to parse komplex key', () => {
      const params = pgp.parseKey(key3Armored);
      expect(params.keyId).to.equal('4001a127a90de8e1');
      expect(params.fingerprint).to.equal('04062c70b446e33016e219a74001a127a90de8e1');
      expect(params.userIds.length).to.equal(4);
      expect(params.created.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsa_encrypt_sign');
      expect(params.keySize).to.equal(4096);
      expect(params.publicKeyArmored).to.equal(pgp.trimKey(key3Armored));
    });
  });

  describe('trimKey', () => {
    it('should be the same as key1', () => {
      const trimmed = pgp.trimKey(key1Armored);
      expect(trimmed).to.equal(key1Armored);
    });

    it('should not be the same as key2', () => {
      const trimmed = pgp.trimKey(key2Armored);
      expect(trimmed).to.not.equal(key2Armored);
    });
  });

  describe('validateKeyBlock', () => {
    const KEY_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
    const KEY_END = '-----END PGP PUBLIC KEY BLOCK-----';

    it('should return true for valid key block', () => {
      const input = KEY_BEGIN + KEY_END;
      expect(pgp.validateKeyBlock(input)).to.be.true;
    });

    it('should return false for invalid key block', () => {
      const input = KEY_END + KEY_BEGIN;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });

    it('should return false for invalid key block', () => {
      const input = KEY_END;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });

    it('should return false for invalid key block', () => {
      const input = KEY_BEGIN;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });
  });

  describe('parseUserIds', () => {
    let key;

    beforeEach(() => {
      key = openpgp.key.readArmored(key1Armored).keys[0];
    });

    it('should parse a valid user id', () => {
      const parsed = pgp.parseUserIds(key.users, key.primaryKey);
      expect(parsed[0].name).to.equal('safewithme testuser');
      expect(parsed[0].email).to.equal('safewithme.testuser@gmail.com');
    });

    it('should throw for an empty user ids array', () => {
      expect(pgp.parseUserIds.bind(pgp, [], key.primaryKey)).to.throw(/no user id/);
    });

    it('should return no user id for an invalid signature', () => {
      key.users[0].userId.userid = 'fake@example.com';
      const parsed = pgp.parseUserIds(key.users, key.primaryKey);
      expect(parsed.length).to.equal(0);
    });

    it('should throw for a invalid email address', () => {
      sandbox.stub(key.users[0], 'isValidSelfCertificate').returns(true);
      key.users[0].userId.userid = 'safewithme testuser <safewithme.testusergmail.com>';
      const parsed = pgp.parseUserIds(key.users, key.primaryKey);
      expect(parsed.length).to.equal(0);
    });
  });
});
