'use strict';

const fs = require('fs');
const expect = require('chai').expect;
const log = require('npmlog');
const openpgp = require('openpgp');
const PGP = require('../../src/service/pgp');
const sinon = require('sinon');

describe('PGP Unit Tests', () => {
  let pgp, key1Armored, key2Armored, key3Armored;

  beforeEach(() => {
    key1Armored = fs.readFileSync(__dirname + '/../key1.asc', 'utf8');
    key2Armored = fs.readFileSync(__dirname + '/../key2.asc', 'utf8');
    key3Armored = fs.readFileSync(__dirname + '/../key3.asc', 'utf8');
    pgp = new PGP();
  });

  describe('parseKey', () => {
    it('should should throw error on key parsing', () => {
      let readStub = sinon.stub(openpgp.key, 'readArmored').returns({err:[new Error()]});
      sinon.stub(log, 'error');
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/Failed to parse/);
      expect(log.error.calledOnce).to.be.true;
      log.error.restore();
      readStub.restore();
    });

    it('should should throw error when more than one key', () => {
      let readStub = sinon.stub(openpgp.key, 'readArmored').returns({keys:[{},{}]});
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only one key/);
      readStub.restore();
    });

    it('should should throw error when more than one key', () => {
      let readStub = sinon.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {},
          verifyPrimaryKey: function() { return false; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/primary key verification/);
      readStub.restore();
    });

    it('should only accept 16 char key id', () => {
      let readStub = sinon.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {
            fingerprint: '4277257930867231ce393fb8dbc0b3d92b1b86e9',
            getKeyId: function() {
              return {
                toHex:function() { return 'asdf'; }
              };
            }
          },
          verifyPrimaryKey: function() { return openpgp.enums.keyStatus.valid; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only v4 keys/);
      readStub.restore();
    });

    it('should only accept version 4 fingerprint', () => {
      let readStub = sinon.stub(openpgp.key, 'readArmored').returns({
        keys: [{
          primaryKey: {
            fingerprint: '4277257930867231ce393fb8dbc0b3d92b1b86e',
            getKeyId: function() {
              return {
                toHex:function() { return 'dbc0b3d92b1b86e9'; }
              };
            }
          },
          verifyPrimaryKey: function() { return openpgp.enums.keyStatus.valid; }
        }]
      });
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/only v4 keys/);
      readStub.restore();
    });

    it('should only accept valid user ids', () => {
      sinon.stub(pgp, 'parseUserIds').returns([]);
      expect(pgp.parseKey.bind(pgp, key3Armored)).to.throw(/invalid user ids/);
    });

    it('should be able to parse RSA key', () => {
      let params = pgp.parseKey(key1Armored);
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
      let params = pgp.parseKey(key2Armored);
      expect(params.keyId).to.equal('b8e4105cc9dedc77');
      expect(params.fingerprint).to.equal('e3317db04d3958fd5f662c37b8e4105cc9dedc77');
      expect(params.userIds.length).to.equal(1);
      expect(params.created.getTime()).to.exist;
      expect(params.algorithm).to.equal('rsa_encrypt_sign');
      expect(params.keySize).to.equal(4096);
      expect(params.publicKeyArmored).to.equal(pgp.trimKey(key2Armored));
    });

    it('should be able to parse komplex key', () => {
      let params = pgp.parseKey(key3Armored);
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
      let trimmed = pgp.trimKey(key1Armored);
      expect(trimmed).to.equal(key1Armored);
    });

    it('should not be the same as key2', () => {
      let trimmed = pgp.trimKey(key2Armored);
      expect(trimmed).to.not.equal(key2Armored);
    });
  });

  describe('validateKeyBlock', () => {
    const KEY_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
    const KEY_END = '-----END PGP PUBLIC KEY BLOCK-----';

    it('should return true for valid key block', () => {
      let input = KEY_BEGIN + KEY_END;
      expect(pgp.validateKeyBlock(input)).to.be.true;
    });

    it('should return false for invalid key block', () => {
      let input = KEY_END + KEY_BEGIN;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });

    it('should return false for invalid key block', () => {
      let input = KEY_END;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });

    it('should return false for invalid key block', () => {
      let input = KEY_BEGIN;
      expect(pgp.validateKeyBlock(input)).to.be.false;
    });
  });

  describe('parseUserIds', () => {
    let key;

    beforeEach(() => {
      key = openpgp.key.readArmored(key1Armored).keys[0];
    });

    it('should parse a valid user id', () => {
      let parsed = pgp.parseUserIds(key.users, key.primaryKey);
      expect(parsed[0].name).to.equal('safewithme testuser');
      expect(parsed[0].email).to.equal('safewithme.testuser@gmail.com');
    });

    it('should throw for an empty user ids array', () => {
      expect(pgp.parseUserIds.bind(pgp, [], key.primaryKey)).to.throw(/no user id/);
    });

    it('should return no user id for an invalid signature', () => {
      key.users[0].userId.userid = 'fake@example.com';
      let parsed = pgp.parseUserIds(key.users, key.primaryKey);
      expect(parsed.length).to.equal(0);
    });

    it('should throw for a invalid email address', () => {
      let verifyStub = sinon.stub(key.users[0], 'isValidSelfCertificate').returns(true);
      key.users[0].userId.userid = 'safewithme.testusergmail.com';
      expect(pgp.parseUserIds.bind(pgp, key.users, key.primaryKey)).to.throw(/invalid email address/);
      verifyStub.restore();
    });
  });

});