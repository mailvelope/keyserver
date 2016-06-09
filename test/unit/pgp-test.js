'use strict';

const fs = require('fs');
const expect = require('chai').expect;
const openpgp = require('openpgp');
const PGP = require('../../src/service/pgp');


describe('PGP Unit Tests', () => {
  let pgp, key1Armored, key2Armored;

  beforeEach(() => {
    key1Armored = fs.readFileSync(__dirname + '/../key1.asc', 'utf8');
    key2Armored = fs.readFileSync(__dirname + '/../key2.asc', 'utf8');
    pgp = new PGP(openpgp);
  });

  describe('parseKey', () => {
    it('should be able to parse RSA key', () => {
      let params = pgp.parseKey(key1Armored);
      expect(params.keyId).to.equal('dbc0b3d92b1b86e9');
      expect(params.fingerprint).to.equal('4277257930867231ce393fb8dbc0b3d92b1b86e9');
      expect(params.userIds.length).to.equal(1);
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
    it('should parse a valid user id', () => {
      let input = ['a <b@c.de>'];
      let parsed = pgp.parseUserIds(input);
      expect(parsed[0].name).to.equal('a');
      expect(parsed[0].email).to.equal('b@c.de');
    });

    it('should parse a valid user id', () => {
      let input = [' <b@c.de>'];
      let parsed = pgp.parseUserIds(input);
      expect(parsed[0].name).to.equal('');
      expect(parsed[0].email).to.equal('b@c.de');
    });

    it('should parse a valid user id', () => {
      let input = ['<b@c.de>'];
      let parsed = pgp.parseUserIds(input);
      expect(parsed[0].name).to.equal('');
      expect(parsed[0].email).to.equal('b@c.de');
    });

    it('should throw for a invalid user id', () => {
      let input = ['a <@c.de>'];
      expect(pgp.parseUserIds.bind(pgp, input)).to.throw(/invalid user id/);
    });

    it('should throw for no user ids', () => {
      let input = [];
      expect(pgp.parseUserIds.bind(pgp, input)).to.throw(/no user id found/);
    });
  });

});