'use strict';

const expect = require('chai').expect;
const util = require('../../src/service/util');

describe('Util Unit Tests', () => {
  describe('isString', () => {
    it('should be true for string', () => {
      expect(util.isString('asdf')).to.be.true;
    });
    it('should be true for String object', () => {
      expect(util.isString(String('asdf'))).to.be.true;
    });
    it('should be true for empty String', () => {
      expect(util.isString('')).to.be.true;
    });
    it('should be false for undefined', () => {
      expect(util.isString(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.isString({})).to.be.false;
    });
  });

  describe('isTrue', () => {
    it('should be true for "true"', () => {
      expect(util.isTrue('true')).to.be.true;
    });
    it('should be true for true', () => {
      expect(util.isTrue(true)).to.be.true;
    });
    it('should be false for "false"', () => {
      expect(util.isTrue('false')).to.be.false;
    });
    it('should be false for false', () => {
      expect(util.isTrue(false)).to.be.false;
    });
    it('should be true for a random string', () => {
      expect(util.isTrue('asdf')).to.be.false;
    });
    it('should be true for undefined', () => {
      expect(util.isTrue(undefined)).to.be.false;
    });
    it('should be true for null', () => {
      expect(util.isTrue(null)).to.be.false;
    });
  });

  describe('validateKeyId', () => {
    it('should be true for 40 byte hex', () => {
      expect(util.validateKeyId('0123456789ABCDEF0123456789ABCDEF01234567')).to.be.true;
    });
    it('should be true for 16 byte hex', () => {
      expect(util.validateKeyId('0123456789ABCDEF')).to.be.true;
    });
    it('should be false for 15 byte hex', () => {
      expect(util.validateKeyId('0123456789ABCDE')).to.be.false;
    });
    it('should be false for 16 byte non-hex', () => {
      expect(util.validateKeyId('0123456789ABCDEZ')).to.be.false;
    });
    it('should be false for 41 byte hex', () => {
      expect(util.validateKeyId('0123456789ABCDEF0123456789ABCDEF012345678')).to.be.false;
    });
    it('should be false for undefined', () => {
      expect(util.validateKeyId(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.validateKeyId({})).to.be.false;
    });
  });

  describe('validateAddress', () => {
    it('should be true valid email', () => {
      expect(util.validateAddress('a@b.co')).to.be.true;
    });
    it('should be false for too short TLD', () => {
      expect(util.validateAddress('a@b.c')).to.be.false;
    });
    it('should be false for no .', () => {
      expect(util.validateAddress('a@bco')).to.be.false;
    });
    it('should be false for no @', () => {
      expect(util.validateAddress('ab.co')).to.be.false;
    });
    it('should be false invalid cahr', () => {
      expect(util.validateAddress('a<@b.co')).to.be.false;
    });
    it('should be false for undefined', () => {
      expect(util.validateAddress(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.validateAddress({})).to.be.false;
    });
  });

  describe('validatePublicKey', () => {
    let key;
    before(() => {
      key = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    });
    it('should be true valid key', () => {
      expect(util.validatePublicKey(key)).to.be.true;
    });
    it('should be false invalid prefix', () => {
      expect(util.validatePublicKey(key.replace(/BEGIN PGP/, 'BEGIN PP'))).to.be.false;
    });
    it('should be false missing suffix', () => {
      expect(util.validatePublicKey(key.replace(/-----END PGP PUBLIC KEY BLOCK-----/, ''))).to.be.false;
    });
  });

  describe('validatePublicKey', () => {
    let key;
    before(() => {
      key = require('fs').readFileSync(__dirname + '/../key1.asc', 'utf8');
    });
    it('should be true valid key', () => {
      expect(util.validatePublicKey(key)).to.be.true;
    });
    it('should be false invalid prefix', () => {
      expect(util.validatePublicKey(key.replace(/BEGIN PGP/, 'BEGIN PP'))).to.be.false;
    });
    it('should be false missing suffix', () => {
      expect(util.validatePublicKey(key.replace(/-----END PGP PUBLIC KEY BLOCK-----/, ''))).to.be.false;
    });
  });

  describe('parseUserIds', () => {
    it('should parse string', () => {
      expect(util.parseUserIds(['A <A@b.co>'])).to.deep.equal([{name:'A', email:'a@b.co'}]);
    });
    it('should work for empty array', () => {
      expect(util.parseUserIds([])).to.deep.equal([]);
    });
  });

  describe('deDup', () => {
    it('should work for empty array', () => {
      expect(util.deDup([])).to.deep.equal([]);
    });
    it('should work for empty array', () => {
      expect(util.deDup(['a','b','a'])).to.deep.equal(['a','b']);
    });
    it('should throw for undefined', () => {
      expect(util.deDup.bind(null, undefined)).to.throw(/Cannot read property/);
    });
  });

  describe('throw', () => {
    it('should throw error with status and expose', () => {
      try {
        util.throw(500, 'boom');
        expect(true).to.be.false;
      } catch(e) {
        expect(e.message).to.equal('boom');
        expect(e.status).to.equal(500);
        expect(e.expose).to.be.true;
      }
    });
  });

  describe('getOrigin', () => {
    it('should work', () => {
      expect(util.getOrigin({host:'h', protocol:'p'})).to.exist;
    });
  });

});