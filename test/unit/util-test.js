'use strict';

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

  describe('isKeyId', () => {
    it('should be true for 16 byte hex', () => {
      expect(util.isKeyId('0123456789ABCDEF')).to.be.true;
    });
    it('should be false for 16 byte non-hex', () => {
      expect(util.isKeyId('0123456789ABCDEZ')).to.be.false;
    });
    it('should be false for 15 byte hex', () => {
      expect(util.isKeyId('0123456789ABCDE')).to.be.false;
    });
    it('should be false for 17 byte hex', () => {
      expect(util.isKeyId('0123456789ABCDEF0')).to.be.false;
    });
    it('should be false for undefined', () => {
      expect(util.isKeyId(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.isKeyId({})).to.be.false;
    });
  });

  describe('isFingerPrint', () => {
    it('should be true for 40 byte hex', () => {
      expect(util.isFingerPrint('0123456789ABCDEF0123456789ABCDEF01234567')).to.be.true;
    });
    it('should be false for 40 byte non-hex', () => {
      expect(util.isKeyId('0123456789ABCDEF0123456789ABCDEF0123456Z')).to.be.false;
    });
    it('should be false for 39 byte hex', () => {
      expect(util.isFingerPrint('0123456789ABCDEF0123456789ABCDEF0123456')).to.be.false;
    });
    it('should be false for 41 byte hex', () => {
      expect(util.isFingerPrint('0123456789ABCDEF0123456789ABCDEF012345678')).to.be.false;
    });
    it('should be false for undefined', () => {
      expect(util.isFingerPrint(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.isFingerPrint({})).to.be.false;
    });
  });

  describe('isEmail', () => {
    it('should be true valid email', () => {
      expect(util.isEmail('a@b.co')).to.be.true;
    });
    it('should be false for too short TLD', () => {
      expect(util.isEmail('a@b.c')).to.be.false;
    });
    it('should be false for no .', () => {
      expect(util.isEmail('a@bco')).to.be.false;
    });
    it('should be false for no @', () => {
      expect(util.isEmail('ab.co')).to.be.false;
    });
    it('should be false invalid cahr', () => {
      expect(util.isEmail('a<@b.co')).to.be.false;
    });
    it('should be false for undefined', () => {
      expect(util.isEmail(undefined)).to.be.false;
    });
    it('should be false for Object', () => {
      expect(util.isEmail({})).to.be.false;
    });
  });

  describe('throw', () => {
    it('should throw error with status and expose', () => {
      try {
        util.throw(500, 'boom');
        expect(true).to.be.false;
      } catch (e) {
        expect(e.message).to.equal('boom');
        expect(e.status).to.equal(500);
        expect(e.expose).to.be.true;
      }
    });
  });

  describe('random', () => {
    it('should generate random 32 char hex string', () => {
      expect(util.random().length).to.equal(32);
    });

    it('should generate random 16 char hex string', () => {
      expect(util.random(8).length).to.equal(16);
    });
  });

  describe('origin', () => {
    it('should work', () => {
      expect(util.origin({secure: true, host: 'h', protocol: 'p'})).to.exist;
    });
  });

  describe('url', () => {
    it('should work with resource', () => {
      const url = util.url({host: 'localhost', protocol: 'http'}, '/foo');
      expect(url).to.equal('http://localhost/foo');
    });

    it('should work without resource', () => {
      const url = util.url({host: 'localhost', protocol: 'http'});
      expect(url).to.equal('http://localhost');
    });
  });
});
