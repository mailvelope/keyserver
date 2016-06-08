'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const config = require('config');
const UserId = require('../../src/service/user-id');
const Mongo = require('../../src/dao/mongo');
const expect = require('chai').expect;

describe('User ID Integration Tests', function() {
  this.timeout(20000);

  const DB_TYPE = 'userid';
  const keyid = '0123456789ABCDEF';
  let mongo, userId, uid1, uid2;

  before(function *() {
    mongo = new Mongo();
    yield mongo.init(config.mongo);
    userId = new UserId(mongo);
  });

  beforeEach(function *() {
    uid1 = {
      name: 'name1',
      email: 'email1'
    };
    uid2 = {
      name: 'name2',
      email: 'email2'
    };
    yield mongo.clear(DB_TYPE);
  });

  after(function *() {
    yield mongo.clear(DB_TYPE);
    yield mongo.disconnect();
  });

  describe("batch", () => {
    it('should persist all the things', function *() {
      let uids = yield userId.batch({ userIds:[uid1, uid2], keyid });
      expect(uids[0].keyid).to.equal(keyid);
      expect(uids[1].keyid).to.equal(keyid);
      expect(uids[0].nonce).to.exist;
      expect(uids[1].nonce).to.exist;
      expect(uids[0]._id).to.exist;
      expect(uids[1]._id).to.exist;
      let gotten = yield mongo.list({ keyid }, DB_TYPE);
      expect(gotten).to.deep.equal(uids);
    });
  });

  describe("verify", () => {
    it('should update the document', function *() {
      let uids = yield userId.batch({ userIds:[uid1], keyid });
      yield userId.verify({ keyid, nonce:uids[0].nonce });
      let gotten = yield mongo.get({ _id:uid1._id }, DB_TYPE);
      expect(gotten.verified).to.be.true;
      expect(gotten.nonce).to.be.null;
    });

    it('should not find the document', function *() {
      yield userId.batch({ userIds:[uid1], keyid });
      try {
        yield userId.verify({ keyid, nonce:'fake_nonce' });
      } catch(e) {
        expect(e.status).to.equal(404);
      }
      let gotten = yield mongo.get({ _id:uid1._id }, DB_TYPE);
      expect(gotten.verified).to.be.undefined;
      expect(gotten.nonce).to.exist;
    });
  });

  describe("getVerfied", () => {
    beforeEach(function *() {
      let uids = yield userId.batch({ userIds:[uid1], keyid });
      yield userId.verify({ keyid, nonce:uids[0].nonce });
    });

    it('should find verified by key id', function *() {
      let gotten = yield userId.getVerfied({ keyid });
      expect(gotten).to.exist;
    });

    it('should find verified by email address', function *() {
      let gotten = yield userId.getVerfied({ userIds:[uid2,uid1] });
      expect(gotten).to.exist;
    });
  });

  describe("flagForRemove", () => {
    let stored;
    beforeEach(function *() {
      stored = yield userId.batch({ userIds:[uid1, uid2], keyid });
    });

    it('should flag one documents for email param', function *() {
      let flagged = yield userId.flagForRemove({ email:uid1.email });
      expect(flagged.length).to.equal(1);
      expect(flagged[0]._id.toHexString()).to.equal(stored[0]._id.toHexString());
      expect(flagged[0].nonce).to.not.equal(stored[0].nonce);
      let gotten = yield mongo.list({ email:uid1.email }, DB_TYPE);
      expect(gotten).to.deep.equal(flagged);
    });

    it('should flag all documents for key id param', function *() {
      let flagged = yield userId.flagForRemove({ keyid });
      expect(flagged.length).to.equal(2);
      expect(flagged[0]._id.toHexString()).to.equal(stored[0]._id.toHexString());
      expect(flagged[0].nonce).to.not.equal(stored[0].nonce);
      let gotten = yield mongo.list({ keyid }, DB_TYPE);
      expect(gotten).to.deep.equal(flagged);
    });

    it('should flag no documents for wrong key id param', function *() {
      let flagged = yield userId.flagForRemove({ keyid:'4' });
      expect(flagged.length).to.equal(0);
    });

    it('should flag no documents no param', function *() {
      let flagged = yield userId.flagForRemove({});
      expect(flagged.length).to.equal(0);
      let gotten = yield mongo.list({ keyid }, DB_TYPE);
      expect(gotten).to.deep.equal(stored);
    });
  });

  describe("getFlaggedForRemove", () => {
    it('should find flagged document', function *() {
      yield userId.batch({ userIds:[uid1, uid2], keyid });
      let flagged = yield userId.flagForRemove({ keyid });
      let gotten = yield userId.getFlaggedForRemove({ keyid, nonce:flagged[0].nonce });
      expect(gotten).to.exist;
    });
  });

  describe("remove", () => {
    it('should delete all documents', function *() {
      yield userId.batch({ userIds:[uid1, uid2], keyid });
      yield userId.remove({ keyid });
      let gotten = yield mongo.get({ keyid }, DB_TYPE);
      expect(gotten).to.not.exist;
    });
  });

});