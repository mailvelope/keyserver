'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const log = require('npmlog');
const UserId = require('../../src/service/user-id');
const Mongo = require('../../src/dao/mongo');
const expect = require('chai').expect;

describe('User ID Integration Tests', function() {
  this.timeout(20000);

  const DB_TYPE = 'userid';
  const keyid = '0123456789ABCDEF';
  let mongo, userId, uid1, uid2;

  before(function *() {
    let credentials;
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.info('mongo-test', 'No credentials.json found ... using environment vars.');
    }
    mongo = new Mongo({
      uri: process.env.MONGO_URI || credentials.mongo.uri,
      user: process.env.MONGO_USER || credentials.mongo.user,
      password: process.env.MONGO_PASS || credentials.mongo.pass
    });
    yield mongo.connect();
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

  afterEach(function() {});

  after(function *() {
    yield mongo.clear(DB_TYPE);
    yield mongo.disconnect();
  });

  describe("batch", function() {
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

  describe("verify", function() {
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

  describe("getVerfied", function() {
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

  describe("flagForRemove", function() {
    it('should flag all documents', function *() {
      let stored = yield userId.batch({ userIds:[uid1, uid2], keyid });
      let flagged = yield userId.flagForRemove({ keyid });
      expect(flagged[0]._id.toHexString()).to.equal(stored[0]._id.toHexString());
      expect(flagged[0].nonce).to.not.equal(stored[0].nonce);
      let gotten = yield mongo.list({ keyid }, DB_TYPE);
      expect(gotten).to.deep.equal(flagged);
    });
  });

  describe("remove", function() {
    it('should delete all documents', function *() {
      yield userId.batch({ userIds:[uid1, uid2], keyid });
      yield userId.remove({ keyid });
      let gotten = yield mongo.get({ keyid }, DB_TYPE);
      expect(gotten).to.not.exist;
    });
  });

});