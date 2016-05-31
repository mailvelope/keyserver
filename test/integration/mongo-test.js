'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const log = require('npmlog');
const Mongo = require('../../src/dao/mongo');
const expect = require('chai').expect;

describe('Mongo Integration Tests', function() {
  this.timeout(20000);

  const DB_TYPE = 'apple';
  let mongo;

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
  });

  beforeEach(function *() {
    yield mongo.clear(DB_TYPE);
  });

  after(function *() {
    yield mongo.clear(DB_TYPE);
    yield mongo.disconnect();
  });

  describe("create", () => {
    it('should insert a document', function *() {
      let r = yield mongo.create({ _id:'0' }, DB_TYPE);
      expect(r.insertedCount).to.equal(1);
    });

    it('should fail if two with the same ID are inserted', function *() {
      let r = yield mongo.create({ _id:'0' }, DB_TYPE);
      expect(r.insertedCount).to.equal(1);
      try {
        r = yield mongo.create({ _id:'0' }, DB_TYPE);
      } catch(e) {
        expect(e.message).to.match(/duplicate/);
      }
    });
  });

  describe("batch", () => {
    it('should insert a document', function *() {
      let r = yield mongo.batch([{ _id:'0' }, { _id:'1' }], DB_TYPE);
      expect(r.insertedCount).to.equal(2);
    });

    it('should fail if docs with the same ID are inserted', function *() {
      let r = yield mongo.batch([{ _id:'0' }, { _id:'1' }], DB_TYPE);
      expect(r.insertedCount).to.equal(2);
      try {
        r = yield mongo.batch([{ _id:'0' }, { _id:'1' }], DB_TYPE);
      } catch(e) {
        expect(e.message).to.match(/duplicate/);
      }
    });
  });

  describe("update", () => {
    it('should update a document', function *() {
      let r = yield mongo.create({ _id:'0' }, DB_TYPE);
      r = yield mongo.update({ _id:'0' }, { foo:'bar' }, DB_TYPE);
      expect(r.modifiedCount).to.equal(1);
      r = yield mongo.get({ _id:'0' }, DB_TYPE);
      expect(r.foo).to.equal('bar');
    });
  });

  describe("get", () => {
    it('should get a document', function *() {
      let r = yield mongo.create({ _id:'0' }, DB_TYPE);
      r = yield mongo.get({ _id:'0' }, DB_TYPE);
      expect(r).to.exist;
    });
  });

  describe("list", () => {
    it('should list documents', function *() {
      let r = yield mongo.batch([{ _id:'0', foo:'bar' }, { _id:'1', foo:'bar' }], DB_TYPE);
      r = yield mongo.list({ foo:'bar' }, DB_TYPE);
      expect(r).to.deep.equal([{ _id:'0', foo:'bar' }, { _id:'1', foo:'bar' }], DB_TYPE);
    });
  });

  describe("remove", () => {
    it('should remove a document', function *() {
      let r = yield mongo.create({ _id:'0' }, DB_TYPE);
      r = yield mongo.remove({ _id:'0' }, DB_TYPE);
      r = yield mongo.get({ _id:'0' }, DB_TYPE);
      expect(r).to.not.exist;
    });
  });

});