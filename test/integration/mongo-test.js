'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const Mongo = require('../../src/dao/mongo'),
  expect = require('chai').expect,
  fs = require('fs');

describe('Mongo Integration Tests', function() {
  this.timeout(20000);

  const defaultType = 'apple';
  const secondaryType = 'orange';
  let mongo;

  before(function *() {
    let credentials;
    try {
      credentials = JSON.parse(fs.readFileSync(__dirname + '/../../credentials.json'));
    } catch(e) {}
    mongo = new Mongo({
      uri: process.env.MONGO_URI || credentials.mongoUri,
      user: process.env.MONGO_USER || credentials.mongoUser,
      password: process.env.MONGO_PASS || credentials.mongoPass,
      type: defaultType
    });
    yield mongo.connect();
  });

  beforeEach(function *() {
    yield mongo.clear();
    yield mongo.clear(secondaryType);
  });

  afterEach(function() {});

  after(function *() {
    yield mongo.clear();
    yield mongo.clear(secondaryType);
    yield mongo.disconnect();
  });

  describe("create", function() {
    it('should insert a document', function *() {
      let r = yield mongo.create({ _id:'0' });
      expect(r.insertedCount).to.equal(1);
    });

    it('should insert a document with a type', function *() {
      let r = yield mongo.create({ _id:'0' });
      expect(r.insertedCount).to.equal(1);
      r = yield mongo.create({ _id:'0' }, secondaryType);
      expect(r.insertedCount).to.equal(1);
    });

    it('should fail if two with the same ID are inserted', function *() {
      let r = yield mongo.create({ _id:'0' });
      expect(r.insertedCount).to.equal(1);
      try {
        r = yield mongo.create({ _id:'0' });
      } catch(e) {
        expect(e.message).to.match(/duplicate/);
      }
    });
  });

  describe("update", function() {
    it('should update a document', function *() {
      let r = yield mongo.create({ _id:'0' });
      r = yield mongo.update({ _id:'0' }, { foo:'bar' });
      expect(r.modifiedCount).to.equal(1);
      r = yield mongo.get({ _id:'0' });
      expect(r.foo).to.equal('bar');
    });

    it('should update a document with a type', function *() {
      let r = yield mongo.create({ _id:'0' }, secondaryType);
      r = yield mongo.update({ _id:'0' }, { foo:'bar' }, secondaryType);
      expect(r.modifiedCount).to.equal(1);
      r = yield mongo.get({ _id:'0' }, secondaryType);
      expect(r.foo).to.equal('bar');
    });
  });

  describe("get", function() {
    it('should get a document', function *() {
      let r = yield mongo.create({ _id:'0' });
      r = yield mongo.get({ _id:'0' });
      expect(r).to.exist;
    });

    it('should get a document with a type', function *() {
      let r = yield mongo.create({ _id:'0' }, secondaryType);
      r = yield mongo.get({ _id:'0' }, secondaryType);
      expect(r).to.exist;
    });
  });

  describe("list", function() {
    it('should list documents', function *() {
      let r = yield mongo.create({ _id:'0', foo:'bar' });
      r = yield mongo.create({ _id:'1', foo:'bar' });
      r = yield mongo.list({ foo:'bar' });
      expect(r).to.deep.equal([{ _id:'0', foo:'bar' }, { _id:'1', foo:'bar' }]);
    });

    it('should list documents with a type', function *() {
      let r = yield mongo.create({ _id:'0', foo:'bar' }, secondaryType);
      r = yield mongo.create({ _id:'1', foo:'bar' }, secondaryType);
      r = yield mongo.list({ foo:'bar' }, secondaryType);
      expect(r).to.deep.equal([{ _id:'0', foo:'bar' }, { _id:'1', foo:'bar' }]);
    });
  });

  describe("remove", function() {
    it('should remove a document', function *() {
      let r = yield mongo.create({ _id:'0' });
      r = yield mongo.remove({ _id:'0' });
      r = yield mongo.get({ _id:'0' });
      expect(r).to.not.exist;
    });

    it('should remove a document with a type', function *() {
      let r = yield mongo.create({ _id:'0' }, secondaryType);
      r = yield mongo.remove({ _id:'0' }, secondaryType);
      r = yield mongo.get({ _id:'0' }, secondaryType);
      expect(r).to.not.exist;
    });
  });

});