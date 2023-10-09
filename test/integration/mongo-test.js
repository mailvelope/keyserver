'use strict';

const config = require('../../config/config');
const log = require('../../src/lib/log');
const Mongo = require('../../src/modules/mongo');

describe('Mongo Integration Tests', function() {
  this.timeout(20000);

  const DB_TYPE = 'apple';
  const sandbox = sinon.createSandbox();
  const conf = structuredClone(config);
  let mongo;

  before(async () => {
    sandbox.stub(log);
    mongo = new Mongo();
    conf.mongo.uri = `${config.mongo.uri}-int`;
    await mongo.init(conf.mongo);
  });

  beforeEach(async () => {
    await mongo.clear(DB_TYPE);
  });

  after(async () => {
    sandbox.restore();
    await mongo.clear(DB_TYPE);
    await mongo.disconnect();
  });

  describe('create', () => {
    it('should insert a document', async () => {
      const r = await mongo.create({_id: '0'}, DB_TYPE);
      expect(r.insertedCount).to.equal(1);
    });

    it('should fail if two with the same ID are inserted', async () => {
      let r = await mongo.create({_id: '0'}, DB_TYPE);
      expect(r.insertedCount).to.equal(1);
      try {
        r = await mongo.create({_id: '0'}, DB_TYPE);
      } catch (e) {
        expect(e.message).to.match(/duplicate/);
      }
    });
  });

  describe('batch', () => {
    it('should insert a document', async () => {
      const r = await mongo.batch([{_id: '0'}, {_id: '1'}], DB_TYPE);
      expect(r.insertedCount).to.equal(2);
    });

    it('should fail if docs with the same ID are inserted', async () => {
      let r = await mongo.batch([{_id: '0'}, {_id: '1'}], DB_TYPE);
      expect(r.insertedCount).to.equal(2);
      try {
        r = await mongo.batch([{_id: '0'}, {_id: '1'}], DB_TYPE);
      } catch (e) {
        expect(e.message).to.match(/duplicate/);
      }
    });
  });

  describe('update', () => {
    it('should update a document', async () => {
      let r = await mongo.create({_id: '0'}, DB_TYPE);
      r = await mongo.update({_id: '0'}, {foo: 'bar'}, DB_TYPE);
      expect(r.modifiedCount).to.equal(1);
      r = await mongo.get({_id: '0'}, DB_TYPE);
      expect(r.foo).to.equal('bar');
    });
  });

  describe('get', () => {
    it('should get a document', async () => {
      let r = await mongo.create({_id: '0'}, DB_TYPE);
      r = await mongo.get({_id: '0'}, DB_TYPE);
      expect(r).to.exist;
    });
  });

  describe('list', () => {
    it('should list documents', async () => {
      let r = await mongo.batch([{_id: '0', foo: 'bar'}, {_id: '1', foo: 'bar'}], DB_TYPE);
      r = await mongo.list({foo: 'bar'}, DB_TYPE);
      expect(r).to.deep.equal([{_id: '0', foo: 'bar'}, {_id: '1', foo: 'bar'}], DB_TYPE);
    });
  });

  describe('remove', () => {
    it('should remove a document', async () => {
      let r = await mongo.create({_id: '0'}, DB_TYPE);
      r = await mongo.remove({_id: '0'}, DB_TYPE);
      r = await mongo.get({_id: '0'}, DB_TYPE);
      expect(r).to.not.exist;
    });
  });
});
