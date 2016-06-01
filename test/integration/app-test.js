'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const request = require('supertest');
const Mongo = require('../../src/dao/mongo');
const nodemailer = require('nodemailer');
const log = require('npmlog');
const config = require('config');
const fs = require('fs');
const expect = require('chai').expect;
const sinon = require('sinon');

log.level = config.log.level;

describe('Koa App (HTTP Server) Integration Tests', function() {
  this.timeout(20000);

  let app, mongo,
    sendEmailStub, publicKeyArmored, emailParams;

  const DB_TYPE_PUB_KEY = 'publickey';
  const DB_TYPE_USER_ID = 'userid';
  const primaryEmail = 'safewithme.testuser@gmail.com';

  before(function *() {
    publicKeyArmored = fs.readFileSync(__dirname + '/../key1.asc', 'utf8');
    let credentials;
    try {
      credentials = require('../../credentials.json');
    } catch(e) {
      log.info('app-test', 'No credentials.json found ... using environment vars.');
    }
    mongo = new Mongo({
      uri: process.env.MONGO_URI || credentials.mongo.uri,
      user: process.env.MONGO_USER || credentials.mongo.user,
      password: process.env.MONGO_PASS || credentials.mongo.pass
    });
    yield mongo.connect();

    sendEmailStub = sinon.stub().returns(Promise.resolve({ response:'250' }));
    sendEmailStub.withArgs(sinon.match(recipient => {
      return recipient.to.address === primaryEmail;
    }), sinon.match(params => {
      emailParams = params;
      return !!params.nonce;
    }));
    sinon.stub(nodemailer, 'createTransport').returns({
      templateSender: () => { return sendEmailStub; }
    });

    global.testing = true;
    let init = require('../../src/app');
    app = yield init();
  });

  beforeEach(function *() {
    yield mongo.clear(DB_TYPE_PUB_KEY);
    yield mongo.clear(DB_TYPE_USER_ID);
    emailParams = null;
  });

  after(function *() {
    nodemailer.createTransport.restore();
    yield mongo.clear(DB_TYPE_PUB_KEY);
    yield mongo.clear(DB_TYPE_USER_ID);
    yield mongo.disconnect();
  });

  describe('REST api', () => {
    describe('POST /api/v1/key', () => {
      it('should return 400 for an invalid pgp key', done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored:'foo' })
        .expect(400)
        .end(done);
      });

      it('should return 400 for an invalid primaryEmail', done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail:'foo' })
        .expect(400)
        .end(done);
      });

      it('should return 201 with primaryEmail', done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(() => {
          expect(emailParams).to.exist;
          done();
        });
      });

      it('should return 201 without primaryEmail', done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored })
        .expect(201)
        .end(() => {
          expect(emailParams).to.exist;
          done();
        });
      });
    });

    describe('GET /api/v1/verify', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(done);
      });

      it('should return 200 for valid params', done => {
        request(app.listen())
        .get('/api/v1/verify?keyid=' + emailParams.keyid + '&nonce=' + emailParams.nonce)
        .expect(200)
        .end(done);
      });

      it('should return 400 for missing keyid and', done => {
        request(app.listen())
        .get('/api/v1/verify?nonce=' + emailParams.nonce)
        .expect(400)
        .end(done);
      });

      it('should return 400 for missing nonce', done => {
        request(app.listen())
        .get('/api/v1/verify?keyid=' + emailParams.keyid)
        .expect(400)
        .end(done);
      });
    });

    describe('GET /api/key', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(done);
      });

      describe('Not yet verified', () => {
        it('should return 404', done => {
          request(app.listen())
          .get('/api/v1/key?keyid=' + emailParams.keyid)
          .expect(404).end(done);
        });
      });

      describe('Verified', () => {
        beforeEach(done => {
          request(app.listen())
          .get('/api/v1/verify?keyid=' + emailParams.keyid + '&nonce=' + emailParams.nonce)
          .expect(200)
          .end(done);
        });

        it('should return 200 and get key by id', done => {
          request(app.listen())
          .get('/api/v1/key?keyid=' + emailParams.keyid)
          .expect(200, {
            _id: emailParams.keyid,
            publicKeyArmored
          })
          .end(done);
        });

        it('should return 200 and get key email address', done => {
          request(app.listen())
          .get('/api/v1/key?email=' + primaryEmail)
          .expect(200, {
            _id: emailParams.keyid,
            publicKeyArmored
          })
          .end(done);
        });

        it('should return 400 for missing params', done => {
          request(app.listen())
          .get('/api/v1/key')
          .expect(400)
          .end(done);
        });

        it('should return 404 for wrong key id', done => {
          request(app.listen())
          .get('/api/v1/key?keyid=0123456789ABCDF')
          .expect(404)
          .end(done);
        });
      });
    });

    describe('GET /:email (sharing link)', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(done);
      });

      describe('Not yet verified', () => {
        it('should return 404', done => {
          request(app.listen())
          .get('/' + primaryEmail)
          .expect(404)
          .end(done);
        });
      });

      describe('Verified', () => {
        beforeEach(done => {
          request(app.listen())
          .get('/api/v1/verify?keyid=' + emailParams.keyid + '&nonce=' + emailParams.nonce)
          .expect(200)
          .end(done);
        });

        it('should return 200 for correct email address', done => {
          request(app.listen())
          .get('/' + primaryEmail)
          .expect(200, publicKeyArmored)
          .end(done);
        });

        it('should return 400 for invalid email', done => {
          request(app.listen())
          .get('/a@bco')
          .expect(400)
          .end(done);
        });

        it('should return 404 for unkown email', done => {
          request(app.listen())
          .get('/a@b.co')
          .expect(404)
          .end(done);
        });

        it('should return 404 for missing email', done => {
          request(app.listen())
          .get('/')
          .expect(404)
          .end(done);
        });
      });
    });

    describe('DELETE /api/v1/key', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(done);
      });

      it('should return 202 for key id', done => {
        request(app.listen())
        .del('/api/v1/key?keyid=' + emailParams.keyid)
        .expect(202)
        .end(done);
      });

      it('should return 202 for email address', done => {
        request(app.listen())
        .del('/api/v1/key?email=' + primaryEmail)
        .expect(202)
        .end(done);
      });

      it('should return 400 for invalid params', done => {
        request(app.listen())
        .del('/api/v1/key')
        .expect(400)
        .end(done);
      });

      it('should return 404 for unknown email address', done => {
        request(app.listen())
        .del('/api/v1/key?email=a@foo.com')
        .expect(404)
        .end(done);
      });
    });

    describe('GET /api/v1/verifyRemove', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ publicKeyArmored, primaryEmail })
        .expect(201)
        .end(function() {
          request(app.listen())
          .del('/api/v1/key?keyid=' + emailParams.keyid)
          .expect(202)
          .end(done);
        });
      });

      it('should return 200 for key id', done => {
        request(app.listen())
        .get('/api/v1/verifyRemove?keyid=' + emailParams.keyid + '&nonce=' + emailParams.nonce)
        .expect(200)
        .end(done);
      });

      it('should return 400 for invalid params', done => {
        request(app.listen())
        .get('/api/v1/verifyRemove')
        .expect(400)
        .end(done);
      });

      it('should return 404 for unknown email address', done => {
        request(app.listen())
        .get('/api/v1/verifyRemove?keyid=0123456789ABCDF&nonce=' + emailParams.nonce)
        .expect(404)
        .end(done);
      });
    });
  });

  describe('HKP api', () => {
    describe('POST /pks/add', () => {
      it('should return 400 for an invalid body', done => {
        request(app.listen())
        .post('/pks/add')
        .type('form')
        .send('keytext=asdf')
        .expect(400)
        .end(done);
      });

      it('should return 201 for a valid PGP key', done => {
        request(app.listen())
        .post('/pks/add')
        .type('form')
        .send('keytext=' + encodeURIComponent(publicKeyArmored))
        .expect(201)
        .end(done);
      });
    });

    describe('GET /pks/lookup', () => {
      beforeEach(done => {
        request(app.listen())
        .post('/pks/add')
        .type('form')
        .send('keytext=' + encodeURIComponent(publicKeyArmored))
        .expect(201)
        .end(done);
      });

      describe('Not yet verified', () => {
        it('should return 404', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=0x' + emailParams.keyid)
          .expect(404)
          .end(done);
        });
      });

      describe('Verified', () => {
        beforeEach(done => {
          request(app.listen())
          .get('/api/v1/verify?keyid=' + emailParams.keyid + '&nonce=' + emailParams.nonce)
          .expect(200)
          .end(done);
        });

        it('should return 200 for a valid request', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=0x' + emailParams.keyid)
          .expect(200, publicKeyArmored)
          .end(done);
        });

        it('should return 200 for correct email address', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=' + primaryEmail)
          .expect(200, publicKeyArmored)
          .end(done);
        });

        it('should return 200 for "mr" (machine readable) option', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&options=mr&search=' + primaryEmail)
          .expect('Content-Type', 'application/pgp-keys; charset=UTF-8')
          .expect('Content-Disposition', 'attachment; filename=openpgpkey.asc')
          .expect(200, publicKeyArmored)
          .end(done);
        });

        it('should return 400 for invalid email', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=a@bco')
          .expect(400)
          .end(done);
        });

        it('should return 404 for unkown email', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=a@b.co')
          .expect(404)
          .end(done);
        });

        it('should return 400 for missing params', done => {
          request(app.listen())
          .get('/pks/lookup?op=get')
          .expect(400)
          .end(done);
        });

        it('should return 400 for a invalid key id format', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=' + emailParams.keyid)
          .expect(400)
          .end(done);
        });

        it('should return 404 for unkown key id', done => {
          request(app.listen())
          .get('/pks/lookup?op=get&search=0xDBC0B3D92A1B86E9')
          .expect(404)
          .end(done);
        });

        it('should return 501 (Not implemented) for "index" op', done => {
          request(app.listen())
          .get('/pks/lookup?op=index&search=0x' + emailParams.keyid)
          .expect(501)
          .end(done);
        });
      });
    });
  });

});