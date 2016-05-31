'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const request = require('supertest');
const fs = require('fs');

describe.skip('Koa App (HTTP Server) Integration Tests', function() {
  this.timeout(20000);

  let app, pgpKey1;

  before(function *() {
    pgpKey1 = fs.readFileSync(__dirname + '/../key1.asc', 'utf8');
    global.testing = true;
    let init = require('../../src/app');
    app = yield init();
  });

  describe('REST api', () => {
    describe('POST /api/v1/key', () => {
      it('should return 400 for an invalid body', done => {
        request(app.listen())
        .post('/api/v1/key')
        .send({ foo: 'bar' })
        .expect(400)
        .end(done);
      });
    });
  });

  describe('HKP api', () => {
    describe('GET /pks/add', () => {
      it.skip('should return 200 for a valid request', done => {
        request(app.listen())
        .get('/pks/lookup?op=get&search=0xDBC0B3D92B1B86E9')
        .expect(200)
        .end(done);
      });

      it('should return 404 if not found', done => {
        request(app.listen())
        .get('/pks/lookup?op=get&search=0xDBC0B3D92A1B86E9')
        .expect(404)
        .end(done);
      });
    });

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
        .send('keytext=' + encodeURIComponent(pgpKey1))
        .expect(201)
        .end(done);
      });
    });
  });

});