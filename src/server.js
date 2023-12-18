/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Hapi = require('@hapi/hapi');
const Vision = require('@hapi/vision');
const Inert = require('@hapi/inert');
const ejs = require('ejs');
const config = require('../config/config');
const path = require('path');
const i18n = require('hapi-i18n');

const Mongo = require('./modules/mongo');
const Email = require('./modules/email');
const PurifyKey = require('./modules/purify-key');
const PGP = require('./modules/pgp');
const PublicKey = require('./modules/public-key');

const HKP = require('./route/hkp');
const REST = require('./route/rest');
const WWW = require('./route/www');
const CSP = require('./lib/csp');

const init = async (conf = config) => {
  const server = Hapi.server({
    port: conf.server.port,
    host: conf.server.host,
  });
  // modules
  const mongo = new Mongo();
  await mongo.init(conf.mongo);
  const email = new Email();
  email.init(conf.email);
  const purify = new PurifyKey(conf.purify);
  const pgp = new PGP(purify);
  const publicKey = new PublicKey(pgp, mongo, email);
  await publicKey.init();
  server.app.publicKey = publicKey;
  // views
  await server.register(Vision);
  server.views({
    engines: {
      html: ejs
    },
    path: path.join(__dirname, 'view'),
    layout: true
  });
  // static
  await server.register(Inert);
  server.route({
    method: 'GET',
    path: '/{param*}',
    handler: {
      directory: {
        path: path.join(__dirname, 'static')
      }
    }
  });
  // content security policy
  if (conf.server.csp) {
    await server.register({plugin: CSP.plugin});
  }
  // routes
  await server.register({plugin: HKP.plugin, options: conf});
  await server.register({plugin: REST.plugin, options: conf});
  await server.register({plugin: WWW.plugin, options: conf});
  // translation
  await server.register({
    plugin: i18n,
    options: {
      locales: ['de', 'en'],
      directory: path.join(__dirname, '../locales'),
      languageHeaderField: 'Accept-Language',
      defaultLocale: 'en'
    }
  });
  // start
  await server.start();
  return server;
};

module.exports = init;
