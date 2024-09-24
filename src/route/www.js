/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

exports.plugin = {
  name: 'www',
  async register(server, options) {
    const routeOptions = {
      security: options.server.security
    };

    server.route({
      method: 'GET',
      path: '/',
      handler: {
        view: 'index'
      },
      options: routeOptions
    });

    server.route({
      method: 'GET',
      path: '/index.html',
      handler(request, h) {
        return h.redirect('/').permanent();
      },
      options: routeOptions
    });

    server.route({
      method: 'GET',
      path: '/manage.html',
      handler: {
        view: 'manage'
      },
      options: routeOptions
    });
  }
};
