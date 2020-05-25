/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

exports.plugin = {
  name: 'CSP',
  async register(server) {
    server.ext('onPreResponse', async (request, h) => {
      const {response} = request;
      if (!response.isBoom) {
        response.header('Content-Security-Policy', "default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'");
      }
      return h.continue;
    });
  }
};
