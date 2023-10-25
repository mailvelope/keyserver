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
        response.header('Content-Security-Policy', "default-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';");
      }
      return h.continue;
    });
  }
};
