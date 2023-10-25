/**
 * Copyright (C) 2023 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const init = require('./server');
const log = require('./lib/log');

(async () => {
  const server = await init();
  log.info('Server running on %s', server.info.uri);
})();

process.on('unhandledRejection', err => {
  console.log(err);
  process.exit(1);
});
