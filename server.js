/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2016 Mailvelope GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const log = require('npmlog');

//
// Error handling
//

process.on('SIGTERM', () => {
  log.warn('exit', 'Exited on SIGTERM');
  process.exit(0);
});

process.on('SIGINT', () => {
  log.warn('exit', 'Exited on SIGINT');
  process.exit(0);
});

process.on('uncaughtException', err => {
  log.error('server', 'Uncaught exception ', err);
  process.exit(1);
});

//
// Start worker cluster depending on number of CPUs
//

if (cluster.isMaster) {
  for (var i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('fork', worker => {
    log.info('cluster', 'Forked worker #%s [pid:%s]', worker.id, worker.process.pid);
  });

  cluster.on('exit', worker => {
    log.warn('cluster', 'Worker #%s [pid:%s] died', worker.id, worker.process.pid);
    setTimeout(() => {
      cluster.fork();
    }, 5000);
  });
} else {
  require('./src/worker');
}