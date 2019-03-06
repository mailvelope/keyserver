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

const log = require('winston');
const {SPLAT} = require('triple-beam');
const config = require('config');
require('winston-papertrail');

log.exitOnError = false;
log.level = config.log.level;

// Reformat logging text, due to deprecated logger usage
const formatLogs = log.format(info => {
  info.message = `${info.message} -> ${info[SPLAT].join(', ')}`;
  return info;
});

exports.init = function({host, port}) {
  if (host && port) {
    log.add(new log.transports.Papertrail({
      format: formatLogs(),
      level: config.log.level,
      host,
      port
    }));
    return;
  }
  if (process.env.NODE_ENV !== 'production') {
    log.add(new log.transports.Console({
      format: log.format.combine(
        formatLogs(),
        log.format.simple()
      )
    }));
  }
};
