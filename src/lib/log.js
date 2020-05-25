/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const winston = require('winston');
require('winston-syslog').Syslog;
const config = require('../../config/config');

const logger = winston.createLogger({
  level: config.log.level,
  levels: winston.config.syslog.levels,
  format: winston.format.combine(
    winston.format.splat(),
    winston.format(info => {
      info.message = `${info.message}\n`;
      return info;
    })(),
    winston.format.simple()
  ),
  exitOnError: false,
  transports: [
    config.syslog.host ? new winston.transports.Syslog(config.syslog) : new winston.transports.Console()
  ]
});

module.exports = logger;
