'use strict';

require('dotenv').config();
const util = require('../src/lib/util');

module.exports = {

  log: {
    level: process.env.LOG_LEVEL || 'info'
  },

  syslog: {
    host: process.env.SYSLOG_HOST,
    port: util.parseNumber(process.env.SYSLOG_PORT)
  },

  server: {
    port: util.parseNumber(process.env.PORT) ?? 8888,
    host: process.env.SERVER_HOST || 'localhost',
    cors: util.isTrue(process.env.CORS_HEADER),
    security: util.isTrue(process.env.HTTP_SECURITY_HEADER),
    csp: util.isTrue(process.env.CSP_HEADER)
  },

  mongo: {
    uri: process.env.MONGO_URI,
    user: process.env.MONGO_USER,
    pass: process.env.MONGO_PASS
  },

  email: {
    host: process.env.SMTP_HOST,
    port: util.parseNumber(process.env.SMTP_PORT),
    tls: util.isTrue(process.env.SMTP_TLS ?? true),
    starttls: util.isTrue(process.env.SMTP_STARTTLS ?? true),
    pgp: util.isTrue(process.env.SMTP_PGP ?? true),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    sender: {
      name: process.env.SENDER_NAME,
      email: process.env.SENDER_EMAIL
    }
  },

  publicKey: {
    purgeTimeInDays: util.parseNumber(process.env.PUBLIC_KEY_PURGE_TIME) ?? 14,
    uploadRateLimit: util.parseNumber(process.env.UPLOAD_RATE_LIMIT)
  },

  purify: {
    purifyKey: util.isTrue(process.env.PURIFY_KEY ?? true),
    maxNumUserEmail: util.parseNumber(process.env.MAX_NUM_USER_EMAIL) ?? 20,
    maxNumSubkey: util.parseNumber(process.env.MAX_NUM_SUBKEY) ?? 20,
    maxNumCert: util.parseNumber(process.env.MAX_NUM_CERT) ?? 5,
    maxSizeUserID: util.parseNumber(process.env.MAX_SIZE_USERID) ?? 1024,
    maxSizePacket: util.parseNumber(process.env.MAX_SIZE_PACKET) ?? 8383,
    maxSizeKey: util.parseNumber(process.env.MAX_SIZE_KEY) ?? 32768
  }

};
