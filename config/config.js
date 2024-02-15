'use strict';

require('dotenv').config();

module.exports = {

  log: {
    level: process.env.LOG_LEVEL || 'info'
  },

  syslog: {
    host: process.env.SYSLOG_HOST,
    port: process.env.SYSLOG_PORT
  },

  server: {
    port: process.env.PORT || 8888,
    host: process.env.SERVER_HOST || 'localhost',
    cors: process.env.CORS_HEADER,
    security: process.env.HTTP_SECURITY_HEADER,
    csp: process.env.CSP_HEADER
  },

  mongo: {
    uri: process.env.MONGO_URI,
    user: process.env.MONGO_USER,
    pass: process.env.MONGO_PASS
  },

  email: {
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    tls: process.env.SMTP_TLS,
    starttls: process.env.SMTP_STARTTLS,
    pgp: process.env.SMTP_PGP ?? true,
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
    purgeTimeInDays: process.env.PUBLIC_KEY_PURGE_TIME || 14,
    uploadRateLimit: process.env.UPLOAD_RATE_LIMIT || 10
  },

  purify: {
    purifyKey: process.env.PURIFY_KEY ?? true,
    maxNumUserEmail: process.env.MAX_NUM_USER_EMAIL || 20,
    maxNumSubkey: process.env.MAX_NUM_SUBKEY || 20,
    maxNumCert: process.env.MAX_NUM_CERT || 5,
    maxSizeUserID: process.env.MAX_SIZE_USERID || 1024,
    maxSizePacket: process.env.MAX_SIZE_PACKET || 8383,
    maxSizeKey: process.env.MAX_SIZE_KEY || 32768
  }

};
