'use strict';

module.exports = {

  log: {
    level: process.env.LOG_LEVEL || 'silly'
  },

  papertrail: {
    host: process.env.PAPERTRAIL_HOST,
    port: process.env.PAPERTRAIL_PORT
  },

  server: {
    port: process.env.PORT || 8888,
    httpsUpgrade: process.env.HTTPS_UPGRADE,
    httpsKeyPin: process.env.HTTPS_KEY_PIN,
    httpsKeyPinBackup: process.env.HTTPS_KEY_PIN_BACKUP
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
    pgp: process.env.SMTP_PGP,
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
    purgeTimeInDays: process.env.PUBLIC_KEY_PURGE_TIME || 30
  }

};
