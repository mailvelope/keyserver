module.exports = {

  log: {
    level: 'error'
  },

  server: {
    httpsUpgrade: process.env.HTTPS_UPGRADE || true // use HTTPS by default
  }

};