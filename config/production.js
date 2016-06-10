module.exports = {

  log: {
    level: 'error'
  },

  server: {
    upgradeHTTPS: process.env.UPGRADE_HTTPS || true // use HTTPS by default
  }

};