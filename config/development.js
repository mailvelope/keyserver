'use strict';

module.exports = {

  mongo: {
    uri: '127.0.0.1:27017/keyserver-test',
    user: 'keyserver-user',
    pass: 'trfepCpjhVrqgpXFWsEF'
  },

  email: {
    host: 'smtp.gmail.com',
    port: 465,
    tls: true,
    starttls: true,
    pgp: true,
    auth: {
      user: 'user@gmail.com',
      pass: 'password'
    },
    sender: {
      name: 'OpenPGP Key Server',
      email: 'user@gmail.com'
    }
  }

};
