'use strict';

const util = require('../service/util');

module.exports = function () {
  let hkpLink = util.hkpUrl(this);
  let removeLink = util.url(util.origin(this), '/api/v1/removeKey?email=user@example.com');
  this.body =
  `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>OpenPGP key server</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
  </head>
  <body>
    <h1>Welcome to the OpenPGP key server</h1>
    <p>This server verifies email address as well as private key ownership by sending an encrypted verification email.</p>
    <h2>Try it out</h2>
    <ol>
      <li>Configure this key server in your HKP compatible OpenPGP client using this url: <a href="${hkpLink}" target="_blank">${hkpLink}</a></li>
      <li>Now just upload a public key like you always do.</li>
      <li>Check your inbox and click on the verification link inside the encrypted message.</li>
      <li>You can delete all your data from the server at any time using this link: <a href="${removeLink}" target="_blank">${removeLink}</a></li>
    </ol>
    <h2>Documentation and code</h2>
    <p>Please refer to <a href="https://github.com/mailvelope/keyserver" target="_blank">the documentation</a> to learn more about the api.</p>
    <p>License AGPL v3.0</p>
  </body>
  </html>
  `;

  this.set('Content-Type', 'text/html; charset=utf-8');
};