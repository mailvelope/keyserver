'use strict';

module.exports = function () {
  let hkp = (this.secure ? 'hkps://' : 'hkp://') + this.host;
  let del = this.origin + '/api/v1/removeKey?email=user@example.com';
  this.body =
  `
  <h1>Welcome to the OpenPGP key server</h1>
  <p>This server verifies email address as well as private key ownership by sending an encrypted verification email.</p>
  <h2>Try it out</h2>
  <ol>
    <li>Configure this key server in your HKP compatible OpenPGP client using this url: <a href="${hkp}" target="_blank">${hkp}</a></li>
    <li>Now just upload a public key like you always do.</li>
    <li>Check your inbox and click on the verification link inside the encrypted message.</li>
    <li>You can delete all your data from the server at any time using this link: <a href="${del}" target="_blank">${del}</a></li>
  </ol>
  <h2>Documentation and code</h2>
  <p>Please refer to <a href="https://github.com/mailvelope/keyserver" target="_blank">the documentation</a> to learn more about the api.</p>
  <p>License AGPL v3.0</p>
  `;

  this.set('Content-Type', 'text/html; charset=utf-8');
};