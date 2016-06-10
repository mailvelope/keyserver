'use strict';

const util = require('../service/util');
const config = require('config');

module.exports = function () {
  let hkpLink = util.hkpUrl(this);
  this.body =
  `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>${config.ui.title}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
  </head>
  <body>
    <h1>${config.ui.title}</h1>

    <h2>Try it out</h2>
    <ol>
      <li>Upload your public OpenPGP key using the form below.</li>
      <li>Check your inbox and click on the verification link inside the encrypted message.</li>
      <li>You can delete all your data from the server at any time using the form below.</li>
      <li>Configure this key server in your HKP compatible OpenPGP client using this url: <a href="${hkpLink}" target="_blank">${hkpLink}</a></li>
    </ol>
    <h2>Documentation and code</h2>
    <p>Please refer to <a href="https://github.com/mailvelope/keyserver" target="_blank">the documentation</a> to learn more about the REST api.</p>
    <p>License AGPL v3.0</p>
    <hr>

    <h2>
      <a id="extract" name="extract">Find OpenPGP Key</a>
    </h2>
    <form action="/pks/lookup" method="get">
      <p>
        Get:
        <input type="radio" name="op" value="get" checked="checked">
        Index:
        <input type="radio" name="op" value="index">
      </p>
      <p>
        Search:
        <input name="search" type="email" spellcheck="false" size="40" placeholder="Email address, long key ID or fingerprint">
      </p>
      <p>
        <input type="reset" value="Reset">
        <input type="submit" value="Search">
      </p>
    </form>
    <hr>

    <h2>
      <a id="upload" name="submit">Upload a new OpenPGP Key</a>
    </h2>
    <form action="/pks/add" method="post">
      <p>Paste ASCII-armored OpenPGP key block here:</p>
      <p>
        <textarea name="keytext" rows="20" cols="50"></textarea>
      </p>
      <p>
        <input type="reset" value="Reset">
        <input type="submit" value="Upload">
      </p>
    </form>
    <hr>

    <h2>
      <a id="delete" name="extract">Delete your OpenPGP Key</a>
    </h2>
    <form action="/api/v1/removeKey" method="get">
      <p>
        Remove:
        <input name="email" type="email" spellcheck="false" size="40" placeholder="Email address">
      </p>
      <p>
        <input type="reset" value="Reset">
        <input type="submit" value="Remove">
      </p>
    </form>
  </body>
  </html>
  `;

  this.set('Content-Type', 'text/html; charset=utf-8');
};