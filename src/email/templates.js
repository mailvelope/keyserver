'use strict';

const util = require('../service/util');

function verifyKey(ctx, {name, email, nonce, origin, keyId}) {
  const link = `${util.url(origin)}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: ctx.__('verify_key_subject'),
    text: ctx.__('verify_key_text', [name, email, link, origin.host])
  };
}

function verifyRemove(ctx, {name, email, nonce, origin, keyId}) {
  const link = `${util.url(origin)}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: ctx.__('verify_removal_subject'),
    text: ctx.__('verify_removal_text', [name, email, origin.host, link])
  };
}

module.exports = {verifyKey, verifyRemove};
