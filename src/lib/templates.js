'use strict';

const util = require('./util');

function verifyKey({name, email, nonce, origin, keyId, i18n}) {
  const link = `${util.url(origin)}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: i18n.__('verify_key_subject'),
    text: i18n.__mf('verify_key_text', {name, email, link, host: origin.host})
  };
}

function verifyRemove({name, email, nonce, origin, keyId, i18n}) {
  const link = `${util.url(origin)}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: i18n.__('verify_removal_subject'),
    text: i18n.__mf('verify_removal_text', {name, email, link, host: origin.host})
  };
}

module.exports = {verifyKey, verifyRemove};
