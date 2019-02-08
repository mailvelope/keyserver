'use strict';

exports.verifyKey = ({name, baseUrl, keyId, nonce}) => ({
  subject: `Verify Your Key`,
  text: `Hello ${name},\n\nplease click here to verify your key:\n\n${baseUrl}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}`,
});

exports.verifyRemove = ({name, baseUrl, keyId, nonce}) => ({
  subject: `Verify Key Removal`,
  text: `Hello ${name},\n\nplease click here to verify the removal of your key:\n\n${baseUrl}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}`,
});
