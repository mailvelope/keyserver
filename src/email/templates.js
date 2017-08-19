'use strict';

exports.verifyKey = ({name, baseUrl, keyId, nonce}) => ({
  subject: `Verify Your Key`,
  text: `Hello ${name},\n\nplease click here to verify your key:\n\n${baseUrl}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}`,
  html: `<p>Hello ${name},</p><p>please <a href=\"${baseUrl}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}\">click here to verify</a> your key.</p>`
});

exports.verifyRemove = ({name, baseUrl, keyId, nonce}) => ({
  subject: `Verify Key Removal`,
  text: `Hello ${name},\n\nplease click here to verify the removal of your key:\n\n${baseUrl}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}`,
  html: `<p>Hello ${name},</p><p>please <a href=\"${baseUrl}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}\">click here to verify</a> the removal of your key.</p>`
});
