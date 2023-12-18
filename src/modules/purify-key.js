/**
 * Copyright (C) 2023 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const Boom = require('@hapi/boom');
const {filterAsync} = require('../lib/util');
const {enums} = require('openpgp');

/**
 * Purify keys to avoid malicious abuse of key server following techniques from:
 * https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-abuse-resistant-keystore-06
 */
class PurifyKey {
  constructor(config) {
    this.conf = {
      allowedUnhashedSubpackets: new Set([
        enums.signatureSubpacket.issuer,
        enums.signatureSubpacket.issuerFingerprint,
        enums.signatureSubpacket.embeddedSignature
      ]),
      ...config
    };
  }

  /**
   * Evaluate the key and filter out all components that violate policy for abuse resistant key server
   * @param {PublicKey} key         The key to be purified
   * @throws {Error}                The key failed the purification
   */
  async purifyKey(key) {
    if (!this.conf.purifyKey) {
      return;
    }
    this.checkKeyPacket(key);
    await this.checkKeySignatures(key);
    await this.checkUsers(key);
    await this.checkSubkeys(key);
    this.limitNumOfCertificates(key);
  }

  checkKeyPacket(key) {
    if (key.keyPacket.write().length > this.conf.maxSizePacket) {
      throw Boom.badRequest(`The primary key packet exceeds the max. allowed size of ${(this.conf.maxSizePacket / 1024).toFixed(2)} kB.`);
    }
    if (key.keyPacket.version !== 4) {
      throw Boom.badRequest('Only keys with v4 primary key packet are supported.');
    }
  }

  async checkKeySignatures(key) {
    // verify and filter all revocation certifications
    key.revocationSignatures = await filterAsync(key.revocationSignatures, cert => this.verifyKeyCerts(key.keyPacket, cert, enums.signature.keyRevocation));
    // remove not allowed unhashed subpackets
    key.revocationSignatures.forEach(cert => this.filterUnhashedSubPackets(cert));
    // verify and filter all direct signatures
    key.directSignatures = await filterAsync(key.directSignatures, cert => this.verifyKeyCerts(key.keyPacket, cert, enums.signature.key));
    // remove not allowed unhashed subpackets
    key.directSignatures.forEach(cert => this.filterUnhashedSubPackets(cert));
  }

  async checkUsers(key) {
    // filter out user attribute packets and user IDs without email address
    key.users = key.users.filter(user => user.userID?.email);
    if (!key.users.length) {
      throw Boom.badRequest('Require at least one user ID with email address.');
    }
    // filter out user IDs that exceeds maxSizeUserID bytes
    key.users = key.users.filter(user => user.userID.write().length <= this.conf.maxSizeUserID);
    if (!key.users.length) {
      throw Boom.badRequest(`Size of all user IDs of key exceeds ${this.conf.maxSizeUserID} bytes.`);
    }
    for (const user of key.users) {
      // verify and filter all self certifications
      user.selfCertifications = await filterAsync(user.selfCertifications, cert => this.verifyUserCerts(user.mainKey.keyPacket, user.userID, cert, enums.signature.certGeneric));
      // remove not allowed unhashed subpackets
      user.selfCertifications.forEach(cert => this.filterUnhashedSubPackets(cert));
      // remove all other certifications
      user.otherCertifications = [];
      // verify and filter all revocation certifications
      user.revocationSignatures = await filterAsync(user.revocationSignatures, cert => this.verifyUserCerts(user.mainKey.keyPacket, user.userID, cert, enums.signature.certRevocation));
      // remove not allowed unhashed subpackets
      user.revocationSignatures.forEach(cert => this.filterUnhashedSubPackets(cert));
    }
    // user needs at least one self or revocation certification
    key.users = key.users.filter(user => user.selfCertifications.length || user.revocationSignatures.length);
    // enforce max. number of email addresses per key
    if (key.users.length > this.conf.maxNumUserEmail) {
      throw Boom.badRequest(`Number of user IDs with email address exceeds allowed max. of ${this.conf.maxNumUserEmail}`);
    }
  }

  async checkSubkeys(key) {
    // filter out subkeys with packet size that exceeds maxSizePacket bytes
    key.subkeys = key.subkeys.filter(subkey => subkey.keyPacket.write().length <= this.conf.maxSizePacket);
    for (const subkey of key.subkeys) {
      // verify and filter all binding signatures
      subkey.bindingSignatures = await filterAsync(subkey.bindingSignatures, cert => this.verifySubkeyCerts(subkey.mainKey.keyPacket, subkey.keyPacket, cert, enums.signature.subkeyBinding));
      // remove not allowed unhashed subpackets
      subkey.bindingSignatures.forEach(cert => this.filterUnhashedSubPackets(cert));
      // verify and filter all revocation certifications
      subkey.revocationSignatures = await filterAsync(subkey.revocationSignatures, cert => this.verifySubkeyCerts(subkey.mainKey.keyPacket, subkey.keyPacket, cert, enums.signature.subkeyRevocation));
      // remove not allowed unhashed subpackets
      subkey.revocationSignatures.forEach(cert => this.filterUnhashedSubPackets(cert));
    }
    // subkey needs at least one binding or revocation signature
    key.subkeys = key.subkeys.filter(subkey => subkey.bindingSignatures.length || subkey.revocationSignatures.length);
    // enforce max. number of subkeys per key
    if (key.subkeys.length > this.conf.maxNumSubkey) {
      throw Boom.badRequest(`Number of subkeys exceeds allowed max. of ${this.conf.maxNumSubkey}`);
    }
  }

  limitNumOfCertificates(key) {
    if (!this.conf.purifyKey) {
      return;
    }
    this.limitRevCerts(key.revocationSignatures, this.conf.maxNumCert);
    this.limitCerts(key.directSignatures, this.conf.maxNumCert);
    for (const user of key.users) {
      this.limitCerts(user.selfCertifications, this.conf.maxNumCert);
      this.limitRevUserCerts(user.revocationSignatures, this.conf.maxNumCert);
    }
    for (const subkey of key.subkeys) {
      this.limitCerts(subkey.bindingSignatures, this.conf.maxNumCert);
      this.limitRevCerts(subkey.revocationSignatures, this.conf.maxNumCert);
    }
  }

  limitCerts(certs, maxNum) {
    // sort by descending signature creation date
    certs.sort((a, b) => b.created - a.created);
    if (certs.length > maxNum) {
      certs.length = maxNum;
    }
  }

  limitRevCerts(certs, maxNum) {
    // sort by descending hard revocation and ascending signature creation date => oldest hard revocations first
    certs.sort((a, b) => this.isHardRevocation(b) - this.isHardRevocation(a) || a.created - b.created);
    if (certs.length > maxNum) {
      certs.length = maxNum;
    }
  }

  limitRevUserCerts(certs, maxNum) {
    // sort by ascending signature creation date
    certs.sort((a, b) => a.created - b.created);
    if (certs.length > maxNum) {
      certs.length = maxNum;
    }
  }

  isHardRevocation(cert) {
    // "Key is superseded" or "Key is retired and no longer used" is a "soft" revocation
    // All other revocations are considered "hard"
    return !(cert.reasonForRevocationFlag === enums.reasonForRevocation.keySuperseded ||
             cert.reasonForRevocationFlag === enums.reasonForRevocation.keyRetired);
  }

  async verifyUserCerts(key, userID, cert, type) {
    try {
      await cert.verify(key, type, {userID, key}, null);
      return cert.write().length <= this.conf.maxSizePacket;
    } catch (e) {}
  }

  async verifyKeyCerts(key, cert, type) {
    try {
      await cert.verify(key, type, {key}, null);
    } catch (e) {
      if (e.message !== 'This key is intended to be revoked with an authorized key, which OpenPGP.js does not support.') {
        return;
      }
    }
    return cert.write().length <= this.conf.maxSizePacket;
  }

  async verifySubkeyCerts(key, bind, cert, type) {
    try {
      await cert.verify(key, type, {key, bind}, null);
      return cert.write().length <= this.conf.maxSizePacket;
    } catch (e) {}
  }

  filterUnhashedSubPackets(cert) {
    // remove all unhashed subpackets except allowed ones
    cert.unhashedSubpackets = cert.unhashedSubpackets.filter(packet => this.conf.allowedUnhashedSubpackets.has(packet[0] & 0x7F));
    if (cert.embeddedSignature) {
      cert.embeddedSignature.unhashedSubpackets = [];
    }
  }

  checkMaxKeySize(key) {
    if (!this.conf.purifyKey) {
      return;
    }
    const keySize = key.toPacketList().write().length;
    if (keySize > this.conf.maxSizeKey) {
      throw Boom.badRequest(`The key exceeds the max. allowed key size of ${(this.conf.maxSizeKey / 1024).toFixed(2)} kB.`);
    }
  }
}

module.exports = PurifyKey;
