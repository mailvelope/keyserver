'use strict';

const fs = require('fs');
const config = require('../../config/config');
const {readKey, enums, SignaturePacket} = require('openpgp');
const PurifyKey = require('../../src/modules/purify-key');

describe('Purify Key Unit Tests', () => {
  let purify;
  let key2Armored;
  let key2;
  let key5Armored;
  let key5;
  let key6Armored;
  let key6;

  before(() => {
    key2Armored = fs.readFileSync(`${__dirname}/../fixtures/key2.asc`, 'utf8');
    key5Armored = fs.readFileSync(`${__dirname}/../fixtures/key5.asc`, 'utf8');
    key6Armored = fs.readFileSync(`${__dirname}/../fixtures/key6.asc`, 'utf8');
  });

  beforeEach(async () => {
    purify = new PurifyKey(config.purify);
  });

  afterEach(async () => {
    sinon.restore();
  });

  describe('checkMaxKeySize checkKeyPacket', () => {
    beforeEach(async () => {
      key2 = await readKey({armoredKey: key2Armored});
    });

    it('should throw error if size of key exceeds upper limit', () => {
      purify.conf.maxSizeKey = 256;
      expect(() => purify.checkMaxKeySize(key2)).to.throw('The key exceeds the max. allowed key size of 0.25 kB.');
    });

    it('should not throw if PURIFY_KEY false', () => {
      purify.conf.maxSizeKey = 256;
      purify.conf.purifyKey = false;
      expect(() => purify.checkMaxKeySize(key2)).to.not.throw();
    });

    it('should not throw if size of key below upper limit', () => {
      purify.conf.maxSizeKey = 512;
      expect(() => purify.checkMaxKeySize(key2)).to.not.throw();
    });

    it('should throw error if size of primary key packet exceeds upper limit', () => {
      purify.conf.maxSizePacket = 32;
      expect(() => purify.checkKeyPacket(key2)).to.throw('The primary key packet exceeds the max. allowed size of 0.03 kB.');
    });

    it('should not throw if size of primary key packet below upper limit', () => {
      purify.conf.maxSizePacket = 64;
      expect(() => purify.checkKeyPacket(key2)).to.not.throw();
    });

    it('should throw error if other than v4 keys are used', () => {
      key2.keyPacket.version = 5;
      expect(() => purify.checkKeyPacket(key2)).to.throw('Only keys with v4 primary key packet are supported.');
    });
  });

  describe('verifyUserCerts verifySubkeyCerts', () => {
    beforeEach(async () => {
      key2 = await readKey({armoredKey: key2Armored});
    });

    it('should return true for valid user cert', async () => {
      const result = await purify.verifyUserCerts(key2.keyPacket, key2.users[0].userID, key2.users[0].selfCertifications[0], enums.signature.certGeneric);
      expect(result).to.be.true;
    });

    it('should not return true for invalid user cert', async () => {
      key2.users[0].selfCertifications[0].signedHashValue[0] = 1;
      const result = await purify.verifyUserCerts(key2.keyPacket, key2.users[0].userID, key2.users[0].selfCertifications[0], enums.signature.certGeneric);
      expect(result).to.not.be.true;
    });

    it('should return true for valid subkey binding cert', async () => {
      const result = await purify.verifySubkeyCerts(key2.keyPacket, key2.subkeys[0].keyPacket, key2.subkeys[0].bindingSignatures[0], enums.signature.subkeyBinding);
      expect(result).to.be.true;
    });

    it('should not return true for invalid subkey binding cert', async () => {
      key2.subkeys[0].bindingSignatures[0].signedHashValue[0] = 1;
      const result = await purify.verifySubkeyCerts(key2.keyPacket, key2.subkeys[0].keyPacket, key2.subkeys[0].bindingSignatures[0], enums.signature.subkeyBinding);
      expect(result).to.not.be.true;
    });
  });

  describe('checkKeySignatures', () => {
    beforeEach(async () => {
      key6 = await readKey({armoredKey: key6Armored});
    });

    it('should verify revocation and direct signatures', async () => {
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(1);
      expect(key6.directSignatures).to.have.lengthOf(1);
    });

    it('should filter out invalid signatures', async () => {
      key6.revocationSignatures[0].signedHashValue[0] = 1;
      key6.directSignatures[0].signedHashValue[0] = 1;
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(0);
      expect(key6.directSignatures).to.have.lengthOf(0);
    });

    it('should not filter out expired signatures', async () => {
      key6.revocationSignatures[0].signatureExpirationTime = 1;
      key6.directSignatures[0].signatureExpirationTime = 1;
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(1);
      expect(key6.directSignatures).to.have.lengthOf(1);
    });

    it('should filter out signatures above maxSizePacket', async () => {
      purify.conf.maxSizePacket = 100;
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(0);
      expect(key6.directSignatures).to.have.lengthOf(0);
    });

    it('should filter out unhashed subpackets', async () => {
      purify.conf.allowedUnhashedSubpackets = new Set();
      expect(key6.revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(1);
      expect(key6.directSignatures[0].unhashedSubpackets).to.have.lengthOf(2);
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(0);
      expect(key6.directSignatures[0].unhashedSubpackets).to.have.lengthOf(0);
      await purify.checkKeySignatures(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(1);
      expect(key6.directSignatures).to.have.lengthOf(1);
    });

    it('should filter out private unhashed subpackets', async () => {
      expect(key6.directSignatures[0].unhashedSubpackets).to.have.lengthOf(2);
      await purify.checkKeySignatures(key6);
      expect(key6.directSignatures[0].unhashedSubpackets).to.have.lengthOf(1);
      await purify.checkKeySignatures(key6);
      expect(key6.directSignatures).to.have.lengthOf(1);
    });
  });

  describe('checkUsers', () => {
    beforeEach(async () => {
      key6 = await readKey({armoredKey: key6Armored});
    });

    it('should filter out user attributes', async () => {
      expect(key6.users.find(user => user.userAttribute)).to.exist;
      await purify.checkUsers(key6);
      expect(key6.users.find(user => user.userAttribute)).to.not.exist;
    });

    it('should filter out user IDs without email address', async () => {
      expect(key6.users.find(user => user.userID?.email === '')).to.exist;
      await purify.checkUsers(key6);
      expect(key6.users.find(user => user.userID.email === '')).to.not.exist;
    });

    it('should throw if no email address', () => {
      key6.users = key6.users.filter(user => user.userID?.email === '');
      return expect(purify.checkUsers(key6)).to.eventually.be.rejectedWith('Require at least one user ID with email address.');
    });

    it('should filter out user IDs above maxSizeUserID', async () => {
      purify.conf.maxSizeUserID = 32;
      await purify.checkUsers(key6);
      expect(key6.users).to.have.lengthOf(2);
    });

    it('should throw if all user IDs above maxSizeUserID', () => {
      purify.conf.maxSizeUserID = 10;
      return expect(purify.checkUsers(key6)).to.eventually.be.rejectedWith(/^Size of all user IDs of key exceeds/);
    });

    it('should verify user certificates', async () => {
      const verify1 = sinon.spy(key6.users[0].selfCertifications[0], 'verify');
      const verify2 = sinon.spy(key6.users[3].selfCertifications[0], 'verify');
      const verify3 = sinon.spy(key6.users[4].selfCertifications[0], 'verify');
      const verify4 = sinon.spy(key6.users[4].revocationSignatures[0], 'verify');
      const verify5 = sinon.spy(key6.users[4].revocationSignatures[1], 'verify');
      const verify6 = sinon.spy(key6.users[4].revocationSignatures[2], 'verify');
      const verify7 = sinon.spy(key6.users[4].revocationSignatures[3], 'verify');
      await purify.checkUsers(key6);
      expect(verify1.calledOnce).to.be.true;
      expect(verify2.calledOnce).to.be.true;
      expect(verify3.calledOnce).to.be.true;
      expect(verify4.calledOnce).to.be.true;
      expect(verify5.calledOnce).to.be.true;
      expect(verify6.calledOnce).to.be.true;
      expect(verify7.calledOnce).to.be.true;
    });

    it('should not filter out valid certificates', async () => {
      await purify.checkUsers(key6);
      expect(key6.users[0].selfCertifications).to.have.lengthOf(1);
      expect(key6.users[1].selfCertifications).to.have.lengthOf(1);
      expect(key6.users[2].selfCertifications).to.have.lengthOf(1);
      expect(key6.users[2].revocationSignatures).to.have.lengthOf(4);
    });

    it('should filter out invalid certificates', async () => {
      key6.users[4].revocationSignatures[0].signedHashValue[0] = 1;
      await purify.checkUsers(key6);
      expect(key6.users[2].revocationSignatures).to.have.lengthOf(3);
    });

    it('should filter out users without self or revocation certificates', async () => {
      key6.users[0].selfCertifications[0].signedHashValue[0] = 1;
      await purify.checkUsers(key6);
      expect(key6.users).to.have.lengthOf(2);
    });

    it('should not filter out users with only revocation certificates', async () => {
      key6.users[4].selfCertifications[0].signedHashValue[0] = 1;
      await purify.checkUsers(key6);
      expect(key6.users).to.have.lengthOf(3);
    });

    it('should remove all other certifications', async () => {
      key6.users[0].otherCertifications.push({});
      await purify.checkUsers(key6);
      expect(key6.users[0].otherCertifications).to.have.lengthOf(0);
    });

    it('should throw if maxNumUserEmail', () => {
      purify.conf.maxNumUserEmail = 1;
      return expect(purify.checkUsers(key6)).to.eventually.be.rejectedWith('Number of user IDs with email address exceeds allowed max. of 1');
    });

    it('should filter out unhashed subpackets', async () => {
      purify.conf.allowedUnhashedSubpackets = new Set();
      expect(key6.users[4].revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(1);
      expect(key6.users[4].selfCertifications[0].unhashedSubpackets).to.have.lengthOf(1);
      await purify.checkUsers(key6);
      expect(key6.users[2].revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(0);
      expect(key6.users[2].selfCertifications[0].unhashedSubpackets).to.have.lengthOf(0);
      await purify.checkKeySignatures(key6);
      expect(key6.users[2].revocationSignatures).to.have.lengthOf(4);
      expect(key6.users[2].selfCertifications).to.have.lengthOf(1);
    });
  });

  describe('parseUserID', () => {
    it('should parse a userID with ,', async () => {
      const userID = {userID: 'Demo, Mailvelope <demo@mailvelope.com>'};
      const {name, email} = purify.parseUserID(userID);
      expect(name).to.equal('Demo, Mailvelope');
      expect(email).to.equal('demo@mailvelope.com');
    });

    it('should do nothing if no email address', async () => {
      const userID = {userID: '!#&'};
      const {name, email} = purify.parseUserID(userID);
      expect(name).to.not.exist;
      expect(email).to.not.exist;
    });

    it('should do nothing if invalid email address', async () => {
      const userID = {userID: 'demo@mailvelope'};
      const {name, email} = purify.parseUserID(userID);
      expect(name).to.not.exist;
      expect(email).to.not.exist;
    });

    it('should return {} if userID undefined', async () => {
      const result = purify.parseUserID();
      expect(result).to.eql({});
    });

    it('should return email address if existent and normalize', async () => {
      const userID = {userID: 'Demo@mailvelope.com', email: 'Demo@mailvelope.com'};
      const {email} = purify.parseUserID(userID);
      expect(email).to.equal('demo@mailvelope.com');
    });

    it('should return name if existent', async () => {
      const userID = {name: 'Demo'};
      const {name, email} = purify.parseUserID(userID);
      expect(name).to.equal('Demo');
      expect(email).to.not.exist;
    });
  });

  describe('checkSubkeys', () => {
    beforeEach(async () => {
      key6 = await readKey({armoredKey: key6Armored});
    });

    it('should filter out subkeys above maxSizePacket', async () => {
      purify.conf.maxSizePacket = 140;
      expect(key6.subkeys).to.have.lengthOf(2);
      await purify.checkSubkeys(key6);
      expect(key6.subkeys).to.have.lengthOf(1);
    });

    it('should filter out subkeys with invalid binding and no revocation signature', async () => {
      key6.subkeys[0].bindingSignatures[0].signedHashValue[0] = 1;
      expect(key6.subkeys[0].revocationSignatures).to.have.lengthOf(0);
      await purify.checkSubkeys(key6);
      expect(key6.subkeys).to.have.lengthOf(1);
    });

    it('should not filter out subkeys with invalid binding but revocation signature', async () => {
      key6.subkeys[1].bindingSignatures[0].signedHashValue[0] = 1;
      expect(key6.subkeys[1].revocationSignatures).to.have.lengthOf(1);
      await purify.checkSubkeys(key6);
      expect(key6.subkeys).to.have.lengthOf(2);
    });

    it('should filter out unhashed subpackets', async () => {
      purify.conf.allowedUnhashedSubpackets = new Set();
      expect(key6.subkeys[1].bindingSignatures[0].unhashedSubpackets).to.have.lengthOf(2);
      expect(key6.subkeys[1].revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(1);
      await purify.checkSubkeys(key6);
      expect(key6.subkeys[1].bindingSignatures[0].unhashedSubpackets).to.have.lengthOf(0);
      expect(key6.subkeys[1].revocationSignatures[0].unhashedSubpackets).to.have.lengthOf(0);
      await purify.checkSubkeys(key6);
      expect(key6.subkeys[1].bindingSignatures).to.have.lengthOf(1);
      expect(key6.subkeys[1].revocationSignatures).to.have.lengthOf(1);
    });

    it('should throw if number of subkeys above maxNumSubkey', () => {
      purify.conf.maxNumSubkey = 1;
      return expect(purify.checkSubkeys(key6)).to.eventually.be.rejectedWith('Number of subkeys exceeds allowed max. of 1');
    });
  });

  describe('filterUnhashedSubPackets', () => {
    beforeEach(async () => {
      key5 = await readKey({armoredKey: key5Armored});
    });

    it('Remove all unhashed subpackets from embedded signatures', () => {
      const signaturePacket = key5.subkeys[0].bindingSignatures[0];
      expect(signaturePacket.embeddedSignature.unhashedSubpackets).to.have.lengthOf(1);
      purify.filterUnhashedSubPackets(signaturePacket);
      expect(signaturePacket.embeddedSignature.unhashedSubpackets).to.have.lengthOf(0);
    });
  });

  describe('limitCerts', () => {
    it('Should sort by descending signature creation date', () => {
      const certs = [{created: new Date('2020')}, {created: new Date('2021')}, {created: new Date('2022')}];
      purify.limitCerts(certs, 10);
      expect(certs[0].created).to.eql(new Date('2022'));
      expect(certs[1].created).to.eql(new Date('2021'));
      expect(certs[2].created).to.eql(new Date('2020'));
    });

    it('Should limit number of certs', () => {
      const certs = [{created: new Date('2020')}, {created: new Date('2021')}, {created: new Date('2022')}];
      purify.limitCerts(certs, 1);
      expect(certs).to.have.lengthOf(1);
      expect(certs[0].created).to.eql(new Date('2022'));
    });
  });

  describe('limitRevCerts', () => {
    it('Should sort by ascending signature creation date', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021')}, {created: new Date('2020')}];
      purify.limitRevCerts(certs, 10);
      expect(certs[0].created).to.eql(new Date('2020'));
      expect(certs[1].created).to.eql(new Date('2021'));
      expect(certs[2].created).to.eql(new Date('2022'));
    });

    it('Should limit number of certs', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021')}, {created: new Date('2020')}];
      purify.limitRevCerts(certs, 1);
      expect(certs).to.have.lengthOf(1);
      expect(certs[0].created).to.eql(new Date('2020'));
    });

    it('Should sort by descending hard revocation, test flag keySuperseded', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021')}, {created: new Date('2020'), reasonForRevocationFlag: enums.reasonForRevocation.keySuperseded}];
      purify.limitRevCerts(certs, 10);
      expect(certs[0].created).to.eql(new Date('2021'));
      expect(certs[1].created).to.eql(new Date('2022'));
      expect(certs[2].created).to.eql(new Date('2020'));
    });

    it('Should sort by descending hard revocation, test flag keyRetired', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021'), reasonForRevocationFlag: enums.reasonForRevocation.keyRetired}, {created: new Date('2020')}];
      purify.limitRevCerts(certs, 10);
      expect(certs[0].created).to.eql(new Date('2020'));
      expect(certs[1].created).to.eql(new Date('2022'));
      expect(certs[2].created).to.eql(new Date('2021'));
    });
  });

  describe('limitRevUserCerts', () => {
    it('Should sort by ascending signature creation date', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021')}, {created: new Date('2020')}];
      purify.limitRevUserCerts(certs, 10);
      expect(certs[0].created).to.eql(new Date('2020'));
      expect(certs[1].created).to.eql(new Date('2021'));
      expect(certs[2].created).to.eql(new Date('2022'));
    });

    it('Should limit number of certs', () => {
      const certs = [{created: new Date('2022')}, {created: new Date('2021')}, {created: new Date('2020')}];
      purify.limitRevUserCerts(certs, 1);
      expect(certs).to.have.lengthOf(1);
      expect(certs[0].created).to.eql(new Date('2020'));
    });
  });

  describe('limitNumOfCertificates', () => {
    beforeEach(async () => {
      key6 = await readKey({armoredKey: key6Armored});
    });

    it('should limit all number of certificates to 1', async () => {
      purify.conf.maxNumCert = 1;
      expect(key6.users[4].revocationSignatures).to.have.lengthOf(4);
      await purify.limitNumOfCertificates(key6);
      expect(key6.users[4].revocationSignatures).to.have.lengthOf(1);
    });

    it('should do nothing if PURIFY_KEY false', async () => {
      purify.conf.purifyKey = false;
      const limitCerts = sinon.spy(purify, 'limitCerts');
      const limitRevCerts = sinon.spy(purify, 'limitRevCerts');
      const limitRevUserCerts = sinon.spy(purify, 'limitRevUserCerts');
      await purify.limitNumOfCertificates(key6);
      expect(limitCerts.notCalled).to.be.true;
      expect(limitRevCerts.notCalled).to.be.true;
      expect(limitRevUserCerts.notCalled).to.be.true;
    });

    it('should limit number of direct signatures', async () => {
      purify.conf.maxNumCert = 2;
      expect(key6.directSignatures).to.have.lengthOf(1);
      const sig = key6.directSignatures[0];
      const sig1 = new SignaturePacket();
      sig1.read(sig.write());
      sig1.created = new Date('2022');
      const sig2 = new SignaturePacket();
      sig2.read(sig.write());
      sig2.created = new Date('2024');
      key6.directSignatures.push(sig1, sig2);
      await purify.limitNumOfCertificates(key6);
      expect(key6.directSignatures).to.have.lengthOf(2);
      expect(key6.directSignatures[0].created).to.eql(new Date('2024'));
      expect(key6.directSignatures[1].created).to.eql(sig.created);
    });

    it('should limit number of key revocation signatures', async () => {
      purify.conf.maxNumCert = 2;
      expect(key6.revocationSignatures).to.have.lengthOf(1);
      const sig = key6.revocationSignatures[0];
      const sig1 = new SignaturePacket();
      sig1.read(sig.write());
      sig1.created = new Date('2022');
      sig1.reasonForRevocationFlag = enums.reasonForRevocation.keySuperseded;
      const sig2 = new SignaturePacket();
      sig2.read(sig.write());
      sig2.created = new Date('2024');
      key6.revocationSignatures.push(sig1, sig2);
      await purify.limitNumOfCertificates(key6);
      expect(key6.revocationSignatures).to.have.lengthOf(2);
      expect(key6.revocationSignatures[0].created).to.eql(sig.created);
      expect(key6.revocationSignatures[1].created).to.eql(new Date('2024'));
    });

    it('should limit number of user certificates', async () => {
      purify.conf.maxNumCert = 2;
      expect(key6.users[0].selfCertifications).to.have.lengthOf(1);
      const sig = key6.users[0].selfCertifications[0];
      const sig1 = new SignaturePacket();
      sig1.read(sig.write());
      sig1.created = new Date('2022');
      const sig2 = new SignaturePacket();
      sig2.read(sig.write());
      sig2.created = new Date('2024');
      key6.users[0].selfCertifications.push(sig1, sig2);
      await purify.limitNumOfCertificates(key6);
      expect(key6.users[0].selfCertifications).to.have.lengthOf(2);
      expect(key6.users[0].selfCertifications[0].created).to.eql(new Date('2024'));
      expect(key6.users[0].selfCertifications[1].created).to.eql(sig.created);
    });

    it('should limit number of subkey binding signatures', async () => {
      purify.conf.maxNumCert = 2;
      expect(key6.subkeys[0].bindingSignatures).to.have.lengthOf(1);
      const sig = key6.subkeys[0].bindingSignatures[0];
      const sig1 = new SignaturePacket();
      sig1.read(sig.write());
      sig1.created = new Date('2022');
      const sig2 = new SignaturePacket();
      sig2.read(sig.write());
      sig2.created = new Date('2024');
      key6.subkeys[0].bindingSignatures.push(sig1, sig2);
      await purify.limitNumOfCertificates(key6);
      expect(key6.subkeys[0].bindingSignatures).to.have.lengthOf(2);
      expect(key6.subkeys[0].bindingSignatures[0].created).to.eql(new Date('2024'));
      expect(key6.subkeys[0].bindingSignatures[1].created).to.eql(sig.created);
    });

    it('should limit number of subkey revocation signatures', async () => {
      purify.conf.maxNumCert = 2;
      expect(key6.subkeys[1].revocationSignatures).to.have.lengthOf(1);
      expect(key6.subkeys[1].revocationSignatures[0].reasonForRevocationFlag).to.equal(enums.reasonForRevocation.keySuperseded);
      const sig = key6.subkeys[1].revocationSignatures[0];
      const sig1 = new SignaturePacket();
      sig1.read(sig.write());
      sig1.created = new Date('2024');
      sig1.reasonForRevocationFlag = null;
      const sig2 = new SignaturePacket();
      sig2.read(sig.write());
      sig2.created = new Date('2022');
      key6.subkeys[1].revocationSignatures.push(sig1, sig2);
      await purify.limitNumOfCertificates(key6);
      expect(key6.subkeys[1].revocationSignatures).to.have.lengthOf(2);
      expect(key6.subkeys[1].revocationSignatures[0].created).to.eql(new Date('2024'));
      expect(key6.subkeys[1].revocationSignatures[1].created).to.eql(new Date('2022'));
    });
  });

  describe('purifyKey', () => {
    beforeEach(async () => {
      key6 = await readKey({armoredKey: key6Armored});
    });

    it('should purify key', async () => {
      expect(key6.toPacketList().write()).to.have.lengthOf(4642);
      await purify.purifyKey(key6);
      expect(key6.toPacketList().write()).to.have.lengthOf(2129);
    });

    it('should verify user certificates', async () => {
      const checkKeyPacket = sinon.spy(purify, 'checkKeyPacket');
      const checkKeySignatures = sinon.spy(purify, 'checkKeySignatures');
      const checkUsers = sinon.spy(purify, 'checkUsers');
      const checkSubkeys = sinon.spy(purify, 'checkSubkeys');
      const limitNumOfCertificates = sinon.spy(purify, 'limitNumOfCertificates');
      await purify.purifyKey(key6);
      expect(checkKeyPacket.calledOnce).to.be.true;
      expect(checkKeySignatures.calledOnce).to.be.true;
      expect(checkUsers.calledOnce).to.be.true;
      expect(checkSubkeys.calledOnce).to.be.true;
      expect(limitNumOfCertificates.calledOnce).to.be.true;
    });

    it('should not purify if PURIFY_KEY false', async () => {
      const checkKeyPacket = sinon.spy(purify, 'checkKeyPacket');
      const checkKeySignatures = sinon.spy(purify, 'checkKeySignatures');
      const checkUsers = sinon.spy(purify, 'checkUsers');
      const checkSubkeys = sinon.spy(purify, 'checkSubkeys');
      const limitNumOfCertificates = sinon.spy(purify, 'limitNumOfCertificates');
      purify.conf.purifyKey = false;
      await purify.purifyKey(key6);
      expect(checkKeyPacket.notCalled).to.be.true;
      expect(checkKeySignatures.notCalled).to.be.true;
      expect(checkUsers.notCalled).to.be.true;
      expect(checkSubkeys.notCalled).to.be.true;
      expect(limitNumOfCertificates.notCalled).to.be.true;
    });
  });
});
