/**
 * Copyright (C) 2024 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const config = require('../../config/config');
const Mongo = require('../modules/mongo');
const PurifyKey = require('../modules/purify-key');
const PGP = require('../modules/pgp');

const DB_TYPE = 'publickey';
const KEY_SIZE = 1; // divided by 4/3 gives binary size of key
const MAX_UPLOAD_DATE = new Date(new Date().setDate(new Date().getDate() - config.publicKey.purgeTimeInDays)); // now - purgeTimeInDays
const YEAR = parseInt(process.argv[2] ?? MAX_UPLOAD_DATE.getFullYear());

let mongo;
let pgp;

async function init() {
  mongo = new Mongo();
  await mongo.init(config.mongo);
  const purify = new PurifyKey({...config.purify, maxNumUserEmail: 60, maxNumSubkey: 25, maxSizeKey: 64 * 1024});
  pgp = new PGP(purify);
}

function aggregate() {
  return mongo.aggregate([
    {$match: {uploaded: {$gte: new Date(YEAR, 0, 1), $lt: new Date(YEAR + 1, 0, 1)}}},
    {$match: {uploaded: {$lt: MAX_UPLOAD_DATE}}},
    {$project: {keySize: {$binarySize: '$publicKeyArmored'}}},
    {$match: {keySize: {$gt: KEY_SIZE}}}
  ], DB_TYPE);
}

async function clean() {
  try {
    console.log(`Start cleaning year ${YEAR}...`);
    await init();
    const result = await aggregate();
    let count = 0;
    for await (const document of result) {
      await cleanKey(document);
      count++;
    }
    console.log('Number of keys processed:', count);
  } catch (e) {
    console.log('Error while traversing keys:', e);
  } finally {
    await mongo.disconnect();
  }
}

async function cleanKey({_id}) {
  const key = await mongo.get({_id}, DB_TYPE);
  if (!key.publicKeyArmored) {
    console.log('No armored key. Key is not yet verified. Skip');
    return;
  }
  try {
    const purified = await pgp.parseKey(key.publicKeyArmored);
    // filter out all unverified user ID and those that are not in the purified set
    key.userIds = key.userIds.filter(userId => userId.verified && purified.userIds.some(id => id.email === userId.email));
    if (!key.userIds.length) {
      throw new Error('No user ID after comparing with purified key.');
    }
    const publicKeyArmored = await pgp.filterKeyByUserIds(key.userIds, purified.publicKeyArmored);
    key.publicKeyArmored = publicKeyArmored;
    await mongo.replace({_id}, key, DB_TYPE);
  } catch (e) {
    console.log('Parsing of key failed:', e.message);
    await mongo.remove({_id}, DB_TYPE);
    console.log(`Key ${key.fingerprint} removed.`);
  }
}

clean();
