/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const log = require('../lib/log');
const MongoClient = require('mongodb').MongoClient;

/**
 * A simple wrapper around the official MongoDB client.
 */
class Mongo {
  /**
   * Initializes the database client by connecting to the MongoDB.
   * @param {String} uri    The mongodb uri
   * @param {String} user   The databse user
   * @param {String} pass   The database user's password
   * @yield {undefined}
   */
  async init({uri, user, pass}) {
    log.info('Connecting to MongoDB ...');
    const url = `mongodb://${user}:${pass}@${uri}`;
    this._client = await MongoClient.connect(url, {useNewUrlParser: true, useUnifiedTopology: true});
    this._client.on('commandFailed', event => log.error('MongoDB command failed\n%s', event));
    this._db = this._client.db();
  }

  /**
   * Cleanup by closing the connection to the database.
   * @yield {undefined}
   */
  disconnect() {
    return this._client.close();
  }

  /**
   * Inserts a single document.
   * @param {Object} document   Inserts a single document
   * @param {String} type       The collection to use e.g. 'publickey'
   * @yield {Object}            The operation result
   */
  create(document, type) {
    const col = this._db.collection(type);
    return col.insertOne(document);
  }

  /**
   * Inserts a list of documents.
   * @param {Array}  documents   Inserts a list of documents
   * @param {String} type        The collection to use e.g. 'publickey'
   * @yield {Object}             The operation result
   */
  batch(documents, type) {
    const col = this._db.collection(type);
    return col.insertMany(documents);
  }

  /**
   * Update a single document.
   * @param {Object} query   The query e.g. { _id:'0' }
   * @param {Object} diff    The attributes to change/set e.g. { foo:'bar' }
   * @param {String} type    The collection to use e.g. 'publickey'
   * @yield {Object}         The operation result
   */
  update(query, diff, type) {
    const col = this._db.collection(type);
    return col.updateOne(query, {$set: diff});
  }

  /**
   * Read a single document.
   * @param {Object} query   The query e.g. { _id:'0' }
   * @param {String} type    The collection to use e.g. 'publickey'
   * @yield {Object}         The document object
   */
  get(query, type) {
    const col = this._db.collection(type);
    return col.findOne(query);
  }

  /**
   * Read multiple documents at once.
   * @param {Object} query   The query e.g. { foo:'bar' }
   * @param {String} type    The collection to use e.g. 'publickey'
   * @yield {Array}          An array of document objects
   */
  list(query, type) {
    const col = this._db.collection(type);
    return col.find(query).toArray();
  }

  /**
   * Delete all documents matching a query.
   * @param {Object} query   The query e.g. { _id:'0' }
   * @param {String} type    The collection to use e.g. 'publickey'
   * @yield {Object}         The operation result
   */
  remove(query, type) {
    const col = this._db.collection(type);
    return col.deleteMany(query);
  }

  /**
   * Clear all documents of a collection.
   * @param {String} type   The collection to use e.g. 'publickey'
   * @yield {Object}        The operation result
   */
  clear(type) {
    const col = this._db.collection(type);
    return col.deleteMany({});
  }
}

module.exports = Mongo;
