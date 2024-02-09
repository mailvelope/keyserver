/**
 * Copyright (C) 2020 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

'use strict';

const log = require('../lib/log');
const {MongoClient} = require('mongodb');

/**
 * A simple wrapper around the official MongoDB client.
 */
class Mongo {
  /**
   * Initializes the database client by connecting to the MongoDB.
   * @param  {String} uri          The mongodb uri
   * @param  {String} user         The databse user
   * @param  {String} pass         The database user's password
   * @return {Promise<undefined>}
   */
  async init({uri, user, pass}) {
    log.info('Connecting to MongoDB ...');
    const url = `mongodb://${user}:${pass}@${uri}`;
    this._client = new MongoClient(url);
    this._client.on('commandFailed', event => log.error('MongoDB command failed\n%s', event));
    await this._client.connect();
    this._db = this._client.db();
  }

  /**
   * Cleanup by closing the connection to the database.
   * @return {Promise<undefined>}
   */
  disconnect() {
    return this._client.close();
  }

  /**
   * Create the database indexes
   * @param  {Array<Object>}     indexSpecs The index specification
   * @param  {String} type       The collection to use e.g. 'publickey'
   * @param  {Object} [options]  create index options
   * @return {Promise<String>}   The operation result
   */
  async createIndexes(indexSpecs, type, options) {
    const col = this._db.collection(type);
    return col.createIndexes(indexSpecs, options);
  }

  /**
   * Inserts a single document.
   * @param  {Object} document   Inserts a single document
   * @param  {String} type       The collection to use e.g. 'publickey'
   * @return {Promise<Object>}   The operation result
   */
  create(document, type) {
    const col = this._db.collection(type);
    return col.insertOne(document);
  }

  /**
   * Inserts a list of documents.
   * @param  {Array}  documents  Inserts a list of documents
   * @param  {String} type       The collection to use e.g. 'publickey'
   * @return {Promise<Object>}   The operation result
   */
  batch(documents, type) {
    const col = this._db.collection(type);
    return col.insertMany(documents);
  }

  /**
   * Update a single document.
   * @param  {Object} query     The query e.g. { _id:'0' }
   * @param  {Object} diff      The attributes to change/set e.g. { foo:'bar' }
   * @param  {String} type      The collection to use e.g. 'publickey'
   * @return {Promise<Object>}  The operation result
   */
  update(query, diff, type) {
    const col = this._db.collection(type);
    return col.updateOne(query, {$set: diff});
  }

  /**
   * Read a single document.
   * @param  {Object} query     The query e.g. { _id:'0' }
   * @param  {String} type      The collection to use e.g. 'publickey'
   * @return {Promise<Object>}  The document object
   */
  get(query, type) {
    const col = this._db.collection(type);
    return col.findOne(query);
  }

  /**
   * Count documents.
   * @param  {Object} query     The query e.g. { _id:'0' }
   * @param  {String} type      The collection to use e.g. 'publickey'
   * @return {Promise<Number>}  The number of found documents
   */
  count(query, type) {
    const col = this._db.collection(type);
    return col.count(query);
  }

  /**
   * Read multiple documents at once.
   * @param  {Object} query    The query e.g. { foo:'bar' }
   * @param  {String} type     The collection to use e.g. 'publickey'
   * @return {Promise<Array>}  An array of document objects
   */
  list(query, type) {
    const col = this._db.collection(type);
    return col.find(query).toArray();
  }

  /**
   * Delete all documents matching a query.
   * @param  {Object} query     The query e.g. { _id:'0' }
   * @param  {String} type      The collection to use e.g. 'publickey'
   * @return {Promise<Object>}  The operation result
   */
  remove(query, type) {
    const col = this._db.collection(type);
    return col.deleteMany(query);
  }

  /**
   * Clear all documents of a collection.
   * @param  {String} type      The collection to use e.g. 'publickey'
   * @return {Promise<Object>}  The operation result
   */
  clear(type) {
    const col = this._db.collection(type);
    return col.deleteMany({});
  }

  /**
   * Aggregate documents from a collection
   * @param  {Array} pipeline                 The aggregation pipeline
   * @param  {String} type                    The collection to use e.g. 'publickey'
   * @return {Promise<AggregationCursor<T>>}  The operation result
   */
  aggregate(pipeline, type) {
    const col = this._db.collection(type);
    return col.aggregate(pipeline);
  }

  /**
   * Replace one document
   * @param  {Object} filter       The filter used to select the document to replace
   * @param  {Object} replacement  The Document that replaces the matching document
   * @param  {String} type         The collection to use e.g. 'publickey'
   * @return {Promise<Document>}
   */
  replace(filter, replacement, type) {
    const col = this._db.collection(type);
    return col.replaceOne(filter, replacement);
  }
}

module.exports = Mongo;
