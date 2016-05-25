/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2016 Mailvelope GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

const MongoClient = require('mongodb').MongoClient;

/**
 * A simple wrapper around the official MongoDB client.
 */
class Mongo {

  /**
   * Create an instance of the MongoDB client.
   * @param  {String} options.uri        The mongodb uri
   * @param  {String} options.user       The databse user
   * @param  {String} options.password   The database user's password
   * @param  {String} options.type       (optional) The default collection type to use e.g. 'publickey'
   * @return {undefined}
   */
  constructor(options) {
    this._uri = 'mongodb://' + options.user + ':' + options.password + '@' + options.uri;
    this._type = options.type;
  }

  /**
   * Initializes the database client by connecting to the MongoDB.
   * @return {undefined}
   */
  *connect() {
    this._db = yield MongoClient.connect(this._uri);
  }

  /**
   * Cleanup by closing the connection to the database.
   * @return {undefined}
   */
  disconnect() {
    return this._db.close();
  }

  /**
   * Inserts a single document.
   * @param  {Object} document   Inserts a single documents
   * @param  {String} type       (optional) The collection to use e.g. 'publickey'
   * @return {Object}            The operation result
   */
  create(document, type) {
    let col = this._db.collection(type || this._type);
    return col.insertOne(document);
  }

  /**
   * Update a single document.
   * @param  {Object} query   The query e.g. { _id:'0' }
   * @param  {Object} diff    The attributes to change/set e.g. { foo:'bar' }
   * @param  {String} type    (optional) The collection to use e.g. 'publickey'
   * @return {Object}         The operation result
   */
  update(query, diff, type) {
    let col = this._db.collection(type || this._type);
    return col.updateOne(query, { $set:diff });
  }

  /**
   * Read a single document.
   * @param  {Object} query   The query e.g. { _id:'0' }
   * @param  {String} type    (optional) The collection to use e.g. 'publickey'
   * @return {Object}         The document object
   */
  get(query, type) {
    let col = this._db.collection(type || this._type);
    return col.findOne(query);
  }

  /**
   * Read multiple documents at once.
   * @param  {Object} query   The query e.g. { foo:'bar' }
   * @param  {String} type    (optional) The collection to use e.g. 'publickey'
   * @return {Array}          An array of document objects
   */
  list(query, type) {
    let col = this._db.collection(type || this._type);
    return col.find(query).toArray();
  }

  /**
   * Delete a single document.
   * @param  {Object} query   The query e.g. { _id:'0' }
   * @param  {String} type    (optional) The collection to use e.g. 'publickey'
   * @return {Object}         The document object
   */
  remove(query, type) {
    let col = this._db.collection(type || this._type);
    return col.deleteOne(query);
  }

  /**
   * Clear all documents of a collection.
   * @param  {String} type   (optional) The collection to use e.g. 'publickey'
   * @return {Object}        The operation result
   */
  clear(type) {
    let col = this._db.collection(type || this._type);
    return col.deleteMany({});
  }

}

module.exports = Mongo;