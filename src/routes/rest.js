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

/**
 * The REST api to provide additional functionality on top of HKP
 */
class REST {

  constructor(publicKey) {
    this._publicKey = publicKey;
  }

  *create(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  *verify(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  *read(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  *remove(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

  *verifyRemove(ctx) {
    ctx.throw(501, 'Not implemented!');
    yield;
  }

}

module.exports = REST;