'use strict';

require('co-mocha')(require('mocha')); // monkey patch mocha for generators

const expect = require('chai').expect;
const sinon = require('sinon');

global.expect = expect;
global.sinon = sinon;
