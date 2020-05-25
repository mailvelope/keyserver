'use strict';

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const sinon = require('sinon');

const log = require('../src/lib/log');

log.silent = false;

chai.use(chaiAsPromised);

global.expect = chai.expect;
global.sinon = sinon;
