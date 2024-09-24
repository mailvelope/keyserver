'use strict';

import * as chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import sinon from 'sinon';

import log from '../src/lib/log.js';

log.silent = false;

chai.use(chaiAsPromised);

global.expect = chai.expect;
global.sinon = sinon;
