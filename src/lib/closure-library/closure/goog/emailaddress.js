// Copyright 2010 The Closure Library Authors. All Rights Reserved.
// Copyright (C) 2020 Mailvelope GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @fileoverview Provides functions to parse and manipulate email addresses.
 * Modified from the original source code to include the goog.string dependencies
 *
 */

'use strict';

const goog = {};

goog.string = {};

/**
 * Determines whether a string contains a substring.
 * @param {string} str The string to search.
 * @param {string} subString The substring to search for.
 * @return {boolean} Whether `str` contains `subString`.
 */
goog.string.contains = function(str, subString) {
  return str.indexOf(subString) != -1;
};

/**
 * Converts multiple whitespace chars (spaces, non-breaking-spaces, new lines
 * and tabs) to a single space, and strips leading and trailing whitespace.
 * @param {string} str Input string.
 * @return {string} A copy of `str` with collapsed whitespace.
 */
goog.string.collapseWhitespace = function(str) {
  // Since IE doesn't include non-breaking-space (0xa0) in their \s character
  // class (as required by section 7.2 of the ECMAScript spec), we explicitly
  // include it in the regexp to enforce consistent cross-browser behavior.
  return str.replace(/[\s\xa0]+/g, ' ').replace(/^\s+|\s+$/g, '');
};

/**
 * Strip quote characters around a string.  The second argument is a string of
 * characters to treat as quotes.  This can be a single character or a string of
 * multiple character and in that case each of those are treated as possible
 * quote characters. For example:
 *
 * <pre>
 * goog.string.stripQuotes('"abc"', '"`') --> 'abc'
 * goog.string.stripQuotes('`abc`', '"`') --> 'abc'
 * </pre>
 *
 * @param {string} str The string to strip.
 * @param {string} quoteChars The quote characters to strip.
 * @return {string} A copy of `str` without the quotes.
 */
goog.string.stripQuotes = function(str, quoteChars) {
  const length = quoteChars.length;
  for (let i = 0; i < length; i++) {
    const quoteChar = length == 1 ? quoteChars : quoteChars.charAt(i);
    if (str.charAt(0) == quoteChar && str.charAt(str.length - 1) == quoteChar) {
      return str.substring(1, str.length - 1);
    }
  }
  return str;
};

/**
 * Checks if a string is empty or contains only whitespaces.
 * @param {string} str The string to check.
 * @return {boolean} Whether `str` is empty or whitespace only.
 */
goog.string.isEmptyOrWhitespace = function(str) {
  // testing length == 0 first is actually slower in all browsers (about the
  // same in Opera).
  // Since IE doesn't include non-breaking-space (0xa0) in their \s character
  // class (as required by section 7.2 of the ECMAScript spec), we explicitly
  // include it in the regexp to enforce consistent cross-browser behavior.
  return /^[\s\xa0]*$/.test(str);
};

goog.format = {};

/**
 * Formats an email address string for display, and allows for extraction of
 * the individual components of the address.
 * @param {string=} opt_address The email address.
 * @param {string=} opt_name The name associated with the email address.
 * @constructor
 */
goog.format.EmailAddress = function(opt_address, opt_name) {
  /**
   * The name or personal string associated with the address.
   * @type {string}
   * @private
   */
  this.name_ = opt_name || '';

  /**
   * The email address.
   * @type {string}
   * @protected
   */
  this.address = opt_address || '';
};

/**
 * Match string for opening tokens.
 * @type {string}
 * @private
 */
goog.format.EmailAddress.OPENERS_ = '"<([';

/**
 * Match string for closing tokens.
 * @type {string}
 * @private
 */
goog.format.EmailAddress.CLOSERS_ = '">)]';

/**
 * Match string for characters that require display names to be quoted and are
 * not address separators.
 * @type {string}
 * @const
 * @package
 */
goog.format.EmailAddress.SPECIAL_CHARS = '()<>@:\\\".[]';

/**
 * Match string for address separators.
 * @type {string}
 * @const
 * @private
 */
goog.format.EmailAddress.ADDRESS_SEPARATORS_ = ',;';

/**
 * Match string for characters that, when in a display name, require it to be
 * quoted.
 * @type {string}
 * @const
 * @private
 */
goog.format.EmailAddress.CHARS_REQUIRE_QUOTES_ =
    goog.format.EmailAddress.SPECIAL_CHARS +
    goog.format.EmailAddress.ADDRESS_SEPARATORS_;

/**
 * A RegExp to match all double quotes.  Used in cleanAddress().
 * @type {RegExp}
 * @private
 */
goog.format.EmailAddress.ALL_DOUBLE_QUOTES_ = /\"/g;

/**
 * A RegExp to match escaped double quotes.  Used in parse().
 * @type {RegExp}
 * @private
 */
goog.format.EmailAddress.ESCAPED_DOUBLE_QUOTES_ = /\\\"/g;

/**
 * A RegExp to match all backslashes.  Used in cleanAddress().
 * @type {RegExp}
 * @private
 */
goog.format.EmailAddress.ALL_BACKSLASHES_ = /\\/g;

/**
 * A RegExp to match escaped backslashes.  Used in parse().
 * @type {RegExp}
 * @private
 */
goog.format.EmailAddress.ESCAPED_BACKSLASHES_ = /\\\\/g;

/**
 * A string representing the RegExp for the local part of an email address.
 * @private {string}
 */
goog.format.EmailAddress.LOCAL_PART_REGEXP_STR_ =
    '[+a-zA-Z0-9_.!#$%&\'*\\/=?^`{|}~-]+';

/**
 * A string representing the RegExp for the domain part of an email address.
 * @private {string}
 */
goog.format.EmailAddress.DOMAIN_PART_REGEXP_STR_ =
    '([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9]{2,63}';

/**
 * A RegExp to match the local part of an email address.
 * @private {!RegExp}
 */
goog.format.EmailAddress.LOCAL_PART_ =
    new RegExp(`^${goog.format.EmailAddress.LOCAL_PART_REGEXP_STR_}$`);

/**
 * A RegExp to match the domain part of an email address.
 * @private {!RegExp}
 */
goog.format.EmailAddress.DOMAIN_PART_ =
    new RegExp(`^${goog.format.EmailAddress.DOMAIN_PART_REGEXP_STR_}$`);

/**
 * A RegExp to match an email address.
 * @private {!RegExp}
 */
goog.format.EmailAddress.EMAIL_ADDRESS_ =
    new RegExp(`^${goog.format.EmailAddress.LOCAL_PART_REGEXP_STR_}@${goog.format.EmailAddress.DOMAIN_PART_REGEXP_STR_}$`);

/**
 * Get the name associated with the email address.
 * @return {string} The name or personal portion of the address.
 * @final
 */
goog.format.EmailAddress.prototype.getName = function() {
  return this.name_;
};

/**
 * Get the email address.
 * @return {string} The email address.
 * @final
 */
goog.format.EmailAddress.prototype.getAddress = function() {
  return this.address;
};

/**
 * Set the name associated with the email address.
 * @param {string} name The name to associate.
 * @final
 */
goog.format.EmailAddress.prototype.setName = function(name) {
  this.name_ = name;
};

/**
 * Set the email address.
 * @param {string} address The email address.
 * @final
 */
goog.format.EmailAddress.prototype.setAddress = function(address) {
  this.address = address;
};

/**
 * Return the address in a standard format:
 *  - remove extra spaces.
 *  - Surround name with quotes if it contains special characters.
 * @return {string} The cleaned address.
 * @override
 */
goog.format.EmailAddress.prototype.toString = function() {
  return this.toStringInternal(goog.format.EmailAddress.CHARS_REQUIRE_QUOTES_);
};

/**
 * Check if a display name requires quoting.
 * @param {string} name The display name
 * @param {string} specialChars String that contains the characters that require
 *  the display name to be quoted. This may change based in whereas we are
 *  in EAI context or not.
 * @return {boolean}
 * @private
 */
goog.format.EmailAddress.isQuoteNeeded_ = function(name, specialChars) {
  for (let i = 0; i < specialChars.length; i++) {
    const specialChar = specialChars[i];
    if (goog.string.contains(name, specialChar)) {
      return true;
    }
  }
  return false;
};

/**
 * Return the address in a standard format:
 *  - remove extra spaces.
 *  - Surround name with quotes if it contains special characters.
 * @param {string} specialChars String that contains the characters that require
 *  the display name to be quoted.
 * @return {string} The cleaned address.
 * @protected
 */
goog.format.EmailAddress.prototype.toStringInternal = function(specialChars) {
  let name = this.getName();

  // We intentionally remove double quotes in the name because escaping
  // them to \" looks ugly.
  name = name.replace(goog.format.EmailAddress.ALL_DOUBLE_QUOTES_, '');

  // If the name has special characters, we need to quote it and escape \'s.
  if (goog.format.EmailAddress.isQuoteNeeded_(name, specialChars)) {
    name = `"${name.replace(goog.format.EmailAddress.ALL_BACKSLASHES_, '\\\\')}"`;
  }

  if (name == '') {
    return this.address;
  }
  if (this.address == '') {
    return name;
  }
  return `${name} <${this.address}>`;
};

/**
 * Determines if the current object is a valid email address.
 * @return {boolean} Whether the email address is valid.
 */
goog.format.EmailAddress.prototype.isValid = function() {
  return goog.format.EmailAddress.isValidAddrSpec(this.address);
};

/**
 * Checks if the provided string is a valid email address. Supports both
 * simple email addresses (address specs) and addresses that contain display
 * names.
 * @param {string} str The email address to check.
 * @return {boolean} Whether the provided string is a valid address.
 */
goog.format.EmailAddress.isValidAddress = function(str) {
  return goog.format.EmailAddress.parse(str).isValid();
};

/**
 * Checks if the provided string is a valid address spec (local@domain.com).
 * @param {string} str The email address to check.
 * @return {boolean} Whether the provided string is a valid address spec.
 */
goog.format.EmailAddress.isValidAddrSpec = function(str) {
  // This is a fairly naive implementation, but it covers 99% of use cases.
  // For more details, see http://en.wikipedia.org/wiki/Email_address#Syntax
  return goog.format.EmailAddress.EMAIL_ADDRESS_.test(str);
};

/**
 * Checks if the provided string is a valid local part (part before the '@') of
 * an email address.
 * @param {string} str The local part to check.
 * @return {boolean} Whether the provided string is a valid local part.
 */
goog.format.EmailAddress.isValidLocalPartSpec = function(str) {
  return goog.format.EmailAddress.LOCAL_PART_.test(str);
};

/**
 * Checks if the provided string is a valid domain part (part after the '@') of
 * an email address.
 * @param {string} str The domain part to check.
 * @return {boolean} Whether the provided string is a valid domain part.
 */
goog.format.EmailAddress.isValidDomainPartSpec = function(str) {
  return goog.format.EmailAddress.DOMAIN_PART_.test(str);
};

/**
 * Parses an email address of the form "name" &lt;address&gt; ("name" is
 * optional) into an email address.
 * @param {string} addr The address string.
 * @param {function(new: goog.format.EmailAddress, string=,string=)} ctor
 *     EmailAddress constructor to instantiate the output address.
 * @return {!goog.format.EmailAddress} The parsed address.
 * @protected
 */
goog.format.EmailAddress.parseInternal = function(addr, ctor) {
  // TODO(ecattell): Strip bidi markers.
  let name = '';
  let address = '';
  for (let i = 0; i < addr.length;) {
    const token = goog.format.EmailAddress.getToken_(addr, i);
    if (token.charAt(0) == '<' && token.indexOf('>') != -1) {
      const end = token.indexOf('>');
      address = token.substring(1, end);
    } else if (address == '') {
      name += token;
    }
    i += token.length;
  }

  // Check if it's a simple email address of the form "jlim@google.com".
  if (address == '' && name.indexOf('@') != -1) {
    address = name;
    name = '';
  }

  name = goog.string.collapseWhitespace(name);
  name = goog.string.stripQuotes(name, '\'');
  name = goog.string.stripQuotes(name, '"');
  // Replace escaped quotes and slashes.
  name = name.replace(goog.format.EmailAddress.ESCAPED_DOUBLE_QUOTES_, '"');
  name = name.replace(goog.format.EmailAddress.ESCAPED_BACKSLASHES_, '\\');
  address = goog.string.collapseWhitespace(address);
  return new ctor(address, name);
};

/**
 * Parses an email address of the form "name" &lt;address&gt; into
 * an email address.
 * @param {string} addr The address string.
 * @return {!goog.format.EmailAddress} The parsed address.
 */
goog.format.EmailAddress.parse = function(addr) {
  return goog.format.EmailAddress.parseInternal(addr, goog.format.EmailAddress);
};

/**
 * Parse a string containing email addresses of the form
 * "name" &lt;address&gt; into an array of email addresses.
 * @param {string} str The address list.
 * @param {function(string)} parser The parser to employ.
 * @param {function(string):boolean} separatorChecker Accepts a character and
 *    returns whether it should be considered an address separator.
 * @return {!Array<!goog.format.EmailAddress>} The parsed emails.
 * @protected
 */
goog.format.EmailAddress.parseListInternal = function(str, parser, separatorChecker) {
  const result = [];
  let email = '';
  let token;

  // Remove non-UNIX-style newlines that would otherwise cause getToken_ to
  // choke. Remove multiple consecutive whitespace characters for the same
  // reason.
  str = goog.string.collapseWhitespace(str);

  for (let i = 0; i < str.length;) {
    token = goog.format.EmailAddress.getToken_(str, i);
    if (separatorChecker(token) || (token == ' ' && parser(email).isValid())) {
      if (!goog.string.isEmptyOrWhitespace(email)) {
        result.push(parser(email));
      }
      email = '';
      i++;
      continue;
    }
    email += token;
    i += token.length;
  }

  // Add the final token.
  if (!goog.string.isEmptyOrWhitespace(email)) {
    result.push(parser(email));
  }
  return result;
};

/**
 * Parses a string containing email addresses of the form
 * "name" &lt;address&gt; into an array of email addresses.
 * @param {string} str The address list.
 * @return {!Array<!goog.format.EmailAddress>} The parsed emails.
 */
goog.format.EmailAddress.parseList = function(str) {
  return goog.format.EmailAddress.parseListInternal(str, goog.format.EmailAddress.parse, goog.format.EmailAddress.isAddressSeparator);
};

/**
 * Get the next token from a position in an address string.
 * @param {string} str the string.
 * @param {number} pos the position.
 * @return {string} the token.
 * @private
 */
goog.format.EmailAddress.getToken_ = function(str, pos) {
  const ch = str.charAt(pos);
  const p = goog.format.EmailAddress.OPENERS_.indexOf(ch);
  if (p == -1) {
    return ch;
  }
  if (goog.format.EmailAddress.isEscapedDlQuote_(str, pos)) {
    // If an opener is an escaped quote we do not treat it as a real opener
    // and keep accumulating the token.
    return ch;
  }
  const closerChar = goog.format.EmailAddress.CLOSERS_.charAt(p);
  let endPos = str.indexOf(closerChar, pos + 1);

  // If the closer is a quote we go forward skipping escaped quotes until we
  // hit the real closing one.
  while (endPos >= 0 &&
         goog.format.EmailAddress.isEscapedDlQuote_(str, endPos)) {
    endPos = str.indexOf(closerChar, endPos + 1);
  }
  const token = (endPos >= 0) ? str.substring(pos, endPos + 1) : ch;
  return token;
};

/**
 * Checks if the character in the current position is an escaped double quote
 * ( \" ).
 * @param {string} str the string.
 * @param {number} pos the position.
 * @return {boolean} true if the char is escaped double quote.
 * @private
 */
goog.format.EmailAddress.isEscapedDlQuote_ = function(str, pos) {
  if (str.charAt(pos) != '"') {
    return false;
  }
  let slashCount = 0;
  for (let idx = pos - 1; idx >= 0 && str.charAt(idx) == '\\'; idx--) {
    slashCount++;
  }
  return ((slashCount % 2) != 0);
};

/**
 * @param {string} ch The character to test.
 * @return {boolean} Whether the provided character is an address separator.
 */
goog.format.EmailAddress.isAddressSeparator = function(ch) {
  return goog.string.contains(goog.format.EmailAddress.ADDRESS_SEPARATORS_, ch);
};

module.exports = goog;
