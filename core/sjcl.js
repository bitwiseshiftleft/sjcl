/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

"use strict";
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape, module, require, Uint32Array */

/**
 * The Stanford Javascript Crypto Library, top-level namespace.
 * @namespace
 */
var sjcl = {
  /**
   * Symmetric ciphers.
   * @namespace
   */
  cipher: {},

  /**
   * Hash functions.  Right now only SHA256 is implemented.
   * @namespace
   */
  hash: {},

  /**
   * Key exchange functions.  Right now only SRP is implemented.
   * @namespace
   */
  keyexchange: {},
  
  /**
   * Cipher modes of operation.
   * @namespace
   */
  mode: {},

  /**
   * Miscellaneous.  HMAC and PBKDF2.
   * @namespace
   */
  misc: {},
  
  /**
   * Bit array encoders and decoders.
   * @namespace
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},
  
  /**
   * Exceptions.
   * @namespace
   */
  exception: {
    /**
     * Ciphertext is corrupt.
     * @constructor
     */
    corrupt: function(message) {
      this.toString = function() { return "CORRUPT: "+this.message; };
      this.message = message;
    },
    
    /**
     * Invalid parameter.
     * @constructor
     */
    invalid: function(message) {
      this.toString = function() { return "INVALID: "+this.message; };
      this.message = message;
    },
    
    /**
     * Bug or missing feature in SJCL.
     * @constructor
     */
    bug: function(message) {
      this.toString = function() { return "BUG: "+this.message; };
      this.message = message;
    },

    /**
     * Something isn't ready.
     * @constructor
     */
    notReady: function(message) {
      this.toString = function() { return "NOT READY: "+this.message; };
      this.message = message;
    }
  }
};
