/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Stefan Bühler
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = (function() {
  /** Make a partial word for a bit array.
   * @function
   * @name sjcl.bitArray.partial
   * @param {Number} len           The number of bits in the word (1-32).
   * @param {Number} x             The bits.
   * @param {boolean} [_end=false] Pass true if x has already been shifted to the high side.
   * @return {Number}              The partial word.
   */
  function partial(len, x, _end) {
    if (len === 32) { return x|0; }
    var mask = 0x80000000 >> (len-1);
    x = mask & (_end ? x : x << (32 - len));
    return x + len * 0x10000000000;
  }

  /** Get the number of bits used by a partial word.
   * @function
   * @name sjcl.bitArray.getPartial
   * @param {Number} x The partial word.
   * @return {Number}  The number of bits used by the partial word.
   */
  function getPartial(x) {
    return Math.round(x/0x10000000000) || 32;
  }

  /** Find the length of an array of bits.
   * @function
   * @name sjcl.bitArray.bitLength
   * @param {sjcl.bitArray} a The array.
   * @return {Number}         The length of a, in bits.
   */
  function bitLength(a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + getPartial(x);
  }

  /** Sets partial length on last word.
   * @function
   * @name sjcl.bitArray._clampLastM
   * @param {sjcl.bitArray} a The array to modify.
   * @param {Number} len      The partial length to set (0-32; 0 is intepreted as 32).
   * @return {sjcl.bitArray}  The modified array.
   * @private
   */
  function _clampLastM(a, len) {
    len &= 31;
    if (a.length > 0 && len > 0) {
      a[a.length-1] = partial(len, a[a.length-1], 1);
    }
    return a;
  }

  /** Truncate an array inplace.
   * @function
   * @name sjcl.bitArray.clampM
   * @param {sjcl.bitArray} a The array.
   * @param {Number} len      The length to truncate to, in bits.
   * @return {sjcl.bitArray}  The array, truncated to len bits.
   */
  function clampM(a, len) {
    if (a.length * 32 <= len) { return a; }
    a.splice(Math.ceil(len / 32), a.length);
    return _clampLastM(a, len & 31);
  }

  /** Shift an array left inplace. Doesn't set any partial information.
   * @function
   * @name sjcl.bitArray._shiftLeftM
   * @param {sjcl.bitArray} a  The array to shift.
   * @param {Number} shift     The number of bits to shift (0-31)
   * @param {Number} start     Array index of first word to shift in array
   * @param {Number} end       Array index of the word after the last word to shift
   * @param {Number} [carry=0] A word to shift in from the right (using "shift" low bits)
   * @return {Number}          The word shifted out on the left (using "shift" low bits)
   * @private
   */
  function _shiftLeftM(a, shiftL, start, end, carry) {
    var i, t, shiftR;
    if (0 === shiftL) {
      return 0;
    }
    shiftR = 32 - shiftL;
    for (i = end; i-- > start; ) {
      t = a[i];
      a[i] = (t << shiftL) | carry;
      carry = t >>> shiftR;
    }
    return 0|carry; // carry is an "unsigned" word. make it a signed word.
  }

  /** Shift an array left inplace, dropping the first shift bits
   * @function
   * @name sjcl.bitArray.shiftLeftM
   * @param {sjcl.bitArray} a The array to shift.
   * @param {Number} shift    The number of bits to shift
   * @return {sjcl.bitArray}  The shifted array.
   */
  function shiftLeftM(a, shiftL) {
    if (shiftL >= 32) {
      a.splice(0, Math.floor(shiftL / 32));
    }
    shiftL &= 31;
    if (0 === a.length || 0 === shiftL) {
      return a;
    }
    var last = getPartial(a[a.length-1]);
    _shiftLeftM(a, shiftL, 0, a.length);
    last = last - shiftL;
    if (last <= 0) {
      a.pop();
    }
    return _clampLastM(a, last & 31);
  }

  /** @scope sjcl.bitArray */
  return {
    /** Array slices in units of bits.
     * @param {sjcl.bitArray} a The array to slice.
     * @param {Number} bstart   The offset to the start of the slice, in bits.
     * @param {Number} [bend]   The offset to the end of the slice, in bits.
     *                          If this is undefined, slice until the end of the array.
     * @return {sjcl.bitArray}  The requested slice.
     */
    bitSlice: function (a, bstart, bend) {
      // only slice the part of the input that is actually needed
      a = a.slice(bstart/32, undefined === bend ? a.length : Math.ceil(bend / 32));
      shiftLeftM(a, bstart & 31);
      return (undefined === bend ? a : clampM(a, bend - bstart));
    },

    /** Extract a number packed into a bit array.
     * @param {sjcl.bitArray} a The array to slice.
     * @param {Number} bstart   The offset to the start of the slice, in bits.
     * @param {Number} length   The length of the number to extract.
     * @return {Number}         The number in the requested slice.
     */
    extract: function(a, bstart, blength) {
      // FIXME: this Math.floor is not necessary at all, but for some reason
      // seems to suppress a bug in the Chromium JIT.
      var x, sh = Math.floor((-bstart-blength) & 31);
      if ((bstart + blength - 1 ^ bstart) & -32) {
        // it crosses a boundary
        x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
      } else {
        // within a single word
        x = a[bstart/32|0] >>> sh;
      }
      return x & ((1<<blength) - 1);
    },

    /** Concatenate two bit arrays.
     * @param {sjcl.bitArray} a1 The first array.
     * @param {sjcl.bitArray} a2 The second array.
     * @return {sjcl.bitArray}   The concatenation of a1 and a2.
     */
    concat: function (a1, a2) {
      if (a1.length === 0 || a2.length === 0) {
        return a1.concat(a2);
      }

      var a = a1.concat(a2), last1 = a1[a1.length-1], last2 = a2[a2.length-1],
        shift = 32 - getPartial(last1),
        last = getPartial(last2) - shift;
      // shift second part to the left by what is missing in last1, add carry at the end of the first part */
      a[a1.length-1] |= _shiftLeftM(a, shift, a1.length, a.length);
      // set partial length on last byte. if < 0 all bits were shifted out of the last word, drop it
      if (last <= 0) {
        a.pop();
      }
      return _clampLastM(a, last & 31);
    },

    /** Truncate an array.
     * @param {sjcl.bitArray} a The array.
     * @param {Number} len      The length to truncate to, in bits.
     * @return {sjcl.bitArray}  A new array, truncated to len bits.
     */
    clamp: function (a, len) {
      a = a.slice(0, Math.ceil(len / 32));
      return _clampLastM(a, len & 31);
    },

    /** Compare two arrays for equality in a predictable amount of time.
     * @param {sjcl.bitArray} a The first array.
     * @param {sjcl.bitArray} b The second array.
     * @return {boolean}        true if a == b; false otherwise.
     */
    equal: function (a, b) {
      if (bitLength(a) !== bitLength(b)) {
        return false;
      }
      var x = 0, i;
      for (i=0; i<a.length; i++) {
        x |= a[i]^b[i];
      }
      return (x === 0);
    },

    partial: partial,
    getPartial: getPartial,
    bitLength: bitLength,
    _clampLastM: _clampLastM,
    clampM: clampM,
    _shiftLeftM: _shiftLeftM,
    shiftLeftM: shiftLeftM,

    /** xor two blocks of 4 words together.
     * @param {sjcl.bitArray} a1 Array with 4 words
     * @param {sjcl.bitArray} a2 Array with 4 words
     * @return {sjcl.bitArray}   Array with 4 words
     * @private
     */
    _xor4: function(x,y) {
      return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
    },

    /** byteswap a word array inplace.
     * (does not handle partial words)
     * @param {sjcl.bitArray} a word array
     * @return {sjcl.bitArray} byteswapped array
     */
    byteswapM: function(a) {
      var i, v, m = 0xff00;
      for (i = 0; i < a.length; ++i) {
        v = a[i];
        a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24);
      }
      return a;
    }
  };
}());
