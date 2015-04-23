/** @fileOverview Arrays of bits, encoded as arrays of little endian Numbers.
 *
 * @author Stefan Bühler
 */

/** @namespace Arrays of bits, encoded as arrays of little endian Numbers.
 *
 * @description
 * <p>
 * Some crypto functions need little endian input; these functions provide
 * the functions to convert and handle them.
 * </p>
 *
 * <p>
 * There are two ways converting bit arrays from and to little-endian:
 * one just reverses all bits in a word, and the other only reverses the
 * bytes (and can only be used with byte aligned input).
 * </p>
 *
 * <p>
 * Uses the same magic "bit length" encoding in the last word as sjcl.bitArray.
 * </p>
 */
sjcl.bitArrayLE = (function() {
  /** Make a partial word for a bit array.
   * @function
   * @name sjcl.bitArrayLE.partial
   * @param {Number} len           The number of bits in the word (1-32).
   * @param {Number} x             The bits.
   * @return {Number}              The partial word.
   */
  function partial(len, x) {
    if (len === 32) { return x|0; }
    var mask = (1 << len) - 1;
    x = mask & x;
    return x + len * 0x10000000000;
  }

  /** Get the number of bits used by a partial word.
   * @function
   * @name sjcl.bitArrayLE.getPartial
   * @param {Number} x The partial word.
   * @return {Number}  The number of bits used by the partial word.
   */
  function getPartial(x) {
    return Math.round(x/0x10000000000) || 32;
  }

  /** Find the length of an array of bits.
   * @function
   * @name sjcl.bitArrayLE.bitLength
   * @param {sjcl.bitArrayLE} a The array.
   * @return {Number}           The length of a, in bits.
   */
  function bitLength(a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + getPartial(x);
  }

  /** Sets partial length on last word.
   * @function
   * @name sjcl.bitArrayLE._clampLastM
   * @param {sjcl.bitArrayLE} a The array to modify.
   * @param {Number} len        The partial length to set (0-32; 0 is intepreted as 32).
   * @return {sjcl.bitArrayLE}  The modified array.
   * @private
   */
  function _clampLastM(a, len) {
    len &= 31;
    if (a.length > 0 && len > 0) {
      a[a.length-1] = partial(len, a[a.length-1]);
    }
    return a;
  }

  /** Truncate an array inplace.
   * @function
   * @name sjcl.bitArrayLE.clampM
   * @param {sjcl.bitArrayLE} a The array.
   * @param {Number} len        The length to truncate to, in bits.
   * @return {sjcl.bitArrayLE}  The array, truncated to len bits.
   */
  function clampM(a, len) {
    if (a.length * 32 <= len) { return a; }
    a.splice(Math.ceil(len / 32), a.length);
    return _clampLastM(a, len & 31);
  }

  /** Shift an array left inplace. Doesn't set any partial information.
   * @function
   * @name sjcl.bitArrayLE._shiftLeftM
   * @param {sjcl.bitArrayLE} a  The array to shift.
   * @param {Number} shift       The number of bits to shift (0-31)
   * @param {Number} start       Array index of first word to shift in array
   * @param {Number} end         Array index of the word after the last word to shift
   * @param {Number} [carry=0]   A word to shift in from the right (using "shift" high bits)
   * @return {Number}            The word shifted out on the left (using "shift" high bits)
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
      // shifting array left means shifting bits right in a word
      a[i] = (t >>> shiftL) | carry;
      carry = t << shiftR;
    }
    return carry;
  }

  /** Shift an array left inplace, dropping the first shift bits
   * @function
   * @name sjcl.bitArrayLE.shiftLeftM
   * @param {sjcl.bitArrayLE} a The array to shift.
   * @param {Number} shift      The number of bits to shift
   * @return {sjcl.bitArrayLE}  The shifted array.
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

  /** bit reverse all words in an array inplace
   * (does not handle partial words)
   * @function
   * @name sjcl.bitArrayLE.bitReverseM
   * @param {sjcl.bitArray} a    The word array
   * @return {sjcl.bitArray}     bit reversed array
   */
  function bitReverseM(a) {
    var i, j, v, w;
    for (i = 0; i < a.length; ++i) {
      v = a[i];
      w = 0;
      for (j = 0; j < 32; ++j) {
        w = (w << 1) | (v & 1);
        v >>>= 1;
      }
      a[i] = w;
    }
    return a;
  }

  /** @scope sjcl.bitArrayLE */
  return {
    /** Array slices in units of bits.
     * @param {sjcl.bitArrayLE} a The array to slice.
     * @param {Number} bstart     The offset to the start of the slice, in bits.
     * @param {Number} [bend]     The offset to the end of the slice, in bits.
     *                            If this is undefined, slice until the end of the array.
     * @return {sjcl.bitArrayLE}  The requested slice.
     */
    bitSlice: function (a, bstart, bend) {
      // only slice the part of the input that is actually needed
      a = a.slice(bstart/32, undefined === bend ? a.length : Math.ceil(bend / 32));
      shiftLeftM(a, bstart & 31);
      return (undefined === bend ? a : clampM(a, bend - bstart));
    },

    /** Concatenate two bit arrays.
     * @param {sjcl.bitArrayLE} a1 The first array.
     * @param {sjcl.bitArrayLE} a2 The second array.
     * @return {sjcl.bitArrayLE}   The concatenation of a1 and a2.
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
     * @param {sjcl.bitArrayLE} a The array.
     * @param {Number} len        The length to truncate to, in bits.
     * @return {sjcl.bitArrayLE}  A new array, truncated to len bits.
     */
    clamp: function (a, len) {
      a = a.slice(0, Math.ceil(len / 32));
      return _clampLastM(a, len & 31);
    },

    /** Compare two arrays for equality in a predictable amount of time.
     * @param {sjcl.bitArrayLE} a The first array.
     * @param {sjcl.bitArrayLE} b The second array.
     * @return {boolean}          true if a == b; false otherwise.
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
    bitReverseM: bitReverseM,

    /** convert big endian bit array to little endian by byteswapping all
     * words. the bytes stored in the input are reinterpreted as little endian
     * bytes. a partial byte at the end gets realigned (shifted).
     * @param {sjcl.bitArray} a   The array to convert
     * @return {sjcl.bitArrayLE}  The converted array
     */
    fromBitArrayByteSwap: function(a) {
      if (0 === a.length) {
        return [];
      }
      var i = a.length - 1, lastLen = sjcl.bitArray.getPartial(a[i]), mask;
      a = sjcl.bitArray.byteswapM(a.slice(0));
      if (lastLen & 0x7) {
        // realign last byte
        mask = 0xff << (lastLen & 0x18);
        a[i] = (a[i] & ~mask) | (mask & ( (a[i] & mask) >>> (8 - lastLen & 0x7) ));
      }
      return _clampLastM(a, lastLen);
    },

    /** convert little endian bit array to big endian by byteswapping all
     * words. the bytes stored in the input are reinterpreted as big endian
     * bytes. a partial byte at the end gets realigned (shifted).
     * @param {sjcl.bitArrayLE} a  The array to convert
     * @return {sjcl.bitArray}     The converted array
     */
    toBitArrayByteSwap: function(a) {
      if (0 === a.length) {
        return [];
      }
      var i = a.length - 1, lastLen = getPartial(a[i]), mask;
      a = sjcl.bitArray.byteswapM(a.slice(0));
      if (lastLen & 0x7) {
        // realign last byte
        mask = 0xff << (24 - (lastLen & 0x18));
        a[i] = (a[i] & ~mask) | (mask & ( (a[i] & mask) << (8 - lastLen & 0x7) ));
      }

      // don't depend on sjcl.bitArray._clampLastM yet
      // return sjcl.bitArray._clampLastM(a, lastLen);
      a[i] = sjcl.bitArray.partial(lastLen, a[i], 1);
      return a;
    },

    /** convert big endian bit array to little endian.
     * simple reverses the bits in all words.
     * @param {sjcl.bitArray} a   The array to convert
     * @return {sjcl.bitArrayLE}  The converted array
     */
    fromBitArrayBitReverse: function(a) {
      if (0 === a.length) {
        return [];
      }
      var lastLen = sjcl.bitArray.getPartial(a[a.length-1]);
      return _clampLastM(bitReverseM(a.slice(0)), lastLen);
    },

    /** convert little endian bit array to big endian.
     * simple reverses the bits in all words.
     * @param {sjcl.bitArrayLE} a  The array to convert
     * @return {sjcl.bitArray}     The converted array
     */
    toBitArrayBitReverse: function(a) {
      if (0 === a.length) {
        return [];
      }
      var lastLen = getPartial(a[a.length-1]);
      // don't depend on sjcl.bitArray._clampLastM yet
      // return sjcl.bitArray._clampLastM(bitReverseM(a.slice(0)), lastLen);
      a = bitReverseM(a.slice(0));
      a[a.length-1] = sjcl.bitArray.partial(lastLen, a[a.length-1], 1);
      return a;
    }
  };
}());
