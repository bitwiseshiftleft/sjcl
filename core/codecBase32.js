/** @fileOverview Bit array codec implementations.
 *
 * @author Nils Kenneweg
 */

/** @namespace Base32 encoding/decoding */
sjcl.codec.base32 = {
  /** The base32 alphabet.
   * @private
   */
  _chars: "0123456789abcdefghjkmnpqrstvwxyz",

  /* bits in an array */
  BITS: 32,
  /* base to encode at (2^x) */
  BASE: 5,
  /* bits - base */
  REMAINING: 27,
  
  /** Convert from a bitArray to a base32 string. */
  fromBits: function (arr, _noEquals) {
    var BITS = sjcl.codec.base32.BITS, BASE = sjcl.codec.base32.BASE, REMAINING = sjcl.codec.base32.REMAINING;
    var out = "", i, bits=0, c = sjcl.codec.base32._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);

    for (i=0; out.length * BASE <= bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> REMAINING);
      if (bits < BASE) {
        ta = arr[i] << (BASE-bits);
        bits += REMAINING;
        i++;
      } else {
        ta <<= BASE;
        bits -= BASE;
      }
    }

    return out;
  },
  
  /** Convert from a base32 string to a bitArray */
  toBits: function(str) {
    var BITS = sjcl.codec.base32.BITS, BASE = sjcl.codec.base32.BASE, REMAINING = sjcl.codec.base32.REMAINING;
    var out = [], i, bits=0, c = sjcl.codec.base32._chars, ta=0, x;

    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base32!");
      }
      if (bits > REMAINING) {
        bits -= REMAINING;
        out.push(ta ^ x>>>bits);
        ta  = x << (BITS-bits);
      } else {
        bits += BASE;
        ta ^= x << (BITS-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};
