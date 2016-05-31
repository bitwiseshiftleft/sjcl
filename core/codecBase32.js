/** @fileOverview Bit array codec implementations.
 *
 * @author Nils Kenneweg
 */

/**
 * Base32 encoding/decoding
 * @namespace
 */
sjcl.codec.base32 = {
  /** The base32 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  _hexChars: "0123456789ABCDEFGHIJKLMNOPQRSTUV",

  /* bits in an array */
  BITS: 32,
  /* base to encode at (2^x) */
  BASE: 5,
  /* bits - base */
  REMAINING: 27,

  /** Convert from a bitArray to a base32 string. */
  fromBits: function (arr, _noEquals, _hex) {
    var BITS = sjcl.codec.base32.BITS, BASE = sjcl.codec.base32.BASE, REMAINING = sjcl.codec.base32.REMAINING;
    var out = "", i, bits=0, c = sjcl.codec.base32._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);

    if (_hex) {
      c = sjcl.codec.base32._hexChars;
    }

    for (i=0; out.length * BASE < bl; ) {
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
    while ((out.length & 7) && !_noEquals) { out += "="; }

    return out;
  },

  /** Convert from a base32 string to a bitArray */
  toBits: function(str, _hex) {
    str = str.replace(/\s|=/g,'').toUpperCase();
    var BITS = sjcl.codec.base32.BITS, BASE = sjcl.codec.base32.BASE, REMAINING = sjcl.codec.base32.REMAINING;
    var out = [], i, bits=0, c = sjcl.codec.base32._chars, ta=0, x, format="base32";

    if (_hex) {
      c = sjcl.codec.base32._hexChars;
      format = "base32hex";
    }

    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        // Invalid character, try hex format
        if (!_hex) {
          try {
            return sjcl.codec.base32hex.toBits(str);
          }
          catch (e) {}
        }
        throw new sjcl.exception.invalid("this isn't " + format + "!");
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

sjcl.codec.base32hex = {
  fromBits: function (arr, _noEquals) { return sjcl.codec.base32.fromBits(arr,_noEquals,1); },
  toBits: function (str) { return sjcl.codec.base32.toBits(str,1); }
};
