/**
 * @fileOverview    Z85 codec implementation.
 * @summary         Z85 encoding is the "string-safe" ZeroMQ variant of Base85 
 *                  encoding. The character set avoids the single and double
 *                  quotes and the backslash, making the encoded string
 *                  safe to embed in command-line interpreters.
 *                  Base85 uses 5 characters to encode 4 bytes of data,
 *                  making the encoded size 1/4 larger than the original;
 *                  this also makes it more efficient than uuencode or Base64,
 *                  which uses 4 characters to encode 3 bytes of data, making
 *                  the encoded size 1/3 larger than the original.
 *
 * @author          Manjul Apratim
 */

/**
 * Z85 encoding/decoding
 * http://rfc.zeromq.org/spec:32/Z85/
 * @namespace
 */
sjcl.codec.z85 = {
  /** The Z85 alphabet.
   * @private
   */
  _chars: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",

  /** The decoder map (maps base 85 to base 256).
   * @private
   */
  _byteMap: [
    0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 
    0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47, 
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 
    0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 
    0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00
  ],

  /**
   * @summary Method to convert a bitArray to a Z85-encoded string.
   *          The bits represented by the array MUST be multiples of 4 bytes.
   * @param   {bitArray} arr - The input bitArray.
   * @return  {string} The Z85-encoded string.
   */
  fromBits: function (arr) {
    // Sanity checks
    if (!arr) {
      return null;
    }
    // Check we have multiples of 4 bytes (32 bits)
    if (0 !== sjcl.bitArray.bitLength(arr) % 32) {
      throw new sjcl.exception.invalid("Invalid bitArray length!");
    }

    var out = "", c = sjcl.codec.z85._chars;

    // Convert sequences of 4 bytes (each word) to 5 characters.
    for (var i = 0; i < arr.length; ++i) {
      // Each element in the bitArray is a 32-bit (4-byte) word.
      var word = arr[i];
      var value = 0;
      for (var j = 0; j < 4; ++j) {
        // Extract each successive byte from the word from the left.
        var byteChunk = (word >>> 8*(4 - j - 1)) & 0xFF;
        // Accumulate in base-256
        value = value*256 + byteChunk;
      }
      var divisor = 85*85*85*85;
      while (divisor) {
        out += c.charAt(Math.floor(value/divisor) % 85);
        divisor = Math.floor(divisor/85);
      }
    }

    // Sanity check - each 4-bytes (1 word) should yield 5 characters.
    var encodedSize = arr.length*5;
    if (out.length !== encodedSize) {
      throw new sjcl.exception.invalid("Bad Z85 conversion!");
    }
    return out;
  },

  /**
   * @summary Method to convert a Z85-encoded string to a bitArray.
   *          The length of the string MUST be a multiple of 5
   *          (else it is not a valid Z85 string).
   * @param   {string} str - A valid Z85-encoded string.
   * @return  {bitArray} The decoded data represented as a bitArray.
   */
  toBits: function(str) {
    // Sanity check
    if (!str) {
        return [];
    }
    // Accept only strings bounded to 5 bytes
    if (0 !== str.length % 5) {
      throw new sjcl.exception.invalid("Invalid Z85 string!");
    }

    var out = [], value = 0, byteMap = sjcl.codec.z85._byteMap;
    var word = 0, wordSize = 0;
    for (var i = 0; i < str.length;) {
      // Accumulate value in base 85.
      value = value * 85 + byteMap[str[i++].charCodeAt(0) - 32]; 
      if (0 === i % 5) {
        // Output value in base-256
        var divisor = 256*256*256;
        while (divisor) {
          // The following is equivalent to a left shift by 8 bits
          // followed by OR-ing; however, left shift may cause sign problems
          // due to 2's complement interpretation,
          // and we're operating on unsigned values.
          word = (word * Math.pow(2, 8)) + (Math.floor(value/divisor) % 256);
          ++wordSize;
          // If 4 bytes have been acumulated, push the word into the bitArray.
          if (4 === wordSize) {
            out.push(word);
            word = 0, wordSize = 0;
          }
          divisor = Math.floor(divisor/256);
        }
        value = 0;
      }
    }

    return out;
  }
}
