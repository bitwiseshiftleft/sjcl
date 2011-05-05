/** @fileOverview Javascript MD5 implementation.
 *
 * Based on the implementation in RFC 1321, and on the SJCL
 * SHA-1 implementation.
 *
 * @author Brandon Smith
 */

/**
 * Context for a MD5 operation in progress.
 * @constructor
 * @class MD5, 128 bits.
 */
sjcl.hash.md5 = function (hash) {
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 5 big-endian words.
 */
sjcl.hash.md5.hash = function (data) {
  return (new sjcl.hash.md5()).update(data).finalize();
};

sjcl.hash.md5.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = this.blockSize+ol & -this.blockSize; i <= nl;
         i+= this.blockSize) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 4 big-endian words.
   */
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }

    // append the length
    b.push(this._BS(this._length | 0));
    b.push(this._BS(Math.floor(this._length / 0x100000000)));

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    for (i=0; i<4; i++) { h[i] = this._BS(h[i]); }
    return h;
  },

  /**
   * The MD5 initialization vector.
   * @private
   */
  _init:[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],

  /**
   * The MD5 inner functions
   * @private
   */
  _FGHI:[
    function(x, y, z) { return (x & y) | (~x & z); },
    function(x, y, z) { return (x & z) | (y & ~z); },
    function(x, y, z) { return x ^ y ^ z; },
    function(x, y, z) { return y ^ (x | ~z); }
  ],

  /**
   * Circular left-shift operator.
   * @private
   */
  _RL:function(n, x) {
    return (x << n) | (x >>> 32-n);
  },

  /**
   * Byte swap
   * @private
   */
  _BS:function(x) {
    return (x>>24&0xff) | (x>>8&0xff00) | ((x&0xff00)<<8) | ((x&0xff)<<24);
  },
  
  /**
   * 32 bit addition via 2 16 bit words, from http://pajhome.org.uk/crypt/md5/
   * @private
   */
  _A:function(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  },

  _S:[[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]],

  _T:[
    [ 0, 0xd76aa478], [ 1, 0xe8c7b756], [ 2, 0x242070db], [ 3, 0xc1bdceee],
    [ 4, 0xf57c0faf], [ 5, 0x4787c62a], [ 6, 0xa8304613], [ 7, 0xfd469501],
    [ 8, 0x698098d8], [ 9, 0x8b44f7af], [10, 0xffff5bb1], [11, 0x895cd7be],
    [12, 0x6b901122], [13, 0xfd987193], [14, 0xa679438e], [15, 0x49b40821],
    [ 1, 0xf61e2562], [ 6, 0xc040b340], [11, 0x265e5a51], [ 0, 0xe9b6c7aa],
    [ 5, 0xd62f105d], [10, 0x02441453], [15, 0xd8a1e681], [ 4, 0xe7d3fbc8],
    [ 9, 0x21e1cde6], [14, 0xc33707d6], [ 3, 0xf4d50d87], [ 8, 0x455a14ed],
    [13, 0xa9e3e905], [ 2, 0xfcefa3f8], [ 7, 0x676f02d9], [12, 0x8d2a4c8a],
    [ 5, 0xfffa3942], [ 8, 0x8771f681], [11, 0x6d9d6122], [14, 0xfde5380c],
    [ 1, 0xa4beea44], [ 4, 0x4bdecfa9], [ 7, 0xf6bb4b60], [10, 0xbebfbc70],
    [13, 0x289b7ec6], [ 0, 0xeaa127fa], [ 3, 0xd4ef3085], [ 6, 0x04881d05],
    [ 9, 0xd9d4d039], [12, 0xe6db99e5], [15, 0x1fa27cf8], [ 2, 0xc4ac5665],
    [ 0, 0xf4292244], [ 7, 0x432aff97], [14, 0xab9423a7], [ 5, 0xfc93a039],
    [12, 0x655b59c3], [ 3, 0x8f0ccc92], [10, 0xffeff47d], [ 1, 0x85845dd1],
    [ 8, 0x6fa87e4f], [15, 0xfe2ce6e0], [ 6, 0xa3014314], [13, 0x4e0811a1],
    [ 4, 0xf7537e82], [11, 0xbd3af235], [ 2, 0x2ad7d2bb], [ 9, 0xeb86d391]
  ],

  /**
   * The MD5 outer function
   * @private
   */
  _FFGGHHII:function(a, b, c, d, w, f, s, i, j) {
    var A = this._A, R = this._RL, tx = this._T[i+j];
    return A(R(s[j], A(A(a, f(b, c, d)), A(w[tx[0]], tx[1]))), b);
  },

  /**
   * Perform one cycle of MD5.
   * @param {bitArray} words one block of words.
   * @private
   */
  _block:function (words) {  
    var i, r, f, s,
    a, b, c, d,
    w = words.slice(0),
    h = this._h;

    a = h[0]; b = h[1]; c = h[2]; d = h[3];

    for (i=0; i<16; i++) { w[i] = this._BS(w[i]); }
    for (i=0; i<64; i+=4) {
      r = i/16|0;
      f = this._FGHI[r];
      s = this._S[r];
      a = this._FFGGHHII(a, b, c, d, w, f, s, i, 0)
      d = this._FFGGHHII(d, a, b, c, w, f, s, i, 1)
      c = this._FFGGHHII(c, d, a, b, w, f, s, i, 2)
      b = this._FFGGHHII(b, c, d, a, w, f, s, i, 3)
    }

    h[0] = this._A(h[0], a);
    h[1] = this._A(h[1], b);
    h[2] = this._A(h[2], c);
    h[3] = this._A(h[3], d);
  }
};
