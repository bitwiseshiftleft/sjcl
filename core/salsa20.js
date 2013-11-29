/** @fileOverview Low-level Salsa20/r + XSalsa20/r implementation.
 *
 * @author Stefan Bühler
 */

/** @ignore */
sjcl.cipher.salsa20 = (function() {
  var
    // aliases
    ExcInvalid = sjcl.exception.invalid,
    ExcBug = sjcl.exception.bug,
    byteswapM = sjcl.bitArray.byteswapM,
    // consts
    ROUND_OFFSETS, TAU,
    // function forward declaration
    salsa20KeyExpand;

  /** Initialize (X)Salsa20/r context
   * @name sjcl.cipher.salsa20
   * @param {bitArray} key         128- or 256-bit key (given as 4 or 8 big endian words)
   * @param {bitArray} [nonce]     64- or 192-bit nonce (given as 2 or 6 big endian words); 64-bit nonce select
   *                               the "standard" Salsa20/r mode, 192-bit nonce selects XSalsa20/r mode
   *                               (requiring a 256-bit key).
   * @param {Number}   [rounds=20] Number of rounds (must be 8, 12 or 20; ESTREAM uses 12)
   * @constructor
   * @extends sjcl.cipher.stream
   */
  function salsa20(key, nonce, rounds) {
    this._rounds = rounds || 20;
    if (this._rounds !== 8 && this._rounds !== 12 && this._rounds !== 20) {
      throw new ExcInvalid("invalid number of rounds for (X)Salsa20");
    }
    this._key = salsa20KeyExpand(key, nonce, this._rounds);
    this._cache = this._key.slice(0);
    this._eos = false;
  }

  /** double round mixing offsets; group entries of "4x4 matrix" (stored as flat array) into 4 tuples
   * @name sjcl.cipher.salsa20-ROUND_OFFSETS
   * @constant
   * @inner
   */
  ROUND_OFFSETS = [
  // column round
     0,  4,  8, 12,
     5,  9, 13,  1,
    10, 14,  2,  6,
    15,  3,  7, 11,
  // row round
     0,  1,  2,  3,
     5,  6,  7,  4,
    10, 11,  8,  9,
    15, 12, 13, 14
  ];
  /** 256-bit key expansions consts
   * @example TAU == sjcl.bitArray.byteswapM(sjcl.codec.utf8String.toBits("expand 32-byte k"));
   * @name sjcl.cipher.salsa20-TAU
   * @constant
   * @inner
   */
  TAU = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

  /** Salsa double round: alternate between column and row rounds (see ROUND_OFFSETS), always does multiple of two rounds
   * @parameter {sjcl.bitArray} x           Byteswapped (little endian) input, gets modified
   * @parameter {Number}        [rounds=20] (Even) number of rounds
   * @inner
   */
  function doublerounds(x, rounds) {
    var i, t, k, a, b, c, d, oa, ob, oc, od;
    for (i = rounds || 20;i > 0;i -= 2) {
      for (k = 0; k < 32; ) {
/*
        oa = ROUND_OFFSETS[k++]; ob = ROUND_OFFSETS[k++]; oc = ROUND_OFFSETS[k++]; od = ROUND_OFFSETS[k++];
        t = (x[oa]+x[od])^0; x[ob] ^= t <<  7 | t >>> 25;  t = (x[ob]+x[oa])^0; x[oc] ^= t <<  9 | t >>> 23;
        t = (x[oc]+x[ob])^0; x[od] ^= t << 13 | t >>> 19;  t = (x[od]+x[oc])^0; x[oa] ^= t << 18 | t >>> 14;
*/
        // optimized
        oa = ROUND_OFFSETS[k++]; ob = ROUND_OFFSETS[k++]; oc = ROUND_OFFSETS[k++]; od = ROUND_OFFSETS[k++];
        t = ((a = x[oa]) + (d = x[od])); x[ob] = b = x[ob] ^ (t <<  7 | t >>> 25);  t = (b + a)^0; x[oc] = c = x[oc] ^ (t <<  9 | t >>> 23);
        t = (c+b); x[od] = d ^= t << 13 | t >>> 19;  t = (d+c); x[oa] = a ^ (t << 18 | t >>> 14);
      }
    }
  }

  /** Run the Salsa20 hash function on byteswapped data
   * @name sjcl.cipher.salsa20.core
   * @function
   * @param {sjcl.bitArray} data        16 byteswapped (little endian) 32-bit words to hash
   * @param {Number     }   [rounds=20] (Even) number of rounds (ESTREAM uses 12)
   * @param {Array}         [target]    Target array for caching
   * @return {sjcl.bitArray}            16 byteswapped (little-endian) 32-bit words
   */
  function salsa20Core(data, rounds, target) {
    var i;
    if (!target) {
      target = data.slice(0);
    } else {
      for (i = 0; i < 16; ++i) {
        target[i] = data[i];
      }
    }
    doublerounds(target, rounds);
    for (i = 0; i < 16; ++i) {
      target[i] = (target[i] + data[i]) ^ 0;
    }
    return target;
  }

  /**
   * Run the HSalsa20 function on byteswapped data (key deriving from 256-bit key and 128-bit nonce to 256-bit key)
   * @param {sjcl.bitArray} key         8 byteswapped (little endian) 32-bit words to use as key
   * @param {sjcl.bitArray} nonce       4 byteswapped (little endian) 32-bit words to use as nonce
   * @param {Number}        [rounds=20] (Even) number of rounds
   * @return {sjcl.bitArray}            8 byteswapped (little-endian) 32-bit words
   * @inner
   */
  function hsalsa20(key, nonce, rounds) {
    var x, y, i;
    y = [TAU[0], key[0], key[1], key[2], key[3], TAU[1], nonce[0], nonce[1], nonce[2], nonce[3], TAU[2], key[4], key[5], key[6], key[7], TAU[3]];
    // use salsa20Core, and undo the input mixin; that way only salsa20Core uses doublerounds,
    // and the optimizer is more likely to inline doublerounds in salsa20Core
    // performance of salsa20Core is more important than performance of hsalsa20, which is only used in key expansion.
    x = salsa20Core(y, rounds);
    for (i = 0; i < 16; ++i) {
      x[i] = (x[i] - y[i]) ^ 0;
    }
    // x == doublerounds(y, rounds);
    return [ x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9] ];
  }

  /** Handle key expansion for (X)Salsa20(/r). 64-bit counter is set to 0.
   * @param {sjcl.bitArray} key         128 or 256 bit key (16 or 32 bytes)
   * @param {sjcl.bitArray} [nonce]     64-bit (8 byte) nonce or, for XSalsa20 and a 256-bit key, 196-bit (24 byte) nonce
   * @param {Number}        [rounds=20] (Even) number of rounds (only used for HSalsa20 in expansion for XSalsa20)
   * @return {sjcl.bitArray}            The expanded key (input for salsa20), 16 byteswapped (little-endian) 32-bit words
   * @name sjcl.cipher.salsa20-salsa20KeyExpand
   * @function
   * @inner
   */
  salsa20KeyExpand = function(key, nonce, rounds) {
    // preselect consts for 256-bit key
    var b=TAU[1],c=TAU[2],k0,k1;
    key = byteswapM(key.slice(0));
    nonce = nonce ? byteswapM(nonce.slice(0)) : [0, 0];
    if (nonce.length === 6 && key.length === 8) {
      // XSalsa20 (only 256-bit keys) with 196-bit nonce
      // use first 128-bit (4 words) of nonce and 256-bit key to generate the "real" 256-bit key
      // remaining 64-bit (2 words) of the nonce will be used below
      key = hsalsa20(key, nonce, rounds);
      nonce[0] = nonce[4]; nonce[1] = nonce[5];
    } else if (nonce.length !== 2) {
      throw new ExcInvalid("invalid salsa20 nonce size");
    }
    if (key.length === 4) {
      // 128-bit key: flip the two different bits in constants ("expand 16-byte k")
      b ^= 1<<25; c ^= 4;
      k0 = k1 = key; // use 128-bit key twice
    } else if (key.length === 8) {
      k0 = key; k1 = key.slice(4);
    } else {
      throw new ExcInvalid("invalid salsa20 key size");
    }

    return [TAU[0], k0[0], k0[1], k0[2], k0[3], b, nonce[0], nonce[1], 0, 0, c, k1[0], k1[1], k1[2], k1[3], TAU[3]];
  };

  /** increment counter in salsa20 input
   * @param {sjcl.bitArray} x   salsa20 input to increment counter in (gets modified)
   * @return {boolean}          whether overflow in counter happened
   * @inner
   */
  function keyInc(key) {
    return (0 === (key[8] = (key[8] + 1) ^ 0)) && (0 === (key[9] = (key[9] + 1) ^ 0));
  }

  salsa20.core = salsa20Core;

  salsa20.prototype = new sjcl.cipher.stream({
    /** @scope sjcl.cipher.salsa20.prototype */

    // public
    /* Something like this might appear here eventually
      name: 'Salsa20',
      blockSize: 16, // 16 words = 64 bytes = 512 bits
      keySizes: [4,8],
    */

    /** size of a block returned by {@link sjcl.cipher.salsa20#nextMask}. */
    blockBits: 512,

    /** Create XOR mask for next block with 512 bits.
     *
     * @return {sjcl.bitArray} Array containing the mask. The array is reused in future calls.
     */
    nextMask: function() {
      if (this._eos) {
        throw new ExcInvalid("Salsa20 stream cipher reached maximum message length");
      }
      var m = byteswapM(salsa20Core(this._key, this._rounds, this._cache));
      this._eos = keyInc(this._key);
      return m;
    },

    /** Set (32-bit) block index for next block
     * @param {Number} [blockLow=0]
     */
    setBlock: function(blockLow) {
      this.setBlock2(blockLow, 0);
    },

    /** Get current block index.
     * raises an exception if 64-bit block index doesn't fit in 32 bits
     * @return {Number} (32-bit) block index
     */
    getBlock: function() {
      if (this._key[9]) {
        throw new ExcBug("block index doesn't fit in 32 bits");
      }
      return this._key[8];
    },

    /** Set current block index (useful to seek in encrypted data); each block has 64 bytes (512 bits).
     *
     * @param {Number} [blockLow=0]  block index to use; must be < 2^32 (supporting 256GB offsets)
     * @param {Number} [blockHigh=0] support larger block indices: block = 2^32 * blockHigh + blockLow
     *                               (one javascript number cannot represent all 2^64 indices)
     */
    setBlock2: function(blockLow, blockHigh) {
      this._key[8] = blockLow ^ 0;
      this._key[9] = blockHigh ^ 0;
      this._eos = false;
    }
  });

  return salsa20;
}());
