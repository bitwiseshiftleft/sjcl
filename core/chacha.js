/** @fileOverview Low-level ChaCha20 (+ ChaCha12/ChaCha8) implementation.
 *
 * ChaCha is a 256-bit (preferred, 128-bit available too) key stream cipher
 * using a 64-bit nonce, by D. J. Bernstein: http://cr.yp.to/chacha.html
 *
 * The ChaCha family is a variant of Salsa20, adding more "diffusion" in each round
 * and aligning data for bettter SIMD performance.
 *
 * @author Stefan Bühler
 *
 *
 * Differences to Salsa20:
 *  - different key expansion: constants at the beginning,
 *    block index at a different position (different keyInc!), ...
 *  - different ROUND_OFFSETS (grouping in "columns" and "rows")
 *  - different mixing in round, but should use same number of xor/rotate/+ operations; uses different rotates
 *  - no HChaCha/XChaCha yet
 */

/** @ignore */
sjcl.cipher.chacha = (function() {
  var
    // aliases
    ExcInvalid = sjcl.exception.invalid,
    ExcBug = sjcl.exception.bug,
    byteswapM = sjcl.bitArray.byteswapM,
    // consts
    ROUND_OFFSETS, TAU,
    // function forward declaration
    chachaKeyExpand;

  /** Initialize ChaCha20 (ChaCha12 / ChaCha8) context
   * @name sjcl.cipher.chacha
   * @param {sjcl.bitArray} key         128-bit or 256-bit key (given as 4 or 8 big endian words)
   * @param {sjcl.bitArray} [nonce]     64-bit nonce (given as 2 big endian words)
   * @param {Number}        [rounds=20] Number of rounds (must be 8, 12 or 20)
   * @constructor
   * @extends sjcl.cipher.stream
   */
  function chacha(key, nonce, rounds) {
    this._rounds = rounds || 20;
    if (this._rounds !== 8 && this._rounds !== 12 && this._rounds !== 20) {
      throw new ExcInvalid("invalid number of rounds for ChaCha");
    }
    this._key = chachaKeyExpand(key, nonce);
    this._cache = this._key.slice(0);
    this._eos = false;
  }

  /** double round mixing offsets; group entries of "4x4 matrix" (stored as flat array) into 4 tuples
   * @name sjcl.cipher.chacha-ROUND_OFFSETS
   * @constant
   * @inner
   */
  ROUND_OFFSETS = [
  // column round
    0,  4,  8, 12,
    1,  5,  9, 13,
    2,  6, 10, 14,
    3,  7, 11, 15,
  // row round
    0,  5, 10, 15,
    1,  6, 11, 12,
    2,  7,  8, 13,
    3,  4,  9, 14
  ];
  /** 256-bit key expansions consts (from Salsa20)
   * @example TAU == sjcl.bitArray.byteswapM(sjcl.codec.utf8String.toBits("expand 32-byte k"));
   * @name sjcl.cipher.chacha-TAU
   * @constant
   * @inner
   */
  TAU = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

  /** ChaCha double round: alternate between column and row rounds (see ROUND_OFFSETS), always does multiple of two rounds
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
        x[oa] = (x[oa] + x[ob])^0; t = x[od] ^ x[oa]; x[od] = t << 16 | t >>> 16;
        x[oc] = (x[oc] + x[od])^0; t = x[ob] ^ x[oc]; x[ob] = t << 12 | t >>> 20;
        x[oa] = (x[oa] + x[ob])^0; t = x[od] ^ x[oa]; x[od] = t <<  8 | t >>> 24;
        x[oc] = (x[oc] + x[od])^0; t = x[ob] ^ x[oc]; x[ob] = t <<  7 | t >>> 25;
*/

        // optimized
        oa = ROUND_OFFSETS[k++]; ob = ROUND_OFFSETS[k++]; oc = ROUND_OFFSETS[k++]; od = ROUND_OFFSETS[k++];
        a = (x[oa] + (b = x[ob])); t = x[od] ^ a;         d = t << 16 | t >>> 16;
        c = (x[oc] + d);           t = b ^ c;             b = t << 12 | t >>> 20;
        x[oa] = (a += b)^0;        t = d ^ a;     x[od] = d = t <<  8 | t >>> 24;
        x[oc] = (c += d)^0;        t = b ^ c;     x[ob]     = t <<  7 | t >>> 25;
      }
    }
  }

  /** Run the ChaCha hash function
   * @name sjcl.cipher.chacha.core
   * @function
   * @param {sjcl.bitArray} data        16 byteswapped (little endian) 32-bit words to hash
   * @param {Number     }   [rounds=20] (Even) number of rounds
   * @param {Array}         [target]    Target array for caching
   * @return {sjcl.bitArray}            16 byteswapped (little-endian) 32-bit words
   */
  function chachaCore(data, rounds, target) {
    // same as salsa20Core, but does ChaCha doublerounds instead
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

  /** Handle key expansion for ChaCha. 64-bit counter is set to 0.
   * @param {sjcl.bitArray} key         128 or 256 bit key (16 or 32 bytes)
   * @param {sjcl.bitArray} [nonce]     64-bit (8 byte) nonce
   * @return {sjcl.bitArray}            The expanded key (input for chacha), 16 byteswapped (little-endian) 32-bit words
   * @name sjcl.cipher.chacha-chachaKeyExpand
   * @function
   * @inner
   */
  chachaKeyExpand = function chachaKeyExpand(key, nonce) {
    // preselect consts for 256-bit key
    key = byteswapM(key.slice(0));
    nonce = byteswapM(nonce.slice(0));
    if (nonce.length !== 2) {
      throw new ExcInvalid("invalid ChaCha nonce size");
    }
    if (key.length === 4) {
      var r = TAU.concat(key, key, [0,0], nonce);
      // 128-bit key: flip the two different bits in constants ("expand 16-byte k")
      r[1] ^= 1<<25; r[2] ^= 4;
      return r;
    } else if (key.length === 8) {
      return TAU.concat(key, [0,0], nonce);
    } else {
      throw new ExcInvalid("invalid ChaCha key size");
    }
  };

  /** increment counter in chacha input
   * @param {sjcl.bitArray} x   chacha input to increment counter in (gets modified)
   * @return {boolean}          whether overflow in counter happened
   * @inner
   */
  function keyInc(key) {
    return (0 === (key[12] = (key[12] + 1) ^ 0)) && (0 === (key[13] = (key[13] + 1) ^ 0));
  }

  // little endian interface!
  chacha.core = chachaCore;

  chacha.prototype = new sjcl.cipher.stream({
    /** @scope sjcl.cipher.chacha.prototype */

    // public
    /* Something like this might appear here eventually
      name: 'ChaCha',
      blockSize: 16, // 16 words = 64 bytes = 512 bits
      keySizes: [4,8],
    */

    /** size of a block returned by {@link sjcl.cipher.chacha#nextMask}. */
    blockBits: 512,

    /** Create XOR mask for next block with 512 bits.
     *
     * @return {sjcl.bitArray} Array containing the mask. The array is reused in future calls.
     */
    nextMask: function() {
      if (this._eos) {
        throw new ExcInvalid("ChaCha stream cipher reached maximum message length");
      }
      var m = byteswapM(chachaCore(this._key, this._rounds, this._cache));
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
      if (this._key[13]) {
        throw new ExcBug("block index doesn't fit in 32 bits");
      }
      return this._key[12];
    },

    /** Set current block index (useful to seek in encrypted data); each block has 64 bytes (512 bits).
     *
     * @param {Number} [blockLow=0]  block index to use; must be < 2^32 (supporting 256GB offsets)
     * @param {Number} [blockHigh=0] support larger block indices: block = 2^32 * blockHigh + blockLow
     *                               (one javascript number cannot represent all 2^64 indices)
     */
    setBlock2: function(blockLow, blockHigh) {
      this._key[12] = blockLow ^ 0;
      this._key[13] = blockHigh ^ 0;
      this._eos = false;
    }
  });

  return chacha;
}());
