/** @fileOverview GCM Incremental/streaming/progressive mode implementation.
 *
 * Extends original GCM implementation to support chunked processing.
 * @author Dusan Klinec (ph4r05)
 */

/** @namespace Galois/Counter mode. */
sjcl.mode.gcmProgressive = {
  /** The name of the mode.
   * @constant
   */
  name: "gcmProgressive",

  /**
   * Creates a new GCM engine.
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {boolean} encrypt mode of operation. true for encryption, false for decryption.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @returns {Object} encryption engine {update: function(data), finalize:function(data)}
   */
  create: function (prf, encrypt, iv, adata, tlen) {
    return new sjcl.mode.gcmProgressive.engine(prf, encrypt, iv, adata, tlen);
  },

  /**
   * Creates a new GCM engine for encryption.
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @returns {Object} encryption engine {update: function(data), finalize:function(data)}
   */
  createEncryptor: function (prf, iv, adata, tlen) {
    return new sjcl.mode.gcmProgressive.engine(prf, true, iv, adata, tlen);
  },

  /**
   * Creates a new GCM engine for decryption.
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @returns {Object} encryption engine {update: function(data), finalize:function(data)}
   */
  createDecryptor: function (prf, iv, adata, tlen) {
    return new sjcl.mode.gcmProgressive.engine(prf, false, iv, adata, tlen);
  },

  /**
   * Convenience function for encryption of the input data.
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {bitArray} data input data to encrypt
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @returns {bitArray} ciphertext + tag
   */
  encrypt: function (prf, data, iv, adata, tlen) {
    return (new sjcl.mode.gcmProgressive.engine(prf, true, iv, adata, tlen)).finalize(data);
  },

  /**
   * Convenience function for decryption of the input data.
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {bitArray} data input data to decrypt (with tag).
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @returns {bitArray} plaintext
   */
  decrypt: function (prf, data, iv, adata, tlen) {
    return (new sjcl.mode.gcmProgressive.engine(prf, false, iv, adata, tlen)).finalize(data);
  },

  /**
   * Incremental/streaming/progressive GCM mode.
   * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
   *
   * @param {Object} prf The pseudo-random function. It must have a block size of 16 bytes.
   * @param {boolean} encrypt mode of operation. true for encryption, false for decryption.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata Data to include in authentication tag.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   */
  engine: function (prf, encrypt, iv, adata, tlen) {
    this._gcmInitState(prf, encrypt, iv, adata || [], tlen || 128);
  }
};

sjcl.mode.gcmProgressive.engine.prototype = {
  _prf: undefined,     // pseudo random function (cipher).
  _enc: undefined,     // encryption/decryption flag.
  _H: undefined,       // H value used in tag computation, H = prf.encrypt(key, 0^{128}).
  _tlen: undefined,    // tag length in bits.
  _abl: undefined,     // authenticated data bit length, used for the final tag computation.
  _J0: undefined,      // initial counter value for the first block = used for the final tag computation.
  _ctr: undefined,     // current counter value.
  _tag: undefined,     // current tag value.
  _bl: undefined,      // total plaintext/ciphertext bitlength. Used in the final tag computation.
  _buff: undefined,    // buffer keeping streaming input, not processed yet, not multiple of a block size.
  _buffTag: undefined, // in decryption mode, buffer for potential tag in stream processing. Holds last tlen bits from the last update() block.
  _finalized: false,   // if mode was already finalized.

  /**
   * Incremental processing function.
   * Processes input data, returns output.
   * Output from the function is multiple of 16B, unprocessed data are stored in the internal state.
   * Note the function may return empty result = [].
   *
   * @param data
   * @returns {*|Array}
   */
  update: function (data) {
    return this._update(data, false);
  },
  process: function (data) {
    return this._update(data, false);
  },

  /**
   * Processes the last block (potentially empty) and produces the final output.
   *
   * @param data
   * @param options if options.returnTag == true, function returns {tag: tag, data: data}.
   * @returns {bitArray | {tag: (bitArray), data: (bitArray)}}
   */
  finalize: function (data, options) {
    // Process final data, finalize tag computation & buffers.
    var last, enc, w = sjcl.bitArray;
    options = options || {};
    var returnTag = options && options.returnTag || false;
    var interm = this._update(data, true);

    // Calculate last tag block from bit lengths, ugly because bitwise operations are 32-bit
    last = [
      Math.floor(this._abl / 0x100000000), this._abl & 0xffffffff,  // adata bit length
      Math.floor(this._bl / 0x100000000), this._bl & 0xffffffff     // data bit length
    ];

    // Calculate the final tag block
    // Tag computation including bit lengths
    this._tag = sjcl.mode.gcm._ghash(this._H, this._tag, last);

    // XORing with the first counter value to obtain final auth tag.
    enc = this._prf.encrypt(this._J0);
    this._tag[0] ^= enc[0];
    this._tag[1] ^= enc[1];
    this._tag[2] ^= enc[2];
    this._tag[3] ^= enc[3];

    // Decryption -> check tag. If invalid -> throw exception.
    if (!this._enc && !w.equal(this._tag, this._buffTag)) {
      throw new sjcl.exception.corrupt("gcm: tag doesn't match");
    }

    if (returnTag) {
      return {tag: w.bitSlice(this._tag, 0, this._tlen), data: interm};
    }

    return this._enc ? w.concat(interm || [], this._tag) : interm;
  },

  /**
   * Initializes the internal state state for streaming processing.
   *
   * @param encrypt
   * @param prf
   * @param adata
   * @param iv
   * @param tlen
   * @private
   */
  _gcmInitState: function (prf, encrypt, iv, adata, tlen) {
    var ivbl, S0, w = sjcl.bitArray;

    // Calculate data lengths
    this._enc = encrypt;
    this._prf = prf;
    this._tlen = tlen;
    this._abl = w.bitLength(adata);
    this._bl = 0;
    this._buff = [];
    this._buffTag = [];
    ivbl = w.bitLength(iv);

    // Calculate the parameters - H = E(K, 0^{128}), tag multiplier
    this._H = this._prf.encrypt([0, 0, 0, 0]);
    // IV size reflection to the J0 = counter
    if (ivbl === 96) {
      // J0 = IV || 0^{31}1
      this._J0 = iv.slice(0);
      this._J0 = w.concat(this._J0, [1]);
    } else {
      // J0 = GHASH(H, {}, IV)
      this._J0 = sjcl.mode.gcm._ghash(this._H, [0, 0, 0, 0], iv);
      // Last step of GHASH = (j0 + len(iv)) . H
      this._J0 = sjcl.mode.gcm._ghash(this._H, this._J0, [0, 0, Math.floor(ivbl / 0x100000000), ivbl & 0xffffffff]);
    }
    // Authenticated data hashing. Result will be XORed with first ciphertext block.
    S0 = sjcl.mode.gcm._ghash(this._H, [0, 0, 0, 0], adata);

    // Initialize ctr and tag
    this._ctr = this._J0.slice(0);
    this._tag = S0.slice(0);
  },

  /**
   * Internal update method. Processes input data in the given encryption mode.
   * Takes care of the internal state. In normal update mode (not finalizing), only a multiple
   * of a cipher block size is processed. Rest is kept in the state.
   *
   * Special care is taken in decryption, where last tlen bytes can be auth tag.
   *
   * When finalizing, no aligning is applied and whole state and input data is processed. Object should be called
   * only once with finalize=true.
   *
   * @param {Array} data
   * @param {boolean} finalize
   * @returns {Array}
   * @private
   */
  _update: function (data, finalize) {
    var enc, bl, i, l, inp = [], w = sjcl.bitArray;

    // Data to process = unprocessed buffer from the last update call + current data so
    // it gives multiple of a block size. Rest goes to the buffer.
    // In decryption case, keep last 16 bytes in the buffTag as it may be a potential auth tag that must not go
    // to decryption routine.
    // Add data from the previous update().
    inp = w.concat(inp, this._buff);
    this._buff = [];

    // Finalize only once - prevent programmers mistake.
    if (this._finalized && finalize) {
      throw new sjcl.exception.invalid("Cipher already finalized, cannot process new data, need to init a new cipher");
    }
    this._finalized |= finalize;

    // In case of a decryption, add also potential tag buffer - may not be the tag but the part of the ciphertext.
    if (!this._enc) {
      inp = w.concat(inp, this._buffTag);
      this._buffTag = [];
    }

    // Add all input data to the processing buffer inp.
    inp = w.concat(inp, data || []);
    bl = w.bitLength(inp);

    // In decryption case, move last tlen bits back to the buffTag as it may be a potential auth tag.
    if (!this._enc) {
      if (bl < this._tlen) {
        this._buffTag = inp;
        return [];
      }

      this._buffTag = w.bitSlice(inp, bl - this._tlen);
      inp = w.clamp(inp, bl - this._tlen);
      bl -= this._tlen;
    }

    // Move last bytes not aligned to 1 block (16B) size to buff. When finalizing, process everything.
    var blForNextTime = bl % 128;
    if (blForNextTime > 0 && !finalize) {
      this._buff = w.bitSlice(inp, bl - blForNextTime);
      inp = w.clamp(inp, bl - blForNextTime);
      bl -= blForNextTime;
    }

    // Sanity check.
    if (bl < 0) {
      throw new sjcl.exception.invalid("Invariant invalid - buffer underflow");
    } else if (bl == 0) {
      return [];
    }

    this._bl += bl;

    // In GCM ciphertext goes to the tag computation. In decryption mode, it is our input.
    if (!this._enc) {
      this._tag = sjcl.mode.gcm._ghash(this._H, this._tag, inp);
    }

    // Encrypt all the data
    // Last 32bits of the ctr is actual counter.
    for (i = 0, l = inp.length; i < l; i += 4) {
      this._ctr[3]++;
      enc = this._prf.encrypt(this._ctr);
      inp[i] ^= enc[0];
      inp[i + 1] ^= enc[1];
      inp[i + 2] ^= enc[2];
      inp[i + 3] ^= enc[3];
    }
    // Take the actual length of the original input (as in the Streaming mode).
    // Should be a multiple of a cipher block size - no effect on data, unless we are finalizing.
    inp = w.clamp(inp, bl);

    // In GCM ciphertext goes to the tag computation. In encryption mode, it is our output.
    if (this._enc) {
      this._tag = sjcl.mode.gcm._ghash(this._H, this._tag, inp);
    }

    return inp;
  }
};



