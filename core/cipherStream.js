/** @fileOverview construct stream cipher
 *
 * @author Stefan Bühler
 */

/** @ignore */
sjcl.cipher.stream = (function() {
  /* aliases */
  var
    ExcInvalid = sjcl.exception.invalid,
    ExcBug = sjcl.exception.bug,
    bitLength = sjcl.bitArray.bitLength,
    getPartial = sjcl.bitArray.getPartial,
    partial = sjcl.bitArray.partial,
    bitSlice = sjcl.bitArray.bitSlice,
    streamPrototype;

  // masks out unused bits as otherwise sjcl.bitArray.equal fails
  // can be reduced to simple partial as soon as sjcl.bitArray.partial does
  // the masking itself.
  function masked_partial(len, x, _end) {
    if (32 === len) { return x|0; }
    var mask = 0x80000000 >> (len-1);
    return partial(len, mask & (_end ? x : x << (32-len)), 1);
  }

  /** constructor for stream cipher prototype
   * @name sjcl.cipher.stream
   * @param {Object} [props] object with properties to extend the base class with
   *
   * @example MyStreamCipher.prototype = new sjcl.cipher.stream({ blockBits: ..., nextMask: function() { ... }});
   * @constructor
   */
  function stream(props) {
    var p;
    for (p in streamPrototype) {
      if (streamPrototype.hasOwnProperty(p)) {
        this[p] = streamPrototype[p];
      }
    }
    for (p in props) {
      if (props.hasOwnProperty(p)) {
        this[p] = props[p];
      }
    }
  }

  /** apply xor mask to data
   *
   * stores remainder of mask in obj._mask
   * @param {sjcl.cipher.stream} obj
   * @param {sjcl.bitArray} data data to apply xor mask to
   * @param {sjcl.bitArray} mask xor mask (does not get modified)
   * @param {Number} offset offset in data at which mask to apply
   * @return {Number} number of processed bits
   * @inner
   */
  function xor(obj, data, mask, offset) {
    var ndx = offset / 32, i, l, prev = 0, m, bits, masklen;
    offset = offset & 31;
    /* last word could be partial, handle at bottom */
    l = Math.min(mask.length, data.length - ndx) - 1;
    if (offset) {
      prev = 0;
      for (i = 0; i < l; ++i, ++ndx) {
        m = mask[i];
        data[ndx] ^= (m >>> offset) ^ prev;
        prev = m << (32 - offset);
      }
    } else {
      for (i = 0; i < l; ++i, ++ndx) {
        data[ndx] ^= mask[i];
      }
    }

    /* if offset == 0 => prev == 0 and (mask[i] >>> offset) ^ prev == mask[i] */
    /* only the last word could be partial */
    bits = getPartial(data[ndx]);
    data[ndx] ^= (mask[i] >>> offset) ^ prev;
    if (32 !== bits) {
      data[ndx] = masked_partial(bits, data[ndx], 1);
    }

    l = l * 32 + bits - offset;
    obj._mask = bitSlice(mask, l);
    if (0 === obj._mask.length) {
      obj._mask = null;
    }
    return l;
  }

  /** Encrypt/Decrypt a message
   * @function
   * @this {sjcl.cipher.stream}
   * @name sjcl.cipher.stream.prototype.crypt
   * @param {sjcl.bitArray} data message bits to encrypt/decrypt
   * @return {sjcl.bitArray} encrypted/decrypted message
   */
  function crypt(data) {
    data = data.slice(0);
    var pos = 0, len = bitLength(data);
    if (this._mask) {
      pos += xor(this, data, this._mask, pos);
    }
    while (pos < len) {
      if (this._mask) {
        throw new ExcBug("_mask must be null");
      }
      pos += xor(this, data, this.nextMask(), pos);
    }
    return data;
  }

  /* closure compiler is killing a "real" prototype, so fake it. */
  streamPrototype = {
    /** @scope sjcl.cipher.stream.prototype */

    /** size of a block returned by {@link sjcl.cipher.stream#nextMask}.
     * Override in implementation!
     */
    blockBits: 0,
    /** Create XOR mask for next block with {@link sjcl.cipher.stream#blockBits} bits.
     * Override in implementation!
     *
     * @return {sjcl.bitArray} Array containing the mask.
     *   Array object can be reused in next nextMask() run,
     *   sjcl.cipher.stream doesn't modify it.
     */
    nextMask: function() {
      throw new ExcInvalid("nextMask not implemented");
    },
    /* optional:
    setBlock: function(index) {
    },
    getBlock: function() {
    },
    */

    crypt: crypt,
    /** alias for {@link sjcl.cipher.stream#crypt}
     * @function
     * @param {sjcl.bitArray} data message bits to encrypt
     */
    encrypt: crypt,
    /** alias for {@link sjcl.cipher.stream#crypt}
     * @function
     * @param {sjcl.bitArray} data message bits to decrypt
     */
    decrypt: crypt,

    /** set position in stream.
     * TODO: support big ints, check overflows, ...
     *
     * requires a setBlock method in the ciphers implementation, taking a block index
     * @this {sjcl.cipher.stream}
     * @param {Number} pos
     */
    setPosition: function(pos) {
      if (!this.setBlock) {
        throw new ExcBug("(this) stream cipher can't seek position");
      }
      var relPos = pos % this.blockBits;
      this.setBlock((pos - relPos) / this.blockBits);
      if (0 === relPos) {
        this._mask = null;
      } else {
        this._mask = this.nextMask();
        bitSlice(this._mask, relPos);
      }
    },

    /** get position in stream.
     *
     * requires a getBlock method in the ciphers implementation, returning the current block index
     * @this {sjcl.cipher.stream}
     * @return {Number}
     */
    getPosition: function() {
      if (!this.getBlock) {
        throw new ExcBug("(this) stream cipher can't tell position");
      }
      var relPos = (this._mask ? bitLength(this._mask) : 0);
      return this.getBlock() * this.blockBits - relPos;
    }
  };

  return stream;
}());
