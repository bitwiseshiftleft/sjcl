/** @fileOverview Poly1305 implementation.
 *
 * Poly1305 is a MAC by D. J. Bernstein: http://cr.yp.to/mac.html
 *
 * Poly1305(key, c) builds a checksum with a polynom:
 *    csum = (c_1*r'^q + ... + c_q*r'^1) mod (2^130 - 5),
 * and encrypts that csum with s:
 *    mac = (csum + s) mod 2^128
 * c_i are derived from the input message c (split into 128-bit/16-byte blocks,
 * (little-endian) deserialize to number, add 2^blocklen as padding).
 * r' is r with some bits clamped to 0.
 * r and s are 16 bytes long (128 bits) and concat(r, s) is the key, c is the message (byte aligned).
 *
 * Poly1305-AES(r, k, n, c) = Poly1305(concat(r, AES-128_k(n)), c)
 *
 * Poly1305 uses little endian to (de)serialize numbers.
 *
 * @author Stefan Bühler
 */

/** @ignore */
sjcl.misc.poly1305 = (function() {
  var Bn = sjcl.bn, P1305 = Bn.prime.p1305, radix = P1305.prototype.radix, bA = sjcl.bitArray,
    bit129ndx = Math.floor(128 / radix),
    bit129value = 1 << (128 % radix);

  /** convert (up to) 4 little endian 32-bit unsigned words in
   * a[offset..offset+4] to a bignumber of class cls
   *
   * input can end in partial big-endian word if it is byte aligned
   * @private
   */
  function bits128ToNum(a, offset, cls) {
    return cls.fromBits(bA.byteswapM(a.slice(offset, offset + 4)).reverse());
  }

  /** Context for a Poly1305 operation. Can be called as normal function too,
   * with the data to authenticate as second parameter and returning the
   * {@link sjcl.misc.poly1305#finalize}d tag.
   * @constructor
   * @name sjcl.misc.poly1305
   * @param {sjcl.bitArray} key    256-bit key (128-bit "r" for the polynom,
   *     128-bit "s" to encrypt ("+" mod 2^128) the resulting tag)
   * @param {sjcl.bitArray} [data] (only in non-constructor mode) the data to
   *     authenticate.
   * @return {sjcl.misc.poly1305|sjcl.bitArray}
   */
  function Poly1305(key, data) {
    if (null !== data && 'undefined' !== typeof data) {
      return (new Poly1305(key)).update(data).finalize();
    }

    if (8 !== key.length) {
      throw new sjcl.exception.invalid("invalid Poly1305 key size");
    }

    key[0] &= ~0xf0;
    key[1] &= ~(0x30000f0);
    key[2] &= ~(0x30000f0);
    key[3] &= ~(0x30000f0);
    this._r = bits128ToNum(key, 0, P1305);
    this._s = bits128ToNum(key, 4, Bn);
    this._h = new P1305(0);
    this._buffer = null;
  }

  /** Input several words to the message to verify.
   * @name sjcl.misc.poly1305#update
   * @function
   * @param {sjcl.bitArray} data   The data to authenticate.
   * @return {sjcl.misc.poly1305}  The poly1305 object (for chaining calls)
   */
  Poly1305.prototype.update = function(data) {
    var h = this._h, r = this._r, i, l, ci;
    if (this._buffer) {
      data = bA.concat(this._buffer, data);
      this._buffer = null;
    }

    l = Math.floor(bA.bitLength(data) / 32) & ~0x3;
    for (i = 0; i < l; i += 4) {
      ci = bits128ToNum(data, i, P1305);
      ci.limbs[bit129ndx] = (ci.limbs[bit129ndx] || 0) + bit129value;
      h.addM(ci).cnormalize();
      h = h.mul(r);
    }
    if (i < data.length) {
      this._buffer = data.slice(i);
    }
    this._h = h;

    return this;
  };

  /** Calculate final authentication tag for message; doesn't modify the
   * state.
   * @function
   * @name sjcl.misc.poly1305#finalize
   * @return {sjcl.bitArray} 128-bit tag
   */
  Poly1305.prototype.finalize = function() {
    var h = this._h.copy(), r = this._r, s = this._s, data, l, ci, ndx;
    if (this._buffer) {
      data = this._buffer;
      l = bA.bitLength(data);
      ci = bits128ToNum(data, 0, P1305);
      ndx = Math.floor(l / radix);
      ci.limbs[ndx] = (ci.limbs[ndx] || 0) + (1 << (l % radix));
      h.addM(ci).cnormalize();
      h = h.mul(r);
    }
    h = new Bn(h.fullReduce());
    h.addM(s);
    return bA.byteswapM(h.toBits(128)).reverse();
  };

  /** Verifies given tag authenticates the message; doesn't modify the state.
   * Uses constant time comparision.
   * @function
   * @name sjcl.misc.poly1305#verify
   * @param {sjcl.bitArray} [tag] 128-bit tag to compare with
   * @return {boolean}
   */
  Poly1305.prototype.verify = function(tag) {
    var t = this.finalize();
    return bA.equal(t, tag);
  };

  return Poly1305;
}());

/** Context for a Poly1305(-AES) operation. Can be called as normal function
 * too, with the data to authenticate as fourth parameter.
 *
 * Requires {@link sjcl.cipher.aes}.
 * @param {sjcl.bitArray} r       128-bit "r"
 * @param {sjcl.bitArray} key     128-bit AES key
 * @param {sjcl.bitArray} nonce   128-bit nonce
 * @param {sjcl.bitArray} [data]  (only in non-constructor mode) the data to
 *     authenticate.
 * @return {sjcl.misc.poly1305|sjcl.bitArray}
 *
 * @constructor (returns a sjcl.misc.poly1305 object)
 */
sjcl.misc.poly1305aes = function(r, key, nonce, data) {
  if (4 !== key.length || 4 !== nonce.length) {
    throw new sjcl.exception.invalid("invalid Poly1305-AES key/nonce size");
  }
  var s = new sjcl.cipher.aes(key).encrypt(nonce);
  return new sjcl.misc.poly1305(r.concat(s), data);
};
