/** @fileOverview SHA3
 *
 * @author Stefan Bühler
 */

/** Context for a Sponge operations.
 * @constructor
 * @param {function} f       The transformation function to run on a
 *     {@link sjcl.bitArrayLE} state with f.width bits (rounded up to next
 *     multiple of 32).
 * @param {function} pad     The padding function that pads a
 *     {@link sjcl.bitArrayLE} buffer to a number of bits on finalize.
 * @param {Number} rate      The bit rate; number of bits to read/write per
 *     round of transformation
 * @param {Number} [outlen]  The number of bits to output. Can be specified in
 *     call to {@link #finalize} too.
 */
sjcl.hash.sponge = function(f, pad, rate, outlen) {
  this._f = f;
  this._pad = pad;
  this._r = rate;
  this._l = outlen;
  this._buffer = false;

  var s = [], i;
  for (i = 0; i < f.width; i += 32) {
    s.push(0);
  }
  this._state = s;
};

/** "10*1" padding
 * @param {sjcl.bitArrayLE} data  The data to pad
 * @param {Number} r              The length to pad to a multiple of.
 * @param {sjcl.bitArrayLE}       The padded message
 */
sjcl.hash.sponge.pad_101 = function(msg, r) {
  var baLE = sjcl.bitArrayLE, len = baLE.bitLength(msg), dstLen, bit;
  msg = msg.slice(0);
  /* round len + 2 up to multiple of r */
  dstLen = len + 1 + r;
  dstLen -= dstLen % r;
  /* append "1" */
  bit = len % 32;
  if (bit) {
    msg[msg.length-1] |= 1 << bit;
  } else {
    msg.push(1);
  }
  len += (32 - bit);
  for (; len < dstLen; len += 32) {
    msg.push(0);
  }
  msg[msg.length-1] |= 1 << (r-1);
  baLE.clampM(msg, dstLen);
  return msg;
};

/** Domain + "10*1" padding; appends a domain to the message before
 * {@link sjcl.hash.sponge.pad_101} padding.
 * @param {sjcl.bitArrayLE} domain  The domain to pad with
 * @return {function}               A padding function
 */
sjcl.hash.sponge.pad_domain_101 = function(domain) {
  var baLE = sjcl.bitArrayLE, pad_101 = sjcl.hash.sponge.pad_101;
  return function(msg, r) {
    return pad_101(baLE.concat(msg, domain), r);
  };
};

/** Absorb data in rounds, store remainder in this._buffer
 * @this {sjcl.hash.sponge}
 * @param {sjcl.bitArrayLE} data  The data to hash in little endian words.
 */
sjcl.hash.sponge.prototype._absorb = function _absorb(data) {
  var baLE = sjcl.bitArrayLE, i, j, p, l, r = this._r, s = this._state, f = this._f;
  for (i = 0, l = baLE.bitLength(data); i + r <= l; i += r) {
    p = baLE.bitSlice(data, i, i + r);
    for (j = 0; j < p.length; ++j) {
      s[j] ^= p[j];
    }
    f(s);
  }
  if (i < l) {
    this._buffer = baLE.bitSlice(data, i, l);
  } else {
    this._buffer = false;
  }
};

/** Input several words to hash.
 * @this {sjcl.hash.sponge}
 * @param {sjcl.bitArrayLE} data  The data to hash in little endian words.
 * @return {sjcl.hash.sponge} this
 */
sjcl.hash.sponge.prototype.updateLE = function updateLE(data) {
  if (this._buffer) {
    data = sjcl.bitArrayLE.concat(this._buffer, data);
    this._buffer = false;
  }
  this._absorb(data);
  return this;
};

/** Input several words to hash.
 * @this {sjcl.hash.sponge}
 * @param {sjcl.bitArray|String} data the data to hash.
 * @return {sjcl.hash.sponge} this
 */
sjcl.hash.sponge.prototype.update = function update(data) {
  if (typeof data === "string") {
    data = sjcl.codec.utf8String.toBits(data);
  }
  data = sjcl.bitArrayLE.fromBitArrayByteSwap(data);
  return this.updateLE(data);
};

/** Complete hashing and output the hash value.
 * @this {sjcl.hash.sponge}
 * @param {Number} [outlen]   bit-length of output to generate
 * @return {sjcl.bitArrayLE}  The hash value.
 */
sjcl.hash.sponge.prototype.finalizeLE = function finalizeLE(outlen) {
  var baLE = sjcl.bitArrayLE, j, r = this._r, s, f = this._f, z,
    data = this._pad(this._buffer || [], r);
  this._buffer = false;
  outlen = outlen || this._l;

  this._absorb(data);
  if (this._buffer) {
    throw new sjcl.exception.invalid("sponge padding misaligned");
  }

  s = this._state;
  this._state = null; // undefined after finalize
  z = baLE.clamp(s, r);
  for (j = r; j < outlen; j += r) {
    f(s);
    z = baLE.concat(z, baLE.clamp(s, r));
  }
  return baLE.clamp(z, outlen);
};

/** Complete hashing and output the hash value (converted from
 * {@link sjcl.hash.sponge#finalizeLE} with
 * {@link sjcl.bitArrayLE.toBitArrayByteSwap})
 * @this {sjcl.hash.sponge}
 * @param {Number} [outlen]  bit-length of output to generate (should be
 *     a multiple of 8)
 * @return {sjcl.bitArray}   The hash value
 */
sjcl.hash.sponge.prototype.finalize = function finalize(outlen) {
  return sjcl.bitArrayLE.toBitArrayByteSwap(this.finalizeLE(outlen));
};

/** Create a class for a Sponge operations; returns an function object with
 * the following properties: "rate": the rate parameter and "hash": a shortcut
 * function (data, outlen) { return class().update(data).finalize(outlen); };
 * calling the returned function returns a {@link sjcl.hash.sponge} object.
 *
 * @param {function} f       The transformation function to run on a
 *     {@link sjcl.bitArrayLE} state with f.width bits (rounded up to next
 *     multiple of 32).
 * @param {function} pad     The padding function that pads a
 *     {@link sjcl.bitArrayLE} buffer to a number of bits on finalize.
 * @param {Number} rate      The bit rate; number of bits to read/write per
 *     round of transformation
 * @param {Number} [outlen]  The number of bits to output. Can be specified in
 *     call to {@link #finalize} too.
 */
sjcl.hash.sponge.makeClass = function(f, pad, rate, outlen) {
  function constr() {
    return new sjcl.hash.sponge(f, pad, rate, outlen);
  }
  constr.rate = rate;
  constr.hash = function(data, outlen) {
    return constr().update(data).finalize(outlen);
  };
  return constr;
};
