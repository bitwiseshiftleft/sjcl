/** @fileOverview CTR mode implementation
 *
 * @author Torben Haase
 */

if (sjcl.beware === undefined) {
  sjcl.beware = {};
}
sjcl.beware["CTR mode is dangerous because it doesn't protect message integrity."
] = function() {
  /**
   * Dangerous: CTR mode.
   * @namespace
   * @author Torben Haase
   */
  sjcl.mode.ctr = {
    /** The name of the mode.
     * @constant
     */
    name: "ctr",

    /** Encrypt in CTR mode.
     * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.  It must be 128 bits.
     * @param {bitArray} [adata=[]] The authenticated data.  Must be empty.
     * @return The encrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits or if any adata is specified.
     */
    encrypt: function(prf, plaintext, iv, adata) {
      return sjcl.mode.ctr._calculate(prf, plaintext, iv, adata);
    },

    /** Decrypt in CTR mode.
     * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.  It must be 128 bits.
     * @param {bitArray} [adata=[]] The authenticated data.  It must be empty.
     * @return The decrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits or if any adata is specified.
     * @throws {sjcl.exception.corrupt} if if the message is corrupt.
     */
    decrypt: function(prf, ciphertext, iv, adata) {
      return sjcl.mode.ctr._calculate(prf, ciphertext, iv, adata);
    },

    _calculate: function(prf, data, iv, adata) {
      var l, bl, res, c, d, e, i;
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("ctr can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("ctr iv must be 128 bits");
      }
      if (!(l = data.length)) {
        return [];
      }
      c = iv.slice(0);
      d = data.slice(0);
      bl = sjcl.bitArray.bitLength(d);
      for (i=0; i<l; i+=4) {
        e = prf.encrypt(c);
        d[i] ^= e[0];
        d[i+1] ^= e[1];
        d[i+2] ^= e[2];
        d[i+3] ^= e[3];
        c[3]++;
      }
      return sjcl.bitArray.clamp(d, bl);
    }
  };
};
