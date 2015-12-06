/** @fileOverview CTR mode implementation
 *
 * @author Torben Haase
 */

if (sjcl.beware === undefined) {
  sjcl.beware = {};
}
sjcl.beware["CTR mode is dangerous because it doesn't protect message integrity."
] = function() {
  /** @namespace
   * Dangerous: CTR mode.
   *
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
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     */
    encrypt: function(prf, plaintext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("ctr can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("ctr iv must be 128 bits");
      }
      return sjcl.mode.ctr._calculate(prf, plaintext, iv);
    },

    /** Decrypt in CTR mode.
     * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.  It must be 128 bits.
     * @param {bitArray} [adata=[]] The authenticated data.  It must be empty.
     * @return The decrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     * @throws {sjcl.exception.corrupt} if if the message is corrupt.
     */
    decrypt: function(prf, ciphertext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("ctr can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("ctr iv must be 128 bits");
      }
      return sjcl.mode.ctr._calculate(prf, ciphertext, iv);
    },

    /** Calculate CTR.
     * Encrypt or decrypt data with CTR mode.
     * @param {Object} prf The pseudorandom function.
     * @param {bitArray} data The data to be encrypted or decrypted.
     * @param {bitArray} iv The initialization vector.
     * @return {Object} The en/decryption of the data values.
     * @private
     */
    _calculate: function(prf, data, iv) {
      var l, bl, ctr, enc, i;
      if (!(l = data.length))
		  return [];
      bl = sjcl.bitArray.bitLength(data);
      ctr = iv.slice(0);
      for (i=0; i<l; i+=4) {
        enc = prf.encrypt(ctr);
        data[i] ^= enc[0];
        data[i+1] ^= enc[1];
        data[i+2] ^= enc[2];
        data[i+3] ^= enc[3];
        ctr[3]++;
      }
      return sjcl.bitArray.clamp(data, bl);
    }
  };
};
