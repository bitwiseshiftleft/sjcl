/** @fileOverview Really fast & small implementation of CCM using JS' array buffers
 *
 * @author Marco Munizaga
 */

/** @namespace CTR mode with CBC MAC. */

sjcl.arrayBuffer = sjcl.arrayBuffer || {};

//patch arraybuffers if they don't exist
if (typeof(ArrayBuffer) === 'undefined') {
  (function(globals){
      "use strict";
      globals.ArrayBuffer = function(){};
      globals.DataView = function(){};
  }(this));
}


sjcl.arrayBuffer.ccm = {
  mode: "ccm",

  defaults: {
    tlen:128 //this is M in the NIST paper
  },

  /** Encrypt in CCM mode. Meant to return the same exact thing as the bitArray ccm to work as a drop in replacement
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  compat_encrypt: function(prf, plaintext, iv, adata, tlen){
    var plaintext_buffer = sjcl.codec.arrayBuffer.fromBits(plaintext, true, 16),
        ol = sjcl.bitArray.bitLength(plaintext)/8,
        encrypted_obj,
        ct,
        tag;

    tlen = tlen || 64;
    adata = adata || [];

    encrypted_obj = sjcl.arrayBuffer.ccm.encrypt(prf, plaintext_buffer, iv, adata, tlen, ol);
    ct = sjcl.codec.arrayBuffer.toBits(encrypted_obj.ciphertext_buffer);

    ct = sjcl.bitArray.clamp(ct, ol*8);


    return sjcl.bitArray.concat(ct, encrypted_obj.tag);
  },

  /** Decrypt in CCM mode. Meant to imitate the bitArray ccm 
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [[]] adata The authenticated data.
   * @param {Number} [64] tlen the desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  compat_decrypt: function(prf, ciphertext, iv, adata, tlen){
    tlen = tlen || 64;
    adata = adata || [];
    var L, i, 
        w=sjcl.bitArray,
        ol = w.bitLength(ciphertext), 
        out = w.clamp(ciphertext, ol - tlen),
        tag = w.bitSlice(ciphertext, ol - tlen), tag2,
        ciphertext_buffer = sjcl.codec.arrayBuffer.fromBits(out, true, 16);

    var plaintext_buffer = sjcl.arrayBuffer.ccm.decrypt(prf, ciphertext_buffer, iv, tag, adata, tlen, (ol-tlen)/8);
    return sjcl.bitArray.clamp(sjcl.codec.arrayBuffer.toBits(plaintext_buffer), ol-tlen);

  },

  /** Really fast ccm encryption, uses arraybufer and mutates the plaintext buffer
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes. 
   * @param {ArrayBuffer} plaintext_buffer The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {ArrayBuffer} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] the desired tag length, in bits.
   * @return {ArrayBuffer} The encrypted data, in the same array buffer as the given plaintext, but given back anyways
   */
  encrypt: function(prf, plaintext_buffer, iv, adata, tlen, ol){
    var auth_blocks, mac, L, w = sjcl.bitArray,
      ivl = w.bitLength(iv) / 8;

    //set up defaults
    adata = adata || [];
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen;
    ol = ol || plaintext_buffer.byteLength;
    tlen = Math.ceil(tlen/8);
    
    for (L=2; L<4 && ol >>> 8*L; L++) {}
    if (L < 15 - ivl) { L = 15-ivl; }
    iv = w.clamp(iv,8*(15-L));

    //prf should use a 256 bit key to make precomputation attacks infeasible

    mac = sjcl.arrayBuffer.ccm._computeTag(prf, plaintext_buffer, iv, adata, tlen, ol, L);

    //encrypt the plaintext and the mac 
    //returns the mac since the plaintext will be left encrypted inside the buffer
    mac = sjcl.arrayBuffer.ccm._ctrMode(prf, plaintext_buffer, iv, mac, tlen, L);


    //the plaintext_buffer has been modified so it is now the ciphertext_buffer
    return {'ciphertext_buffer':plaintext_buffer, 'tag':mac};
  },

  /** Really fast ccm decryption, uses arraybufer and mutates the given buffer
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes. 
   * @param {ArrayBuffer} ciphertext_buffer The Ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} The authentication tag for the ciphertext
   * @param {ArrayBuffer} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] the desired tag length, in bits.
   * @return {ArrayBuffer} The decrypted data, in the same array buffer as the given buffer, but given back anyways
   */
  decrypt: function(prf, ciphertext_buffer, iv, tag, adata, tlen, ol){
    var mac, mac2, i, L, w = sjcl.bitArray, 
      ivl = w.bitLength(iv) / 8;

    //set up defaults
    adata = adata || [];
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen;
    ol = ol || ciphertext_buffer.byteLength;
    tlen = Math.ceil(tlen/8) ;

    for (L=2; L<4 && ol >>> 8*L; L++) {}
    if (L < 15 - ivl) { L = 15-ivl; }
    iv = w.clamp(iv,8*(15-L));
    
    //prf should use a 256 bit key to make precomputation attacks infeasible

    //decrypt the buffer
    mac = sjcl.arrayBuffer.ccm._ctrMode(prf, ciphertext_buffer, iv, tag, tlen, L);

    mac2 = sjcl.arrayBuffer.ccm._computeTag(prf, ciphertext_buffer, iv, adata, tlen, ol, L);

    //check the tag
    if (!sjcl.bitArray.equal(mac, mac2)){
      throw new sjcl.exception.corrupt("ccm: tag doesn't match");
    }

    return ciphertext_buffer;

  },

  /* Compute the (unencrypted) authentication tag, according to the CCM specification
   * @param {Object} prf The pseudorandom function.
   * @param {ArrayBuffer} data_buffer The plaintext data in an arraybuffer.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} adata The authenticated data.
   * @param {Number} tlen the desired tag length, in bits.
   * @return {bitArray} The tag, but not yet encrypted.
   * @private
   */
  _computeTag: function(prf, data_buffer, iv, adata, tlen, ol, L){
    var i, plaintext, mac, data, data_blocks_size, data_blocks,
      w = sjcl.bitArray, tmp, macData;

    mac = sjcl.mode.ccm._macAdditionalData(prf, adata, iv, tlen, ol, L);

    if (data_buffer.byteLength !== 0) {
      data = new DataView(data_buffer);
      //set padding bytes to 0
      for (i=ol; i< data_buffer.byteLength; i++){
        data.setUint8(i,0);
      }

      //now to mac the plaintext blocks
      for (i=0; i < data.byteLength; i+=16){
        mac[0] ^= data.getUint32(i);
        mac[1] ^= data.getUint32(i+4);
        mac[2] ^= data.getUint32(i+8);
        mac[3] ^= data.getUint32(i+12);

        mac = prf.encrypt(mac);
      }
    }

    return sjcl.bitArray.clamp(mac,tlen*8);
  },

  /** CCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
   * Mutates given array buffer
   * @param {Object} prf The PRF.
   * @param {ArrayBuffer} data_buffer The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} tag The authentication tag.
   * @param {Number} tlen The length of th etag, in bits.
   * @return {Object} An object with data and tag, the en/decryption of data and tag values.
   * @private
   */
  _ctrMode: function(prf, data_buffer, iv, mac, tlen, L){
    var data, ctr, word0, word1, word2, word3, keyblock, i, w = sjcl.bitArray, xor = w._xor4, n = data_buffer.byteLength/50, p = n;

    ctr = new DataView(new ArrayBuffer(16)); //create the first block for the counter

    //prf should use a 256 bit key to make precomputation attacks infeasible

    // start the ctr
    ctr = w.concat([w.partial(8,L-1)],iv).concat([0,0,0]).slice(0,4);

    // en/decrypt the tag
    mac = w.bitSlice(xor(mac,prf.encrypt(ctr)), 0, tlen*8);

    ctr[3]++;
    if (ctr[3]===0) ctr[2]++; //increment higher bytes if the lowest 4 bytes are 0

    if (data_buffer.byteLength !== 0) {
      data = new DataView(data_buffer);
      //now lets encrypt the message
      for (i=0; i<data.byteLength;i+=16){
        if (i > n) {
          sjcl.mode.ccm._callProgressListener(i/data_buffer.byteLength);
          n += p;
        }
        keyblock = prf.encrypt(ctr);

        word0 = data.getUint32(i);
        word1 = data.getUint32(i+4);
        word2 = data.getUint32(i+8);
        word3 = data.getUint32(i+12);

        data.setUint32(i,word0 ^ keyblock[0]);
        data.setUint32(i+4, word1 ^ keyblock[1]);
        data.setUint32(i+8, word2 ^ keyblock[2]);
        data.setUint32(i+12, word3 ^ keyblock[3]);

        ctr[3]++;
        if (ctr[3]===0) ctr[2]++; //increment higher bytes if the lowest 4 bytes are 0
      }
    }

    //return the mac, the ciphered data is available through the same data_buffer that was given
    return mac;
  }

};
