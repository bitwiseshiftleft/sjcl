/** @fileOverview Really fast & small implementation of CCM using JS' array buffers
 *
 * @author Marco Munizaga
 */

/** @namespace CTR mode with CBC MAC. */

sjcl.arrayBuffer = sjcl.arrayBuffer || {}

//patch arraybuffers if they don't exist
if (typeof(ArrayBuffer) === 'undefined') {
  //I honestly didn't want to use an eval but here is the problem
  //
  //If I do var ArrayBuffer = function(){}
  //Then ArrayBuffer will be set to undefined because some js implementations set all vars to undefined at the beginning
  //
  //If I do ArrayBuffer = function(){}
  //That breaks in strict mode because I'm declaring a variable  w/o var 
  eval("ArrayBuffer = function(){}; DataView = function(){}")
}

sjcl.arrayBuffer.ccm = {
  mode: "ccm",

  defaults: {
    adata_buffer: new ArrayBuffer(),
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
        tlen = tlen || 64,
        adata = adata || [],
        l_m = sjcl.bitArray.bitLength(plaintext)/8,
        adata_buffer = sjcl.codec.arrayBuffer.fromBits(adata, false),
        encrypted_obj,
        ct,
        tag

    encrypted_obj = sjcl.arrayBuffer.ccm.encrypt(prf, plaintext_buffer, iv, adata_buffer, tlen, l_m)
    ct = sjcl.codec.arrayBuffer.toBits(encrypted_obj["ciphertext_buffer"])

    ct = sjcl.bitArray.clamp(ct, l_m*8)


    return sjcl.bitArray.concat(ct, encrypted_obj['tag'])
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
        ivl = w.bitLength(iv) / 8,
        ol = w.bitLength(ciphertext), 
        out = w.clamp(ciphertext, ol - tlen),
        tag = w.bitSlice(ciphertext, ol - tlen), tag2,
        adata_buffer = sjcl.codec.arrayBuffer.fromBits(adata, false),
        ciphertext_buffer = sjcl.codec.arrayBuffer.fromBits(out, true, 16)

    var plaintext_buffer = sjcl.arrayBuffer.ccm.decrypt(prf, ciphertext_buffer, iv, tag, adata_buffer, tlen, (ol-tlen)/8)
    return sjcl.bitArray.clamp(sjcl.codec.arrayBuffer.toBits(plaintext_buffer), ol-tlen)

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
  encrypt: function(prf, plaintext_buffer, iv, adata_buffer, tlen, l_m){
    var auth_blocks, mac, plaintext, ctr, keyblock, word0, word1, word2, word3, i, l_m

    //set up defaults
    adata_buffer = adata_buffer || sjcl.arrayBuffer.ccm.defaults.adata_buffer
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen
    l_m = l_m || plaintext_buffer.byteLength
    tlen = Math.ceil(tlen/8)
    
    //prf should use a 256 bit key to make precomputation attacks infeasible
    //the iv should be 8bytes
    //assume the iv is set to an array of 32 ints, so we need a length of 2 to get 8 bytes
    if (iv.length !== 2) throw new sjcl.exception.invalid("Invalid IV length, it should be 8 bytes")

    mac = sjcl.arrayBuffer.ccm.compute_tag(prf, plaintext_buffer, iv, adata_buffer, tlen, l_m)

    //encrypt the plaintext and the mac 
    //returns the mac since the plaintext will be left encrypted inside the buffer
    mac = sjcl.arrayBuffer.ccm.ctrCipher(prf, plaintext_buffer, iv, mac, tlen)


    //the plaintext_buffer has been modified so it is now the ciphertext_buffer
    return {'ciphertext_buffer':plaintext_buffer, 'tag':mac}
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
  decrypt: function(prf, ciphertext_buffer, iv, tag, adata_buffer, tlen, l_m){
    var mac, mac2, i

    //set up defaults
    adata_buffer = adata_buffer || sjcl.arrayBuffer.ccm.defaults.adata_buffer
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen
    l_m = l_m || ciphertext_buffer.byteLength
    tlen = Math.ceil(tlen/8) 
    
    //prf should use a 256 bit key to make precomputation attacks infeasible
    //the iv should be 8bytes
    //assume the iv is set to an array of 32 ints, so we need a length of 2 to get 8 bytes
    if (iv.length !== 2) throw new sjcl.exception.invalid("Invalid IV length, it should be 8 bytes")

    //decrypt the buffer
    mac = sjcl.arrayBuffer.ccm.ctrCipher(prf, ciphertext_buffer, iv, tag, tlen)

    mac2 = sjcl.arrayBuffer.ccm.compute_tag(prf, ciphertext_buffer, iv, adata_buffer, tlen, l_m)

    //check the tag
    if (!sjcl.bitArray.equal(mac, mac2)){
      throw new sjcl.exception.corrupt("ccm: tag doesn't match");
    }

    return ciphertext_buffer

  },

  /* Compute the (unencrypted) authentication tag, according to the CCM specification
   * @param {Object} prf The pseudorandom function.
   * @param {ArrayBuffer} data_buffer The plaintext data in an arraybuffer.
   * @param {bitArray} iv The initialization value.
   * @param {ArrayBuffer} adata_buffer The authenticated data in an arraybuffer.
   * @param {Number} tlen the desired tag length, in bits.
   * @return {bitArray} The tag, but not yet encrypted.
   * @private
   */
  compute_tag: function(prf, data_buffer, iv, adata_buffer, tlen, l_m){
    var i, l_a, l_a_encoded_length, l_a_encoded_prefix, data_blocks, data_blocks_size, flags, offset, adata, plaintext, mac, data

    //Let calculate l(a), the length of the authenticated data
    l_a = adata_buffer.byteLength

    //now we need to calculate how many bytes we will need to encode l(a)
    if (l_a === 0){
      l_a_encoded_length = 0
      l_a_encoded_prefix = []
    }
    else if (l_a < 0xFF00){ //0xff00 === 2^16-2^8
      l_a_encoded_length = 2
      l_a_encoded_prefix = []
    }else if (l_a < 0x100000000){
      l_a_encoded_length = 6
      l_a_encoded_prefix = [0xff, 0xfe]
    }else{
      //the length is greater than 4GB... no way, not supported 
      //we really shouldn't end up here
      throw("your authenticated data is too big: "+l_a+" "+adata_buffer)
      //l_a_encoded_length = 10
      //l_a_encoded_prefix = [0xff, 0xff]
    }

    //calculate the amount of blocks we will need, then add one for the first block 
    data_blocks_size = Math.ceil((l_a_encoded_length+l_a+16)/16) 

    data_blocks = new DataView(new ArrayBuffer(data_blocks_size*16))

    //set the first block
    //the format is flag (1 byte) (IV 8 bytes) (l(m) 7 bytes)
    //flag looks like [<bit>:content] [7:reserved 6:Adata 5-3:M(aka tlen), 2-0 L(hardcoded to 6] 
    flags = l_a_encoded_length === 0 ? 0x06 : 0x46 //depending on the length of adata we vary the second MSB
    //flip the tlen bits
    flags |= ((tlen-2)/2) << 3
    data_blocks.setUint8(0, flags)
    
    //Copy the IV over to the first block
    data_blocks.setUint32(1,iv[0])
    data_blocks.setUint32(5,iv[1])

    //copy the message length
    data_blocks.setUint32(12, l_m)
    //The higher three bytes are going to be 0 since we never expect to encrypt > 4GB file with this

    //now we add the bytes encoding the length of the adata
    //start at 16 because that's the start of the next block
    offset = 16
    //if there was a prefix we need to but before the length lets do that
    if ( l_a_encoded_prefix.length > 0){
      data_blocks.setUint8(offset++,l_a_encoded_prefix[0])
      data_blocks.setUint8(offset++,l_a_encoded_prefix[1])
    }

    //place the length
    if (l_a_encoded_length === 0){
    }else if(l_a_encoded_length === 2){
      data_blocks.setUint16(offset,l_a)
      offset += 2
    }else if(l_a_encoded_length === 6){
      //setting the bottom 4bytes, the top two(prefix, were already set
      data_blocks.setUint32(offset,l_a)
      offset += 4
    }else{
      throw("Error in encoding length into Authorized blocks")
    }
    
    //now copy the adata over to the blocks
    //This will implicitly add 0 padding 
    adata = new DataView(adata_buffer)
    for (i = 0; i < adata.byteLength; i++){
      data_blocks.setUint8(offset, adata.getUint8(i))
      offset++;
    }


    //now lets do the cbc-mac

    mac = [0,0,0,0]

    for (i=0; i < data_blocks.byteLength; i+=16){
      mac[0] ^= data_blocks.getUint32(i)
      mac[1] ^= data_blocks.getUint32(i+4)
      mac[2] ^= data_blocks.getUint32(i+8)
      mac[3] ^= data_blocks.getUint32(i+12)

      mac = prf.encrypt(mac)
    }

    data = new DataView(data_buffer)
    //set padding bytes to 0
    for (i=l_m; i< data_buffer.byteLength; i++){
      data.setUint8(i,0)
    }

    //now to mac the plaintext blocks
    for (i=0; i < data.byteLength; i+=16){
      mac[0] ^= data.getUint32(i)
      mac[1] ^= data.getUint32(i+4)
      mac[2] ^= data.getUint32(i+8)
      mac[3] ^= data.getUint32(i+12)

      mac = prf.encrypt(mac)
    }

    return sjcl.bitArray.clamp(mac,tlen*8)
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
  ctrCipher: function(prf, data_buffer, iv, mac, tlen){
    var data, ctr, word0, word1, word2, word3, keyblock, i

    data = new DataView(data_buffer)
    ctr = new DataView(new ArrayBuffer(16)) //create the first block for the counter

    //prf should use a 256 bit key to make precomputation attacks infeasible
    //the iv should be 8bytes
    //assume the iv is set to an array of 32 ints, so we need a length of 2 to get two bytes
    
    ctr.setUint8(0,0x06) //set the flags
    ctr.setUint32(1,iv[0]) //set the iv
    ctr.setUint32(5,iv[1])
    //the counter is already set to 0
    
    ctr = [ctr.getUint32(0),ctr.getUint32(4),ctr.getUint32(8),ctr.getUint32(12)]
    keyblock = prf.encrypt(ctr) //this gives us the first block in the keystream that we are going to use to encrypt the mac

    mac[0] ^= keyblock[0]
    mac[1] ^= keyblock[1]
    mac[2] ^= keyblock[2]
    mac[3] ^= keyblock[3]

    ctr[3]++
    if (ctr[3]===0) ctr[2]++ //increment higher bytes if the lowest 4 bytes are 0

    //now lets encrypt the message
    for (i=0; i<data.byteLength;i+=16){
      keyblock = prf.encrypt(ctr)

      word0 = data.getUint32(i)
      word1 = data.getUint32(i+4)
      word2 = data.getUint32(i+8)
      word3 = data.getUint32(i+12)

      data.setUint32(i,word0 ^ keyblock[0])
      data.setUint32(i+4, word1 ^ keyblock[1])
      data.setUint32(i+8, word2 ^ keyblock[2])
      data.setUint32(i+12, word3 ^ keyblock[3])

      ctr[3]++
      if (ctr[3]===0) ctr[2]++ //increment higher bytes if the lowest 4 bytes are 0
    }

    //return the mac, the ciphered data is available through the same data_buffer that was given
    return sjcl.bitArray.clamp(mac,tlen*8)
  }

}
