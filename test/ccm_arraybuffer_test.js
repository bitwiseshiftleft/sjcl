new sjcl.test.TestCase("CCM arrayBuffer tests", function (cb) {
  if (!sjcl.cipher.aes || !sjcl.mode.ccm || !sjcl.arrayBuffer) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var sessionKey = sjcl.codec.hex.toBits("b058d2931f46abb2a6062abcddf61d88");
  var params = {};
  params.mode = 'ccm';
  var plaintext = 'aaa';
  var plaintextBits = sjcl.codec.utf8String.toBits(plaintext);
  var plaintextArrayBuffer = sjcl.codec.arrayBuffer.fromBits(plaintextBits);
  var ciphertext = sjcl.encrypt(sessionKey, plaintextArrayBuffer, params);
  var decryptedInArrayBuffer = sjcl.decrypt(sessionKey, ciphertext, params);
  var decryptedInBits = sjcl.codec.arrayBuffer.toBits(decryptedInArrayBuffer);
  var decryptedInPlaintext = sjcl.codec.utf8String.fromBits(decryptedInBits);
  this.require(plaintext === decryptedInPlaintext);
  
  var buffer = new ArrayBuffer(131);
  ciphertext = sjcl.encrypt(sessionKey, buffer, params);
  buffer1 = sjcl.decrypt(sessionKey, ciphertext, params);
  var a = new Uint8Array(buffer);
  var a1 = new Uint8Array(buffer1);
  var a_values = "";
  var a1_values = "";
  this.require(a.byteLength == a1.byteLength);
  for(var i=0; i<a.byteLength; i++) {
    a_values += a[0];
    a1_values += a1[0];
  }
  this.require(a_values === a1_values);

  var i, kat = sjcl.test.vector.ccm, tv, iv, ct, aes, len, tlen, thiz=this, w=sjcl.bitArray, pt, h=sjcl.codec.hex, ad;
  browserUtil.cpsIterate(function (j, cbb) {
    for (i=100*j; i<kat.length && i<100*(j+1); i++) {
      tv = kat[i];
      len = 32 * tv.key.length;
      aes = new sjcl.cipher.aes(h.toBits(tv.key));

      // Convert from strings
      iv = h.toBits(tv.iv);
      ad = h.toBits(tv.adata);
      pt = h.toBits(tv.pt);
      ct = h.toBits(tv.ct + tv.tag);
      tlen = tv.tag.length * 4;

      arrayBuffer = sjcl.codec.arrayBuffer.fromBits(pt);
      encrypted = sjcl.arrayBuffer.ccm.encrypt(aes, arrayBuffer, iv, ad, tlen);
      ciphertextInArrayBuffer = encrypted["ciphertextBuffer"];
      ciphertextTag = encrypted["ciphertextTag"];
      ciphertextInArrayBits = sjcl.codec.arrayBuffer.toBits(ciphertextInArrayBuffer);
      decryptedInArrayBuffer = sjcl.arrayBuffer.ccm.decrypt(aes, ciphertextInArrayBuffer, iv, ciphertextTag, ad, tlen);
      decryptedInBits = sjcl.codec.arrayBuffer.toBits(decryptedInArrayBuffer);

      thiz.require(w.equal(ct, sjcl.bitArray.concat(ciphertextInArrayBits, ciphertextTag)), "aes-"+len+"-ccm-encrypt #"+i);
      thiz.require(w.equal(pt, decryptedInBits), "aes-"+len+"-ccm-decrypt #"+i);
    }
    cbb();
  }, 0, kat.length / 100, true, cb);
});
