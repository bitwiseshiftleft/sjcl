new sjcl.test.TestCase("CCM arrayBuffer tests", function (cb) {
  if (!sjcl.cipher.aes || !sjcl.mode.ccm || !sjcl.arrayBuffer) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var sessionKey = sjcl.codec.hex.toBits("b058d2931f46abb2a6062abcddf61d88");
  var params = {};
  params.mode = 'ccm';
  var p = 'aaa';
  var ciphertext = sjcl.encrypt(sessionKey, p, params);
  var p1 = sjcl.decrypt(sessionKey, ciphertext, params);
  this.require(p === p1);

  // test with buffer input:
  //var buffer = new Uint8Array(131).buffer;
  var buffer = new ArrayBuffer(131);
  ciphertext = sjcl.encrypt(sessionKey, buffer, params);
  params.raw = 1; // to prevent sjcl converting to utf8String
  ciphertext = sjcl.decrypt(sessionKey, ciphertext, params);

  console.log(sjcl.codec); // debugging Travis failure
  console.log(sjcl.codec.arrayBuffer); // debugging Travis failure
  console.log(Object.getOwnPropertyNames(sjcl.codec.arrayBuffer)); // debugging Travis failure

  var buffer1 = sjcl.codec.arrayBuffer.toBuffer(ciphertext);
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

      thiz.require(w.equal(sjcl.arrayBuffer.ccm.compat_encrypt(aes, pt, iv, ad, tlen), ct), "aes-"+len+"-ccm-encrypt #"+i);
      try {
        thiz.require(w.equal(sjcl.arrayBuffer.ccm.compat_decrypt(aes, ct, iv, ad, tlen), pt), "aes-"+len+"-ccm-decrypt #"+i);
      } catch (e) {
        thiz.fail("aes-ccm-decrypt #"+i+" (exn "+e+")");
      }
    }
    cbb();
  }, 0, kat.length / 100, true, cb);
});
