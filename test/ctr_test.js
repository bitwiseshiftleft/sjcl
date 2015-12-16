new sjcl.test.TestCase("CTR mode tests", function (cb) {
  ((sjcl.beware &&
  sjcl.beware["CTR mode is dangerous because it doesn't protect message integrity."]) ||
  function(){})();

  if (!sjcl.cipher.aes || !sjcl.mode.ctr) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.ctr, tv, iv, ct, aes, len, thiz=this, w=sjcl.bitArray, pt, h=sjcl.codec.hex;
  browserUtil.cpsIterate(function (j, cbb) {
    for (i=100*j; i<kat.length && i<100*(j+1); i++) {
      tv = kat[i];
      len = 4 * tv.key.length;
      aes = new sjcl.cipher.aes(h.toBits(tv.key));
      iv = h.toBits(tv.iv);
      pt = h.toBits(tv.pt);
      ct = h.toBits(tv.ct);
      try {
        r = sjcl.mode.ctr.encrypt(aes, pt, iv);
        thiz.require(w.equal(r, ct), "aes-"+len+"-ctr-encrypt #"+i+" failed");
        try {
          r = sjcl.mode.ctr.decrypt(aes, ct, iv);
          thiz.require(w.equal(r, pt), "aes-"+len+"-ctr-decrypt #"+i+" failed");
        } catch (e) {
          thiz.fail("aes-ctr-decrypt #"+i+" exception: "+e);
        }
      } catch (e) {
        thiz.fail("aes-ctr-encrypt #"+i+" exception: "+e);
      }
    }
    cbb();
  }, 0, kat.length / 100, true, cb);
});
