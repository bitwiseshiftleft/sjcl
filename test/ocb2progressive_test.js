new sjcl.test.TestCase("OCB 2.0 progressive mode tests", function (cb) {
  if (!sjcl.cipher.aes || !sjcl.mode.ocb2 || !sjcl.mode.ocb2progressive) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.ocb2, tv, iv, ct, aes, len, tlen, thiz=this, w=sjcl.bitArray, pt, iv, h = sjcl.codec.hex, ad, tlen;
  browserUtil.cpsIterate(function (j, cbb) {
    for (i=100*j; i<kat.length && i<100*(j+1); i++) {
      tv = kat[i];
      len = 32 * tv.key.length;
      aes = new sjcl.cipher.aes(h.toBits(tv.key));

      // sort of a hack because of the format of the vectors file
      pt = h.toBits(tv.pt);
      ct = h.toBits(tv.ct+tv.tag);
      iv = h.toBits(tv.iv);
      ad = h.toBits(tv.adata);
      tlen = tv.tag.length * 4;

      var enc = sjcl.mode.ocb2progressive.createEncryptor(aes, iv, ad, tlen);
      var result = [];
      var sliceSizeRange = 3; // 1 to 3 bytes
      var slice = [0, Math.floor((Math.random() * sliceSizeRange) + 1)];
      while (slice[0] < pt.length) {
        result = result.concat(enc.process(pt.slice(slice[0], slice[1])));
        slice[0] = slice[1];
        slice[1] = slice[0] + Math.floor((Math.random() * sliceSizeRange) + 1);
      }
      result = result.concat(enc.finalize());

      thiz.require(w.equal(result, ct), "aes-"+len+"-ocb2-encrypt #"+i);
      try {
        var dec = sjcl.mode.ocb2progressive.createDecryptor(aes, iv, ad, tlen);
        var dresult = [];
        var sliceSizeRange = 3; // 1 to 3 bytes
        var slice = [0, Math.floor((Math.random() * sliceSizeRange) + 1)];
        while (slice[0] < ct.length) {
          dresult = dresult.concat(dec.process(ct.slice(slice[0], slice[1])));
          slice[0] = slice[1];
          slice[1] = slice[0] + Math.floor((Math.random() * sliceSizeRange) + 1);
        }
        dresult = dresult.concat(dec.finalize());
        thiz.require(w.equal(dresult, pt), "aes-"+len+"-ocb2-decrypt #"+i);
      } catch (e) {
        thiz.fail("aes-ocb-decrypt #"+i+" (exn " + e + ")");
      }
    }
    cbb();
  }, 0, kat.length / 100, true, cb);
});
