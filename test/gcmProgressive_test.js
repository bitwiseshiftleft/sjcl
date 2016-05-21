new sjcl.test.TestCase("GCM progressive mode tests", function (cb) {
  if (!sjcl.cipher.aes || !sjcl.mode.gcm || !sjcl.mode.gcmProgressive) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.gcm, tv, iv, ct, aes, len, tlen, thiz = this, w = sjcl.bitArray, pt, iv, h = sjcl.codec.hex, ad, tlen;
  browserUtil.cpsIterate(function (j, cbb) {
    for (i = 100 * j; i < kat.length && i < 100 * (j + 1); i++) {
      tv = kat[i];
      len = 32 * tv.key.length;
      aes = new sjcl.cipher.aes(h.toBits(tv.key));

      // sort of a hack because of the format of the vectors file
      pt = h.toBits(tv.pt);
      ct = h.toBits(tv.ct + tv.tag);
      iv = h.toBits(tv.iv);
      ad = h.toBits(tv.adata);
      tlen = tv.tag.length * 4;

      // Encryption.
      var enc = sjcl.mode.gcmProgressive.createEncryptor(aes, iv, ad, tlen);
      var result = [];
      var sliceSizeRange = 3; // 1 to 3 bytes
      var slice = [0, Math.floor((Math.random() * sliceSizeRange) + 1)];
      while (slice[0] < pt.length) {
        result = result.concat(enc.process(pt.slice(slice[0], slice[1])));
        slice[0] = slice[1];
        slice[1] = slice[0] + Math.floor((Math.random() * sliceSizeRange) + 1);
      }
      result = result.concat(enc.finalize());
      thiz.require(w.equal(result, ct), "aes-" + len + "-gcm-encrypt #" + i);

      // Decryption.
      var convResult = sjcl.mode.gcmProgressive.encrypt(aes, pt, iv, ad, tlen);
      thiz.require(w.equal(convResult, ct), "aes-" + len + "-gcm-encrypt-conv #" + i);
      try {
        var dec = sjcl.mode.gcmProgressive.createDecryptor(aes, iv, ad, tlen);
        var dresult = [];
        var sliceSizeRange = 3; // 1 to 3 bytes
        var slice = [0, Math.floor((Math.random() * sliceSizeRange) + 1)];
        while (slice[0] < ct.length) {
          dresult = dresult.concat(dec.process(ct.slice(slice[0], slice[1])));
          slice[0] = slice[1];
          slice[1] = slice[0] + Math.floor((Math.random() * sliceSizeRange) + 1);
        }
        dresult = dresult.concat(dec.finalize());
        thiz.require(w.equal(dresult, pt), "aes-" + len + "-gcm-decrypt #" + i);

        var convDresult = sjcl.mode.gcmProgressive.decrypt(aes, ct, iv, ad, tlen);
        thiz.require(w.equal(convDresult, pt), "aes-" + len + "-gcm-decrypt-conv #" + i);
      } catch (e) {
        thiz.fail("aes-gcm-decrypt #" + i + " (exn " + e + ")");
      }

      // Decryption with invalid tag.
      try {
        ct[ct.length - 2] ^= 1; // make tag invalid, flip 1 bit
        sjcl.mode.gcmProgressive.decrypt(aes, ct, iv, ad, tlen);
        thiz.fail("aes-gcm-decrypt-invalid-tag #" + i + "");
      } catch (e) {
        if (e instanceof sjcl.exception.corrupt) {
          thiz.require(true, "aes-" + len + "-gcm-decrypt-conv #" + i);
        } else {
          thiz.fail("aes-gcm-decrypt-invalid-tag #" + i + " (exn " + e + ")");
        }
      }
    }
    cbb();
  }, 0, kat.length / 100, true, cb);
});
