new sjcl.test.TestCase("HKDF official test vectors", function (cb) {
  if (!sjcl.misc.hkdf || !sjcl.misc.hmac) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.hkdf, tv, h = sjcl.codec.hex, out, ikm, salt, info, hash;
  for (i = 0; i < kat.length; i++) {
    tv = kat[i];

	hash = sjcl.hash[tv.hash];
    if (!hash) {
      this.unimplemented();
      cb && cb();
      return;
    }

    ikm = h.toBits(tv.ikm);
    salt = tv.salt && h.toBits(tv.salt);
    info = h.toBits(tv.info);

    out = h.fromBits(sjcl.misc.hkdf(ikm, tv.keyLength, salt, info, hash));
    this.require(out == tv.key, "hkdf #" + i);
  }
  cb && cb();
});
