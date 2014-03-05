new sjcl.test.TestCase("Base58 tests", function (cb) {
  if (!sjcl.codec.base58) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.base58, tv, h=sjcl.codec.hex, bits, hex;
  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    bits = sjcl.codec.base58.toBits(tv.base58);
    this.require(sjcl.bitArray.equal(bits, h.toBits(tv.hex)), "Test failed for vector " + tv.base58 + " " + tv.hex);
  }

  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    base58 = sjcl.codec.base58.fromBits(h.toBits(tv.hex));
    this.require(base58 === tv.base58, "Test failed for vector " + tv.base58 + " " + tv.hex);
  }
  cb && cb();
});
