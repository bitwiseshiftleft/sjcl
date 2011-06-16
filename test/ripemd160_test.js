new sjcl.test.TestCase("RIPEMD-160", function (cb) {
  if (!sjcl.hash.ripemd160) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat=sjcl.test.vector.ripemd160, p=0, f=0;
  for (i=0; i<kat.length; i++) {
    var out = sjcl.hash.ripemd160.hash(kat[i][0]);
    this.require(sjcl.codec.hex.fromBits(out) == kat[i][1], kat[i][0]);
  }

  cb && cb();
});
