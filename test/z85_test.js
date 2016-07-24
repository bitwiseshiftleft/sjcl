new sjcl.test.TestCase("Z85-encoding from rfc.zeromq.org/spec:32/Z85/", function (cb) {
  if (!sjcl.codec.z85) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat=sjcl.test.vector.z85, p=0, f=0;
  for (i=0; i<kat.length; i++) {
    // Test encoding
    this.require(sjcl.codec.z85.fromBits(sjcl.codec.hex.toBits(kat[i][0])) ==
                 kat[i][1], i);
    // Test decoding
    this.require(sjcl.codec.hex.fromBits(sjcl.codec.z85.toBits(kat[i][1])) ==
                 kat[i][0], i);
  }

  cb && cb();
});
