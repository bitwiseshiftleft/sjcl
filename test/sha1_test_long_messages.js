new sjcl.test.TestCase("SHA-1 long messages", function (cb) {
  if (!sjcl.hash.sha1) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  var i, kat=sjcl.test.vector.sha1long, p=0, f=0;
  for (i=0; i<kat.length; i++) {
    var out = sjcl.hash.sha1.hash(kat[i][0]);
    this.require(sjcl.codec.hex.fromBits(out) == kat[i][1], i);
  }
  cb && cb();
});
