new sjcl.test.TestCase("MD5 from md5", function (cb) {
  if (!sjcl.hash.md5) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  var i, kat=sjcl.test.vector.md5, p=0, f=0;
  for (i=0; i<kat.length; i++) {
    var out = sjcl.hash.md5.hash(kat[i][0]);
    this.require(sjcl.codec.hex.fromBits(out) == kat[i][1], i);
  }
  cb && cb();
});
