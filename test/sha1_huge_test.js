new sjcl.test.TestCase("SHA1 huge zero vector test", function (cb) {
  if (!sjcl.hash.sha1) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var base = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; // 128B
  var w = sjcl.bitArray, i, mx, hasher = new sjcl.hash.sha1(), tmpHasher, hash, bl;
  var kat = sjcl.test.vector.sha1huge;

  base = w.concat(base, base); // 256 B
  base = w.concat(base, base); // 512 B
  base = w.concat(base, base); // 1024 B

  bl = w.bitLength(base)/8;
  mx = 312*1024*1024/bl;

  for(i=0; i<=mx; ++i){
    if ((i*bl) in kat){
      tmpHasher = new sjcl.hash.sha1(hasher);
      hash = tmpHasher.finalize();
      this.require(sjcl.codec.hex.fromBits(hash) == kat[i*bl], i*bl);
    }

    hasher.update(base);
  }

  cb && cb();
});
