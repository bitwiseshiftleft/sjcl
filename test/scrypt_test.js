new sjcl.test.TestCase("scrypt", function (cb) {
  var self = this;
  if (!sjcl.misc.scrypt) {
    this.unimplemented();
    cb && cb();
    return;
  }

  sjcl.test.vector.scrypt.forEach(function (vect) {
    var cand = sjcl.codec.hex.fromBits(sjcl.misc.scrypt(
      vect["password"],
      vect["salt"],
      vect["N"],
      vect["r"],
      vect["p"],
      vect["dkLen"] * 8
    ));

    self.require(vect["expected"] == cand);
  });

  cb && cb();
});
