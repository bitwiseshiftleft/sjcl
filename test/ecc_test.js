new sjcl.test.TestCase("ECC point multiplication test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, vec, pnt;
  for (i=0; i<sjcl.test.vector.ecc_pntmul.length; i++) {
    vec = sjcl.test.vector.ecc_pntmul[i];
    if (vec.curve == "k224") {
        this.log("warn", "Skipping broken curve k224");
        continue;
    }
    pnt = sjcl.ecc.curves[vec.curve].G.mult(new sjcl.bn(vec.pri));
    this.require(pnt.x.equals(new sjcl.bn(vec.x)) && pnt.y.equals(new sjcl.bn(vec.y)), vec.curve+" failed");
  }

  cb && cb();
});
