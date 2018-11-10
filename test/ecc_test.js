new sjcl.test.TestCase("ECC point multiplication test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, vec, pnt;
  for (i=0; i<sjcl.test.vector.ecc_pntmul.length; i++) {
    vec = sjcl.test.vector.ecc_pntmul[i];
    pnt = sjcl.ecc.curves[vec.curve].G.mult(new sjcl.bn(vec.pri));
    this.require(pnt.x.equals(new sjcl.bn(vec.x)) && pnt.y.equals(new sjcl.bn(vec.y)), vec.curve+" failed");
  }
  cb && cb();
});

new sjcl.test.TestCase("ECC jac multiplication regression test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var point = new sjcl.ecc.point(
    sjcl.ecc.curves.c521,

    new sjcl.bn.prime.p521( "0x1b62fe3d057dd651b6c04e925c3be527ff7d36775a0a786dff42e7c1f40ce4f806deb1da099819689865ae995d0ba7d121b3ff6c8b78c1cddeb18b7e12f3a6d35f9" ),
    new sjcl.bn.prime.p521( "0x146583b5b1da68f4be58d8a361fedc2b3522b90e93a32850ed7cebd75fbc72f1d046c805a5ffc36af29559fdc78bd05bba74d820d80df2561c7118bd1a2f5745be3" )
  );

  this.require(point.isValid(), "Point invalid");

  var doublJacPoint = point.toJac().doubl();

  this.require(doublJacPoint.isValid(), "doubled point invalid");

  cb && cb();
});

new sjcl.test.TestCase("All curves should have a valid G", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var curves = sjcl.ecc.curves;
  var keys = Object.keys(curves);

  var curve, key, i;

  for (i = 0; i < keys.length; i += 1) {
    key = keys[i];
    curve = curves[key];
    this.require(curve.G.isValid(), "G of curve " + key + " is invalid");
  }

  cb && cb();
});

new sjcl.test.TestCase("Multiplication regression test part 2", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var pnt, i, vec;

  for (i = 0; i < sjcl.test.vector.ecc_mul.length; i += 1) {
    vec = sjcl.test.vector.ecc_mul[i];
    pnt = sjcl.ecc.curves[vec.curve].G.mult(new sjcl.bn(vec.pri));
    this.require(pnt.x.equals(new sjcl.bn(vec.x)), "X should match after Multiplication for vec" + i);
    this.require(pnt.y.equals(new sjcl.bn(vec.y)), "Y should match after Multiplication for vec " + i);
  }

  cb && cb();
});
