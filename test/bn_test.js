new sjcl.test.TestCase("Bignum modular reduction test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var a, N, r, i, tv;
  for (i=0; i < sjcl.test.vector.bn_mod.length; i++) {
    tv = sjcl.test.vector.bn_mod[i];
    try {
      a = new sjcl.bn(tv.a);
      N = new sjcl.bn(tv.N);
      r = a.mod(N);
      this.require(r.equals(new sjcl.bn(tv.r)));
    } catch(e) {
      this.fail(e);
    }
  }
  cb && cb();
});

new sjcl.test.TestCase("Bignum modular multiplication test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var a, b, N, r, i, tv;
  for(var j=0;j<10;j++)for (i=0; i < sjcl.test.vector.bn_mulmod.length; i++) {
      tv = sjcl.test.vector.bn_mulmod[i];
    try {
      a = new sjcl.bn(tv.a);
      b = new sjcl.bn(tv.b);
      N = new sjcl.bn(tv.N);
      r = a.mulmod(b, N);
      this.require(r.equals(new sjcl.bn(tv.r)));
    } catch(e) {
      this.fail(e);
    }
  }
  cb && cb();
});

new sjcl.test.TestCase("Bignum modular exponentiation test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, tv, g, x, N, v;
  for (i=0; i < sjcl.test.vector.bn_powermod.length; i++) {
    tv = sjcl.test.vector.bn_powermod[i];
    try {
      g = new sjcl.bn(tv.g);
      x = new sjcl.bn(tv.x);
      N = new sjcl.bn(tv.N);
      v = g.powermod(x, N);
      this.require(v.equals(new sjcl.bn(tv.v)));
    } catch(e) {
      this.fail(e);
    }
  }
  cb && cb();
});

new sjcl.test.TestCase("Bignum toString test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }
  this.require((new sjcl.bn(12312434)).power(10).toString() ===
    '0xb99c06973dcc72429aa1dd41b0bc40a424289a05d3d72f066ee4e71c400');
  cb && cb();
});

new sjcl.test.TestCase("Big Limbs Multiplication test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var expected = "0x1000001800002100000a000002fffffa000001",
       bigLimb = Math.pow(2,26) - 1;

  var x = new sjcl.bn(0);
  x.limbs = [bigLimb, bigLimb, bigLimb];
  var actual = x.square().toString();

  this.require(actual === expected, "Expected: " + expected + " Actual: " + actual);

  cb && cb();
});
