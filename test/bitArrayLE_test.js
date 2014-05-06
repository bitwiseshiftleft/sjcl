(function() {

  function word2hex(w) {
    return "0x" + ((w|0)+0xF00000000000).toString(16).substr(4);
  }

  var b0 = sjcl.bitArrayLE.partial(1, 0);
  var b1 = sjcl.bitArrayLE.partial(1, 1);
  var b0_BE = sjcl.bitArray.partial(1, 0);
  var b1_BE = sjcl.bitArray.partial(1, 1);

  function concatbitsBE(s) {
    var j, b, a = [];
    for (j = 0; j < s.length; ++j) {
      b = (s[j] === '1' ? b1_BE : b0_BE);
      a = sjcl.bitArray.concat(a, [b]);
    }
    return a;
  }
  function concatbits(s) {
    var j, b, a = [];
    for (j = 0; j < s.length; ++j) {
      b = (s[j] === '1' ? b1 : b0);
      a = sjcl.bitArrayLE.concat(a, [b]);
    }
    return a;
  }
  function concatbits_reverse(s) {
    var j, b, a = [];
    for (j = s.length; j-- > 0; ) {
      b = (s[j] === '1' ? b1 : b0);
      a = sjcl.bitArrayLE.concat(a, [b]);
    }
    return a;
  }


  new sjcl.test.TestCase("bitArrayLE single bits", function (cb) {
    if (!sjcl.bitArrayLE) {
      this.unimplemented();
      cb && cb();
      return;
    }

    this.require((b0|0) === (0x00000000|0), "bitstring '0': " + word2hex(b0));
    this.require((b1|0) === (0x00000001|0), "bitstring '1': " + word2hex(b1));

    cb && cb();
  });

  new sjcl.test.TestCase("bitArrayLE concat small bitstrings", function (cb) {
    if (!sjcl.bitArrayLE) {
      this.unimplemented();
      cb && cb();
      return;
    }

    var i, kat = sjcl.test.vector.bitArray.bits, tv, a, b, a_BE, a2, a2_BE, bitlen, t;
    for (i=0; i<kat.length; i++) {
      tv = kat[i];
      a = concatbits_reverse(tv[0]);
      a2 = concatbits(tv[0]);
      a2_BE = sjcl.bitArrayLE.toBitArrayBitReverse(a2);
      a_BE = concatbitsBE(tv[0]);
      bitlen = sjcl.bitArrayLE.bitLength(a);
      t = "bitstring '" + tv[0] + "': ";
      this.require(1 === a.length, t + "array length is 1: " + a.length);
      this.require(bitlen === tv[0].length, t + "length " + bitlen + " matches input length " + tv[0].length);
      b = sjcl.bitArrayLE.partial(tv[0].length, tv[1]);

      this.require(a[0] === b, t + "array matches shifted number: " + word2hex(a[0]) + " == " + word2hex(b));

      this.require(sjcl.bitArray.equal(a2_BE, a_BE), t + "toBitArrayBitReverse(" + word2hex(a2[0]) + ") matches big endian result: " + word2hex(a2_BE[0]) + " == " + word2hex(a_BE[0]));
      a = sjcl.bitArrayLE.fromBitArrayBitReverse(a_BE);
      this.require(sjcl.bitArrayLE.equal(a, a2), t + "fromBitArrayBitReverse(" + word2hex(a_BE[0]) + ") matches little endian result: " + word2hex(a[0]) + " == " + word2hex(a2[0]));
    }

    cb && cb();
  });


  new sjcl.test.TestCase("bitArrayLE concat, slicing, shifting and clamping", function (cb) {
    if (!sjcl.bitArrayLE) {
      this.unimplemented();
      cb && cb();
      return;
    }

    var i, j, kat = sjcl.test.vector.bitArray.slices, tv, a, a1, b, bitlen, t;
    for (i=0; i<kat.length; i++) {
      tv = kat[i];
      a = [];
      b = [];

      bitlen = 0;
      for (j=0; j<tv[0].length; j++) {
        b[j] = concatbits(tv[0][j]);
        a = sjcl.bitArrayLE.concat(a, b[j]);
        bitlen += tv[0][j].length;
      }

      // shift last array entry and set partial length on it
      a1 = tv[1]; a1 = a1.slice(0, a1.length);
      bitlen &= 31;
      if (0 !== bitlen) a1[a1.length-1] = sjcl.bitArray.partial(bitlen, a1[a1.length-1]);
      a1 = sjcl.bitArrayLE.fromBitArrayBitReverse(a1);

      this.require(sjcl.bitArrayLE.equal(a, a1), "concat: [" + a + "] == [" + a1 + "]");

      t = 0;
      for (j=0; j<tv[0].length; j++) {
        bitlen = sjcl.bitArrayLE.bitLength(b[j]);
        this.require(bitlen === tv[0][j].length, "bitstring length");
        a1 = sjcl.bitArrayLE.bitSlice(a, t, t + bitlen);
        this.require(sjcl.bitArrayLE.equal(b[j], a1), "slice after concat: [" + b[j] + "] == [" + a1 + "]");
        t += bitlen;
      }
    }

    cb && cb();
  });

})();
