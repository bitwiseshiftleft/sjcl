function test_sha3(security) {
  var name = 'sha3_' + security;
  new sjcl.test.TestCase("SHA3-" + security + " based on Keccak[" + (2*security) + "]", function (cb) {
    if (!sjcl.hash[name]) {
      this.unimplemented();
      cb && cb();
      return;
    }

    var i, kat, sha3=sjcl.hash[name];
    kat=sjcl.test.vector[name];
    for (i=0; i<kat.length; i++) {
      // clamp after byteswap! these test vectors have the bytes already aligned,
      // clamping before swapping would kill needed bits.
      var data = sjcl.bitArrayLE.clampM(sjcl.bitArrayLE.fromBitArrayByteSwap(sjcl.codec.hex.toBits(kat[i][1])), kat[i][0]);
      var out = sha3().updateLE(data).finalize();
      this.require(sjcl.bitArray.equal(out, sjcl.codec.hex.toBits(kat[i][2])), i+": "+sjcl.codec.hex.fromBits(out) + " != " + kat[i][2]);
    }
    kat=sjcl.test.vector[name + '_strings'];
    for (i=0; i<kat.length; i++) {
      var out = sha3.hash(kat[i][0]);
      this.require(sjcl.bitArray.equal(out, sjcl.codec.hex.toBits(kat[i][1])), i+": "+sjcl.codec.hex.fromBits(out) + " != " + kat[i][1]);
    }
    cb && cb();
  });
}

function test_sha3_shake(security) {
  var name = 'shake' + security;
  new sjcl.test.TestCase("SHAKE" + security + " based on Keccak[" + (2*security) + "]", function (cb) {
    if (!sjcl.hash[name]) {
      this.unimplemented();
      cb && cb();
      return;
    }

    var i, kat, sha3=sjcl.hash[name];
    kat=sjcl.test.vector[name];
    for (i=0; i<kat.length; i++) {
      // clamp after byteswap! these test vectors have the bytes already aligned,
      // clamping before swapping would kill needed bits.
      var data = sjcl.bitArrayLE.clampM(sjcl.bitArrayLE.fromBitArrayByteSwap(sjcl.codec.hex.toBits(kat[i][1])), kat[i][0]);
      var expected = sjcl.codec.hex.toBits(kat[i][2]);
      var out = sha3().updateLE(data).finalize(sjcl.bitArray.bitLength(expected));
      this.require(sjcl.bitArray.equal(out, expected), i+": "+sjcl.codec.hex.fromBits(out) + " != " + kat[i][2]);
    }
    cb && cb();
  });
}


test_sha3(224);
test_sha3(256);
test_sha3(384);
test_sha3(512);

test_sha3_shake(128);
test_sha3_shake(256);
