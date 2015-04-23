function test_keccak(capacity, rate) {
  if (!rate) {
    // the test cases are named after the output length...
    // out := capacity / 2
    var name = 'keccak_' + (capacity >> 1);
    new sjcl.test.TestCase("Keccak[" + capacity + "] from Keccak KAT Keccak-" + (capacity >> 1), function (cb) {
      if (!sjcl.hash.keccak) {
        this.unimplemented();
        cb && cb();
        return;
      }

      var i, kat=sjcl.test.vector[name], p=0, f=0, keccak=sjcl.hash.keccak(capacity);
      for (i=0; i<kat.length; i++) {
        var data = sjcl.bitArray.clamp(sjcl.codec.hex.toBits(kat[i][1]), kat[i][0]);
        var out = keccak.hash(data);
        this.require(sjcl.bitArray.equal(out, sjcl.codec.hex.toBits(kat[i][2])), i+": "+sjcl.codec.hex.fromBits(out) + " != " + kat[i][2]);
      }
      cb && cb();
    });
  } else {
    new sjcl.test.TestCase("Keccak-r" + rate + "c" + capacity + " from Keccak KAT", function (cb) {
      var keccak;
      try {
        keccak = sjcl.hash.keccak(capacity, 4096, capacity + rate);
      } catch (e) {
        this.unimplemented();
        cb && cb();
        return;
      }

      var i, kat=sjcl.test.vector['keccak_r' + rate + 'c' + capacity], p=0, f=0;
      for (i=0; i<kat.length; i++) {
        var data = sjcl.bitArray.clamp(sjcl.codec.hex.toBits(kat[i][1]), kat[i][0]);
        var out = keccak.hash(data, kat[i][2].length * 4);
        this.require(sjcl.bitArray.equal(out, sjcl.codec.hex.toBits(kat[i][2])), i+": "+sjcl.codec.hex.fromBits(out) + " != " + kat[i][2]);
      }
      cb && cb();
    });
  }
}

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


test_keccak(448);
test_keccak(512);
test_keccak(768);
test_keccak(1024);

test_keccak(272, 128);
test_keccak(256, 1344);
test_keccak(256, 144);
test_keccak(544, 256);
test_keccak(160, 40);
test_keccak(288, 512);
test_keccak(256, 544);

test_sha3(224);
test_sha3(256);
test_sha3(384);
test_sha3(512);

test_sha3_shake(128);
test_sha3_shake(256);
