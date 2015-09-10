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
