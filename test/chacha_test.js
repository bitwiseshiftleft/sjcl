new sjcl.test.TestCase("ChaCha20 TLS Draft", function (cb) {
  if (!sjcl.cipher.chacha || !sjcl.codec.hex) {
    this.unimplemented();
    cb && cb();
    return;
  }

  function zeroedCopy(bits) {
    var zeroes = bits.slice(0), i;
    for (i = 0; i < zeroes.length; ++i) zeroes[i] = 0;
    if (i > 0) zeroes[i-1] = sjcl.bitArray.partial(sjcl.bitArray.getPartial(bits[i-1]), 0);
    return zeroes;
  }

  var i, kat = sjcl.test.vector.chacha20Tls, tv, chacha, plain, crypted, wantCrypted;

  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    chacha = new sjcl.cipher.chacha(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]));
    plain = sjcl.codec.hex.toBits(tv[2]);
    wantCrypted = sjcl.codec.hex.toBits(tv[2]);
    plain = zeroedCopy(wantCrypted);
    crypted = chacha.crypt(plain);
    this.require(sjcl.bitArray.equal(crypted, wantCrypted), i + ": " + sjcl.codec.hex.fromBits(crypted) + " != " + tv[2]);
  }
  cb && cb();
});

function testChachaEcryptKat(rounds) {
  var title = "ChaCha" + (rounds || 20) + ": ECRYPT known-answer tests";

  new sjcl.test.TestCase(title, function (cb) {
    if (!sjcl.cipher.chacha || !sjcl.codec.hex) {
      this.unimplemented();
      cb && cb();
      return;
    }

    var zeroes = {};
    function makeZeroes(n) {
      if (0 == n) return [];
      var l=zeroes[n], i, j;
      if (!l) {
        zeroes[n] = l = [];
        for (i = 0; i < n; i += 4) {
          l.push(0);
        }
        j = i % 4;
        if (0 != j) l[l.length-1] = sjcl.bitArray.partial(8*j, 0);
      }
      return l;
    }


    var i, j, k, kat = sjcl.test.vector['chacha' + (rounds || 20)], tv, chacha, plain, crypted, wantCrypted, wantXorsum, xorsum, off, slice, title, msglen, sliceOffsets;

    for (i=0; i<kat.length; ++i) {
      tv = kat[i];
      msglen = tv[7].msglen;
      sliceOffsets = [0, (msglen>>>1) - 64, msglen>>>1, msglen - 64]; // 64-byte chunks
      title = i + ": (" + (tv[0].length * 4) + "-bit key): ";

      // encrypt with seek
      chacha = new sjcl.cipher.chacha(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      for (j = 0; j < 4; ++j) {
        wantCrypted = tv[j+2];
        plain = makeZeroes(wantCrypted.length / 2);
        off = sliceOffsets[j];
        chacha.setPosition(8 * off); // position in bits
        crypted = chacha.crypt(plain);
        this.require(sjcl.bitArray.equal(crypted, sjcl.codec.hex.toBits(tv[j+2])), title + ": crypt 0s [" + off + ".." + (off + 63)+ "](" + j + "): " + sjcl.codec.hex.fromBits(crypted) + " != " + tv[j+2]);
      }

      // encrypt as one large block
      plain = makeZeroes(msglen);
      chacha = new sjcl.cipher.chacha(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      crypted = chacha.crypt(plain);

      // check some slices of the block
      for (j = 0; j < 4; ++j) {
        off = sliceOffsets[j];
        slice = sjcl.bitArray.bitSlice(crypted, 8*off, 8*(off+64)); // 64 bytes per slice
        this.require(sjcl.bitArray.equal(slice, sjcl.codec.hex.toBits(tv[j+2])), title + ": crypt 0s [" + off + ".." + (off + 63)+ "](" + j + "): " + sjcl.codec.hex.fromBits(slice) + " != " + tv[j+2]);
      }

      // check decryption
      chacha = new sjcl.cipher.chacha(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      this.require(sjcl.bitArray.equal(plain, chacha.crypt(crypted), title + ": decrypt encrypted 0s"));

      // check xor sum or large block
      wantXorsum = tv[6];
      xorsum = crypted.slice(0, wantXorsum.length / 8);
      for (j = xorsum.length; j < crypted.length;) {
        for (k = 0; k < xorsum.length; ++k, ++j) xorsum[k] ^= crypted[j];
      }
      this.require(sjcl.bitArray.equal(xorsum, sjcl.codec.hex.toBits(wantXorsum), title + ": xor sum: " + sjcl.codec.hex.fromBits(xorsum) != wantXorsum));
    }
    cb && cb();
  });
}

testChachaEcryptKat(8);
testChachaEcryptKat(12);
testChachaEcryptKat();
