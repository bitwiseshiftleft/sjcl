function testSalsaEcryptKat(rounds) {
  var title = "Salsa20" + (rounds ? "/" + rounds : "") + ": ECRYPT known-answer tests";

  new sjcl.test.TestCase(title, function (cb) {
    if (!sjcl.cipher.salsa20 || !sjcl.codec.hex) {
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


    var i, j, k, kat = sjcl.test.vector['salsa20' + (rounds ? "r" + rounds : "")], tv, salsa20, plain, crypted, wantCrypted, wantXorsum, xorsum, off, slice, title, msglen, sliceOffsets;

    for (i=0; i<kat.length; ++i) {
      tv = kat[i];
      msglen = tv[7].msglen;
      sliceOffsets = [0, (msglen>>>1) - 64, msglen>>>1, msglen - 64]; // 64-byte chunks
      title = i + ": (" + (tv[0].length * 4) + "-bit key): ";

      // encrypt with seek
      salsa20 = new sjcl.cipher.salsa20(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      for (j = 0; j < 4; ++j) {
        wantCrypted = tv[j+2];
        plain = makeZeroes(wantCrypted.length / 2);
        off = sliceOffsets[j];
        salsa20.setPosition(8 * off); // position in bits
        crypted = salsa20.crypt(plain);
        this.require(sjcl.bitArray.equal(crypted, sjcl.codec.hex.toBits(tv[j+2])), title + ": crypt 0s [" + off + ".." + (off + 63)+ "](" + j + "): " + sjcl.codec.hex.fromBits(crypted) + " != " + tv[j+2]);
      }

      // encrypt as one large block
      plain = makeZeroes(msglen);
      salsa20 = new sjcl.cipher.salsa20(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      crypted = salsa20.crypt(plain);

      // check some slices of the block
      for (j = 0; j < 4; ++j) {
        off = sliceOffsets[j];
        slice = sjcl.bitArray.bitSlice(crypted, 8*off, 8*(off+64)); // 64 bytes per slice
        this.require(sjcl.bitArray.equal(slice, sjcl.codec.hex.toBits(tv[j+2])), title + ": crypt 0s [" + off + ".." + (off + 63)+ "](" + j + "): " + sjcl.codec.hex.fromBits(slice) + " != " + tv[j+2]);
      }

      // check decryption
      salsa20 = new sjcl.cipher.salsa20(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]), rounds);
      this.require(sjcl.bitArray.equal(plain, salsa20.crypt(crypted), title + ": decrypt encrypted 0s"));

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

testSalsaEcryptKat(8);
testSalsaEcryptKat(12);
testSalsaEcryptKat();

new sjcl.test.TestCase("XSalsa20", function (cb) {
  if (!sjcl.cipher.salsa20 || !sjcl.codec.hex) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.xsalsa20, tv, xsalsa20, plain, crypted, wantCrypted;

  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    xsalsa20 = new sjcl.cipher.salsa20(sjcl.codec.hex.toBits(tv[0]), sjcl.codec.hex.toBits(tv[1]));
    plain = sjcl.codec.hex.toBits(tv[2]);
    wantCrypted = sjcl.codec.hex.toBits(tv[3]);
    crypted = xsalsa20.crypt(plain);
    this.require(sjcl.bitArray.equal(crypted, wantCrypted), i + ": " + sjcl.codec.hex.fromBits(crypted) + " != " + tv[3]);
  }
  cb && cb();
});
