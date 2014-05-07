new sjcl.test.TestCase("Poly1305 TLS Draft", function (cb) {
  if (!sjcl.misc.poly1305 || !sjcl.codec.hex) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.poly1305_tls, tv, key, message, want_tag, tag;

  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    key = sjcl.codec.hex.toBits(tv[0]);
    message = sjcl.codec.hex.toBits(tv[1]);
    want_tag = sjcl.codec.hex.toBits(tv[2]);
    tag = sjcl.misc.poly1305(key, message);
    this.require(sjcl.bitArray.equal(tag, want_tag), i + ": " + sjcl.codec.hex.fromBits(tag) + " != " + tv[2]);
  }
  cb && cb();
});

new sjcl.test.TestCase("Poly1305-AES", function (cb) {
  if (!sjcl.misc.poly1305aes || !sjcl.codec.hex) {
    this.unimplemented();
    cb && cb();
    return;
  }

  // http://cr.yp.to/mac/test-poly1305aes.c
  // splitted "kr" into poly1305_r and aes_key
  var aes_key = [0,0,0,0];
  var poly1305_r = [0,0,0,0];
  var poly1305_nonce = [0,0,0,0];
  var loop, len, msg = [], tag, i;
  var kat = sjcl.test.vector.poly1305_aes_tes, tv, tvi = 0, clampedMsg;
  for (loop = 0; loop < 10; ++loop) {
    for (len = 0; len <= 1000; ++len) {
      tv = kat[tvi++];
      clampedMsg = sjcl.bitArray.clamp(msg, 8*len);
      tag = sjcl.misc.poly1305aes(poly1305_r, aes_key, poly1305_nonce, clampedMsg);
      this.require(sjcl.bitArray.equal(tag, sjcl.codec.hex.toBits(tv)), i + ": " + sjcl.codec.hex.fromBits(tag) + " != " + tv);
      if (len < 1000) {
        poly1305_nonce[0] ^= (loop << 24); // xor first byte of nonce with loop
        for (i = 0; i < 4; ++i) {
          // xor tag into nonce/key/r (all 128-bit)
          poly1305_nonce[i] ^= tag[i];
          if (len % 2) aes_key[i] ^= tag[i];
          if (len % 3) poly1305_r[i] ^= tag[i];
        }
        // xor next message byte "msg-byte[len]" with first byte of tag
        msg[Math.floor(len/4)] ^= (tag[0] & 0xff000000) >>> (8 * (len % 4));
      }
    }
  }

  cb && cb();
});
