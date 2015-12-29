new sjcl.test.TestCase("ECC convenience test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }

  try {
    // Uses hard-coded randomness just to give the test something to work with.
    // This isn't how this is supposed to be used in the real world.
    var random = [ -625324409,
      -1863172196,
      -1745409890,
      -1513341554,
      1970821986,
      -532843769,
      -200096675,
      -1271344660 ];

    sjcl.random.addEntropy(random, 8 * 4 * random.length, "crypto.randomBytes")

    var keys = sjcl.ecc.elGamal.generateKeys(192,0);

    var ciphertext = sjcl.encrypt(keys.pub, "hello world");
    var plaintext  = sjcl.decrypt(keys.sec, ciphertext);

    this.require(plaintext == "hello world");
  } catch(e) {
    console.log(e.stack)
    this.fail(e);
  }
  cb && cb();
});
