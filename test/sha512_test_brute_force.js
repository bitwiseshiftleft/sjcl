/**
 * Test SHA-512 using an ad-hoc iterative technique.
 * This uses a string buffer which has n characters on the nth iteration.
 * Each iteration, the buffer is hashed and the hash is converted to a string.
 * The first two characters of the string are prepended to the buffer, then the
 * last character of the buffer is removed.  This way, neither the beginning nor
 * the end of the buffer is fixed.
 *
 * The hashes from each output step are also hashed together into one final hash.
 * This is compared against a final hash which was computed with OpenSSL/Node.js.
 */

new sjcl.test.TestCase("SHA-512 iterative", function (cb) {
  if (!sjcl.hash.sha512) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  var toBeHashed = "", cumulative = new sjcl.hash.sha512(), hash, thiz=this;
  browserUtil.cpsIterate(function (i, cbb) {
    for (var n=100*i; n<100*(i+1); n++) {
      hash = sjcl.hash.sha512.hash(toBeHashed);
      hash = sjcl.codec.hex.fromBits(hash);
      cumulative.update(hash);
      toBeHashed = (hash.substring(0,2)+toBeHashed).substring(0,n+1);
    }
    cbb && cbb();
  }, 0, 10, true, function () {
    hash = sjcl.codec.hex.fromBits(cumulative.finalize());
    thiz.require(hash === "602923787640dd6d77a99b101c379577a4054df2d61f39c74172cafa2d9f5b26a11b40b7ba4cdc87e84a4ab91b85391cb3e1c0200f3e3d5e317486aae7bebbf3");
    cb && cb();
  });
});
