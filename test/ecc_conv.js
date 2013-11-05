new sjcl.test.TestCase("ECC convenience test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  try {  
    var keys = sjcl.ecc.elGamal.generateKeys(192,0);
    
    var ciphertext = sjcl.encrypt(keys.pub, "hello world");
    var plaintext  = sjcl.decrypt(keys.sec, ciphertext);
    
    this.require(plaintext == "hello world");
  } catch(e) {
    this.fail(e);
  }
  cb && cb();
});
