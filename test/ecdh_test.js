new sjcl.test.TestCase("ECDH test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  try {  
    var keys = sjcl.ecc.elGamal.generateKeys(192,0),
        keyTag = keys.pub.kem(0),
        key2 = keys.sec.unkem(keyTag.tag);

    var serializedPubKey = keys.pub.serialize();
    var deserializedPubKey = sjcl.ecc.deserialize(serializedPubKey);
    var serializedSecKey = keys.sec.serialize();
    var deserializedSecKey = sjcl.ecc.deserialize(serializedSecKey);

    this.require(sjcl.bitArray.equal(keys.pub.get().x, 
	deserializedPubKey.get().x));
    this.require(sjcl.bitArray.equal(keys.pub.get().y, 
	deserializedPubKey.get().y));
    this.require(sjcl.bitArray.equal(deserializedSecKey.get(), keys.sec.get()));

    var ciphertext = sjcl.encrypt(deserializedPubKey, "hello world");
    var plaintext  = sjcl.decrypt(keys.sec, ciphertext);
    this.require(plaintext == "hello world");

    ciphertext = sjcl.encrypt(keys.pub, "hello world");
    plaintext  = sjcl.decrypt(deserializedSecKey, ciphertext);
    this.require(plaintext == "hello world");
        
    this.require(sjcl.bitArray.equal(keyTag.key, key2));
  } catch(e) {
    this.fail(e);
  }
  cb && cb();
});
