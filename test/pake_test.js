new sjcl.test.TestCase("SPAKE2/PAKE2+ test", function (cb) {
  if (!sjcl.pake || !sjcl.misc || !sjcl.misc.hkdf || !sjcl.hash.sha256 || !sjcl.ecc || !sjcl.random) {
    this.unimplemented();
    cb && cb();
    return;
  }

  // Init salt and shared keys
  var salt = sjcl.random.randomWords(4);
  var sharedKey1 = "password1";
  var sharedKey2 = "password2";
  var aPake, bPake, aData, bData, aKey, bKey, dbData;


  // You need to stretch these keys but testing doesn't really need to. So only do it if it's available.
  if (sjcl.misc.pbkdf2) {
    sharedKey1 = sjcl.misc.pbkdf2(sharedKey1, salt, 20000);
    sharedKey2 = sjcl.misc.pbkdf2(sharedKey2, salt, 20000);
  }

  // Test SPAKE2 Correct PW
  aPake = sjcl.pake.createSpake2("Alice", "Bob", false);
  bPake = sjcl.pake.createSpake2("Alice", "Bob", false);
  aData = aPake.startA(sharedKey1); // send aData & salt to b
  bData = bPake.startB(sharedKey1); // send bData to a
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "SPAKE2 Correct PW");

  // Test SPAKE2 Wrong PW
  aPake = sjcl.pake.createSpake2("Alice", "Bob", false);
  bPake = sjcl.pake.createSpake2("Alice", "Bob", false);
  aData = aPake.startA(sharedKey1); // send aData & salt to b
  bData = bPake.startB(sharedKey2); // send bData to a
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(!sjcl.bitArray.equal(aKey, bKey), "SPAKE2 Wrong PW");

  // Test SPAKE2 default
  aPake = sjcl.pake.createSpake2("Alice", "Bob", false);
  bPake = sjcl.pake.createSpake2("Alice", "Bob");
  aData = aPake.startA(sharedKey1); // send aData & salt to b
  bData = bPake.startB(sharedKey1); // send bData to a
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "SPAKE2 Default");

  // Test SPAKE2-EE Correct PW
  aPake = sjcl.pake.createSpake2("Alice", "Bob", true);
  bPake = sjcl.pake.createSpake2("Alice", "Bob", true);
  aData = aPake.startA(sharedKey1); // send aData & salt to b
  bData = bPake.startB(sharedKey1); // send bData to a
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "SPAKE2-EE Correct PW");

  // Test SPAKE2-EE Wrong PW
  aPake = sjcl.pake.createSpake2("Alice", "Bob", true);
  bPake = sjcl.pake.createSpake2("Alice", "Bob", true);
  aData = aPake.startA(sharedKey1); // send aData & salt to b
  bData = bPake.startB(sharedKey2); // send bData to a
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(!sjcl.bitArray.equal(aKey, bKey), "SPAKE2-EE Wrong PW");


  // Init salt and shared keys
  salt = "data from server or username@domain"; // get salt from server
  sharedKey1 = "password1";
  sharedKey2 = "password2";
  // You need to stretch these keys but testing doesn't really need to. So only do it if it's available.
  if (sjcl.misc.pbkdf2) {
    sharedKey1 = sjcl.misc.pbkdf2(sharedKey1, salt, 20000);
    sharedKey2 = sjcl.misc.pbkdf2(sharedKey2, salt, 20000);
  }

  // Test PAKE2+ Correct PW
  aPake = sjcl.pake.createPake2Plus("Alice", "example.com", false);
  bPake = sjcl.pake.createPake2Plus("Alice", "example.com", false);
  aData = aPake.startClient(sharedKey1); // send aData to server
  dbData = bPake.generateServerData(sharedKey1); // read from DB
  bData = bPake.startServer(dbData.pwKey1_M, dbData.pwKey1_N, dbData.pwKey2, dbData.pwKey3_G); // send bData to client
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "PAKE2+ Correct PW");

  // Test PAKE2+ Wrong PW
  aPake = sjcl.pake.createPake2Plus("Alice", "example.com", false);
  bPake = sjcl.pake.createPake2Plus("Alice", "example.com", false);
  aData = aPake.startClient(sharedKey1); // send aData to server
  dbData = bPake.generateServerData(sharedKey2); // read from DB
  bData = bPake.startServer(dbData.pwKey1_M, dbData.pwKey1_N, dbData.pwKey2, dbData.pwKey3_G); // send bData to client
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(!sjcl.bitArray.equal(aKey, bKey), "PAKE2+ Wrong PW");

  // Test PAKE2+ default
  aPake = sjcl.pake.createPake2Plus("Alice", "example.com", false);
  bPake = sjcl.pake.createPake2Plus("Alice", "example.com");
  aData = aPake.startClient(sharedKey1); // send aData to server
  dbData = bPake.generateServerData(sharedKey1); // read from DB
  bData = bPake.startServer(dbData.pwKey1_M, dbData.pwKey1_N, dbData.pwKey2, dbData.pwKey3_G); // send bData to client
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "PAKE2+ Default");

  // Test PAKE2+EE Correct PW
  aPake = sjcl.pake.createPake2Plus("Alice", "example.com", true);
  bPake = sjcl.pake.createPake2Plus("Alice", "example.com", true);
  aData = aPake.startClient(sharedKey1); // send aData to server
  dbData = bPake.generateServerData(sharedKey1); // read from DB
  bData = bPake.startServer(dbData.pwKey1_M, dbData.pwKey1_N, dbData.pwKey2, dbData.pwKey3_G); // send bData to client
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(sjcl.bitArray.equal(aKey, bKey), "PAKE2+EE Correct PW");

  // Test PAKE2+EE Wrong PW
  aPake = sjcl.pake.createPake2Plus("Alice", "example.com", true);
  bPake = sjcl.pake.createPake2Plus("Alice", "example.com", true);
  aData = aPake.startClient(sharedKey1); // send aData to server
  dbData = bPake.generateServerData(sharedKey2); // read from DB
  bData = bPake.startServer(dbData.pwKey1_M, dbData.pwKey1_N, dbData.pwKey2, dbData.pwKey3_G); // send bData to client
  aKey = aPake.finish(bData);
  bKey = bPake.finish(aData);
  this.require(!sjcl.bitArray.equal(aKey, bKey), "PAKE2+EE Wrong PW");

  cb && cb();
});
