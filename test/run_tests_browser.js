function testCore(coreName, cb) {
  var corePath = "../", testPath = "../test/", testFiles = [
    corePath + coreName,
    "test.js",
    "aes_test.js",
    "aes_vectors.js",
    "bitArray_test.js",
    "bitArray_vectors.js",
    "bn_test.js",
    "bn_vectors.js",
    "cbc_test.js",
    "cbc_vectors.js",
    "ccm_test.js",
    "ccm_vectors.js",
    "ecc_conv.js",
    "ecdh_test.js",
    "ecdsa_test.js",
    "ecdsa_vectors.js",
    "gcm_test.js",
    "gcm_vectors.js",
    "hkdf_test.js",
    "hkdf_vectors.js",
    "hmac_test.js",
    "hmac_vectors.js",
    "json_test.js",
    "ocb2_test.js",
    "ocb2progressive_test.js",
    "ocb2_vectors.js",
    "pbkdf2_test.js",
    "ripemd160_test.js",
    "ripemd160_vectors.js",
    "scrypt_test.js",
    "scrypt_vectors.js",
    "sha1_test.js",
    "sha1_vectors.js",
    "sha1_huge_test_messages.js",
    "sha1_huge_test.js",
    "sha256_test.js",
    "sha256_vectors.js",
    "sha256_test_brute_force.js",
    "sha256_huge_test_messages.js",
    "sha256_huge_test.js",
    "sha512_test.js",
    "sha512_vectors.js",
    "sha512_test_brute_force.js",
    "sha512_huge_test_messages.js",
    "sha512_huge_test.js",
    "srp_test.js",
    "srp_vectors.js",
    "z85_test.js",
    "z85_vectors.js",
  ], i;

  for (i=1; i<testFiles.length; i++) {
    testFiles[i] = testPath + testFiles[i];
  }

  browserUtil.loadScripts(testFiles, function() {
    browserUtil.write("begin", coreName);
    browserUtil.status("Testing...");
    sjcl.test.run([], function () {
      browserUtil.status("");
      cb && cb();
    });
  },
  function (script, err) {
    browserUtil.allPassed = false;
    browserUtil.write("begin fail", coreName);
    browserUtil.write("fail", "Failed to load "+script+": "+err);
    cb();
  });
}

function testCores(coreNames, cb) {
  browserUtil.cpsMap(function (n,x,y,cb) { testCore(n,cb); }, coreNames, true, function() {
    if (browserUtil.allPassed) {
      browserUtil.write("pass all", "All tests passed.");
    } else {
      browserUtil.write("fail all", "All tests complete, but some failed!");
    }
    cb && cb();
  });
}
