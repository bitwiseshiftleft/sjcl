function testCore(coreName, cb) {
  var corePath = "../", testPath = "../test/", testFiles = [
    corePath + coreName,
    "test.js",
    "aes_test.js",
    "aes_vectors.js",
    "ccm_test.js",
    "ccm_vectors.js",
    "cbc_test.js",
    "cbc_vectors.js",
    "ocb2_test.js",
    "ocb2_vectors.js",
    "gcm_test.js",
    "gcm_vectors.js",
    "sha256_test.js",
    "sha256_vectors.js",
    "sha256_test_brute_force.js",
    "sha512_test.js",
    "sha512_vectors.js",
    "sha512_test_brute_force.js",
    "sha1_test.js",
    "sha1_vectors.js",
    "hmac_test.js",
    "hmac_vectors.js",
    "pbkdf2_test.js",
    "bn_test.js",
    "bn_vectors.js",
    "ecdsa_test.js",
    "ecdsa_vectors.js",
    "ecdh_test.js",
    "srp_test.js",
    "srp_vectors.js",
    "ecc_conv.js"
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
