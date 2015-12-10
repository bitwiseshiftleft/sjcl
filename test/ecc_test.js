new sjcl.test.TestCase("ECC curves multiplication test", function (cb) {
  if (!sjcl.bn) {
    this.unimplemented();
    cb && cb();
    return;
  }

  /**
   *
   * The values for pri and pub have been generated via OpenSSL
   * with the following commands:
   *
   * c192: openssl ecparam -name secp192r1 -genkey | openssl ec -text
   * c224: openssl ecparam -name secp224r1 -genkey | openssl ec -text
   * c256: openssl ecparam -name secp256r1 -genkey | openssl ec -text
   * c384: openssl ecparam -name secp384r1 -genkey | openssl ec -text
   * c521: openssl ecparam -name secp521r1 -genkey | openssl ec -text
   * k192: openssl ecparam -name secp192k1 -genkey | openssl ec -text
   * k224: openssl ecparam -name secp224k1 -genkey | openssl ec -text
   * k256: openssl ecparam -name secp256k1 -genkey | openssl ec -text
   *
   */
  var cn, pnt, pri = {
    c192: new sjcl.bn("0x7323b21a836de35418b612cb317ca9b024f4918a5ea1ffcd"),
    c224: new sjcl.bn("0x6f4b25e353201936254479cad382447b8dfde9365ccb9772f2467835"),
    c256: new sjcl.bn("0x58bc0bc6ef097f2ac366b1d7dd0bd75a195409d9413ce80a9f93a5225324e10a"),
    c384: new sjcl.bn("0xf66fbbe65283e4a20ebf1e2163109de08f0bdd9e4d20d24fe6be69805ca9f6d76bd9c24a351cbecc452b9bfe104074bd"),
    c521: new sjcl.bn("0x01cb7f660777685b444b6ddf0ec359c460d0644773d4cf1df4d80e0a0f0bdd6ad3780c1f4ee8e23169a10ec1914ab6c45beb13621d9add137c05ac237f9177621256"),
    k192: new sjcl.bn("0x3d02d7932cbee39a20be8d52c0e20820b3fc8cd6258cf158"),
    k224: new sjcl.bn("0x2669789cb1356519cbb457e1b8e98ef8c1e673a9939d444a70ce8cce"),
    k256: new sjcl.bn("0x5a2b847b9dbfa3b8c95e8ef0d9dead6cc6f3c22dae6c162f759f2d640495dce0")
  }, pub = {
    c192: {
      x: new sjcl.bn("0xb2610635675f427112f50247d540c02cae8c3419f309244d"),
      y: new sjcl.bn("0x9cbddb422ad84a8013ceacad763329a7c88c55e5d0d6f679")
    },
    c224: {
      x: new sjcl.bn("0xd665b5a8aa20b359a173274ff1ac4c51e5720b8315fb3b53adea8875"),
      y: new sjcl.bn("0x4b0292dc6d2487aa8e8bd1663ec799c45abcb1730407d22051557885")
    },
    c256: {
      x: new sjcl.bn("0x9b7b49fbf1096ecdcd169f4107e14ba6bbdbcf6cf00b5291df139987b75a59ad"),
      y: new sjcl.bn("0x80bf2f6ec3317e30d404868a0ba8defaeed8b6306cf3a36b81d2f5368aa0ad48")
    },
    c384: {
      x: new sjcl.bn("0xe271f1d1dfaf78fc33addec8183430df76f9a76e0534bd5f11fa1de5590661fa4bbb231f3065c10e3b375322c19551f7"),
      y: new sjcl.bn("0x24bfb224d5170548624226d5ec35f49660198cbd4590295eef722dc82e259d30d361ff56bab761e656bec6e3d5d186aa")
    },
    c521: {
      x: new sjcl.bn("0x0198e5c2da1f4dca85a51abcdb594e94e9b755b81a73b64cbe760388302fd00fe3f534e513360369c101b03bcb3f79c12211733bb9582376b233999376c408d7abf8"),
      y: new sjcl.bn("0x002f5a5341f6277bb810e4d9c7eb1b1580cc7a027cd1e1f159e1beebdc02e7a453653b48e667c9e05ef9b849bde90365f5ea3fb35564f2a9ea97b40e2937147a095b")
    },
    k192: {
      x: new sjcl.bn("0x826519b44cea20d3a5b52f7d7c65221d50c491b285d0853c"),
      y: new sjcl.bn("0x555609257711b16e5fa872aab5346cf1716d434f7dc8ddd2")
    },
    k224: {
      x: new sjcl.bn("0xdc7f88028d384523a3d7fba09a33097be55858af33443fe574dd035a"),
      y: new sjcl.bn("0x253edd056b78332ac6c7631315d457e5442394a87d70f74548730975")
    },
    k256: {
      x: new sjcl.bn("0x5d1247a9177f4943cfca74355af3e9fc61e5900b5e41e5c5db293f52c397ec28"),
      y: new sjcl.bn("0xd4d36e5dad4230b525c83ee4e4477d62b143fa4e69934f9531759a356982ce08")
    }
  };

  for (cn in pri) {
    pnt = sjcl.ecc.curves[cn].G.mult(pri[cn]);
    this.require(pnt.x.equals(pub[cn].x) && pnt.y.equals(pub[cn].y), cn+" failed");
  }
  cb && cb();
});
