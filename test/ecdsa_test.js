new sjcl.test.TestCase("ECDSA test", function (cb) {
  if (!sjcl.ecc) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  var keys = sjcl.ecc.ecdsa.generateKeys(192,0),
      hash = sjcl.hash.sha256.hash("The quick brown fox jumps over the lazy dog."),
      signature = keys.sec.sign(hash,0);
      
  try {
    keys.pub.verify(hash, signature);
    this.pass();
  } catch (e) {
    this.fail("good message rejected");
  }
  
  hash[1] ^= 8; // minor change to hash
  
  try {
    keys.pub.verify(hash, signature);
    this.fail();
  } catch (e) {
    this.pass("bad message accepted");
  }

  // Run through the test vectors
  for (var key in sjcl.test.vector.ecdsa) {
    var match = /^p(\d+)sha(\d+)/.exec(key);
    var curvenum = parseInt(match[1]);
    var shanum = parseInt(match[2]);

    var vectors = sjcl.test.vector.ecdsa[key];
    var curve = sjcl.ecc.curves['c'+curvenum];
    var sha = sjcl.hash['sha'+shanum];
    if (!sha) continue;

    var h = sjcl.codec.hex;
    var ba = sjcl.bitArray;
    var bn = sjcl.bn;

  for (var i=0; i<vectors.length; i++) {
    var msgbits = h.toBits(vectors[i].msg);
    var d = bn.fromBits(h.toBits(vectors[i].d));
    var x = bn.fromBits(h.toBits(vectors[i].Qx));
    var y = bn.fromBits(h.toBits(vectors[i].Qy));
    var k = bn.fromBits(h.toBits(vectors[i].k));
    var r = bn.fromBits(h.toBits(vectors[i].R));
    var s = bn.fromBits(h.toBits(vectors[i].S));

    keys = sjcl.ecc.ecdsa.generateKeys(curvenum,0,d);
    var pub = keys.pub;
    var sec = keys.sec;

    // verify generated x and y
    var genx = bn.fromBits(pub.get().x);
    var geny = bn.fromBits(pub.get().y);
    this.require(x.equals(genx));
    this.require(y.equals(geny));

    // sign
    try {
        hash = sha.hash(msgbits);
        var sig = sec.sign(hash,0,0,k);
        siglen = ba.bitLength(sig);
        var genr = bn.fromBits(ba.bitSlice(sig, 0, siglen/2));
        var gens = bn.fromBits(ba.bitSlice(sig, siglen/2, siglen));

        this.require(genr.equals(r));
        this.require(gens.equals(s));
      } catch (e) {
        this.fail("error signing!");
      }

      // verify signature
      try {
        pub.verify(hash, sig);
        this.pass();
      } catch (e) {
        this.fail();
      }
    }

    // sign legacy style
    try {
        hash = sha.hash(msgbits);
        var sig = sec.sign(hash,0,1);
        pub.verify(hash, sig);
        pub.verify(hash, sig, 1);
        try {
          pub.verify(hash, sig, 0);
          this.fail();
        } catch (ee) {
          this.pass();
        }
    } catch (e) {
      this.fail(e);
    }
  }
  
  cb && cb();
});
