new sjcl.test.TestCase("SRP known-answer (RFC 5054) tests", function (cb) {
  if (!sjcl.keyexchange.srp) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.srp, tv, group, v, x;

  for (i=0; i<kat.length; i++) {
    // Make shallow copy of test vector as to not modify the original
    // Note: This is a workaround for older EcmaScript variants (<=5), for EcmaScript 6+ Object.assign could be used instead.
    tv = {}
    for (var attr in kat[i]) { tv[attr] = kat[i][attr]; }
    group = sjcl.keyexchange.srp.knownGroup(tv.known_group_size);
    tv.s = sjcl.codec.hex.toBits(tv.s);
    tv.v = new sjcl.bn(tv.v);
    tv.a = new sjcl.bn(tv.a);
    tv.A = new sjcl.bn(tv.A);
    tv.b = new sjcl.bn(tv.b);
    tv.B = new sjcl.bn(tv.B);
    tv.pmsk = sjcl.codec.hex.toBits(tv.pmsk);

    x = sjcl.keyexchange.srp.makeX(tv.I, tv.P, tv.s);
    this.require(sjcl.codec.hex.fromBits(x).toUpperCase() === tv.x, "srpx #"+i);

    v = sjcl.keyexchange.srp.makeVerifier(tv.I, tv.P, tv.s, group);
    this.require(v.equals(tv.v), "srpv #"+i);

    k = sjcl.keyexchange.srp.makeK(group);
    this.require(sjcl.codec.hex.fromBits(k).toUpperCase() === tv.k, "srpk #"+i);

    u = sjcl.keyexchange.srp.makeU(tv.A, tv.B, group);
    this.require(sjcl.codec.hex.fromBits(u).toUpperCase() === tv.u, "srpu #"+i);

    clientMsg = sjcl.keyexchange.srp.makeClientMsg(group, tv.a);
    this.require(clientMsg.private.equals(tv.a), "srpa #"+i);
    this.require(clientMsg.public.equals(tv.A), "srpA #"+i);

    serverMsg = sjcl.keyexchange.srp.makeServerMsg(tv.v, group, tv.b);
    this.require(serverMsg.private.equals(tv.b), "srpb #"+i);
    this.require(serverMsg.public.equals(tv.B), "srpB #"+i);

    clientPmsk = sjcl.keyexchange.srp.makeClientPmsk(tv.I, tv.P, tv.s, {private: tv.a, public: tv.A}, tv.B, group);
    this.require(sjcl.bitArray.equal(clientPmsk, tv.pmsk), "srppmsk-a #"+i)
    serverPmsk = sjcl.keyexchange.srp.makeServerPmsk(tv.v, tv.A, {private: tv.b, public: tv.B}, group);
    this.require(sjcl.bitArray.equal(clientPmsk, tv.pmsk), "srppmsk-b #"+i)
  }
  cb && cb();
});

new sjcl.test.TestCase("SRP simulation (RFC 5054) tests", function (cb) {
  // Simple interaction simulation based on the RFC 5054 test vectors

  if (!sjcl.keyexchange.srp) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.srp, tv, group, v, x;

  // NOTE: This initializes the global PRNG with a known seed
  var entropy = [ 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, 0xFEEDBEEF, 0xDEADD00D, ];
  sjcl.random.addEntropy(entropy, 256, "object");

  for (i=0; i<kat.length; i++) {
    // Make shallow copy of test vector as to not modify the original
    // Note: This is a workaround for older EcmaScript variants (<=5), for EcmaScript 6+ Object.assign could be used instead.
    tv = {}
    for (var attr in kat[i]) { tv[attr] = kat[i][attr]; }
    group = sjcl.keyexchange.srp.knownGroup(tv.known_group_size);
    tv.s = sjcl.codec.hex.toBits(tv.s);
    tv.v = new sjcl.bn(tv.v);

    // Simulation with random private messages
        
    clientMsg = sjcl.keyexchange.srp.makeClientMsg(group);
    serverMsg = sjcl.keyexchange.srp.makeServerMsg(tv.v, group);

    clientPmsk = sjcl.keyexchange.srp.makeClientPmsk(tv.I, tv.P, tv.s, clientMsg, serverMsg.public, group);
    serverPmsk = sjcl.keyexchange.srp.makeServerPmsk(tv.v, clientMsg.public, serverMsg, group);

    this.require(sjcl.bitArray.equal(clientPmsk, serverPmsk), "srppmsk-rand #"+i)
  }
  cb && cb();
});