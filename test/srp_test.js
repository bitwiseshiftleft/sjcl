new sjcl.test.TestCase("SRP known-answer tests", function (cb) {
  if (!sjcl.keyexchange.srp) {
    this.unimplemented();
    cb && cb();
    return;
  }

  var i, kat = sjcl.test.vector.srp, tv, hash, group, verifier, client, server;

  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    hash = sjcl.hash[tv.hash];
    group = sjcl.keyexchange.srp.groups[tv.group];

    salt = sjcl.codec.hex.toBits(tv.s);

    /* check calculateVerifier */
    client = new sjcl.keyexchange.srp.client(tv.I, tv.P, hash, group);
    var res = client.calculateVerifier(salt);
    verifier = sjcl.codec.hex.toBits(tv.v);
    this.require(sjcl.bitArray.equal(res.salt, salt), "srp salt #" + i);
    this.require(sjcl.bitArray.equal(res.verifier, verifier), "srp verifier #" + i);

    /* check _calculateX */
    client = new sjcl.keyexchange.srp.client(tv.I, tv.P, hash, group);
    var x = client._calculateX(salt);
    this.require(sjcl.bitArray.equal(x.toBits(), sjcl.codec.hex.toBits(tv.x)), "srp x #" + i);

    /* check group.calculateK */
    var k = group.calculateK(hash);
    this.require(sjcl.bitArray.equal(k.toBits(), sjcl.codec.hex.toBits(tv.k)), "srp k #" + i);

    /* check success */
    client = new sjcl.keyexchange.srp.client(tv.I, tv.P, hash, group);
    var clientA = client.getClientChallenge(sjcl.codec.hex.toBits(tv.a));
    this.require(sjcl.bitArray.equal(clientA, sjcl.codec.hex.toBits(tv.A)), "srp A #" + i);

    server = new sjcl.keyexchange.srp.server(tv.I, salt, verifier, hash, group);
    var serverB = server.getServerChallenge(sjcl.codec.hex.toBits(tv.b));
    this.require(sjcl.bitArray.equal(serverB, sjcl.codec.hex.toBits(tv.B)), "srp B #" + i);

    var clientK = client.setServerResponse(salt, serverB);
    this.require(sjcl.bitArray.equal(client._u.toBits(), sjcl.codec.hex.toBits(tv.u)), "srp client u #" + i);
    this.require(sjcl.bitArray.equal(client._S.toBits(), sjcl.codec.hex.toBits(tv.S)), "srp client S #" + i);

    var serverK = server.setClientResponse(clientA);
    this.require(sjcl.bitArray.equal(server._u.toBits(), sjcl.codec.hex.toBits(tv.u)), "srp server u #" + i);
    this.require(sjcl.bitArray.equal(server._S.toBits(), sjcl.codec.hex.toBits(tv.S)), "srp server S #" + i);

    this.require(sjcl.bitArray.equal(clientK, serverK), "srp K #" + i);
    var clientM = client.getClientAuth();
    this.require(!server.authenticated, "srp client !auth #" + i);
    var auth = server.authenticateClient(clientM);
    this.require(auth && server.authenticated, "srp client auth #" + i);

    var serverM = server.getServerAuth();
    this.require(!client.authenticated, "srp server !auth #" + i);
    var auth = client.authenticateServer(serverM);
    this.require(auth && client.authenticated, "srp server auth #" + i);

    /* check fail */
    client = new sjcl.keyexchange.srp.client(tv.I, tv.P + "1", hash, group);
    var clientA = client.getClientChallenge(sjcl.codec.hex.toBits(tv.a));

    server = new sjcl.keyexchange.srp.server(tv.I, salt, verifier, hash, group);
    var serverB = server.getServerChallenge(sjcl.codec.hex.toBits(tv.b));

    var clientK = client.setServerResponse(salt, serverB);
    var serverK = server.setClientResponse(clientA);

    this.require(!sjcl.bitArray.equal(clientK, serverK), "srp bad K #" + i);
    var clientM = client.getClientAuth();
    this.require(!server.authenticated, "srp bad client !auth #" + i);
    var auth = server.authenticateClient(clientM);
    this.require(!auth && !server.authenticated, "srp bad client !auth #" + i);
  }
  cb && cb();
});
