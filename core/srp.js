/** @fileOverview Javascript SRP-6a implementation.
 *
 * This file contains an implementation of cryptographically strong network
 * authentication mechanism known as the Secure Remote Password (SRP) protocol.
 * It is suitable for negotiating secure connections using a user-supplied password.
 * It also performs a secure key exchange in the process of authentication.
 *
 * The supported version is SRP-6a, which is described in rfc5054 and at http://srp.stanford.edu/
 * Default hash function is SHA1 and default group is 1024-bit group from rfc5054
 *
 * Example Registration:
 * [client] client = new sjcl.keyex.srp.client(name, password);
 * [client] data = client.calculateVerifier();
 * [client -> server] (name, data.salt, data.verifier)
 * [server] store (name, salt, verifier)
 *
 * Example Authentication:
 * [client -> server] name
 * [server] lookup (salt, verifier) by name
 * [server] server = new sjcl.keyex.srp.server(name, salt, verifier);
 * [server] B = server.getServerChallenge();
 * [server -> client] (salt, B)
 * [client] client = new sjcl.keyex.srp.client(name, password);
 * [client] A = client.getClientChallenge();
 * [client] K = client.setServerResponse(salt, B);
 * [client] M1 = client.getClientAuth();
 * [client -> server] (A, M1)
 * [server] K = server.setClientResponse(A);
 * [server] OK1 = server.authenticateClient(M1);
 * [server] M2 = server.getServerAuth();
 * [server -> client] (M2)
 * [client] OK2 = client.authenticateServer(M2);
 * (If OK1 and OK2 are true, then authentication is successful.
 * In addition both server and client have the same secret session key K)
 *
 * For more information, see http://srp.stanford.edu/, rfc5054 and rfc2945.
 *
 * @author Valery Yundin
 */

/**
 * SRP namespace
 */
sjcl.keyex.srp = {
  /**
   * Private values SHOULD be at least 256-bit random numbers [rfc5054]
   * SECRET_BITS default size for private values to generate  (if not passed as an argument)
   * SECRET_BITS_MIN minimal acceptable secret size (will throw if less)
   */
  SECRET_BITS: 256,
  SECRET_BITS_MIN: 128,

  /**
   * SALT_BITS default size for salt to generate (if not passed as an argument)
   * SALT_BITS_MIN minimal acceptable salt size (will throw if less)
   */
  SALT_BITS: 64,
  SALT_BITS_MIN: 32,

  /**
   * DEFAULT_HASH name of default hash to use (if not passed as an argument)
   * DEFAULT_GROUP name of default group to use (if not passed as an argument)
   */
  DEFAULT_HASH: "sha1",
  DEFAULT_GROUP: "ng1024",

  /** Get known group by name
   * @param {String} name Group name
   * @return {sjcl.keyex.srp.group} Object with g and N properties
   */
  getGroup: function(name) {
    var group = sjcl.keyex.srp._groups[name];
    if (!group) {
      throw new sjcl.exception.invalid("No such group!");
    }
    group.initialize();
    return group;
  },

  /** Generate random words and truncate to given number of bits.
   * @param {Number} len The number of bits to generate.
   * @param {Number} paranoia Desired paranoia level.
   * @return {bitArray} random bitArray with len bits.
   */
  _randomBits: function (len, paranoia) {
    var out = sjcl.random.randomWords(Math.ceil(len / 32), paranoia);
    out = sjcl.bitArray.clamp(out, len);
    return out;
  },

  /**
  * Calculate SRP-6 u value.
  * @param {Object} Hash Hash function to use.
  * @param {Object} group Group to use (defines padding length).
  * @param {bitArray} A client A.
  * @param {bitArray} B server B.
  * @param {Boolean} omitpad If True do not pad A and B. If False pad as per rfc5054 TLS-SRP.
  * @return {sjcl.bn} SRP u value.
  */
  _calculateU: function(Hash, group, A, B, omitpad) {
    var padlen, u;
    if (!omitpad) {
      padlen = group.N.bitLength();
      A = sjcl.bitArray.zeropadLeft(A, padlen);
      B = sjcl.bitArray.zeropadLeft(B, padlen);
    }
    u = new Hash();
    u.update(A);
    u.update(B);
    u = sjcl.bn.fromBits(u.finalize());
    return u;
  },

  /**
  * Calculate SRP-6 authentication message: M1 = H(H(N) xor H(g), H(I), s, A, B, K).
  * @param {Object} Hash Hash function to use.
  * @param {Object} group Group to use.
  * @param {String} username Username.
  * @param {bitArray} salt User salt.
  * @param {bitArray} A client A.
  * @param {bitArray} B server B.
  * @param {bitArray} K shared K.
  * @return {bitArray} SRP M1 client authentication
  */
  _getAuth1: function(Hash, group, username, salt, A, B, K) {
    var M1 = new Hash();
    M1.update(group.calculatePM(Hash));
    M1.update(Hash.hash(username));
    M1.update(salt);
    M1.update(A);
    M1.update(B);
    M1.update(K);
    return M1.finalize();
  },

  /**
  * Calculate SRP-6 authentication message: M2 = H(A, M1, K).
  * @param {Object} Hash Hash function to use.
  * @param {bitArray} A client A.
  * @param {bitArray} M1 client authentication message.
  * @param {bitArray} K shared K.
  * @return {bitArray} SRP M2 server authentication
  */
  _getAuth2: function(Hash, A, M1, K) {
    var M2 = new Hash();
    M2.update(A);
    M2.update(M1);
    M2.update(K);
    return M2.finalize();
  },
};

/**
 * SRP Client
 * @constructor
 * @param {String} username Username.
 * @param {bitArray|String} password User password.
 * @param {Object} [Hash=sjcl.keyex.srp.DEFAULT_HASH] Hash function to use.
 * @param {Object} [group=sjcl.keyex.srp.DEFAULT_GROUP] Group to use.
 */
sjcl.keyex.srp.client = function(username, password, Hash, group) {
  if (typeof username !== "string") {
    throw new sjcl.exception.invalid("username must be a string!");
  }
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  this.username = username;
  this._password = password;
  this._Hash = Hash || sjcl.hash[sjcl.keyex.srp.DEFAULT_HASH];
  this._group = group || sjcl.keyex.srp.getGroup(sjcl.keyex.srp.DEFAULT_GROUP);

  if (!sjcl.keyex.srp.group.prototype.isPrototypeOf(this._group)) {
    throw new sjcl.exception.invalid("group must be a sjcl.keyex.srp.group!");
  }
};

sjcl.keyex.srp.client.prototype = {
  /**
  * Calculate SRP verifier with given salt.
  *    Verifier and salt are sent to server during client registration.
  * @param {bitArray} salt Random salt (random SALT_BITS bits if omitted).
  * @return {Object} SRP verifier as obj.verifier and random salt as obj.salt.
  */
  calculateVerifier: function(salt) {
    salt = salt || sjcl.keyex.srp._randomBits(sjcl.keyex.srp.SALT_BITS);
    if (typeof salt !== "object" || sjcl.bitArray.bitLength(salt) < sjcl.keyex.srp.SALT_BITS_MIN) {
      throw new sjcl.exception.invalid("Salt must be a bitArray longer than SALT_BITS_MIN!");
    }
    return {salt: salt, verifier: this._calculateV(salt).toBits()};
  },

  /**
  * Generate client challenge A.
  * @param {bitArray} secretA User secret ephemeral value a (random SECRET_BITS bits if omitted).
  * @return {bitArray} user public ephemeral value A.
  */
  getClientChallenge: function(secretA) {
    var group = this._group;

    secretA = secretA || sjcl.keyex.srp._randomBits(sjcl.keyex.srp.SECRET_BITS);
    if (typeof secretA !== "object" || sjcl.bitArray.bitLength(secretA) < sjcl.keyex.srp.SECRET_BITS_MIN) {
      throw new sjcl.exception.invalid("SecretA must be a bitArray longer than SECRET_BITS_MIN!");
    }

    this._secretA = sjcl.bn.fromBits(secretA);
    this._publicA = group.g.powermod(this._secretA, group.N);
    return this._publicA.toBits();
  },

  /**
  * Set salt and server response B.
  * @param {bitArray} salt User salt.
  * @param {bitArray} publicB Server public ephemeral value B.
  * @return {bitArray} Session key
  */
  setServerResponse: function(salt, publicB) {
    var group = this._group, u, k, x, v, S;

    if (typeof salt !== "object" || sjcl.bitArray.bitLength(salt) == 0) {
      throw new sjcl.exception.invalid("salt must be a bitArray!");
    }
    if (typeof publicB !== "object" || sjcl.bitArray.bitLength(publicB) == 0) {
      throw new sjcl.exception.invalid("publicB must be a bitArray!");
    }
    this._salt = salt;
    publicB = sjcl.bn.fromBits(publicB);
    if (publicB.mod(this._group.N).equals(0)) {
      throw new sjcl.exception.corrupt("A mod N == 0! SRP must be aborted!");
    }
    this._publicB = publicB;

    u = sjcl.keyex.srp._calculateU(this._Hash, group,
                                   this._publicA.toBits(), this._publicB.toBits());
    if (u.mod(group.N).equals(0)) {
      throw new sjcl.exception.corrupt("u mod N == 0! SRP must be aborted!");
    }
    this._u = u;

    /* S = (B - kg^x) ^ (a + ux) */
    k = group.calculateK(this._Hash);
    x = this._calculateX(this._salt);
    v = this._calculateV(this._salt, x);
    S = this._publicB.sub(v.mulmod(k, group.N));
    S = S.powermod(this._secretA.add(u.mulmod(x, group.N)), group.N);
    this._S = S;

    this._K = this._Hash.hash(this._S.toBits());
    return this._K;
  },

  /**
  * Calculate client authentication message.
  * @return {bitArray} SRP M1 client authentication
  */
  getClientAuth: function() {
    this._M1 = sjcl.keyex.srp._getAuth1(this._Hash, this._group, this.username, this._salt,
                                        this._publicA.toBits(), this._publicB.toBits(), this._K);
    return this._M1;
  },

  /**
  * Authenticate server.
  * @param {bitArray} serverM Server authentication message (optional).
  * @return {Boolean} True indicates authentication success and False failure.
  */
  authenticateServer: function(serverM) {
    if (typeof serverM !== "object" || sjcl.bitArray.bitLength(serverM) == 0) {
      throw new sjcl.exception.invalid("serverM must be a bitArray!");
    }
    this._M2 = sjcl.keyex.srp._getAuth2(this._Hash, this._publicA.toBits(), this._M1, this._K);
    this.authenticated = sjcl.bitArray.equal(serverM, this._M2);
    return this.authenticated;
  },

  /**
  * Calculate SRP x
  * @param {bitArray} salt User salt.
  * @return {sjcl.bn} SRP x.
  */
  _calculateX: function(salt) {
    var password_hash, x;

    password_hash = new this._Hash();
    password_hash.update(this.username);
    password_hash.update(":");
    password_hash.update(this._password);
    password_hash = password_hash.finalize();

    x = new this._Hash();
    x.update(salt);
    x.update(password_hash);
    return sjcl.bn.fromBits(x.finalize());
  },

  /**
  * Calculate SRP v
  * @param {bitArray} salt User salt.
  * @return {sjcl.bn} SRP v.
  */
  _calculateV: function(salt, x) {
    var group = this._group;

    x = x || this._calculateX(salt);
    return group.g.powermod(x, group.N);
  },

  /**
  * Test helper. Compare computed x against provided
  * @param {bitArray} salt User salt.
  * @param {bitArray} x SRP x
  * @return {Boolean} True is equal.
  */
  testX: function(salt, x) {
    return sjcl.bitArray.equal(this._calculateX(salt).toBits(), x);
  },

  /**
  * Test helper. Compare computed u against provided
  * @param {bitArray} u SRP u
  * @return {Boolean} True is equal.
  */
  testU: function(u) {
    return sjcl.bitArray.equal(this._u.toBits(), u);
  },

  /**
  * Test helper. Compare computed S against provided
  * @param {bitArray} S SRP S
  * @return {Boolean} True is equal.
  */
  testS: function(S) {
    return sjcl.bitArray.equal(this._S.toBits(), S);
  },
};

/**
 * SRP Server
 * @constructor
 * @param {String} username Username.
 * @param {bitArray} salt User salt.
 * @param {bitArray} verifier User password verifier.
 * @param {Object} [Hash=sjcl.keyex.srp.DEFAULT_HASH] Hash function to use.
 * @param {Object} [group=sjcl.keyex.srp.DEFAULT_GROUP] Group to use.
 */
sjcl.keyex.srp.server = function(username, salt, verifier, Hash, group) {
  if (typeof username !== "string") {
    throw new sjcl.exception.invalid("username must be a string!");
  }
  if (typeof salt !== "object" || sjcl.bitArray.bitLength(salt) == 0) {
    throw new sjcl.exception.invalid("salt must be a bitArray!");
  }
  if (typeof verifier !== "object" || sjcl.bitArray.bitLength(verifier) == 0) {
    throw new sjcl.exception.invalid("verifier must be a bitArray!");
  }
  this.username = username;
  this._salt = salt;
  this._verifier = sjcl.bn.fromBits(verifier);
  this._Hash = Hash || sjcl.hash[sjcl.keyex.srp.DEFAULT_HASH];
  this._group = group || sjcl.keyex.srp.getGroup(sjcl.keyex.srp.DEFAULT_GROUP);

  if (!sjcl.keyex.srp.group.prototype.isPrototypeOf(this._group)) {
    throw new sjcl.exception.invalid("group must be a sjcl.keyex.srp.group!");
  }
};

sjcl.keyex.srp.server.prototype = {
  /**
  * Generate server challenge B.
  * @param {bitArray} secretB Server secret ephemeral value b (random SECRET_BITS bits if omitted).
  * @return {bitArray} server public ephemeral value B.
  */
  getServerChallenge: function(secretB) {
    var group = this._group, g2b, k;

    secretB = secretB || sjcl.keyex.srp._randomBits(sjcl.keyex.srp.SECRET_BITS);
    if (typeof secretB !== "object" || sjcl.bitArray.bitLength(secretB) < sjcl.keyex.srp.SECRET_BITS_MIN) {
      throw new sjcl.exception.invalid("SecretB must be a bitArray longer than SECRET_BITS_MIN!");
    }

    this._secretB = sjcl.bn.fromBits(secretB);
    g2b = group.g.powermod(this._secretB, group.N);
    k = group.calculateK(this._Hash);
    this._publicB = this._verifier.mulmod(k, group.N).addM(g2b).mod(group.N);
    return this._publicB.toBits();
  },

  /**
  * Set client response A.
  * @param {bitArray} publicA Client public ephemeral value A.
  * @return {bitArray} Session key.
  */
  setClientResponse: function(publicA) {
    var group = this._group, u, S;

    if (typeof publicA !== "object" || sjcl.bitArray.bitLength(publicA) == 0) {
      throw new sjcl.exception.invalid("publicA must be a bitArray!");
    }
    publicA = sjcl.bn.fromBits(publicA);
    if (publicA.mod(this._group.N).equals(0)) {
      throw new sjcl.exception.corrupt("A mod N == 0! SRP must be aborted!");
    }
    this._publicA = publicA;

    u = sjcl.keyex.srp._calculateU(this._Hash, group,
                                   this._publicA.toBits(), this._publicB.toBits());
    if (u.mod(group.N).equals(0)) {
      throw new sjcl.exception.corrupt("u mod N == 0! SRP must be aborted!");
    }
    this._u = u;

    /* S = (Av^u) ^ b */
    S = this._publicA.mulmod(this._verifier.powermod(u, group.N), group.N);
    S = S.powermod(this._secretB, group.N);
    this._S = S;

    this._K = this._Hash.hash(this._S.toBits());
    return this._K;
  },

  /**
  * Authenticate client.
  * @param {bitArray} clientM Client authentication message.
  * @return {Boolean} True indicates authentication success and False failure.
  */
  authenticateClient: function(clientM) {
    if (typeof clientM !== "object" || sjcl.bitArray.bitLength(clientM) == 0) {
      throw new sjcl.exception.invalid("clientM must be a bitArray!");
    }
    this._M1 = sjcl.keyex.srp._getAuth1(this._Hash, this._group, this.username, this._salt,
                                        this._publicA.toBits(), this._publicB.toBits(), this._K);
    this.authenticated = sjcl.bitArray.equal(clientM, this._M1);
    return this.authenticated;
  },

  /**
  * Calculate server authentication message (optional).
  * @return {bitArray} SRP M2 server authentication
  */
  getServerAuth: function() {
    this._M2 = sjcl.keyex.srp._getAuth2(this._Hash, this._publicA.toBits(), this._M1, this._K);
    return this._M2;
  },

  /**
  * Test helper. Compare computed u against provided
  * @param {bitArray} u SRP u
  * @return {Boolean} True is equal.
  */
  testU: function(u) {
    return sjcl.bitArray.equal(this._u.toBits(), u);
  },

  /**
  * Test helper. Compare computed S against provided
  * @param {bitArray} S SRP S
  * @return {Boolean} True is equal.
  */
  testS: function(S) {
    return sjcl.bitArray.equal(this._S.toBits(), S);
  },
};

/**
 * SRP Group Parameters
 *   Lazily converts arguments to bigInt in property getters
 * @constructor
 * @param {bigInt} N The prime.
 * @param {bigInt} g The generator.
 */
sjcl.keyex.srp.group = function(N, g, lazy) {
  this._N = N;
  this._g = g;
  if (!lazy) {
    this.initialize();
  }
};

sjcl.keyex.srp.group.prototype = {
  /**
  * Initialize g and N
  */
  initialize: function() {
    if (!this.N) {
      this.N = new sjcl.bn(this._N);
    }
    if (!this.g) {
      this.g = new sjcl.bn(this._g);
    }
  },

  /**
  * Calculate SRP k multiplier parameter for this group
  * @param {Object} Hash function to use.
  * @param {Boolean} omitpad If True do not pad the generator. If False pad as per rfc5054 TLS-SRP.
  * @return {sjcl.bn}
  */
  calculateK: function(Hash, omitpad) {
    var Nbits, gbits, k;
    Nbits = this.N.toBits();
    gbits = this.g.toBits();
    if (!omitpad) {
      gbits = sjcl.bitArray.zeropadLeft(gbits, sjcl.bitArray.bitLength(Nbits));
    }
    k = new Hash();
    k.update(Nbits);
    k.update(gbits);
    return sjcl.bn.fromBits(k.finalize());
  },

  /**
  * Calculate SRP authentication hash M prefix: H(N) xor H(g)
  * @param {Object} Hash Hash function to use.
  * @return {bitArray}
  */
  calculatePM: function(Hash) {
    var HN, Hg;
    HN = Hash.hash(this.N.toBits());
    Hg = Hash.hash(this.g.toBits());
    return sjcl.bitArray.xorAll(HN, Hg);
  },
};

/*
 * SRP Group Parameters from rfc5054 Appendix A
 *
 * Use sjcl.keyex.srp.getGroup to access these objects.
 */
sjcl.keyex.srp._groups = {
  ng1024: new sjcl.keyex.srp.group(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
    "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
    "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
    "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
    "FD5138FE8376435B9FC61D2FC0EB06E3",
    2,
    true
  ),
  ng1536: new sjcl.keyex.srp.group(
    "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961" +
    "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843" +
    "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B" +
    "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5" +
    "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A" +
    "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E" +
    "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
    2,
    true
  ),
  ng2048: new sjcl.keyex.srp.group(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
    "9E4AFF73",
    2,
    true
  ),
  ng3072: new sjcl.keyex.srp.group(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    5,
    true
  ),
  ng4096: new sjcl.keyex.srp.group(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
    "FFFFFFFFFFFFFFFF",
    5,
    true
  ),
  ng6144: new sjcl.keyex.srp.group(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" +
    "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406" +
    "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918" +
    "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151" +
    "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03" +
    "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F" +
    "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" +
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B" +
    "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632" +
    "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E" +
    "6DCC4024FFFFFFFFFFFFFFFF",
    5,
    true
  ),
  ng8192: new sjcl.keyex.srp.group(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" +
    "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406" +
    "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918" +
    "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151" +
    "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03" +
    "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F" +
    "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" +
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B" +
    "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632" +
    "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E" +
    "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA" +
    "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C" +
    "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9" +
    "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886" +
    "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6" +
    "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5" +
    "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268" +
    "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6" +
    "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71" +
    "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
    19,
    true
  ),
};
