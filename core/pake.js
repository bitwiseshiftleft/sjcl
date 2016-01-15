/** @fileOverview SPAKE2/SPAKE2-EE/PAKE2+/PAKE2+EE implementation.
 *
 * PAKE2+/PAKE2+EE is a client-server PAKE
 * SPAKE2/SPAKE2-EE is a peer to peer PAKE
 * PAKE2+/PAKE2+EE can work as a peer to peer PAKE but requires more work than SPAKE2/SPAKE2-EE.
 *
 * @author Steve Thomas
 */

/**
 * Construct a SPAKE2, SPAKE2-EE, PAKE2+, or PAKE2+EE.
 *
 * @constructor
 * @param {String|bitArray} clientIdOrAId                ID of client (user name, email, etc) or ID of user A
 * @param {String|bitArray} serverIdOrBId                ID of server (domain name) or ID of user B
 * @param {Bool}            [useSpake2=false]            Use SPAKE2 or PAKE2+
 * @param {Bool}            [ee=false]                   Use elligator edition
 * @param {sjcl.ecc.curve}  [curve=sjcl.ecc.curves.c256] The curve to use for SPAKE2/PAKE2+
 * @param {Object}          [Hash=sjcl.hash.sha256]      The hash function for finish()
 * @param {Bool}            [compressPoints=true]        Whether to compress points
 * @param {Bool}            [littleEndian=true]          Whether points are in little endian
 */
sjcl.pake = function(clientIdOrAId, serverIdOrBId, useSpake2, ee, curve, Hash, compressPoints, littleEndian) {
  curve = curve || 256;
  Hash = Hash || sjcl.hash.sha256;
  if (typeof curve === "number") {
    curve = sjcl.ecc.curves['c'+curve];
    if (curve === undefined) {
      throw new sjcl.exception.invalid("No such curve");
    }
  }

  this.aId = clientIdOrAId;
  this.bId = serverIdOrBId;
  this.curve = curve;
  this.Hash = Hash;
  this.compressPoints = !compressPoints;
  this.littleEndian = !littleEndian;
  this.started = false;
  this.finished = false;
  this.ee = !!ee;
  this.useSpake2 = !!useSpake2;

  if (!ee) {
    if (this.curve.N && this.curve.M) {
      this.N = this.curve.N;
      this.M = this.curve.M;
    } else {
      this.N = this._generatePoint("N");
      this.M = this._generatePoint("M");
    }
  } else if (!this.curve.canDeterministicRandomPoint()) {
    throw new sjcl.exception.invalid("Curve doesn't support creating a deterministic random point in constant time");
  }
};

/**
 * Creates a sjcl.pake for SPAKE2.
 *
 * @param {String|bitArray} aId                          ID of user A
 * @param {String|bitArray} bId                          ID of user B
 * @param {Bool}            [ee=false]                   Use elligator edition
 * @param {sjcl.ecc.curve}  [curve=sjcl.ecc.curves.c256] The curve to use for SPAKE2
 * @param {Object}          [Hash=sjcl.hash.sha256]      The hash function for finish()
 * @param {Bool}            [compressPoints=true]        Whether to compress points
 * @param {Bool}            [littleEndian=true]          Whether points are in little endian
 */
sjcl.pake.createSpake2 = function(aId, bId, ee, curve, Hash, compressPoints, littleEndian) {
  var spake2 = new sjcl.pake(aId, bId, true, ee, curve, Hash, compressPoints, littleEndian);

  spake2.startClient = undefined;
  spake2.startServer = undefined;
  spake2.generateServerData = undefined;
  return spake2;
};

/**
 * Creates a sjcl.pake for PAKE2+.
 *
 * @param {String|bitArray} clientId                     ID of client (user name, email, etc)
 * @param {String|bitArray} serverId                     ID of server (domain name)
 * @param {Bool}            [ee=false]                   Use elligator edition
 * @param {sjcl.ecc.curve}  [curve=sjcl.ecc.curves.c256] The curve to use for PAKE2+
 * @param {Object}          [Hash=sjcl.hash.sha256]      The hash function for finish()
 * @param {Bool}            [compressPoints=true]        Whether to compress points
 * @param {Bool}            [littleEndian=true]          Whether points are in little endian
 */
sjcl.pake.createPake2Plus = function(clientId, serverId, ee, curve, Hash, compressPoints, littleEndian) {
  var pake2Plus = new sjcl.pake(clientId, serverId, false, ee, curve, Hash, compressPoints, littleEndian);

  pake2Plus.startA = undefined;
  pake2Plus.startB = undefined;
  return pake2Plus;
};

sjcl.pake.prototype = {
  /**
   * Starts user A side operation.
   *
   * @param {bitArray} sharedKey The shared key between user A and B (ie salted and iterated password hash)
   * @param {Number}   paranoia  Paranoia for generation (default 6)
   * @return {bitArray} Data to send to user B
   */
  startA: function(sharedKey, paranoia) {
    if (!this.useSpake2) {
      throw new sjcl.exception.invalid("This is PAKE2+ not SPAKE2");
    }
    return this._start(sharedKey, true, paranoia);
  },

  /**
   * Starts user B side operation.
   *
   * @param {bitArray} sharedKey The shared key between user A and B (ie salted and iterated password hash)
   * @param {Number}   paranoia  Paranoia for generation (default 6)
   * @return {bitArray} Data to send to user A
   */
  startB: function(sharedKey, paranoia) {
    if (!this.useSpake2) {
      throw new sjcl.exception.invalid("This is PAKE2+ not SPAKE2");
    }
    return this._start(sharedKey, false, paranoia);
  },

  /**
   * Starts the client side operation.
   *
   * @param {bitArray} sharedKey The shared key between the client and server (ie salted and iterated password hash)
   * @param {Number}   paranoia  Paranoia for generation (default 6)
   * @return {bitArray} Data to send to server
   */
  startClient: function(sharedKey, paranoia) {
    if (this.useSpake2) {
      throw new sjcl.exception.invalid("This is SPAKE2 not PAKE2+");
    }
    return this._start(sharedKey, true, paranoia);
  },

  /**
   * Starts the server side operation.
   *
   * @param {point|bitArray} pw_M     Server's "pw*M"
   * @param {point|bitArray} pw_N     Server's "pw*N"
   * @param {bitArray}       pw       Shared key pw
   * @param {point|bitArray} pw2_G    Server's pw2*G
   * @param {Number}         paranoia Paranoia for generation (default 6)
   * @return {bitArray} Data to send to client
   */
  startServer: function(pw_M, pw_N, pw, pw2_G, paranoia) {
    if (this.started) {
      throw new sjcl.exception.invalid("PAKE already started");
    }
    if (this.useSpake2) {
      throw new sjcl.exception.invalid("This is SPAKE2 not PAKE2+");
    }

    // Copy info
    if (pw_M instanceof Array) {
      pw_M = this.curve.fromBits(pw_M);
    }
    if (pw_N instanceof Array) {
      pw_N = this.curve.fromBits(pw_N);
    }
    if (pw2_G instanceof Array) {
      pw2_G = this.curve.fromBits(pw2_G);
    }
    this.myPt     = pw_N;
    this.othersPt = pw_M;
    this.pw       = pw;
    this.pw2_G    = pw2_G;

    return this._start(null, false, paranoia);
  },

  /**
   * Starts PAKE operation.
   *
   * @private
   * @param {bitArray} sharedKey The shared key between user A and user B or client and server
   *                             (ie salted and iterated password hash) [ignored if server]
   * @param {bool}     isA       If user A or client
   * @param {Number}   paranoia  Paranoia for generation (default 6)
   * @return {bitArray} Data to send to other side
   */
  _start: function(sharedKey, isA, paranoia) {
    var rBits = this.curve.r.bitLength(), keys, tmp, myData;

    if (this.started) {
      throw new sjcl.exception.invalid("PAKE already started");
    }
    this.started  = true;
    this.finished = false;
    this.isA      = !!isA;

    // Generate password keys
    // if not server
    if (this.useSpake2 || !!isA) {
      keys = this._generateKeys(sharedKey);
      if (this.ee) {
        this.myPt = keys.pw_M;
        this.othersPt = keys.pw_N;
      } else {
        this.myPt = this.M;
        this.othersPt = this.N;
        this.pwScalar = keys.pwScalar;
      }
      if (!isA) {
        tmp = this.myPt;
        this.myPt = this.othersPt;
        this.othersPt = tmp;
      }
      this.pw = keys.pw;
      this.pw2Scalar = keys.pw2Scalar;
    }

    // Generate data
    this.sec = sjcl.bn.random(this.curve.r, paranoia);
    // ee or server
    if (this.ee || (!this.useSpake2 && !isA)) {
      // a*G + {pw_M|pw_N}
      myData = this.curve.G.toJac().mult(this.sec, this.curve.G).add(this.myPt).toAffine();
    } else {
      // a*G + pwScalar*{M|N}
      myData = this.curve.G.mult2(this.sec, this.pwScalar, this.myPt);
    }
    this.myData = myData.toBits(this.compressPoints, this.littleEndian);
    return sjcl.bitArray.concat(sjcl.codec.utf8String.toBits(!isA ? "B" : "A"), this.myData);
  },

  /**
   * Generates the server data.
   *
   * @param {bitArray} sharedKey The shared key between the client and server (ie salted and iterated password hash)
   * @return {Array} Server data
   */
  generateServerData: function(sharedKey) {
    var pw_M, pw_N, pw2_G, keys;

    if (this.useSpake2) {
      throw new sjcl.exception.invalid("This is SPAKE2 not PAKE2+");
    }

    // Generate password keys
    keys = this._generateKeys(sharedKey);
    if (this.ee) {
      pw_M = keys.pw_M; // Server's deterministicRandomPoint(pw, "M").
      pw_N = keys.pw_N; // Server's deterministicRandomPoint(pw, "N").
    } else {
      pw_M = this.M.mult(keys.pwScalar); // Server's pwScalar*M.
      pw_N = this.N.mult(keys.pwScalar); // Server's pwScalar*N.
    }
    pw2_G = this.curve.G.mult(keys.pw2Scalar); // Server's pwKey3*G.

    return { "pw_M": pw_M, "pw_N": pw_N, "pw": keys.pw, "pw2_G": pw2_G };
  },

  /**
   * Finishes the PAKE operation.
   *
   * @param {bitArray} othersData Data from the other side
   * @return {bitArray} Key
   */
  finish: function(othersData) {
    var key = new this.Hash(), othersPub, dhKey, pw2_serverSec_G;

    if (!this.started) {
      throw new sjcl.exception.invalid("PAKE hasn't started");
    }
    if (this.finished) {
      throw new sjcl.exception.invalid("PAKE already finished");
    }
    this.started  = false; // reset
    this.finished = true;

    // key = H(H(aId) || H(bId) || aData || bData || dhKey || pw [|| pw2Scalar*serverSec*G])

    // H(aId) || H(bId)
    key.update(this.Hash.hash(this.aId));
    key.update(this.Hash.hash(this.bId));

    // aData || bData
    othersData = sjcl.bitArray.bitSlice(othersData, 8);
    if (this.isA) {
      key.update(this.myData);
      key.update(othersData);
    } else {
      key.update(othersData);
      key.update(this.myData);
    }

    // Check others point
    othersData = this.curve.fromBits(othersData, this.littleEndian);
    if (!othersData.isValid() || !othersData.mult(this.curve.r).isIdentity) {
      throw new sjcl.exception.invalid("othersData is not a valid point");
    }

    // ee or server
    if (this.ee || (!this.useSpake2 && !this.isA)) {
      othersPub = othersData.toJac().add(this.othersPt.negate()).toAffine();
    } else {
      othersPub = othersData.toJac().add(this.othersPt.negate().mult(this.pwScalar)).toAffine();
    }
    dhKey = othersPub.mult(this.sec).toBits(this.compressPoints, this.littleEndian);

    // dhKey || pw [|| pw2Scalar*serverSec*G]
    key.update(dhKey);
    key.update(this.pw);
    if (!this.useSpake2) {
      if (this.isA) {
        pw2_serverSec_G = othersPub.mult(this.pw2Scalar).toBits(this.compressPoints, this.littleEndian);
      } else {
        pw2_serverSec_G = this.pw2_G.mult(this.sec).toBits(this.compressPoints, this.littleEndian);
      }
      key.update(pw2_serverSec_G);
    }
    return key.finalize();
  },

  /**
   * Generates keys.
   *
   * @private
   * @param {String|bitArray} sharedKey The shared key between the client and server (ie salted and iterated password hash)
   * @return {Object} The key data
   */
  _generateKeys: function(sharedKey) {
    var keys = {}, pw, sha512 = new sjcl.hash.sha512();

    // Copy sharedKey
    if (sharedKey instanceof Array) {
      pw = sharedKey.slice(0);
    } else {
      pw = sjcl.codec.utf8String.toBits(sharedKey);
    }

    // Generate keys
    if (this.useSpake2) {
      keys.pw = pw;
      pw = sjcl.hash.sha512.hash(pw);
    } else {
      sha512.update("2");
      sha512.update(pw);
      keys.pw2Scalar = sjcl.bn.fromBits(sha512.finalize()).mod(this.curve.r);
      sha512.update("1");
      sha512.update(pw);
      keys.pw = pw = sha512.finalize();
    }
    if (this.ee) {
      keys.pw_M = this._generatePoint("M", pw);
      keys.pw_N = this._generatePoint("N", pw);
    } else {
      keys.pwScalar = sjcl.bn.fromBits(pw).mod(this.curve.r);
    }
    return keys;
  },

  /**
   * Generates a deterministic random point on the curve given a name.
   *
   * @private
   * @param {String|bitArray} name The name of point
   * @param {String|bitArray} name2 The name of point
   * @return {point} Point
   */
  _generatePoint: function(name, name2) {
    var sha512 = new sjcl.hash.sha512();

    sha512.update(name || "");
    sha512.update(name2 || "");
    return this.curve.deterministicRandomPoint(
      sjcl.bn.fromBits(sha512.finalize())
      .mod(this.curve.field.modulus));
  }
};
