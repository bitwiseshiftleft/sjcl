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
 * @param {Object}          [hash=sjcl.hash.sha256]      The hash function to use for HKDF
 */
sjcl.pake = function(clientIdOrAId, serverIdOrBId, useSpake2, ee, curve, Hash) {
  var algoName;

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
  this.started = false;
  this.finished = false;
  this.ee = !!ee;
  this.useSpake2 = !!useSpake2;
  if (!useSpake2) {
    algoName = "PAKE2+" + (!ee ? "" : "EE");
  } else {
    algoName = "SPAKE2" + (!ee ? "" : "-EE");
  }
  this.algoName = algoName;

  if (!ee) {
    if (this.curve.N && this.curve.M) {
      this.N = this.curve.N;
      this.M = this.curve.M;
    } else {
      this.N = this._generatePoint(algoName + " N");
      this.M = this._generatePoint(algoName + " M");
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
 * @param {Object}          [hash=sjcl.hash.sha256]      The hash function to use for HKDF
 */
sjcl.pake.createSpake2 = function(aId, bId, ee, curve, Hash) {
  var spake2 = new sjcl.pake(aId, bId, true, ee, curve, Hash);

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
 * @param {Object}          [hash=sjcl.hash.sha256]      The hash function to use for HKDF
 */
sjcl.pake.createPake2Plus = function(clientId, serverId, ee, curve, Hash) {
  var pake2Plus = new sjcl.pake(clientId, serverId, false, ee, curve, Hash);

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
   * @param {point|bitArray} pwKey1_M Server's "pwKey1*M"
   * @param {point|bitArray} pwKey1_N Server's "pwKey1*N"
   * @param {bitArray}       pwKey2   Shared key pwKey2
   * @param {point|bitArray} pwKey3_G Server's pwKey3*G
   * @param {Number}         paranoia Paranoia for generation (default 6)
   * @return {bitArray} Data to send to client
   */
  startServer: function(pwKey1_M, pwKey1_N, pwKey2, pwKey3_G, paranoia) {
    if (this.started) {
      throw new sjcl.exception.invalid("PAKE already started");
    }
    if (this.useSpake2) {
      throw new sjcl.exception.invalid("This is SPAKE2 not PAKE2+");
    }

    // Copy info
    if (pwKey1_M instanceof Array) {
      pwKey1_M = this.curve.fromBits(pwKey1_M);
    }
    if (pwKey1_N instanceof Array) {
      pwKey1_N = this.curve.fromBits(pwKey1_N);
    }
    if (pwKey3_G instanceof Array) {
      pwKey3_G = this.curve.fromBits(pwKey3_G);
    }
    this.myPwKey1Pt    = pwKey1_M;
    this.otherPwKey1Pt = pwKey1_N;
    this.pwKey2        = pwKey2;
    this.pwKey3_G      = pwKey3_G;

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
    var rBits = this.curve.r.bitLength(), keys, tmp;

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
        this.myPwKey1Pt = keys.pwKey1_N;
        this.otherPwKey1Pt = keys.pwKey1_M;
      } else {
        this.myPwKey1Pt = this.N;
        this.otherPwKey1Pt = this.M;
        this.pwKey1 = keys.pwKey1;
      }
      if (!isA) {
        tmp = this.myPwKey1Pt;
        this.myPwKey1Pt = this.otherPwKey1Pt;
        this.otherPwKey1Pt = tmp;
      }
      this.pwKey2 = keys.pwKey2;
      this.pwKey3 = keys.pwKey3;
    }

    // Generate data
    this.sec = sjcl.bn.random(this.curve.r, paranoia);
    // ee or server
    if (this.ee || (!this.useSpake2 && !isA)) {
      // a*G + {pwKey1_N|pwKey1_M}
      this.myData = this.curve.G.toJac().mult(this.sec, this.curve.G).add(this.myPwKey1Pt).toAffine().toBits();
    } else {
      // a*G + pwKey1*{N|M}
      this.myData = this.curve.G.mult2(this.sec, this.pwKey1, this.myPwKey1Pt).toBits();
    }
    return this.myData;
  },

  /**
   * Generates the server data.
   *
   * @param {bitArray} sharedKey The shared key between the client and server (ie salted and iterated password hash)
   * @return {Array} Server data
   */
  generateServerData: function(sharedKey) {
    var pwKey1_M, pwKey1_N, pwKey3_G, keys;

    if (this.useSpake2) {
      throw new sjcl.exception.invalid("This is SPAKE2 not PAKE2+");
    }

    // Generate password keys
    keys = this._generateKeys(sharedKey);
    if (this.ee) {
      pwKey1_M = keys.pwKey1_M; // Server's deterministicRandomPoint(pwKey1, "M").
      pwKey1_N = keys.pwKey1_N; // Server's deterministicRandomPoint(pwKey1, "N").
    } else {
      pwKey1_M = this.M.mult(keys.pwKey1); // Server's pwKey1*M.
      pwKey1_N = this.N.mult(keys.pwKey1); // Server's pwKey1*N.
    }
    pwKey3_G = this.curve.G.mult(keys.pwKey3); // Server's pwKey3*G.

    return { "pwKey1_M": pwKey1_M, "pwKey1_N": pwKey1_N, "pwKey2": keys.pwKey2, "pwKey3_G": pwKey3_G };
  },

  /**
   * Finishes the PAKE operation.
   *
   * @param {bitArray} othersData Data from the other side
   * @return {bitArray} Key
   */
  finish: function(othersData) {
    var key = new this.Hash(), aIdLen, bIdLen, othersPub, dhKey, pw3_serverSec_G;

    if (!this.started) {
      throw new sjcl.exception.invalid("PAKE hasn't started");
    }
    if (this.finished) {
      throw new sjcl.exception.invalid("PAKE already finished");
    }
    this.started  = false; // reset
    this.finished = true;

    // key = H(
    //         bitLen32bitBE(aId) || aId ||
    //         bitLen32bitBE(bId) || bId ||
    //         aData || bData || dhKey || pw2 [|| pw3*serverSec*G])

    // bitLen32bitBE(aId) || aId || bitLen32bitBE(bId) || bId
    if (typeof this.aId === "string") {
      aIdLen = 8 * this.aId.length;
    } else {
      aIdLen = sjcl.bitArray.bitLength(this.aId);
    }
    if (typeof this.bId === "string") {
      bIdLen = 8 * this.bId.length;
    } else {
      bIdLen = sjcl.bitArray.bitLength(this.bId);
    }
    key.update([sjcl.bitArray.partial(32, aIdLen & 0xffffffff)]);
    key.update(this.aId);
    key.update([sjcl.bitArray.partial(32, bIdLen & 0xffffffff)]);
    key.update(this.bId);

    // aData || bData
    if (this.isA) {
      key.update(this.myData);
      key.update(othersData);
    } else {
      key.update(othersData);
      key.update(this.myData);
    }

    othersData = this.curve.fromBits(othersData);
    if (!othersData.isValid() || !othersData.mult(this.curve.r).isIdentity) {
      throw new sjcl.exception.invalid("othersData is not a valid point");
    }
    // ee or server
    if (this.ee || (!this.useSpake2 && !this.isA)) {
      othersPub = othersData.toJac().add(this.otherPwKey1Pt.negate()).toAffine();
    } else {
      othersPub = othersData.toJac().add(this.otherPwKey1Pt.negate().mult(this.pwKey1)).toAffine();
    }
    dhKey = othersPub.mult(this.sec).toBits();

    // dhKey || pw2 [|| pw3*serverSec*G]
    key.update(dhKey);
    key.update(this.pwKey2);
    if (!this.useSpake2) {
      if (this.isA) {
        pw3_serverSec_G = othersPub.mult(this.pwKey3).toBits();
      } else {
        pw3_serverSec_G = this.pwKey3_G.mult(this.sec).toBits();
      }
      key.update(pw3_serverSec_G);
    }
    return key.finalize();
  },

  /**
   * Generates pw1 (or pw1 points), pw2, pw3 keys.
   *
   * @private
   * @param {String|bitArray} sharedKey The shared key between the client and server (ie salted and iterated password hash)
   * @return {Object} The key data
   */
  _generateKeys: function(sharedKey) {
    var rBits = 8 * ((this.curve.r.bitLength() + 7) >> 3),
      mBits = 8 * ((this.curve.field.modulus.bitLength() + 7) >> 3),
      keys = {};

    if (this.ee) {
      keys.pwKey1_M = this.curve.deterministicRandomPoint(
        sjcl.bn.fromBits(sjcl.misc.hkdf(sharedKey, mBits + 128, null, this.algoName + " PW1 M", this.Hash))
        .mod(this.curve.field.modulus));
      keys.pwKey1_N = this.curve.deterministicRandomPoint(
        sjcl.bn.fromBits(sjcl.misc.hkdf(sharedKey, mBits + 128, null, this.algoName + " PW1 N", this.Hash))
        .mod(this.curve.field.modulus));
    } else {
      keys.pwKey1 = sjcl.bn.fromBits(sjcl.misc.hkdf(sharedKey, rBits + 128, null, this.algoName + " PW1", this.Hash))
        .mod(this.curve.r);
    }
    keys.pwKey2 =                  sjcl.misc.hkdf(sharedKey,         256, null, this.algoName + " PW2", this.Hash);
    keys.pwKey3 = sjcl.bn.fromBits(sjcl.misc.hkdf(sharedKey, rBits + 128, null, this.algoName + " PW3", this.Hash))
        .mod(this.curve.r);

    return keys;
  },

  /**
   * Generates a deterministic random point on the curve given a name.
   *
   * @private
   * @param {String} name The name of point
   * @return {point} Point
   */
  _generatePoint: function(name) {
    var mBits = 8 * ((this.curve.field.modulus.bitLength() + 7) >> 3);

    if (!this.curve.canDeterministicRandomPoint()) {
      throw new sjcl.exception.bug(
        "_generatePoint isn't fully implemented and curve doesn't " +
        "support creating a deterministic random point in constant time");
    }
    return this.curve.deterministicRandomPoint(
      sjcl.bn.fromBits(sjcl.misc.hkdf(name, mBits + 128, null, "", this.Hash))
      .mod(this.curve.field.modulus));
  }
};
