/** @fileOverview Keccak
 *
 * @author Stefan Bühler
 */

 /** Create a Keccak sponge class with given parameters. Uses
  * {@link sjcl.hash.sponge.makeClass} and adds a width and a capacity
  * property.
  * @param {Number} capacity          The capacity of the sponge
  * @param {Number} [out=2*capacity]  The output bit width
  * @param {Number} [width=1600]      Bitwidth for {@link sjcl.hash.keccak.fPermutation}
  * @param {function} [pad]           Custom padding function (defaults to
  *     {@link sjcl.hash.sponge.pad_101})
  * @return {function} Sponge class
  */
 sjcl.hash.keccak = function (capacity, out, width, pad) {
   var rate, fPerm, sponge = sjcl.hash.sponge, constr;
   out = out || (capacity >>> 1);
   capacity = capacity || 2 * out;
   width = width || 1600;
   rate = width - capacity;
   fPerm = fPermutation(width);
   pad = pad || sponge.pad_101;

   constr = sponge.makeClass(fPerm, pad, rate, out);
   // set additional properties
   constr.width = width;
   constr.capacity = capacity;
   return constr;
 };

/** @ignore */
var fPermutation = (function() {
  // Keccak 1600: each lane as [low,high] little endian (32-bit) words. state[2*(5*y+x)] = low, state[2*(5*y+x)+1] = high
  // Keccak <= 800: each lane as little endian word in state[5*y+x]

  var RC, rhoBY, piMAP;

  function precompute() {
    var p, rc, i, j, x, y;
    // RC
    RC = [];
    p = 1; // p = X^0 = 1
    for (i = 0; i < 24; ++i) {
      rc = 0;
      for (j = 0; j < 6; ++j) {
        rc ^= (p & 0x1) << ((1 << j) - 1); // (p mod X) << (2^j - 1)
        if (0x100 & (p <<= 1)) { p ^= 0x171; } // p := (p * X) mod X^8 + X^6 + X^5 + X^4 + 1
      }
      RC[i] = [rc,p << 31]; // 31 = (2^6-1) - 32: high word
      if (0x100 & (p <<= 1)) { p ^= 0x171; }
    }
    // rhoBY
    rhoBY = [0];
    x = 1; y = 0;
    for (i = 0; i < 24; ++i) {
      rhoBY[x+5*y] = (((i+1)*(i+2))/2) & 63;
      y = (2*x+3*y)%5; x = (x+2*y)%5;
    }
    // piMAP
    piMAP = [];
    for (x = 0; x < 5; ++x) {
      for (y = 0; y < 5; ++y) {
        piMAP[x+5*y] = y + 5*((2*x+3*y)%5);
      }
    }
  }

  /** Run the Keccak-f transformation on a 1600-bit state
   * @name sjcl.hash.keccak.f1600
   * @param {sjcl.bitArrayLE} a  The state to transform (gets modified)
   * @return {sjcl.bitArrayLE}   The modified state
   */
  function keccak_f1600(state) {
    // manually inlined
    var i,
      buf = state.slice(),
      ccL,ccH,ddL,ddH,x,y,x1,x2,x4,
      k,lo, hi, t, by;
    if (!RC) { precompute(); }
    for (i = 0; i < 24; ++i) {
      // theta
      for (x = 0; x < 10; x+=2) {
        ccL = state[x]; ccH = state[x+1];
        for (y = 10; y < 50; y+=10) {
          ccL ^= state[x+y]; ccH ^= state[x+y+1];
        }
        buf[x] = ccL; buf[x+1] = ccH;
      }
      for (x = 0; x < 10; x+=2) {
        x1 = (x+2) % 10; x4 = (x+8) % 10;
        ddL = buf[x1]; ddH = buf[x1+1];
        ccL = buf[x4] ^ (ddL << 1 | ddH >>> 31);
        ccH = buf[x4+1] ^ (ddH << 1 | ddL >>> 31);
        for(y = 0; y < 50; y+=10) {
          state[x+y] ^= ccL;
          state[x+y+1] ^= ccH;
        }
      }
      // rhopi (state -> buf)
      for (k = 0; k < 25; ++k) {
        by = rhoBY[k];
        lo = state[2*k]; hi = state[2*k+1];
        if (by >= 32) { t = lo; lo = hi; hi = t; }
        t = piMAP[k];
        if ((by &= 31)) {
          buf[2*t] = lo << by | hi >>> (32-by);
          buf[2*t+1] = hi << by | lo >>> (32-by);
        } else {
          buf[2*t] = lo; buf[2*t+1] = hi;
        }
      }
      // chi (buf -> state)
      for (x = 0; x < 10; x+=2) {
        x1 = (x+2)%10; x2 = (x+4)%10;
        for (y = 0; y < 50; y+=10) {
          state[x+y]   = buf[x+y]   ^ (~buf[x1+y]   & buf[x2+y]);
          state[x+y+1] = buf[x+y+1] ^ (~buf[x1+y+1] & buf[x2+y+1]);
        }
      }
      // iota
      state[0] ^= RC[i][0];
      state[1] ^= RC[i][1];
    }
    return state;
  }
  keccak_f1600.width = 1600;
  sjcl.hash.keccak.f1600 = keccak_f1600;

  /** Return the Keccak-f transformation for a state with (25 * 2^l) bits, for l <= 5 (=> w = 2^l <= 32, width <= 800)
   * (the 1600 bit state has an explicit function, as for l <= 5 only one word per lane is needed)
   * @return {function} the Keccak-f transformation, taking a {@link sjcl.bitArrayLE} to operate on, and returning the modified state
   */
  function keccak_f_gen(l) {
    var w = 1 << l, mask = w === 32 ? ~0 : (1 << w) - 1, rounds = 12 + 2*l;

    function rotate(x, by) {
      if (!(by %= w)) { return x; }
      return ((x << by) | (x >>> (w - by))) & mask;
    }

    function read(data) {
      var i, j, p, v, l = 32 / w, state = [];
      for (i = 0, p = 0; i < 25; ++p) {
        v = data[p];
        for (j = 0; i < 25 && j < l; ++j, ++i) {
          state[i] = v & mask; v >>>= w;
        }
      }
      return state;
    }
    function write(data, state) {
      var i, j, p, v, l = 32 / w;
      for (i = 0, p = 0; i < 25; ++p) {
        v = 0;
        for (j = 0; j < l; ++j, ++i) {
          v = (v >>> w) | ((state[i] & mask) << (32 - w));
        }
        data[p] = v;
      }
    }

    /** Run the Keccak-f transformation
     * @param {sjcl.bitArrayLE} a  The state to transform (gets modified)
     * @return {sjcl.bitArrayLE}   The modified state
     */
    function keccak_f(data) {
      var state, i, buf,
        cc, x, y, k, x1, x2;
      if (!RC) { precompute(); }

      state = w === 32 ? data : read(data);
      buf = state.slice();
      for (i = 0; i < rounds; ++i) {
        // theta
        for (x = 0; x < 5; ++x) {
          cc = state[x];
          for (y = 5; y < 25; y+=5) {
            cc ^= state[x + y];
          }
          buf[x] = cc;
        }
        for (x = 0; x < 5; ++x) {
          cc = buf[(x+1)%5];
          cc = ((cc << 1) | (cc >>> (w - 1))) & mask;
          cc ^= buf[(x+4)%5];
          for(y = 0; y < 25; y+=5) {
            state[x + y] ^= cc;
          }
        }
        // rho + pi (state -> buf)
        for (k = 0; k < 25; ++k) {
          buf[piMAP[k]] = rotate(state[k], rhoBY[k]);
        }
        // chi (buf -> state)
        for (x = 0; x < 5; ++x) {
          x1 = (x+1)%5; x2 = (x+2)%5;
          for (y = 0; y < 25; y+=5) {
            state[x+y] = buf[x+y] ^ (~buf[x1+y] & buf[x2+y]);
          }
        }
        // iota
        state[0] ^= RC[i][0] & mask;
      }
      if (w !== 32) {
        write(data, state);
      }
      return data;
    }
    keccak_f.width = 25 * w;
    sjcl.hash.keccak['f' + keccak_f.width] = keccak_f;
    return keccak_f;
  }

  /** Create a Keccak-f transformation function for a specified bit width.
   * @function
   * @name sjcl.hash.keccak.fPermutation
   * @param {Number} bitwidth   Anything in [25,50,100,200,400,800,1600];
   *                            bitwidth = 25*2^l for 0 <= l <= 6
   * @return {function}         The transformation function: taking, modifying
   *                            and returning a {@link sjcl.bitArrayLE}
   */
  function keccak_f_get(b) {
    var f = sjcl.hash.keccak['f' + b], l;
    if (f) {
      return f;
    }
    l = [25,50,100,200,400,800,1600].indexOf(b);
    if (l < 0) {
      throw new sjcl.exception.invalid("invalid keccak bit width");
    }
    if (b === 1600) {
      return keccak_f1600;
    }
    if ('undefined' !== typeof keccak_f_gen) {
      return keccak_f_gen(l);
    }
    throw new sjcl.exception.invalid("keccak bit width < 1600 not supported");
  }

  return keccak_f_get;
}());

 // common keccak variants used for SHA3, SHAKE128 and SHAKE256
 /** Keccak[256] sponge (= sjcl.hash.keccak(256)) */
 sjcl.hash.keccak256 = sjcl.hash.keccak(256);
 /** Keccak[448] sponge (= sjcl.hash.keccak(448)) */
 sjcl.hash.keccak448 = sjcl.hash.keccak(448);
 /** Keccak[512] sponge (= sjcl.hash.keccak(512)) */
 sjcl.hash.keccak512 = sjcl.hash.keccak(512);
 /** Keccak[768] sponge (= sjcl.hash.keccak(768)) */
 sjcl.hash.keccak768 = sjcl.hash.keccak(768);
 /** Keccak[1024] sponge (= sjcl.hash.keccak(1024)) */
 sjcl.hash.keccak1024 = sjcl.hash.keccak(1024);
