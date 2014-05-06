/** @fileOverview Keccak-f permutations
 *
 * @author Stefan Bühler
 */

/** @ignore */
sjcl.hash.keccak_f = (function() {
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

/*
  // debug helpers to print internal states similar to official implementation
  function w32h(v) {
    var m = 4294967296;
    return ("00000000" + (((v ^ 0) + m) % m).toString(16)).slice(-8);
  }
  function print1600(msg, state) {
    var lines = [], line,x,y;
    for (y = 0; y < 50; y+=10) {
      line = [];
      for (x = 0; x < 10; x+=2) {
        line.push(w32h(state[x+y+1]) + w32h(state[x+y]));
      }
      lines.push(line.join(' ') + "\n");
    }
    console.log(msg + ":\n" + lines.join(''));
  }
  function print(msg, state, w) {
    var lines = [], line,x,y;
    w = (w + 3) >>> 2;
    for (y = 0; y < 25; y+=5) {
      line = [];
      for (x = 0; x < 5; ++x) {
        line.push(w32h(state[x+y]).slice(-w));
      }
      lines.push(line.join(' ') + "\n");
    }
    console.log(msg + ":\n" + lines.join(''));
  }
*/

/*
  function theta1600(state, buf) {
    var ccL,ccH,ddL,ddH,x,y,x1,x4;
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
      ccL = buf[x4] ^ (ddL << 1 | ddH >>> 31)
      ccH = buf[x4+1] ^ (ddH << 1 | ddL >>> 31);
      for(y = 0; y < 50; y+=10) {
        state[x+y] ^= ccL;
        state[x+y+1] ^= ccH;
      }
    }
  }
  function rotate1600(state, laneLo, by) {
    var laneHi=laneLo+1,lo, hi, t;
    if ((by &= 63)) {
      lo = state[laneLo]; hi = state[laneHi];
      if (by >= 32) { t = lo; lo = hi; hi = t; }
      if ((by &= 31)) {
        state[laneLo] = lo << by | hi >>> (32-by);
        state[laneHi] = hi << by | lo >>> (32-by);
      } else {
        state[laneLo] = lo; state[laneHi] = hi;
      }
    }
  }
  function rho1600(state) {
    var k;
    for (k = 0; k < 25; ++k) rotate1600(state, 2*k, rhoBY[k]);
  }
  function pi1600(to, from) {
    var k, t;
    for (k = 0; k < 25; ++k) {
      t = piMAP[k];
      to[2*t]   = from[2*k];
      to[2*t+1] = from[2*k+1];
    }
  }
  function chi1600(to, from) {
    var x,x1,x2,y;
    for (x = 0; x < 10; x+=2) {
      x1 = (x+2)%10; x2 = (x+4)%10;
      for (y = 0; y < 50; y+=10) {
        to[x+y]   = from[x+y]   ^ (~from[x1+y]   & from[x2+y]);
        to[x+y+1] = from[x+y+1] ^ (~from[x1+y+1] & from[x2+y+1]);
      }
    }
  }
  function iota1600(state, round) {
    state[0] ^= RC[round][0];
    state[1] ^= RC[round][1];
  }
  function keccak_f1600(state) {
    var i;
    var buf = state.slice();
    //print1600("input", state);
    for (i = 0; i < 24; ++i) {
      theta1600(state, buf);
      //print1600("round " + i + " after theta", state);
      rho1600(state);
      //print1600("round " + i + " after rho", state);
      pi1600(buf, state);
      //print1600("round " + i + " after pi", state);
      chi1600(state, buf);
      //print1600("round " + i + " after chi", state);
      iota1600(state, i);
      //print1600("round " + i + " after iota", state);
    }
    return state;
  }
*/

  /** Run the Keccak-f transformation on a 1600-bit state
   * @name sjcl.hash.keccak_f1600
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
  sjcl.hash.keccak_f1600 = keccak_f1600;

/*
  function keccak_f_gen(l) {
    var w = 1 << l, mask = w === 32 ? ~0 : (1 << w) - 1, rounds = 12 + 2*l;

    function rotate(x, by) {
      if (!(by %= w)) return x;
      x &= mask;
      return ((x << by) | (x >>> (w - by))) & mask;
    }

    function theta(state) {
      var cc,c=[], x, y;
      for (x = 0; x < 5; ++x) {
        cc = state[x];
        for (y = 5; y < 25; y+=5) {
          cc ^= state[x + y];
        }
        c[x] = cc;
      }
      for (x = 0; x < 5; ++x) {
        cc = c[(x+4)%5] ^ rotate(c[(x+1)%5], 1);
        for(y = 0; y < 25; y+=5) {
          state[x + y] ^= cc;
        }
      }
    }
    function rho(state) {
      var k;
      for (k = 0; k < 25; ++k) state[k] = rotate(state[k], rhoBY[k]);
    }
    function pi(state) {
      var s = state.slice(), k;
      for (k = 0; k < 25; ++k) state[piMAP[k]] = s[k];
    }
    function chi(state) {
      var s = state.slice(), x,x1,x2,y;
      for (x = 0; x < 5; ++x) {
        x1 = (x+1)%5; x2 = (x+2)%5;
        for (y = 0; y < 25; y+=5) {
          state[x+y] = s[x+y] ^ (~s[x1+y] & s[x2+y]);
        }
      }
    }
    function iota(state, round) {
      state[0] ^= RC[round][0] & mask;
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
    function keccak_f(data) {
      var state, i;
      state = read(data);
      // print("input", state, w);
      for (i = 0; i < rounds; ++i) {
        theta(state);
        // print("round " + i + " after theta", state, w);
        rho(state);
        // print("round " + i + " after rho", state, w);
        pi(state);
        // print("round " + i + " after pi", state, w);
        chi(state);
        // print("round " + i + " after chi", state, w);
        iota(state, i);
        // print("round " + i + " after iota", state, w);
      }
      write(data, state);
      return data;
    }
    keccak_f.width = 25 * w;
    return keccak_f;
  }
*/

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
    sjcl.hash['keccak_f' + keccak_f.width] = keccak_f;
    return keccak_f;
  }

  /** Create a Keccak-f transformation function for a specified bit width.
   * @function
   * @name sjcl.hash.keccak_f
   * @param {Number} bitwidth   Anything in [25,50,100,200,400,800,1600];
   *                            bitwidth = 25*2^l for 0 <= l <= 6
   * @return {function}         The transformation function: taking, modifying
   *                            and returning a {@link sjcl.bitArrayLE}
   */
  function keccak_f_get(b) {
    var f = sjcl.hash['keccak_f' + b], l;
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
