/** scrypt Password-Based Key-Derivation Function.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray|String} salt      The salt.  Should have lots of entropy.
 *
 * @param {Number} [N=16384] CPU/Memory cost parameter.
 * @param {Number} [r=8]     Block size parameter.
 * @param {Number} [p=1]     Parallelization parameter.
 *
 * @param {Number} [length] The length of the derived key.  Defaults to the
 *                          output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 *
 * @return {bitArray} The derived key.
 */
sjcl.misc.scrypt = function (password, salt, N, r, p, length, Prff) {
  var reverse = function (words) { // Converts Big <-> Little Endian words
    return words.map(function (word) {
      return sjcl.codec.bytes.toBits(
        sjcl.codec.bytes.fromBits([word]).reverse()
      )[0];
    })
  }

  var salsa20Core = function (word, rounds) {
    var R = function(a, b) { return (a << b) | (a >>> (32 - b)); }
    var x = word.slice(0);

    for (var i = rounds; i > 0; i -= 2) {
      x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
      x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
      x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
      x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
      x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
      x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
      x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
      x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
      x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
      x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
      x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
      x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
      x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
      x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
      x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
      x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
    }

    for (i = 0; i < 16; i++) { word[i] = x[i]+word[i]; }

    return word;
  }

  var scryptBlockMix = function(blocks) {
    var temp = [];
    while (blocks.length > 0) { temp.push(blocks.splice(0, 16)); }
    blocks = temp;

    var X = blocks[blocks.length - 1],
        out = [];

    for (var i = 0; i < blocks.length; i++) {
      var T = X.map(function (xj, j) { return xj ^ blocks[i][j] });
      X = salsa20Core(T, 8);
      blocks[i] = X
    }

    for (i = 0; i < blocks.length; i++) {
      if ((i % 2) == 0) {
        out[i / 2] = blocks[i]
      } else {
        out[((i - 1) / 2) + (blocks.length / 2)] = blocks[i]
      }
    }

    return out.reduce(function(a, b) { return a.concat(b); });
  }

  var scryptROMix = function(block, N) {
    var X = block.slice(0),
        V = [];

    for (var i = 0; i < N; i++) {
      V.push(X.slice(0));
      X = scryptBlockMix(X);
    }

    for (i = 0; i < N; i++) {
      var j = X[X.length - 16] & (N - 1);

      var T = X.map(function(b, k) { return b ^ V[j][k]; });
      X = scryptBlockMix(T);
    }

    return X;
  }

  N = N || 16384;
  r = r || 8;
  p = p || 1;

  var blocks = [],
      tmp = sjcl.misc.pbkdf2(password, salt, 1, p * 128 * r * 8, Prff),
      len = tmp.length / p;

  while (tmp.length > 0) { blocks.push(tmp.splice(0, len)); }

  blocks = blocks.map(function (block) {
    return reverse(scryptROMix(reverse(block), N));
  }).reduce(function(a, b) {
    return a.concat(b);
  });

  return sjcl.misc.pbkdf2(password, blocks, 1, length, Prff);
}
