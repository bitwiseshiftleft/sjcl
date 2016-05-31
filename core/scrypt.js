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
  var SIZE_MAX = Math.pow(2, 32) - 1,
      self = sjcl.misc.scrypt;

  N = N || 16384;
  r = r || 8;
  p = p || 1;

  if (r * p >= Math.pow(2, 30)) {
    throw sjcl.exception.invalid("The parameters r, p must satisfy r * p < 2^30");
  }

  if ((N < 2) || (N & (N - 1) != 0)) {
    throw sjcl.exception.invalid("The parameter N must be a power of 2.");
  }

  if (N > SIZE_MAX / 128 / r) {
    throw sjcl.exception.invalid("N too big.");
  }

  if (r > SIZE_MAX / 128 / p) {
    throw sjcl.exception.invalid("r too big.");
  }

  var blocks = sjcl.misc.pbkdf2(password, salt, 1, p * 128 * r * 8, Prff),
      len = blocks.length / p;

  self.reverse(blocks);

  for (var i = 0; i < p; i++) {
    var block = blocks.slice(i * len, (i + 1) * len);
    self.blockcopy(self.ROMix(block, N), 0, blocks, i * len);
  }

  self.reverse(blocks);

  return sjcl.misc.pbkdf2(password, blocks, 1, length, Prff);
};

sjcl.misc.scrypt.salsa20Core = function (word, rounds) {
  var R = function(a, b) { return (a << b) | (a >>> (32 - b)); };
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

  for (i = 0; i < 16; i++) word[i] = x[i]+word[i];
};

sjcl.misc.scrypt.blockMix = function(blocks) {
  var X = blocks.slice(-16),
      out = [],
      len = blocks.length / 16,
      self = sjcl.misc.scrypt;

  for (var i = 0; i < len; i++) {
    self.blockxor(blocks, 16 * i, X, 0, 16);
    self.salsa20Core(X, 8);

    if ((i & 1) == 0) {
      self.blockcopy(X, 0, out, 8 * i);
    } else {
      self.blockcopy(X, 0, out, 8 * (i^1 + len));
    }
  }

  return out;
};

sjcl.misc.scrypt.ROMix = function(block, N) {
  var X = block.slice(0),
      V = [],
      self = sjcl.misc.scrypt;

  for (var i = 0; i < N; i++) {
    V.push(X.slice(0));
    X = self.blockMix(X);
  }

  for (i = 0; i < N; i++) {
    var j = X[X.length - 16] & (N - 1);

    self.blockxor(V[j], 0, X, 0);
    X = self.blockMix(X);
  }

  return X;
};

sjcl.misc.scrypt.reverse = function (words) { // Converts Big <-> Little Endian words
  for (var i in words) {
    var out = words[i] &  0xFF;
    out = (out << 8) | (words[i] >>>  8) & 0xFF;
    out = (out << 8) | (words[i] >>> 16) & 0xFF;
    out = (out << 8) | (words[i] >>> 24) & 0xFF;

    words[i] = out;
  }
};

sjcl.misc.scrypt.blockcopy = function (S, Si, D, Di, len) {
  var i;

  len = len || (S.length - Si);

  for (i = 0; i < len; i++) D[Di + i] = S[Si + i] | 0;
};

sjcl.misc.scrypt.blockxor = function(S, Si, D, Di, len) {
  var i;

  len = len || (S.length - Si);

  for (i = 0; i < len; i++) D[Di + i] = (D[Di + i] ^ S[Si + i]) | 0;
};
