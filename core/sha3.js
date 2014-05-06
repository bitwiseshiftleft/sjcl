/** @fileOverview SHA3 functions
 *
 * @author Stefan Bühler
 */

/** Create a Keccak sponge class with given parameters. Uses
 * {@link sjcl.hash.sponge.makeClass} and adds a width and a capacity
 * property.
 * @param {Number} capacity          The capacity of the sponge
 * @param {Number} [out=2*capacity]  The output bit width
 * @param {Number} [width=1600]      Bitwidth for {@link sjcl.hash.keccak_f}
 * @param {function} [pad]           Custom padding function (defaults to
 *     {@link sjcl.hash.sponge.pad_101})
 * @return {function} Sponge class
 */
sjcl.hash.keccak = function (capacity, out, width, pad) {
  var rate, keccak_f, sponge = sjcl.hash.sponge, constr;
  out = out || (capacity >>> 1);
  capacity = capacity || 2 * out;
  width = width || 1600;
  rate = width - capacity;
  keccak_f = sjcl.hash.keccak_f(width);
  pad = pad || sponge.pad_101;

  constr = sponge.makeClass(keccak_f, pad, rate, out);
  // set additional properties
  constr.width = width;
  constr.capacity = capacity;
  return constr;
};

// common keccak variants used for SHA3, SHAKE128 and SHAKE256
/** Keccak[256] sponge (= sjcl.hash.keccak(256)) */
sjcl.hash.keccak_256 = sjcl.hash.keccak(256);
/** Keccak[448] sponge (= sjcl.hash.keccak(448)) */
sjcl.hash.keccak_448 = sjcl.hash.keccak(448);
/** Keccak[512] sponge (= sjcl.hash.keccak(512)) */
sjcl.hash.keccak_512 = sjcl.hash.keccak(512);
/** Keccak[768] sponge (= sjcl.hash.keccak(768)) */
sjcl.hash.keccak_768 = sjcl.hash.keccak(768);
/** Keccak[1024] sponge (= sjcl.hash.keccak(1024)) */
sjcl.hash.keccak_1024 = sjcl.hash.keccak(1024);

/* domain pad with bits "01" which are encoded as 10b = 2 (little endian) */
sjcl.hash._sha3_domain_pad = sjcl.hash.sponge.pad_domain_101([sjcl.bitArrayLE.partial(2, 2)]);

/** SHA3-224 sponge (using Keccak[448] {@link sjcl.hash.keccak_448} with domain separation) */
sjcl.hash.sha3_224 = sjcl.hash.keccak(448, 0, 0, sjcl.hash._sha3_domain_pad);
/** SHA3-256 sponge (using Keccak[512] {@link sjcl.hash.keccak_512} with domain separation) */
sjcl.hash.sha3_256 = sjcl.hash.keccak(512, 0, 0, sjcl.hash._sha3_domain_pad);
/** SHA3-384 sponge (using Keccak[768] {@link sjcl.hash.keccak_768} with domain separation) */
sjcl.hash.sha3_384 = sjcl.hash.keccak(768, 0, 0, sjcl.hash._sha3_domain_pad);
/** SHA3-512 sponge (using Keccak[1024] {@link sjcl.hash.keccak_1024} with domain separation) */
sjcl.hash.sha3_512 = sjcl.hash.keccak(1024, 0, 0, sjcl.hash._sha3_domain_pad);

/* domain pad with bits "1111" which are encoded as 1111b = 15 (little endian) */
sjcl.hash._sha3_xof_domain_pad = sjcl.hash.sponge.pad_domain_101([sjcl.bitArrayLE.partial(4, 0xf)]);

/** SHAKE128 sponge (using Keccak[256] {@link sjcl.hash.keccak_256} with domain separation) */
sjcl.hash.shake128 = sjcl.hash.keccak(256, 0, 0, sjcl.hash._sha3_xof_domain_pad);
/** SHAKE256 sponge (using Keccak[512] {@link sjcl.hash.keccak_512} with domain separation) */
sjcl.hash.shake256 = sjcl.hash.keccak(512, 0, 0, sjcl.hash._sha3_xof_domain_pad);
