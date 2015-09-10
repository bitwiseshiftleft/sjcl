/** @fileOverview SHA3 functions
 *
 * @author Stefan Bühler
 */

/* domain pad with bits "01" which are encoded as 10b = 2 (little endian) */
var sha3_domain_pad = sjcl.hash.sponge.pad_domain_101([sjcl.bitArrayLE.partial(2, 2)]);

/** SHA3-224 sponge (using Keccak[448] {@link sjcl.hash.keccak_448} with domain separation) */
sjcl.hash.sha3_224 = sjcl.hash.keccak(448, 0, 0, sha3_domain_pad);
/** SHA3-256 sponge (using Keccak[512] {@link sjcl.hash.keccak_512} with domain separation) */
sjcl.hash.sha3_256 = sjcl.hash.keccak(512, 0, 0, sha3_domain_pad);
/** SHA3-384 sponge (using Keccak[768] {@link sjcl.hash.keccak_768} with domain separation) */
sjcl.hash.sha3_384 = sjcl.hash.keccak(768, 0, 0, sha3_domain_pad);
/** SHA3-512 sponge (using Keccak[1024] {@link sjcl.hash.keccak_1024} with domain separation) */
sjcl.hash.sha3_512 = sjcl.hash.keccak(1024, 0, 0, sha3_domain_pad);

/* domain pad with bits "1111" which are encoded as 1111b = 15 (little endian) */
var sha3_xof_domain_pad = sjcl.hash.sponge.pad_domain_101([sjcl.bitArrayLE.partial(4, 0xf)]);

/** SHAKE128 sponge (using Keccak[256] {@link sjcl.hash.keccak_256} with domain separation) */
sjcl.hash.shake128 = sjcl.hash.keccak(256, 0, 0, sha3_xof_domain_pad);
/** SHAKE256 sponge (using Keccak[512] {@link sjcl.hash.keccak_512} with domain separation) */
sjcl.hash.shake256 = sjcl.hash.keccak(512, 0, 0, sha3_xof_domain_pad);
