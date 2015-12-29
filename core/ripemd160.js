/** @fileOverview Javascript RIPEMD-160 implementation.
 *
 * @author Artem S Vybornov <vybornov@gmail.com>
 */
(function() {

/**
 * Context for a RIPEMD-160 operation in progress.
 * @constructor
 * @class RIPEMD, 160 bits.
 */
sjcl.hash.ripemd160 = function (hash) {
    if (hash) {
        this._h = hash._h.slice(0);
        this._buffer = hash._buffer.slice(0);
        this._length = hash._length;
    } else {
        this.reset();
    }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 5 big-endian words.
 */
sjcl.hash.ripemd160.hash = function (data) {
  return (new sjcl.hash.ripemd160()).update(data).finalize();
};

sjcl.hash.ripemd160.prototype = {
    /**
     * Reset the hash state.
     * @return this
     */
    reset: function () {
        this._h = _h0.slice(0);
        this._buffer = [];
        this._length = 0;
        return this;
    },

    /**
     * Reset the hash state.
     * @param {bitArray|String} data the data to hash.
     * @return this
     */
    update: function (data) {
        if ( typeof data === "string" )
            data = sjcl.codec.utf8String.toBits(data);

        var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
            ol = this._length,
            nl = this._length = ol + sjcl.bitArray.bitLength(data);
        for (i = 512+ol & -512; i <= nl; i+= 512) {
            var words = b.splice(0,16);
            for ( var w = 0; w < 16; ++w )
                words[w] = _cvt(words[w]);

            _block.call( this, words );
        }

        return this;
    },

    /**
     * Complete hashing and output the hash value.
     * @return {bitArray} The hash value, an array of 5 big-endian words.
     */
    finalize: function () {
        var b = sjcl.bitArray.concat( this._buffer, [ sjcl.bitArray.partial(1,1) ] ),
            l = ( this._length + 1 ) % 512,
            z = ( l > 448 ? 512 : 448 ) - l % 448,
            zp = z % 32;

        if ( zp > 0 )
            b = sjcl.bitArray.concat( b, [ sjcl.bitArray.partial(zp,0) ] )
        for ( ; z >= 32; z -= 32 )
            b.push(0);

        b.push( _cvt( this._length | 0 ) );
        b.push( _cvt( Math.floor(this._length / 0x100000000) ) );

        while ( b.length ) {
            var words = b.splice(0,16);
            for ( var w = 0; w < 16; ++w )
                words[w] = _cvt(words[w]);

            _block.call( this, words );
        }

        var h = this._h;
        this.reset();

        for ( var w = 0; w < 5; ++w )
            h[w] = _cvt(h[w]);

        return h;
    }
};

var _h0 = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ];

var _k1 = [ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e ];
var _k2 = [ 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 ];
for ( var i = 4; i >= 0; --i ) {
    for ( var j = 1; j < 16; ++j ) {
        _k1.splice(i,0,_k1[i]);
        _k2.splice(i,0,_k2[i]);
    }
}

var _r1 = [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
             7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
             3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
             1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
             4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13 ];
var _r2 = [  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
             6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
            15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
             8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
            12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11 ];

var _s1 = [ 11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
             7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
            11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
            11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
             9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ];
var _s2 = [  8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
             9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
             9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
            15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
             8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ];

function _f0(x,y,z) {
    return x ^ y ^ z;
};

function _f1(x,y,z) {
    return (x & y) | (~x & z);
};

function _f2(x,y,z) {
    return (x | ~y) ^ z;
};

function _f3(x,y,z) {
    return (x & z) | (y & ~z);
};

function _f4(x,y,z) {
    return x ^ (y | ~z);
};

function _rol(n,l) {
    return (n << l) | (n >>> (32-l));
}

function _cvt(n) {
    return ( (n & 0xff <<  0) <<  24 )
         | ( (n & 0xff <<  8) <<   8 )
         | ( (n & 0xff << 16) >>>  8 )
         | ( (n & 0xff << 24) >>> 24 );
}

function _block(X) {
    var A1 = this._h[0], B1 = this._h[1], C1 = this._h[2], D1 = this._h[3], E1 = this._h[4],
        A2 = this._h[0], B2 = this._h[1], C2 = this._h[2], D2 = this._h[3], E2 = this._h[4];

    var j = 0, T;

    for ( ; j < 16; ++j ) {
        T = _rol( A1 + _f0(B1,C1,D1) + X[_r1[j]] + _k1[j], _s1[j] ) + E1;
        A1 = E1; E1 = D1; D1 = _rol(C1,10); C1 = B1; B1 = T;
        T = _rol( A2 + _f4(B2,C2,D2) + X[_r2[j]] + _k2[j], _s2[j] ) + E2;
        A2 = E2; E2 = D2; D2 = _rol(C2,10); C2 = B2; B2 = T; }
    for ( ; j < 32; ++j ) {
        T = _rol( A1 + _f1(B1,C1,D1) + X[_r1[j]] + _k1[j], _s1[j] ) + E1;
        A1 = E1; E1 = D1; D1 = _rol(C1,10); C1 = B1; B1 = T;
        T = _rol( A2 + _f3(B2,C2,D2) + X[_r2[j]] + _k2[j], _s2[j] ) + E2;
        A2 = E2; E2 = D2; D2 = _rol(C2,10); C2 = B2; B2 = T; }
    for ( ; j < 48; ++j ) {
        T = _rol( A1 + _f2(B1,C1,D1) + X[_r1[j]] + _k1[j], _s1[j] ) + E1;
        A1 = E1; E1 = D1; D1 = _rol(C1,10); C1 = B1; B1 = T;
        T = _rol( A2 + _f2(B2,C2,D2) + X[_r2[j]] + _k2[j], _s2[j] ) + E2;
        A2 = E2; E2 = D2; D2 = _rol(C2,10); C2 = B2; B2 = T; }
    for ( ; j < 64; ++j ) {
        T = _rol( A1 + _f3(B1,C1,D1) + X[_r1[j]] + _k1[j], _s1[j] ) + E1;
        A1 = E1; E1 = D1; D1 = _rol(C1,10); C1 = B1; B1 = T;
        T = _rol( A2 + _f1(B2,C2,D2) + X[_r2[j]] + _k2[j], _s2[j] ) + E2;
        A2 = E2; E2 = D2; D2 = _rol(C2,10); C2 = B2; B2 = T; }
    for ( ; j < 80; ++j ) {
        T = _rol( A1 + _f4(B1,C1,D1) + X[_r1[j]] + _k1[j], _s1[j] ) + E1;
        A1 = E1; E1 = D1; D1 = _rol(C1,10); C1 = B1; B1 = T;
        T = _rol( A2 + _f0(B2,C2,D2) + X[_r2[j]] + _k2[j], _s2[j] ) + E2;
        A2 = E2; E2 = D2; D2 = _rol(C2,10); C2 = B2; B2 = T; }

    T = this._h[1] + C1 + D2;
    this._h[1] = this._h[2] + D1 + E2;
    this._h[2] = this._h[3] + E1 + A2;
    this._h[3] = this._h[4] + A1 + B2;
    this._h[4] = this._h[0] + B1 + C2;
    this._h[0] = T;
}

})();
