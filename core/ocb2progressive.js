/**
 * OCB2.0 implementation slightly modified by Yifan Gu
 * to support progressive encryption
 * @author Yifan Gu
 */

/** @fileOverview OCB 2.0 implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** 
 * Phil Rogaway's Offset CodeBook mode, version 2.0.
 * May be covered by US and international patents.
 *
 * @namespace
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

sjcl.mode.ocb2progressive = {
  createEncryptor: function(prp, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    var i,
        times2 = sjcl.mode.ocb2._times2,
        w = sjcl.bitArray,
        xor = w._xor4,
        checksum = [0,0,0,0],
        delta = times2(prp.encrypt(iv)),
        bi, bl,
        datacache = [],
        pad;

    adata = adata || [];
    tlen  = tlen || 64;

    return {
      process: function(data){
        var datalen = sjcl.bitArray.bitLength(data);
        if (datalen == 0){ // empty input natrually gives empty output
          return [];
        }
        var output = [];
        datacache = datacache.concat(data);
        for (i=0; i+4 < datacache.length; i+=4) {
          /* Encrypt a non-final block */
          bi = datacache.slice(i,i+4);
          checksum = xor(checksum, bi);
          output = output.concat(xor(delta,prp.encrypt(xor(delta, bi))));
          delta = times2(delta);
        }
        datacache = datacache.slice(i); // at end of each process we ensure size of datacache is smaller than 4
        return output; //spits out the result.
      },
      finalize: function(){
        // the final block
        bi = datacache;
        bl = w.bitLength(bi);
        pad = prp.encrypt(xor(delta,[0,0,0,bl]));
        bi = w.clamp(xor(bi.concat([0,0,0]),pad), bl);

        /* Checksum the final block, and finalize the checksum */
        checksum = xor(checksum,xor(bi.concat([0,0,0]),pad));
        checksum = prp.encrypt(xor(checksum,xor(delta,times2(delta))));

        /* MAC the header */
        if (adata.length) {
          checksum = xor(checksum, premac ? adata : sjcl.mode.ocb2.pmac(prp, adata));
        }

        return w.concat(bi, w.clamp(checksum, tlen)); // spits out the last block
      }
    };
  },
  createDecryptor: function(prp, iv, adata, tlen, premac){
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    tlen  = tlen || 64;
    var i,
        times2 = sjcl.mode.ocb2._times2,
        w = sjcl.bitArray,
        xor = w._xor4,
        checksum = [0,0,0,0],
        delta = times2(prp.encrypt(iv)),
        bi, bl,
        datacache = [],
        pad;

    adata = adata || [];

    return {
      process: function(data){
        if (data.length == 0){ // empty input natrually gives empty output
          return [];
        }
        var output = [];
        datacache = datacache.concat(data);
        var cachelen = sjcl.bitArray.bitLength(datacache);
        for (i=0; i+4 < (cachelen-tlen)/32; i+=4) {
          /* Decrypt a non-final block */
          bi = xor(delta, prp.decrypt(xor(delta, datacache.slice(i,i+4))));
          checksum = xor(checksum, bi);
          output = output.concat(bi);
          delta = times2(delta);
        }
        datacache = datacache.slice(i);
        return output;
      },
      finalize: function(){
        /* Chop out and decrypt the final block */
        bl = sjcl.bitArray.bitLength(datacache) - tlen;
        pad = prp.encrypt(xor(delta,[0,0,0,bl]));
        bi = xor(pad, w.clamp(datacache,bl).concat([0,0,0]));

        /* Checksum the final block, and finalize the checksum */
        checksum = xor(checksum, bi);
        checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));

        /* MAC the header */
        if (adata.length) {
          checksum = xor(checksum, premac ? adata : sjcl.mode.ocb2.pmac(prp, adata));
        }

        if (!w.equal(w.clamp(checksum, tlen), w.bitSlice(datacache, bl))) {
          throw new sjcl.exception.corrupt("ocb: tag doesn't match");
        }

        return w.clamp(bi,bl);
      }
    };
  }
};
