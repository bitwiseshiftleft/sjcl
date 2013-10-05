new sjcl.test.TestCase("HMAC official test vectors", function (cb) {
  if (!sjcl.misc.hmac || !sjcl.hash.sha256) {
    this.unimplemented();
    cb && cb();
    return;
  }
  
  var i, kat = sjcl.test.vector.hmac, tv, h=sjcl.codec.hex, out, data, mac;
  for (i=0; i<kat.length; i++) {
    tv = kat[i];
    data = h.toBits(tv.data);
    mac = new sjcl.misc.hmac(h.toBits(tv.key));

    out = h.fromBits(mac.mac(data));
    this.require (out.substr(0,tv.mac.length) == tv.mac, "hmac #"+i);

    out = h.fromBits(mac.mac(data));
    this.require (out.substr(0,tv.mac.length) == tv.mac, "hmac reset #"+i);

    mac.update(sjcl.bitArray.bitSlice(data, 0, sjcl.bitArray.bitLength(data)/2));
    mac.update(sjcl.bitArray.bitSlice(data, sjcl.bitArray.bitLength(data)/2));

    out = h.fromBits(mac.digest());
    this.require (out.substr(0,tv.mac.length) == tv.mac, "hmac reset #"+i);
  }
  cb && cb();
});
