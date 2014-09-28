//Run using phantomjs, since rhino doesn't support array buffers, and node has an issue with create dataviews with a bytelength of 0
console.log("Running CCM using ArrayBuffer tests");
var start_time = +(new Date());

//This ccm implementation is only defined for IV Lengths of 8 bytes
var applicable_tests = sjcl.test.vector.ccm;

applicable_tests.map(function(tv, index){
  var len = 32 * tv.key.length,
      h = sjcl.codec.hex,
      aes = new sjcl.cipher.aes(h.toBits(tv.key)),
      iv = h.toBits(tv.iv),
      ad = h.toBits(tv.adata),
      pt = h.toBits(tv.pt),
      ct = h.toBits(tv.ct + tv.tag),
      tlen = tv.tag.length * 4,
      pass_e = false,
      pass_d = false;

  pass_e = sjcl.bitArray.equal(
    sjcl.arrayBuffer.ccm.compat_encrypt(aes, pt, iv, ad, tlen), ct
  );

  pass_d = sjcl.bitArray.equal(
    sjcl.arrayBuffer.ccm.compat_decrypt(aes, ct, iv, ad, tlen), pt
  );

  if (!(pass_e && pass_d)){
    console.log("Failed at : ",len+"-ccm #", index, "Pass?:", pass_d);
    phantom.exit(1);
  }

  return pass_e && pass_d;

});

var total_time = parseInt(+(new Date())-start_time);
console.log("  + passed all",applicable_tests.length,"tests. ("+ total_time, "ms)");

