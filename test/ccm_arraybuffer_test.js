//Run using phantomjs, since rhino doesn't support array buffers, and node has an issue with create dataviews with a bytelength of 0
sjcl = require("../sjcl.js")

sjcl = sjcl || {}
sjcl.test = {}
sjcl.test.vector = {}
require("./ccm_vectors.js")

//This ccm implementation is only defined for IV Lengths of 8 bytes
var applicable_tests = sjcl.test.vector.ccm.filter(function(test){
  return test.iv.length === 16 
})

applicable_tests.map(function(tv, index){
  var len = 32 * tv.key.length,
      h = sjcl.codec.hex
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
  )

  console.log("Running: ",len+"-ccm-encrypt #", index, "Pass?:", pass_e)

  pass_d = sjcl.bitArray.equal(
    sjcl.arrayBuffer.ccm.compat_decrypt(aes, ct, iv, ad, tlen), pt
  )

  console.log("Running: ",len+"-ccm-decrypt #", index, "Pass?:", pass_d)

  if (!(pass_e && pass_d)){
    throw("Failed at: "+i)
  }

  return pass_e && pass_d;

})

phantom.exit()

