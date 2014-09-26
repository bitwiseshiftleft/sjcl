//Run using phantomjs, since rhino doesn't support array buffers, and node has an issue with create dataviews with a bytelength of 0
console.log("Running ArrayBuffer Codec tests");
var start_time = +(new Date());

//This ccm implementation is only defined for IV Lengths of 8 bytes
var test_bytes = [];

var zeropad_hex = function(number){
  var hex = number.toString(16);
  while ( hex.length%2 != 0 ){
    hex = "0"+hex;
  }
  return hex;
};


for (var i = 0; i <= 0xffff; i++){
  test_bytes.push(zeropad_hex(i));
}


test_bytes.map(function(test_byte, index){
  var bitArray = sjcl.codec.hex.toBits(test_byte),
      arrayBuffer = sjcl.codec.arrayBuffer.fromBits(bitArray, false),
      roundTripArrayBuffer = sjcl.codec.arrayBuffer.toBits(arrayBuffer),
      roundTripHex = sjcl.codec.hex.fromBits(roundTripArrayBuffer);

  if (roundTripHex !== test_byte){
    console.error("Failed test, expected ",roundTripHex,"to be",test_byte);
    console.error("Failed at: "+i);
    phantom.exit(1);
  }
});

var total_time = parseInt(+(new Date())-start_time);
console.log("  + passed all",test_bytes.length,"tests. ("+ total_time, "ms)");