new sjcl.test.TestCase("arrayBuffer codec tests", function (cb) {
  if (!sjcl.codec.arrayBuffer) {
    this.unimplemented();
    cb && cb();
    return;
  }

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

  var that = this;

  test_bytes.map(function(test_byte, index){
    var bitArray = sjcl.codec.hex.toBits(test_byte),
        arrayBuffer = sjcl.codec.arrayBuffer.fromBits(bitArray, false),
        roundTripArrayBuffer = sjcl.codec.arrayBuffer.toBits(arrayBuffer),
        roundTripHex = sjcl.codec.hex.fromBits(roundTripArrayBuffer);

    if (roundTripHex !== test_byte){
      that.fail("Failed test, expected " + roundTripHex + "to be" + test_byte + "(at: " + i + ")");
    }
  });

  cb();
});