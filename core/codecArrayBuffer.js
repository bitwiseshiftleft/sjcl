/** @fileOverview Bit array codec implementations.
 *
 * @author Marco Munizaga
 */

//patch arraybuffers if they don't exist
if (typeof(ArrayBuffer) === 'undefined') {
  //I honestly didn't want to use an eval but here is the problem
  //
  //If I do var ArrayBuffer = function(){}
  //Then ArrayBuffer will be set to undefined because some js implementations set all vars to undefined at the beginning
  //
  //If I do ArrayBuffer = function(){}
  //That breaks in strict mode because I'm declaring a variable  w/o var 
  eval("ArrayBuffer = function(){}; DataView = function(){}")
}

/** @namespace ArrayBuffer */
sjcl.codec.arrayBuffer = {
  /** Convert from a bitArray to an ArrayBuffer. */
  fromBits: function (arr, padding, padding_count) {
    var out, i, ol, tmp, smallest;
    padding = padding==undefined  ? true : padding
    padding_count = padding_count || 8
    ol = sjcl.bitArray.bitLength(arr)/8
    if (padding && ol%padding_count !== 0){
      ol += padding_count - (ol%padding_count)
    }


    //padded temp for easy copying
    tmp = new DataView(new ArrayBuffer(arr.length*4)) 
    for (i=0; i<arr.length; i++) {
      tmp.setUint32(i*4, (arr[i]<<32)) //get rid of the higher bits
    }

    //now copy the final message if we are not going to 0 pad
    
    out = new DataView(new ArrayBuffer(ol))

    smallest = tmp.byteLength < out.byteLength ? tmp.byteLength : out.byteLength
    for(i=0; i<smallest; i++){
      out.setUint8(i,tmp.getUint8(i))
    }


    return out.buffer
  },

  /** Convert from an arraybuffer to a bitArray. */
  toBits: function (buffer) {
    var i, out=[], len, inView;
    inView = new DataView(buffer)
    for (var i = 0; i < inView.byteLength; i+=4){
      out.push(inView.getUint32(i))
    }
    return out
  },
  /** Prints a hex output of the buffer contents, akin to hexdump **/
  hexDumpBuffer: function(buffer){
      var stringBufferView = new DataView(buffer)
      var string = ''
      var pad = function (n, width) {
          n = n + '';
          return n.length >= width ? n : new Array(width - n.length + 1).join('0') + n;
      }

      for (var i = 0; i < stringBufferView.byteLength; i+=2) {
          if (i%16 == 0) string += ('\n'+(i).toString(16)+'\t')
          string += ( pad(stringBufferView.getUint16(i).toString(16),4) + ' ')
      }

      if ( typeof console === undefined ){
        console = console || {log:function(){}} //fix for IE
      }
      console.log(string.toUpperCase())
  }
};

