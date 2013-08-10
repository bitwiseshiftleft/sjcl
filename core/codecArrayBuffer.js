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
  fromBits: function (arr) {
    var out, i;
    out = new DataView(new ArrayBuffer(arr.length*4)) //each item in the array has a 32bit int (4Bytes of data). so we want a total of 4*arr.length of bytes
    for (i=0; i<arr.length; i++) {
      out.setUint32(i*4, (arr[i]<<32)) //get rid of the higher bits
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
      console.log(string.toUpperCase())
  }
};

