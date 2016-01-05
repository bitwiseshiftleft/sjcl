/** @fileOverview Bit array codec implementations.
 *
 * @author Marco Munizaga
 * @author Miha Stopar
 */

//patch arraybuffers if they don't exist
if (typeof(ArrayBuffer) === 'undefined') {
  (function(globals){
      "use strict";
      globals.ArrayBuffer = function(){};
      globals.DataView = function(){};
  }(this));
}

/** @namespace ArrayBuffer */
sjcl.codec.arrayBuffer = {
  /** Convert from a bitArray to an ArrayBuffer. 
   * Will default to 8byte padding if padding is undefined*/
  fromBits: function (arr, padding, padding_count) {
    var i, tmp, buffer;
    if (arr.length === 0) {
      return new ArrayBuffer(0);
    }

    //check to make sure the bitLength is divisible by 8, if it isn't 
    //we can't do anything since arraybuffers work with bytes, not bits
    if ( sjcl.bitArray.bitLength(arr)%8 !== 0 ) {
      throw new sjcl.exception.invalid("Invalid bit size, must be divisble by 8 to fit in an arraybuffer correctly")
    }

    //padded temp for easy copying
    tmp = new DataView(new ArrayBuffer(arr.length*4));
    for (i=0; i<arr.length; i++) {
      tmp.setUint32(i*4, (arr[i]<<32)); //get rid of the higher bits
    }

    if (!ArrayBuffer.prototype.slice) {
        ArrayBuffer.prototype.slice = function (start, end) {
            var that = new Uint8Array(this);
            if (end == undefined) end = that.length;
            var result = new ArrayBuffer(end - start);
            var resultArray = new Uint8Array(result);
            for (var i = 0; i < resultArray.length; i++)
                resultArray[i] = that[i + start];
            return result;
	}
    }
    var buffer;
    if(tmp.buffer.hasOwnProperty("slice")){
        buffer = tmp.buffer.slice(0, sjcl.bitArray.bitLength(arr)/8);
    } else {
	// for node 0.8
	var n = new Uint8Array(tmp.buffer);
        var result = new ArrayBuffer(sjcl.bitArray.bitLength(arr)/8);
        var resultArray = new Uint8Array(result);
        for (var i = 0; i < resultArray.length; i++)
            resultArray[i] = n[i];
        buffer = result;
    }

    return sjcl.codec.arrayBuffer.padBuffer(buffer, padding, padding_count);
  },

  toBits: function (buffer) {
    var i, out=[], len, inView, tmp;

    if (buffer.byteLength === 0) {
      return [];
    }

    inView = new DataView(buffer);
    len = inView.byteLength - inView.byteLength%4;

    for (var i = 0; i < len; i+=4) {
      out.push(inView.getUint32(i));
    }

    if (inView.byteLength%4 != 0) {
      tmp = new DataView(new ArrayBuffer(4));
      for (var i = 0, l = inView.byteLength%4; i < l; i++) {
        //we want the data to the right, because partial slices off the starting bits
        tmp.setUint8(i+4-l, inView.getUint8(len+i)); // big-endian, 
      }
      out.push(
        sjcl.bitArray.partial( (inView.byteLength%4)*8, tmp.getUint32(0) )
      ); 
    }
    return out;
  },

  padBuffer: function (buffer, padding, padding_count) {
    var ol, out, i;
    padding = padding==undefined  ? true : padding
    padding_count = padding_count || 16

    if (buffer.byteLength === 0) {
      return new ArrayBuffer(0);
    }

    ol = buffer.byteLength;
    if (padding && ol%padding_count !== 0){
      ol += padding_count - (ol%padding_count);
    }

    var out = new Uint8Array(ol);
    out.set(new Uint8Array(buffer), 0);
    return out.buffer;
  },
  
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

