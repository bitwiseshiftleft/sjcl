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

    var buffer;
    if(tmp.buffer.hasOwnProperty("slice")){
      buffer = tmp.buffer.slice(0, sjcl.bitArray.bitLength(arr)/8);
    } else {
      buffer = sjcl.codec.arrayBuffer.slice(tmp.buffer, sjcl.bitArray.bitLength(arr)/8);
    }

    return buffer;
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

  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  _lookup: {43: 62, 47: 63, 48: 52, 49: 53, 50: 54, 51: 55, 52: 56, 53: 57, 
  			54: 58, 55: 59, 56: 60, 57: 61, 65: 0, 66: 1, 67: 2, 68: 3, 69: 4, 
  			70: 5, 71: 6, 72: 7, 73: 8, 74: 9, 75: 10, 76: 11, 77: 12, 78: 13, 
  			79: 14, 80: 15, 81: 16, 82: 17, 83: 18, 84: 19, 85: 20, 86: 21, 87: 22, 
  			88: 23, 89: 24, 90: 25, 97: 26, 98: 27, 99: 28, 100: 29, 101: 30, 
  			102: 31, 103: 32, 104: 33, 105: 34, 106: 35, 107: 36, 108: 37, 109: 38, 
  			110: 39, 111: 40, 112: 41, 113: 42, 114: 43, 115: 44, 116: 45, 117: 46, 
  			118: 47, 119: 48, 120: 49, 121: 50, 122: 51},

  toBase64: function(arraybuffer) {
    var bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = "";

    for (i = 0; i < len; i+=3) {
      base64 += sjcl.codec.arrayBuffer._chars[bytes[i] >> 2];
      base64 += sjcl.codec.arrayBuffer._chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
      base64 += sjcl.codec.arrayBuffer._chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
      base64 += sjcl.codec.arrayBuffer._chars[bytes[i + 2] & 63];
    }

    if ((len % 3) === 2) {
      base64 = base64.substring(0, base64.length - 1) + "=";
    } else if (len % 3 === 1) {
      base64 = base64.substring(0, base64.length - 2) + "==";
    }

    return base64;
  },

  fromBase64: function(base64) {
    var bufferLength = base64.length * 3 / 4; // compression turns 0.75 into 10
    var len = base64.length;
    var i, p = 0, encoded1, encoded2, encoded3, encoded4;

    if (base64[base64.length - 1] === "=") {
      bufferLength--;
      if (base64[base64.length - 2] === "=") {
        bufferLength--;
      }
    }

    var arraybuffer = new ArrayBuffer(bufferLength),
    bytes = new Uint8Array(arraybuffer);

    for (i = 0; i < len; i+=4) {
      encoded1 = sjcl.codec.arrayBuffer._lookup[base64.charCodeAt(i)];
      encoded2 = sjcl.codec.arrayBuffer._lookup[base64.charCodeAt(i+1)];
      encoded3 = sjcl.codec.arrayBuffer._lookup[base64.charCodeAt(i+2)];
      encoded4 = sjcl.codec.arrayBuffer._lookup[base64.charCodeAt(i+3)];

      bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
      bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }

    return arraybuffer;
  },

  slice: function(buffer, length){
    // for node 0.8
    var n = new Uint8Array(buffer);
    var result = new ArrayBuffer(length);
    var resultArray = new Uint8Array(result);
    for (var i = 0; i < resultArray.length; i++) {
      resultArray[i] = n[i];
    }
    return result;
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

