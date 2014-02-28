sjcl.codec.base58 = {

  _chars: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",

  fromBits: function(arr) {
    if (sjcl.bitArray.bitLength(arr) > 0) {
      var x = sjcl.bn.fromBits(arr),
          modulus = sjcl.bn.fromBits(arr),
          out = '',
          c = sjcl.codec.base58._chars;

      while (x.greaterEquals(1)) {
        var result = this._divmod58(x),
            x = result.q,
            charIndex = result.n.getLimb(0);

        out = c[charIndex] + out;
      }

      var hex = sjcl.codec.hex.fromBits(arr),
          zeros = hex.match(/^0*/)[0].length,
          zeroBytes = Math.floor(zeros/2);

      for (var i=zeroBytes; i>0; i--) {
        out = "1" + out;
      }

      return out;
    } else {
      return '';
    }
  },

  toBits: function(str) {
    var powersOf58 = this._powersOf58(str.length);
    var value = new sjcl.bn(), i, c = sjcl.codec.base58._chars, bitCount = 0;
    for (i=0; i<str.length; i++) {
      x   = c.indexOf(str.charAt(i));
      pos = str.length - i - 1;
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base58!");
      }

      addend = (new sjcl.bn(x)).mul(powersOf58[pos]);
      value.addM(addend);
    }

    if (str.length > 0) {
      var trimmedValue = value.trim(),
          hexValue = trimmedValue == 0 ? '' : trimmedValue.toString().substr(2),
          zeros    = str.match(/^1*/)[0].length,
          bitCount = hexValue.length * 4 + zeros * 8;

      return trimmedValue.toBits(bitCount);
    } else {
      return '';
    }
  },

  _divmod58: function(n) {
    var result = {
      q: new sjcl.bn(0),
      n: new sjcl.bn(n)
    }
    var d = new sjcl.bn(58);
    var powerOf58 = new sjcl.bn(1), powersOf58table = [powerOf58];

    // find max power of 58 that is less than n and build a power of 58 table
    while (result.n.greaterEquals(powerOf58)) {
      powersOf58table.push(powerOf58);
      powerOf58 = powerOf58.mul(d);
    }

    while (result.n.greaterEquals(d)) {
      var i = powersOf58table.length - 1, addToQ = 1;

      if (powersOf58table.length > 1) {
        addToQ = powersOf58table[i-1];
      }

      powerOf58 = powersOf58table[i];
      while (powerOf58.greaterEquals(result.n.add(1))) {
        i--;
        powerOf58 = powersOf58table[i];
        addToQ    = powersOf58table[i-1];
      }

      result.n.subM(powerOf58);
      result.q.addM(addToQ);

      result.n.normalize();
    }

    return result;
  },

  _powersOf58: function(maxPower) {
    var out = [
      new sjcl.bn(1)
    ];

    for (i=1;i<=maxPower;i++) {
      var result = (new sjcl.bn(58)).mul(out[i-1]);
      out.push(result);
    }

    return out;
  }

}
