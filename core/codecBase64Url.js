/** @fileOverview base64url codec implementation.
 *
 * @author Ivan Fomichev
 */

/** @namespace base64url encoding/decoding (as defined by RFC-4648) */
sjcl.codec.base64url = {
  /** The base64url alphabet. Same as Base64 except the last two characters.
   * @private
   */
  _chars: sjcl.codec.base64._chars.substr(0, 62) + '-_',
  
  /** Convert from a bitArray to a base64url string. */
  fromBits: function(arr) {
    return sjcl.codec.base64.fromBits.call(this, arr, true);
  },

  /** Convert from a base64url string to a bitArray.
   * @function
   * @param str
   */
  toBits: sjcl.codec.base64.toBits
};
