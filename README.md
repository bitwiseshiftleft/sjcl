sjcl
====

[![Build Status](https://travis-ci.org/bitwiseshiftleft/sjcl.png)](https://travis-ci.org/bitwiseshiftleft/sjcl)

[![Join the chat at https://gitter.im/bitwiseshiftleft/sjcl](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/bitwiseshiftleft/sjcl?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Stanford Javascript Crypto Library

Security Advisories
===

* 12.02.2014: the current development version has a paranoia bug in the ecc module. The bug was introduced in commit [ac0b3fe0](https://github.com/bitwiseshiftleft/sjcl/commit/ac0b3fe0) and might affect ecc key generation on platforms without a platform random number generator.

Security Contact
====
Security Mail: sjcl@ovt.me  
OpenPGP-Key Fingerprint: 0D54 3E52 87B4 EC06 3FA9 0115 72ED A6C7 7AAF 48ED  
Keyserver: pool.sks-keyservers.net  

Upgrade Guide
====

## 1.0.3 -> 1.0.4

`codecBase32` has been re-enabled with changes to conform to [RFC 4648](http://tools.ietf.org/html/rfc4648#section-6):

* Padding with `=` is now applied to the output of `fromBits`. If you don't want that padding, you can disable it by calling `fromBits` with a second parameter of `true` or anything that evaluates as "truthy" in JS
* The encoding alphabet for `sjcl.codec.base32` now matches that specified by the RFC, rather than the extended hex alphabet.
* The former extended hex alphabet is now available through `sjcl.codec.base32hex` (also matching the RFC). So if you encoded something with `base32` before, you'll want to decode it with `base32hex` now.

Documentation
====
The documentation is available [here](http://bitwiseshiftleft.github.io/sjcl/doc/)
