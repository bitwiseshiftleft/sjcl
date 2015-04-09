sjcl
====

[![Build Status](https://travis-ci.org/bitwiseshiftleft/sjcl.png)](https://travis-ci.org/bitwiseshiftleft/sjcl)

Stanford Javascript Crypto Library

Security Advisories
===

* 12.02.2014: the current development version has a paranoia bug in the ecc module. The bug was introduced in commit [ac0b3fe0](https://github.com/bitwiseshiftleft/sjcl/commit/ac0b3fe0) and might affect ecc key generation on platforms without a platform random number generator.

Security Contact
====
Security Mail: sjcl@ovt.me  
OpenPGP-Key Fingerprint: 0D54 3E52 87B4 EC06 3FA9 0115 72ED A6C7 7AAF 48ED  
Keyserver: pool.sks-keyservers.net  

Documentation
====
The documentation is available [here](http://bitwiseshiftleft.github.io/sjcl/doc/)
