// dd if=/dev/zero bs=1024 count=$((327155712/1024)) | shasum
sjcl.test.vector.sha1huge =
{
  8388608:   "5fde1cce603e6566d20da811c9c8bcccb044d4ae", // 8 MB
  16777216:  "3b4417fc421cee30a9ad0fd9319220a8dae32da2", // 16 MB
  33554432:  "57b587e1bf2d09335bdac6db18902d43dfe76449", // 32 MB
  67108864:  "44fac4bedde4df04b9572ac665d3ac2c5cd00c7d", // 64 MB
  134217728: "ba713b819c1202dcb0d178df9d2b3222ba1bba44", // 128 MB
  268435456: "7b91dbdc56c5781edf6c8847b4aa6965566c5c75", // 256 MB
  327155712: "ba799079bf8151d47045f3715bd4c7bfab0bba09"  // 312 MB
};
