new sjcl.test.TestCase("variable names that share space with compressed variable names", function (cb) {
  t = 10; // assign anything to t
  u = 10; // assign anything to u
  this.pass()
  cb && cb();
});
