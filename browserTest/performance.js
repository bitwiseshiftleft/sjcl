sjcl.perf = { all: {} };

sjcl.perf.PerfCase = function PerfCase (name, cases, runCase) {
  this.name = name;
  this.cases = cases;
  this.runCase = runCase;
  sjcl.perf.all[name] = this;
};

sjcl.perf.PerfCase.prototype.run = function (callback) {
  var thiz = this;

  var repo = browserUtil.write("info", "Running " + this.name + "...");
  var table = browserUtil.writeTable(["iter", "time"]);

  thiz.runCase(this.cases[0]); // cold start

  browserUtil.cpsMap(function (t, i, n, cb) {
      var runs = [];

      // do 3 runs and average them
      for (var k = 0; k < 3; k++) {
        var t0 = performance.now();
        thiz.runCase(t);
        var t1 = performance.now();
        runs.push(t1 - t0);
      }

      var avg = runs.reduce(function(a, b) { return a + b; }) / runs.length;
      table.update([t, avg.toFixed(3) + ' ms']);

      cb && cb();
  }, this.cases, true, function() {

    repo.update("pass", "done.");
    callback();

  });
};

sjcl.perf.run = function (perfs, callback) {
  browserUtil.status("Profiling...");

  var t;
  if (perfs === undefined || perfs.length == 0) {
    perfs = [];
    for (t in sjcl.perf.all) {
      if (sjcl.perf.all.hasOwnProperty(t)) {
        perfs.push(t);
      }
    }
  }

  browserUtil.cpsMap(function (t, i, n, cb) {
    sjcl.perf.all[perfs[i]].run(cb);
  }, perfs, true, callback);
};


// performance case for pbkdf2
var cases = [1000, 2000, 4000, 8000, 16000, 32000, 48000, 64000];
new sjcl.perf.PerfCase("pbkdf2", cases,
  function (iter) {
    sjcl.misc.pbkdf2("mypassword", "01234567890123456789", iter);
  }
);

sjcl.perf.run([], function() {
  browserUtil.status("");
});
