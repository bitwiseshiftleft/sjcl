var fs = require('fs');
var vm = require('vm');

var load = function(path) {
    vm.runInThisContext(fs.readFileSync(path));
};

// Assume we're run using `make test`.
// That means argv[0] is `node` and argv[1] is this file.
process.argv.slice(2).map(load);

sjcl.test.run(undefined, function(){
  if(!browserUtil.allPassed) {
    process.exit(1);
  }
});
