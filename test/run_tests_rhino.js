if (arguments === undefined || load === undefined) {
  throw "This script must be run from Rhino.";
}

for (var i=0; i<arguments.length; i++) {
  var file = arguments[i];
  if (!file.match(/^-/)) load(file);
}

sjcl.test.run(undefined, function(){
  if(!browserUtil.allPassed) {
    throw "All tests complete, but some failed!";
  }
});
