/*
 * Asserts that an object can be encoded to an expected string.
 */
new sjcl.test.TestCase("JSON Encode Test", function (cb) {
	if(!sjcl.json) {
		this.unimplemented();
		cb && cb();
		return;
	}

	//Build up a standard object for encoding, this includes a nice wide variety of properties.
	var obj = new Object();
	obj.int = 4;
	obj.nint = -5;
	obj.str = 'string';
	obj.iv = [ -95577995, -949876189, 1443400017, 697058741 ];
	obj.truth = true;
	obj.lie = false;

	try {
		var str = sjcl.json.encode(obj);
		this.require(!(!str)); //Check for non-'falsey'
	}
	catch (e) {
		//The standard object should encode just fine, so this is out of place. Fail.
		this.fail(e);
	}
	cb && cb();
});


/*
 * Asserts that a JSON string can be decoded to an expected object.
 */
new sjcl.test.TestCase("JSON Decode Test", function (cb) {
	if(!sjcl.json) {
		this.unimplemented();
		cb && cb();
		return;
	}
	
	var str = ''; var i;
	str = '{"int":4,"nint":-5,"str":"string","iv":"/////wAAAAAAAAABAAAAAg==","truth":true,"lie":false}';

	try { 
		var obj = sjcl.json.decode(str);
		this.require(obj.int === 4);
		this.require(obj.nint === -5);
		this.require(obj.str === 'string');
		this.require(obj.truth === true);
		this.require(obj.lie === false);
		for(i in obj.iv) {
			this.require(obj.iv[i] == (i-1)); //Array in iv is [-1,0,1,2]
		}
	} catch (e) { this.fail(e); }

	str = '{ "int" : 4,  "nint"  :  -5,"str":"string",  "iv":  "/////wAAAAAAAAABAAAAAg==","truth": true,"lie":  false  }';
	try { 
		var obj = sjcl.json.decode(str);
		this.require(obj.int === 4);
		this.require(obj.nint === -5);
		this.require(obj.str === 'string');
		this.require(obj.truth === true);
		this.require(obj.lie === false);
		for(i in obj.iv) {
			this.require(obj.iv[i] == (i-1)); //Array in iv is [-1,0,1,2]
		}
	} catch (e) { this.fail(e); }
	
	//Tests passed, return.
	cb && cb();
});


/*
 * Asserts that an Object can be Encoded to a string that can be decoded to an equivalent object
 * as well as the converse.
 */
new sjcl.test.TestCase("JSON Commutative Test", function (cb) {
	if(!sjcl.json) {
		this.unimplemented();
		cb && cb();
		return;
	}

	var obj1 = new Object();
	obj1.int = 4;
	obj1.nint = -5;
	obj1.str = 'string';
	obj1.iv = [ -95577995, -949876189, 1443400017, 697058741 ];
	obj1.truth = true;
	obj1.lie = false;

	var str1 = '';
	var str2 = '';
	var obj2;
	try {
		str1 = sjcl.json.encode(obj1);
		obj2 = sjcl.json.decode(str1);
		str2 = sjcl.json.encode(obj2);
	}
	catch (e) {
		this.fail(e);
	}

	try {
		this.require(str1 === str2);
		this.require(obj1.int == obj2.int);
		this.require(obj1.str == obj2.str);
		this.require(obj1.lie == obj2.lie);
		this.require(obj1.nint == obj2.nint);
		this.require(obj1.truth == obj2.truth);

		var i;
		for(i in obj1.iv)
		{
			this.require(obj1.iv[i] == obj2.iv[i]);
		}
	}
	catch (e) {
		this.fail(e);
	}

	//Tests passed.
	cb && cb();
});
