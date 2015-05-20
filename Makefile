JSDOCSTYLE= codeview
JSDOCDIR= jsdoc_toolkit-2.3.3-beta
JSDOC= $(JSDOCDIR)/jsrun.sh
JSTEMPLATEDIR= $(JSDOCDIR)/templates/$(JSDOCSTYLE)/

YUICOMPRESSOR= yuicompressor-2.4.2.jar

include config.mk

.PHONY: all test test_yui test_closure test_uncompressed lint compression_stats

all: sjcl.js

sjcl.js: $(COMPRESS)
	cp $^ $@

core.js: $(SOURCES) config.mk
	cat $(SOURCES) > $@

# compressed targets
core_closure.js: core.js compress/compress_with_closure.sh compress/*.pl
	compress/compress_with_closure.sh $< > $@

core_yui.js: core.js compress/compress_with_yui.sh compress/*.pl
	compress/compress_with_yui.sh $< > $@

compression_stats: core.js core_closure.js core_yui.js
	gzip -c core.js > core.js.gz
	gzip -c core_yui.js > core_yui.js.gz
	gzip -c core_closure.js > core_closure.js.gz

	@echo
	@echo
	@echo Compression stats:
	@echo
	@wc -c core.js core_closure.js core_yui.js | head -n -1
	@echo
	@wc -c core*.js.gz | head -n -1
	@echo
	@echo

	rm -f core*.js.gz

doc: $(SOURCES)
	rm -fr $@
	JSDOCDIR=$(JSDOCDIR) $(JSDOC) -t=$(JSTEMPLATEDIR) $(SOURCES) -d=$@

doc_private: $(SOURCES)
	rm -fr $@
	JSDOCDIR=$(JSDOCDIR) $(JSDOC) -t=$(JSTEMPLATEDIR) $(SOURCES) --private -d=$@

lint: core.js core/*.js test/*.js browserTest/*.js lint/coding_guidelines.pl
	rhino lint/jslint_rhino.js core.js
	lint/coding_guidelines.pl core/*.js test/*.js browserTest/*.js


TEST_COMMON=  browserTest/nodeUtil.js test/test.js

TEST_SCRIPTS= $(TEST_COMMON) \
              test/ccm_vectors.js test/ccm_arraybuffer_test.js \
              test/codec_arraybuffer_test.js \
              test/aes_vectors.js test/aes_test.js \
              test/bitArray_vectors.js test/bitArray_test.js \
              test/bn_vectors.js test/bn_test.js \
              test/cbc_vectors.js test/cbc_test.js  \
              test/ccm_vectors.js test/ccm_test.js  \
              test/ecc_conv.js \
              test/ecdsa_test.js test/ecdsa_vectors.js test/ecdh_test.js \
              test/gcm_vectors.js test/gcm_test.js  \
              test/hmac_vectors.js test/hmac_test.js \
              test/json_test.js \
              test/ocb2_vectors.js test/ocb2_test.js  \
              test/pbkdf2_test.js \
              test/ripemd160_vectors.js test/ripemd160_test.js \
              test/sha1_vectors.js test/sha1_test.js \
              test/sha256_vectors.js test/sha256_test.js \
              test/sha256_test_brute_force.js \
              test/sha512_vectors.js test/sha512_test.js \
              test/sha512_test_brute_force.js \
              test/srp_vectors.js test/srp_test.js

# Run all tests in node.js.
test: sjcl.js $(TEST_SCRIPTS) test/run_tests_node.js
	node test/run_tests_node.js $< $(TEST_SCRIPTS)

tidy:
	find . -name '*~' -delete
	rm -f core.js core_*.js

clean: tidy
	rm -fr sjcl.js doc doc_private

distclean: clean
	./configure
	make sjcl.js tidy
