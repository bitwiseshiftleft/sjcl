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
	npm run jsdoc -- $(SOURCES) --destination $@

doc_private: $(SOURCES)
	rm -fr $@
	npm run jsdoc -- $(SOURCES) --destination $@ --private

lint:
	npm run lint


TEST_COMMON=  browserTest/nodeUtil.js test/test.js

TEST_SCRIPTS= $(TEST_COMMON) \
              test/ccm_vectors.js test/ccm_arraybuffer_test.js \
              test/codec_arraybuffer_test.js \
              test/aes_vectors.js test/aes_test.js \
              test/bitArray_vectors.js test/bitArray_test.js \
              test/bn_vectors.js test/bn_test.js \
              test/cbc_vectors.js test/cbc_test.js  \
              test/ctr_vectors.js test/ctr_test.js  \
              test/ccm_vectors.js test/ccm_test.js  \
              test/ecc_vectors.js test/ecc_test.js \
              test/ecc_conv.js \
              test/ecdsa_test.js test/ecdsa_vectors.js test/ecdh_test.js \
              test/gcm_vectors.js test/gcm_test.js  \
              test/hmac_vectors.js test/hmac_test.js \
              test/json_test.js \
              test/ocb2_vectors.js test/ocb2_test.js  \
              test/ocb2progressive_test.js  \
              test/pbkdf2_test.js test/scrypt_vectors.js test/scrypt_test.js \
              test/ripemd160_vectors.js test/ripemd160_test.js \
              test/sha1_vectors.js test/sha1_test.js \
              test/sha1_vectors_long_messages.js test/sha1_test_long_messages.js \
              test/sha1_huge_test_messages.js test/sha1_huge_test.js \
              test/sha256_vectors.js test/sha256_test.js \
              test/sha256_huge_test_messages.js test/sha256_huge_test.js \
              test/sha256_vectors_long_messages.js test/sha256_test_long_messages.js \
              test/sha256_test_brute_force.js \
              test/sha512_vectors.js test/sha512_test.js \
              test/sha512_vectors_long_messages.js test/sha512_test_long_messages.js \
              test/sha512_huge_test_messages.js test/sha512_huge_test.js \
              test/sha512_test_brute_force.js \
              test/srp_vectors.js test/srp_test.js \
	      test/z85_vectors.js test/z85_test.js

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
