
check: clean-local

clean-local:
	rm -rf Test_CA/
	rm -rf Test_CA3/
	rm -rf SubCA_Test/
	rm -f .cas/*
	if [ ! -d "./.cas" ]; then \
	    mkdir .cas; \
	fi
	rm -f Test_CA1/keys/*.key
	rm -f Test_CA1/req/*.req
	rm -f Test_CA1/newcerts/*.pem
	rm -f Test_CA1/certs/*.pem
	rm -f Test_CA1/crl/crl.pem
	rm -f Test_CA1/serial; echo -n "01" > Test_CA1/serial
	rm -f Test_CA1/index.txt; touch Test_CA1/index.txt
	rm -f Test_CA1/cam.txt; touch Test_CA1/cam.txt
	if [ ! -d "Test_CA1/keys" ]; then mkdir Test_CA1/keys ; fi
	if [ ! -d "Test_CA1/req" ]; then mkdir Test_CA1/req ; fi
	if [ ! -d "Test_CA1/newcerts" ]; then mkdir Test_CA1/newcerts ; fi
	if [ ! -d "Test_CA1/certs" ]; then mkdir Test_CA1/certs ; fi
	if [ ! -d "Test_CA1/crl" ]; then mkdir Test_CA1/crl ; fi
	cp Test_CA2/cacert.pem .cas/Test_CA2.pem
	cp Test_CA2/crl/crl.pem .cas/crl_Test_CA2.pem
	c_rehash .cas/
	rm -f ca1_test/openssl.cnf
	rm -f ca2_test/openssl.cnf
	rm -f Test_CA1/serial.old
	rm -f Test_CA1/index.txt.old
	rm -f Test_CA1/.rand
	rm -f Test_CA1/index.txt.attr.old
	rm -f .rand


MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = ca1_test/*.* ca2_test/*.* \
             Test_CA1/*                \
             Test_CA2/*                \
             .cas                      \
	     importCATestEnc.key       \
	     importCATest.key importCATest.pem \
	     importRequestTest-DER.req \
	     importRequestTest.req     \
	     openssl.cnf.tmpl \
	     c293624b6a877f401407ce8f8f1f327e.req

dist-hook:
	rm -rf `find $(distdir)/ -name .svn`

