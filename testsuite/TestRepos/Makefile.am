
check:
	echo "clean before check"
	rm -rf Test_CA/
	rm -f .cas/*
	rm -f Test_CA1/keys/*.key
	rm -f Test_CA1/req/*.req
	rm -f Test_CA1/newcerts/*.pem
	rm -f Test_CA1/certs/*.pem
	rm Test_CA1/serial; echo -n "01" > Test_CA1/serial
	rm Test_CA1/index.txt; touch Test_CA1/index.txt
	rm Test_CA1/cam.txt; touch Test_CA1/cam.txt


clean-local:
	rm -f ca1_test/openssl.cnf
	rm -f ca2_test/openssl.cnf
	rm -rf Test_CA/
	rm -f .cas/*

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = ca1_test/* ca2_test/* openssl.cnf.tmpl

