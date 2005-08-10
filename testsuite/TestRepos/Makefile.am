
check:
	echo "clean before check"
	rm -rf Test_CA/
	rm -f .cas/*

clean-local:
	rm -f ca1_test/openssl.cnf
	rm -f ca2_test/openssl.cnf
	rm -rf Test_CA/
	rm -f .cas/*

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = ca1_test/* ca2_test/* openssl.cnf.tmpl

