#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/PathUtils.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/LocalManagement.hpp>
#include <ca-mgm/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater2.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    PerlRegEx r("ENCRYPTED");

    try
    {
        cout << "START" << endl;


        // Logging
        shared_ptr<LogControl::LineFormater> formater(new TestLineFormater2());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        // TestLineFormater2 do not log errors because the openssl errors include
        // a pid which changes everytime
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

        cout << "===================== Test x509Convert =====================" << endl;

        {
        	ByteBuffer pem = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.pem");

        	ByteBuffer der = LocalManagement::x509Convert(pem, E_PEM, E_DER);

        	if(der.size() > 0)
        	{
        		cout << "Got DER certificate" << endl;
        	}

        	ByteBuffer pem2 = LocalManagement::x509Convert(der, E_DER, E_PEM);

        	if(pem2.size() > 0)
        	{
        		cout << "Got PEM certificate" << endl;
        	}

        	if(pem == pem2)
        	{
        		cout << "correct" << endl;
        	}
        }

        cout << "===================== Test reqConvert =====================" << endl;

        {
        	ByteBuffer pem = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.req");

        	ByteBuffer der = LocalManagement::reqConvert(pem, E_PEM, E_DER);

        	if(der.size() > 0)
        	{
        		cout << "Got DER request" << endl;
        	}

        	ByteBuffer pem2 = LocalManagement::reqConvert(der, E_DER, E_PEM);

        	if(pem2.size() > 0)
        	{
        		cout << "Got PEM request" << endl;
        	}

        	if(pem == pem2)
        	{
        		cout << "correct" << endl;
        	}
        }

        cout << "===================== Test crlConvert =====================" << endl;

        {
        	ByteBuffer pem = LocalManagement::readFile("./TestRepos3/SUSERootCA/crl/crl.pem");

        	ByteBuffer der = LocalManagement::crlConvert(pem, E_PEM, E_DER);

        	if(der.size() > 0)
        	{
        		cout << "Got DER CRL" << endl;
        	}

        	ByteBuffer pem2 = LocalManagement::crlConvert(der, E_DER, E_PEM);

        	if(pem2.size() > 0)
        	{
        		cout << "Got PEM CRL" << endl;
        	}

        	if(pem == pem2)
        	{
        		cout << "correct" << endl;
        	}
        }

        cout << "===================== Test rsaConvert =====================" << endl;

        {
        	ByteBuffer pem = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.key");

        	ByteBuffer der = LocalManagement::rsaConvert(pem, E_PEM, E_DER, "system", "");

        	if(der.size() > 0)
        	{
        		cout << "Got DER Key" << endl;
        	}

        	ByteBuffer pem2 = LocalManagement::rsaConvert(der, E_DER, E_PEM, "", "tralla", "aes256");

        	if(pem2.size() > 0)
        	{
        		cout << "Got PEM Key" << endl;

        		PerlRegEx p("DEK-Info: AES-256-CBC");
        		if(p.match(pem2.data()))
        		{
        			cout << "correct encryption" << endl;
        		}
        		else
        		{
        			cout << "!!!WRONG encryption" << endl;
        		}

        		//cout << pem2.data() << endl;
        	}
        }

        cout << "===================== Test pkcs12Convert =====================" << endl;

        {
        	ByteBuffer crt = LocalManagement::readFile("./TestRepos3/SUSERootCA/certs/01.pem");
        	ByteBuffer key = LocalManagement::readFile("./TestRepos3/SUSERootCA/keys/a64a6c95f2a3dc22975e13691ad8e2bb-1111160526.key");
        	ByteBuffer ca  = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.pem");

        	ByteBuffer p12 = LocalManagement::createPKCS12(crt, key, "system", "tralla",
        	                                               ca, "./TestRepos3/.cas/", false);

        	if(p12.size() > 0)
        	{
        		cout << "Got PKCS12 data" << endl;
        	}

        	ByteBuffer pem = LocalManagement::pkcs12ToPEM(p12, "tralla", "system", "aes256");

        	if(pem.size() > 0)
        	{
        		cout << "Got PEM " << endl;

        		PerlRegEx p("ENCRYPTED PRIVATE KEY");
        		if(p.match(pem.data()))
        		{
        			cout << "correct encryption" << endl;
        		}
        		else
        		{
        			cout << "!!!WRONG encryption" << endl;
        		}

        		//cout << pem.data() << endl;
        	}
        }
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }


	cout << "===================== Test rsaConvert Exception =====================" << endl;

	try
	{
		ByteBuffer pem = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.key");

		ByteBuffer der = LocalManagement::rsaConvert(pem, E_PEM, E_DER, "wrong password", "");

		if(der.size() > 0)
		{
			cout << "Got DER Key" << endl;
		}
	}
	catch(ca_mgm::Exception& e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		std::string msg = std::string(e.getMessage());
        std::vector<std::string> sa;
        str::split(msg, std::back_inserter( sa ), "\n\r");
		cerr << sa[0] << endl << "END" << endl;
	}


	cout << "===================== Test pkcs12Convert Exception =====================" << endl;

	ByteBuffer crt = LocalManagement::readFile("./TestRepos3/SUSERootCA/certs/01.pem");
	ByteBuffer key = LocalManagement::readFile("./TestRepos3/SUSERootCA/keys/a64a6c95f2a3dc22975e13691ad8e2bb-1111160526.key");
	ByteBuffer ca  = LocalManagement::readFile("./TestRepos3/SUSERootCA/cacert.pem");

	ByteBuffer p12;

	try
	{
		p12 = LocalManagement::createPKCS12(crt, key, "wrong password", "tralla",
		                                    ca, "./TestRepos3/.cas/", false);

		if(p12.size() > 0)
		{
			cout << "Got PKCS12 data" << endl;
		}
	}
	catch(ca_mgm::Exception &e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		std::string msg = std::string(e.getMessage());
        std::vector<std::string> sa;
        str::split(msg, std::back_inserter( sa ), "\n\r");

		cerr << sa[0] << endl << "END" << endl;
	}

	p12 = LocalManagement::createPKCS12(crt, key, "system", "tralla",
	                                    ca, "./TestRepos3/.cas/", false);

	try
	{
		ByteBuffer pem = LocalManagement::pkcs12ToPEM(p12, "wrong password", "system", "aes256");

		if(pem.size() > 0)
		{
			cout << "Got PEM " << endl;

			PerlRegEx p("ENCRYPTED PRIVATE KEY");
			if(p.match(pem.data()))
			{
				cout << "correct encryption" << endl;
			}
			else
			{
				cout << "!!!WRONG encryption" << endl;
			}

			//cout << pem.data() << endl;
		}
	}
	catch(ca_mgm::Exception &e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		std::string msg = std::string(e.getMessage());
        std::vector<std::string> sa;
        str::split(msg, std::back_inserter( sa ), "\n\r");

		cerr << sa[0] << endl << "END" << endl;
	}

	cout << "DONE" << endl;

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
