#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathUtils.hpp>
#include <limal/Exception.hpp>
#include <limal/ByteBuffer.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    PerlRegEx r("ENCRYPTED");

    try
    {
        cout << "START" << endl;

        blocxx::StringArray cat;
        cat.push_back("FATAL");
		// do not log errors because the openssl errors include a pid which changes everytime
        //cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "ConvertTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

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

        		PerlRegEx p("DEK-Info: AES-256-CBC");
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
    catch(Exception& e)
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
	catch(Exception& e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		blocxx::String msg = blocxx::String(e.getMessage());
		
		cerr <<	msg.tokenize("\n\r")[0] << endl << "END" << endl;
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
	catch(Exception &e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		blocxx::String msg = blocxx::String(e.getMessage());

		cerr << msg.tokenize("\n\r")[0] << endl << "END" << endl;
	}
	
	p12 = LocalManagement::createPKCS12(crt, key, "system", "tralla",
	                                    ca, "./TestRepos3/.cas/", false);
	
	try
	{
		ByteBuffer pem = LocalManagement::pkcs12ToPEM(p12, "wrong password", "system", "aes256");
		
		if(pem.size() > 0)
		{
			cout << "Got PEM " << endl;
			
			PerlRegEx p("DEK-Info: AES-256-CBC");
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
	catch(Exception &e)
	{
		cout << "Got expected Exception." << endl;
		cerr << "Exception:" << endl << e.getFile() << ": " << e.type() << ": " << e.getErrorCode() << ": ";
		blocxx::String msg = blocxx::String(e.getMessage());

		cerr << msg.tokenize("\n\r")[0] << endl << "END" << endl;
	}
		
	cout << "DONE" << endl;

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
