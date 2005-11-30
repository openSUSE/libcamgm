#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;
        
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "RemoveCertificateTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        limal::Logger::setDefaultLogger(l);
        
        cout << "=================== start ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            Array<Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getCertificateList();

            Array<Map<blocxx::String, blocxx::String> >::const_iterator it;
            int i = 0;
            for(it = ret.begin(); it != ret.end(); ++it)
            {            
                blocxx::String certificateName = (*((*it).find("certificate"))).second;
                blocxx::String state           = (*((*it).find("status"))).second;

                PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
                StringArray sa = p.capture(certificateName);

                if(sa.size() != 3)
                {
                    cerr << "Can not parse certificate name ... continue." << endl;
                    continue;
                }

                blocxx::String serial  = sa[1];
                blocxx::String request = sa[2];

                //cerr << "i == " << i << " State == " << state << endl;

                
                if(i == 1 && state != "Valid")
                {
                    path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                            certificateName + ".pem");
                    if(certFile.exists())
                    {                        
                        ca.deleteCertificate(certificateName);

                        certFile.stat();
                        if(!certFile.exists())
                        {
                            cout << "Take 1: Delete Certificate successfull." << endl;
                        }
                        else
                        {
                            cout << "Take 1: Delete Certificate failed." << endl;
                        }

                        path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" +
                                               request + ".key");
                        if(!keyFile.exists())
                        {
                            cout << "Take 1: Delete Key successfull." << endl;
                        }
                        else
                        {
                            cout << "Take 1: Delete Key failed." << endl;
                        }

                        path::PathInfo reqFile("./TestRepos/Test_CA1/req/" +
                                               request + ".req");
                        if(!reqFile.exists())
                        {
                            cout << "Take 1: Delete Request successfull." << endl;
                        }
                        else
                        {
                            cout << "Take 1: Delete Request failed." << endl;
                        }
                    }
                    else
                    {
                        cout << "Take 1: Certificate not found." << endl;
                    }
                    i++;
                }
                else if(i == 2 && state != "Valid")
                {
                    path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                            certificateName + ".pem");
                    if(certFile.exists())
                    {                        
                        ca.deleteCertificate(certificateName, false);
                        
                        certFile.stat();
                        if(!certFile.exists())
                        {
                            cout << "Take 2: Delete Certificate successfull." << endl;
                        }
                        else
                        {
                            cout << "Take 2: Delete Certificate failed." << endl;
                        }

                        path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" +
                                               request + ".key");
                        if(!keyFile.exists())
                        {
                            cout << "Take 2: Key not exists. !!! Wrong !!!" << endl;
                        }
                        else
                        {
                            cout << "Take 2: Key still exists. !!! OK !!!" << endl;
                        }

                        path::PathInfo reqFile("./TestRepos/Test_CA1/req/" +
                                               request + ".req");
                        if(!reqFile.exists())
                        {
                            cout << "Take 2: Request not exists. !!! Wrong !!!" << endl;
                        }
                        else
                        {
                            cout << "Take 2: Request still exists. !!! OK !!!" << endl;
                        }
                    }
                    else
                    {
                        cout << "Take 2: Certificate not found." << endl;
                    }
                    i++;
                }
                else if(i == 0 && state == "Valid")
                {
                    path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                            certificateName + ".pem");
                    if(certFile.exists())
                    {
                        try
                        {
                            ca.deleteCertificate(certificateName, false);
                            
                            certFile.stat();
                            if(!certFile.exists())
                            {
                                cout << "Take 0: Delete Certificate successfull." << endl;
                            }
                            else
                            {
                                cout << "Take 0: Delete Certificate failed." << endl;
                            }
                        }
                        catch(RuntimeException &e)
                        {
                            cout << "Take 0: Delete Certificate failed. This is ok" << endl;
                        }
                    }
                    else
                    {
                        cout << "Take 0: Certificate not found." << endl;
                    }
                    i++;
                }
                else
                {
                    continue;
                }
            }
        }        
        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }
    
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
