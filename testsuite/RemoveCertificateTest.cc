#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

// FIXME: need to be removed
#include <Utils.hpp>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        // Logging
        shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

        cout << "=================== start ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            std::vector<map<std::string, std::string> > ret;
            ret = ca.getCertificateList();

            std::vector<map<std::string, std::string> >::const_iterator it;
            int i = 0;
            for(it = ret.begin(); it != ret.end(); ++it)
            {
                std::string certificateName = (*((*it).find("certificate"))).second;
                std::string state           = (*((*it).find("status"))).second;

                PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
                std::vector<std::string> sa = p.capture(certificateName);

                if(sa.size() != 3)
                {
                    cerr << "Can not parse certificate name ... continue." << endl;
                    continue;
                }

                std::string serial  = sa[1];
                std::string request = sa[2];

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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
