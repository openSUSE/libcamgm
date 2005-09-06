/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                           |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       LocalManagement.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/LocalManagement.hpp>

#include  <limal/PathInfo.hpp>
#include  <limal/PathName.hpp>
#include  <limal/PathUtils.hpp>

#include <fstream>

#include  "OPENSSL.h"

#include  "CertificateData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "Utils.hpp"
#include  "Commands.hpp"

#include  <blocxx/File.hpp>

#include  <string.h>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

inline static blocxx::String errno2String(int e) {
    // FIXME: make strerror working
    //blocxx::String s(::strerror(e));
    blocxx::String s = "(" + blocxx::String(e) + ")";
    return "";
}

void 
LocalManagement::importAsLocalCertificate(const String &pkcs12File,
                                          const String &password,
                                          const String &destinationCAsDir,
                                          const String &destinationCertFile,
                                          const String &destinationKeyFile)
{

    importAsLocalCertificate(readFile(pkcs12File),
                             password, destinationCAsDir,
                             destinationCertFile, destinationKeyFile);

}

void
LocalManagement::importAsLocalCertificate(const ByteArray &pkcs12Data,
                                          const String    &password,
                                          const String    &destinationCAsDir,
                                          const String    &destinationCertFile,
                                          const String    &destinationKeyFile)
{
    Map<String, String> hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = "/";
    hash["DEBUG"]  = "1";
    OPENSSL ossl(hash);
    
    hash.clear();
    hash["DATATYPE"]  = "CERTIFICATE";
    hash["INFORM"]    = "PKCS12";
    hash["DATA"]      = LocalManagement::ba2str(pkcs12Data);
    hash["OUTFORM"]   = "PEM";
    hash["INPASSWD"]  = password;
    hash["OUTPASSWD"] = "";
    //hash[""] = "";

    String data = ossl.convert(hash);

    Array< Map<String, String> > list;

    String info;
    String cert;
    String subject;
    String issuer;
    String keyID;

    StringArray dataList = PerlRegEx("\n").split(data);

    if(dataList.size() <= 1) {

        LOGIT_ERROR("Cannot split certificate output");
        BLOCXX_THROW(limal::RuntimeException,
                     "Cannot split certificate output");

    }

    PerlRegEx endRegex("^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$");
    PerlRegEx beginRegex("^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$");
    PerlRegEx keyIDRegex("^\\s+localKeyID:\\s*([0-9a-fA-F\\s]+)\\s*$");
    PerlRegEx subjectRegex("^subject=(.*)\\s*$");
    PerlRegEx issuerRegex("^issuer=(.*)\\s*$");

    StringArray::const_iterator lineIT = dataList.begin() + 1;
    
    for(; lineIT != dataList.end(); ++lineIT) {

        if(!info.empty()) {

            cert += (*lineIT)+"\n";

            if(endRegex.match(*lineIT)) {
                
                StringArray ia = endRegex.capture(*lineIT);
                if(ia.size() == 2 && ia[1] == info) {
                    
                    Map<String, String> v;
                    v["info"]    = info;
                    v["data"]    = cert;
                    v["keyID"]   = keyID;
                    v["subject"] = subject;
                    v["issuer"]  = issuer;

                    list.push_back(v);

                    LOGIT_DEBUG(">>>> SAVE MAP: \ninfo = " << info <<
                                "\ndata = " << cert <<
                                "\nkeyID = " << keyID <<
                                "\nsubject = " << subject <<
                                "\nissuer = " << issuer);
                    
                }

                info.erase();
                cert.erase();
                keyID.erase();
                subject.erase();
                issuer.erase();
            }
        } else {
            
            if(beginRegex.match(*lineIT)) {
                
                StringArray ia = beginRegex.capture(*lineIT);
                if(ia.size() == 2 ) {
                    
                    info = ia[1];
                    cert += (*lineIT)+"\n";
                    
                } else {
                    LOGIT_DEBUG("Problem with beginRegex size:" << ia.size());
                    // FIXME: do something here ?
                }
            } else {
                
                if(keyIDRegex.match(*lineIT)) {
                    
                    StringArray ia = keyIDRegex.capture(*lineIT);
                    if(ia.size() == 2 ) {
                        
                        keyID = ia[1];
                        
                    } else {
                        LOGIT_DEBUG("Problem with keyIDRegex size:" << ia.size());
                        // FIXME: do something here ?
                        }
                } else if(subjectRegex.match(*lineIT)) {
                    
                    StringArray ia = subjectRegex.capture(*lineIT);
                    if(ia.size() == 2 ) {
                        
                        subject = ia[1];
                        
                    } else {
                        LOGIT_DEBUG("Problem with subjectRegex size:" << ia.size());
                        // FIXME: do something here ?
                    }
                } else if(issuerRegex.match(*lineIT)) {
                    
                    StringArray ia = issuerRegex.capture(*lineIT);
                    if(ia.size() == 2 ) {
                        
                        issuer = ia[1];
                        
                    } else {
                        LOGIT_DEBUG("Problem with issuerRegex size:" << ia.size());
                        // FIXME: do something here ?
                    }
                } else {
                    LOGIT_DEBUG("Unknown line:" << *lineIT);
                }
            }
        }
    }
    
    keyID.erase();

    String serverCertIssuer;

    String serverCert;
    String serverKey;
    String srvIssuerCert;
    Array<String> restCA;

    // search for the server certificate
    
    Array< Map<String, String> >::iterator certMap = list.begin();

    for(; certMap != list.end(); ++certMap) {

        Map<String, String>::iterator keyIT = (*certMap).find("keyID");
        Map<String, String>::iterator subjectIT = (*certMap).find("subject");

        if( keyIT != (*certMap).end() &&
            !((*keyIT).second.empty()) &&
            subjectIT != (*certMap).end() &&
            !((*subjectIT).second.empty()) ) {
            
            keyID            = (*keyIT).second;
            serverCertIssuer = (*(*certMap).find("issuer")).second;
            serverCert       = (*(*certMap).find("data")).second;
            (*(*certMap).find("data")).second.erase();
            (*(*certMap).find("keyID")).second.erase();
            break;
        }
    }

    // search for the private key

    certMap = list.begin();

    for(; certMap != list.end(); ++certMap) {
        
        Map<String, String>::iterator keyIT = (*certMap).find("keyID");

        if( keyIT != (*certMap).end() &&
            (*keyIT).second == keyID ) {
            
            serverKey        = (*(*certMap).find("data")).second;
            (*(*certMap).find("data")).second.erase();
            break;
        }
    }

    // search for the ca which issuered the server certificate

    certMap = list.begin();
    
    for(; certMap != list.end(); ++certMap) {
        
        Map<String, String>::iterator subjectIT = (*certMap).find("subject");

        if( subjectIT != (*certMap).end() &&
            (*subjectIT).second == serverCertIssuer ) {
            
            srvIssuerCert        = (*(*certMap).find("data")).second;
            (*(*certMap).find("data")).second.erase();
            break;
        }
    }

    // collect the rest CAs

    certMap = list.begin();
    
    for(; certMap != list.end(); ++certMap) {
        
        Map<String, String>::iterator dataIT = (*certMap).find("data");

        if( dataIT != (*certMap).end() &&
            !(*dataIT).second.empty() ) {

            restCA.push_back( (*dataIT).second );

        }
    }
    
    if(!serverCert.empty() && !serverKey.empty()) {

        path::PathName pn(destinationCertFile);
        path::PathInfo pi(pn.dirName());

        if(!pi.exists()) {

            int r = createDirRecursive(pi.path());

            if(r != 0) {

                LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
                BLOCXX_THROW(limal::SystemException,
                             Format("Cannot create directory '%1' :%2", 
                                    pi.toString(), errno2String(r)).c_str());

            }
        }

        writeFile(str2ba(serverCert),
                  destinationCertFile);


        pn = path::PathName(destinationKeyFile);
        pi.stat(pn.dirName());

        if(!pi.exists()) {

            int r = createDirRecursive(pi.path());

            if(r != 0) {

                LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
                BLOCXX_THROW(limal::SystemException,
                             Format("Cannot create directory '%1' :%2", 
                                    pi.toString(), errno2String(r)).c_str());

            }
        }
        
        writeFile(str2ba(serverKey),
                  destinationKeyFile, 0600);


        pi.stat(destinationCAsDir);
        if(!pi.exists() ) {

            int r = createDirRecursive(pi.path());
            
            if(r != 0) {
                
                LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
                BLOCXX_THROW(limal::SystemException,
                             Format("Cannot create directory '%1' :%2", 
                                    pi.toString(), errno2String(r)).c_str());
                
            }
        } 

        if(!srvIssuerCert.empty()) {

            pi.stat(destinationCAsDir);
        
            if(!pi.isDir()) {
                
                LOGIT_ERROR( "'" << pi.toString() <<"' is not a directory");
                BLOCXX_THROW(limal::ValueException,
                             Format("'%1' is not a directory", pi.toString()).c_str());
                
            }
            
            writeFile(str2ba(srvIssuerCert),
                      pi.toString() + "/YaST-CA.pem");

            for(uint i = 0; i < restCA.size(); ++i) {
                
                writeFile(str2ba(restCA[i]),
                          pi.toString() + "/YaST-CA-" + String(i) + ".pem");
            }
        
            rehashCAs(pi.toString());
            
        }
        
    } else {

        LOGIT_ERROR("Invalid certificate file.");
        BLOCXX_THROW(limal::SyntaxException,
                     "Invalid certificate file.");
    }
}


void 
LocalManagement::importCommonServerCertificate(const String &pkcs12File,
                                               const String &password)
{
    importAsLocalCertificate(readFile(pkcs12File),
                             password,
                             "/etc/ssl/certs/",
                             "/etc/ssl/servercerts/servercert.pem",
                             "/etc/ssl/servercerts/serverkey.pem");
}

void
LocalManagement::importCommonServerCertificate(const ByteArray &pkcs12Data,
                                               const String    &password)
{
    importAsLocalCertificate(pkcs12Data,
                             password,
                             "/etc/ssl/certs/",
                             "/etc/ssl/servercerts/servercert.pem",
                             "/etc/ssl/servercerts/serverkey.pem");
}

CertificateData
LocalManagement::getCertificate(const String &file,
                                FormatType    type)
{
    return CertificateData_Priv(file, type);
}

RequestData
LocalManagement::getRequest(const String &file,
                            FormatType    type)
{
    return RequestData_Priv(file, type);
}

CRLData
LocalManagement::getCRL(const String &file,
                        FormatType    type)
{
    return CRLData_Priv(file, type);
}

CertificateData
LocalManagement::getCertificate(const ByteArray &data,
                                FormatType    type)
{
    return CertificateData_Priv(data, type);
}
        
RequestData
LocalManagement::getRequest(const ByteArray &data,
                            FormatType    type)
{
    return RequestData_Priv(data, type);
}
        
CRLData
LocalManagement::getCRL(const ByteArray &data,
                        FormatType    type)
{
    return CRLData_Priv(data, type);
}


ByteArray
LocalManagement::readFile(const String& file)
{
    path::PathInfo filePi(file);
    if(!filePi.exists()) {

        LOGIT_ERROR("File not found: " << filePi.toString());
        BLOCXX_THROW(limal::RuntimeException,
                     Format("File not found: %1", filePi.toString()).c_str());
        
    }

    if(filePi.size() > (1024*1024)) {

        LOGIT_ERROR("File too big: " << filePi.toString());
        BLOCXX_THROW(limal::RuntimeException,
                     Format("File too big: %1", filePi.toString()).c_str());

    }

    int fd = ::open(file.c_str(), O_RDONLY);
    if(fd == -1) {

        LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
        BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
                                Format("Cannot open file: %1", file).c_str(),
                                errno);

    }

    File fileObject(fd);
    ByteArray   ret;
    size_t      i = 1;
    
    while( i != 0 ) {
        char *buf = new char[1025];
        i = fileObject.read(buf, 1024);

        if(i == size_t(-1)) {
            
            delete(buf);
            fileObject.close();
            
            LOGIT_ERROR("Cannot read from file: " << file << "(" << errno << ")");
            BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
                                    Format("Cannot read from file: %1", file).c_str(),
                                    errno);
        }

        for(uint k = 0; k < i; ++k) {

            ret.push_back(buf[k]);
        }
        
        delete(buf);
    }

    fileObject.close();

    return ret;
}

void
LocalManagement::writeFile(const ByteArray& data,
                           const String &file,
                           bool overwrite,
                           mode_t mode)
{
    path::PathInfo pi(file);
    if(pi.exists() && !overwrite) {
        
        LOGIT_ERROR ("File already exists: " << file );
        BLOCXX_THROW(limal::SystemException,
                     Format("CFile already exists: %1", file).c_str());
        
    }

    int fd = ::open(file.c_str(), O_CREAT|O_TRUNC|O_WRONLY, mode);
    if(fd == -1) {

        LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
        BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
                                Format("Cannot open file: %1", file).c_str(),
                                errno);

    }

    File fileObject(fd);

    int r = fileObject.getLock();
    if(r != 0) {

        LOGIT_ERROR("Cannot get lock on file: " << file << "(" << errno << ")");
        BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
                                Format("Cannot get lock on file: %1", file).c_str(),
                                errno);

    }
    
    ByteArray::const_iterator it = data.begin();
    char *out = new char[data.size()];

    for(uint i = 0; it != data.end(); ++it, ++i) {
        
        out[i] = static_cast<char>(*it);
    }

    size_t st = fileObject.write(out, data.size());

    if(st == size_t(-1)) {

        delete(out);
        fileObject.unlock();
        fileObject.close();

        LOGIT_ERROR("Cannot write to file: " << file << "(" << errno << ")");
        BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
                                Format("Cannot write to file: %1", file).c_str(),
                                errno);
    }

    delete(out);
    fileObject.flush();
    fileObject.unlock();
    fileObject.close();
}

blocxx::String
LocalManagement::ba2str(const ByteArray& data)
{
    String ret;

    String dbg;

    char *c = new char[data.size()];

    ByteArray::const_iterator it = data.begin();
    
    for(uint i = 0; it != data.end(); ++it, ++i) {

        c[i] = static_cast<char>(*it);
        
    }
    ret = String(c, data.size());
    delete(c);

    return ret;
}

ByteArray
LocalManagement::str2ba(const String& data)
{
    ByteArray ret;

    for(size_t i = 0; i < data.length(); ++i) {

        ret.push_back( data.charAt(i) );

    }

    return ret;

}
