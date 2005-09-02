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

#include <fstream>

#include  "CertificateData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

void 
LocalManagement::importAsLocalCertificate(const String &pkcs12File,
                                          const String &password,
                                          const String &destinationCAsDir,
                                          const String &destinationCertFile,
                                          const String &destinationKeyFile)
{
}

void
LocalManagement::importAsLocalCertificate(const ByteArray &pkcs12Data,
                                          const String    &password,
                                          const String    &destinationCAsDir,
                                          const String    &destinationCertFile,
                                          const String    &destinationKeyFile)
{
}


void 
LocalManagement::importCommonServerCertificate(const String &pkcs12File,
                                               const String &password)
{
}

void
LocalManagement::importCommonServerCertificate(const ByteArray &pkcs12File,
                                               const String    &password)
{
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

    std::ifstream in(filePi.toString().c_str());

    if(!in) {

        LOGIT_ERROR("Cannot open file: " << filePi.toString());
        BLOCXX_THROW(limal::RuntimeException,
                     Format("Cannot open file: %1", filePi.toString()).c_str());

    }
    
    int         i = 0;
    ByteArray ret;

    while(i != EOF) {

        i = in.get();
        ret.push_back(i);

    }
    in.close();

    return ret;
}

void
LocalManagement::writeFile(const ByteArray& data,
                           const String &file)
{
    std::ofstream out(file.c_str());
    
    if (!out) {
        
        LOGIT_ERROR ("Cannot open file " << file.toString() );
        BLOCXX_THROW(limal::SystemException,
                     Format("Cannot open file %1", file.toString()).c_str());
        
    }
    
    ByteArray::const_iterator it = data.begin();
    
    for(; it != data.end(); ++it) {
        
        out << static_cast<char>(*it);
    }
    out.close();
}

blocxx::String
LocalManagement::ba2str(const ByteArray& data)
{
    String ret;

    for(size_t i = 0; i < data.size(); ++i) {

        ret.concat( data[i] );

    }

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
