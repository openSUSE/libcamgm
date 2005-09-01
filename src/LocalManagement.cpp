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
#include  "CertificateData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "RequestData_Priv.hpp"

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

