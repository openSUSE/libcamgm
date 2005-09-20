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

  File:       LocalManagement.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP
#define    LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CertificateData.hpp>
#include  <limal/ca-mgm/RequestData.hpp>
#include  <limal/ca-mgm/CRLData.hpp>
#include  <limal/ByteBuffer.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Functions for local certificate management
     *
     * This class provides functions for local certificate management which
     * are usefull on every host. 
     */
    class LocalManagement {

    public:

        static void 
        importAsLocalCertificate(const String &pkcs12File,
                                 const String &password,
                                 const String &destinationCAsDir,
                                 const String &destinationCertFile,
                                 const String &destinationKeyFile);
        
        static void
        importAsLocalCertificate(const limal::ByteBuffer &pkcs12Data,
                                 const String            &password,
                                 const String            &destinationCAsDir,
                                 const String            &destinationCertFile,
                                 const String            &destinationKeyFile);

        static void 
        importCommonServerCertificate(const String &pkcs12File,
                                      const String &password);
        
        static void
        importCommonServerCertificate(const limal::ByteBuffer &pkcs12File,
                                      const String            &password);
        
        static CertificateData
        getCertificate(const String &file,
                       FormatType    type);
        
        static RequestData
        getRequest(const String &file,
                   FormatType    type);
        
        static CRLData
        getCRL(const String &file,
               FormatType    type);

        static CertificateData
        getCertificate(const limal::ByteBuffer &data,
                       FormatType               type);
        
        static RequestData
        getRequest(const limal::ByteBuffer &data,
                   FormatType               type);
        
        static CRLData
        getCRL(const limal::ByteBuffer &data,
               FormatType               type);
        

        static limal::ByteBuffer
        readFile(const String& file);

        static void
        writeFile(const limal::ByteBuffer& data,
                  const String &file,
                  bool overwrite = true,
                  mode_t mode = 0644);
        
    };

}
}
#endif //LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP
