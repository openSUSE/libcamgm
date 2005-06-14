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

  File:       CertificateData_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_DATA_INT_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_DATA_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CertificateData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CertificateData_Int : public CertificateData {
    public:
        CertificateData_Int();
        CertificateData_Int(const String &caName);
        CertificateData_Int(const String &caName,
                            const String &certificateName);
        virtual ~CertificateData_Int();

        void           setVersion(blocxx::UInt32 v);

        void           setSerial(const String& serial);
        
        void           setCertifiyPeriode(time_t start, time_t end);
        
        void           setIssuerDN(const DNObject& issuer);
        
        void           setSubjectDN(const DNObject& subject);

        void           setKeysize(blocxx::UInt32 size);

        void           setPublicKeyAlgorithm(KeyAlg pubKeyAlg);

        void           setPublicKey(const ByteArray derPublicKey);

        void           setSignatureAlgorithm(SigAlg sigAlg);
        
        void           setSignature(const String& sig);

        void           setExtensions(const X509v3CertificateExtensions& ext);

    private:
        CertificateData_Int(const CertificateData_Int& data);

        CertificateData_Int& operator=(const CertificateData_Int& data);

                     
    };
    
}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
