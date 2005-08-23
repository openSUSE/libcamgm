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

  File:       CertificateData_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_DATA_PRIV_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_DATA_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CertificateData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CertificateData_Priv : public CertificateData {
    public:
        CertificateData_Priv();

        /**
         * Construct a CertificateData object by parsing a certificate 
         * file.
         *
         * If certificateName is empty the CA certificate of caName 
         * will be parsed.
         *
         */
        CertificateData_Priv(const String &certificatePath);
        CertificateData_Priv(const CertificateData_Priv& data);
        virtual ~CertificateData_Priv();

        void           setVersion(blocxx::UInt32 v);

        void           setSerial(const String& serial);
        
        void           setCertifiyPeriode(time_t start, time_t end);
        
        void           setIssuerDN(const DNObject& issuer);
        
        void           setSubjectDN(const DNObject& subject);

        void           setKeysize(blocxx::UInt32 size);

        void           setPublicKeyAlgorithm(KeyAlg pubKeyAlg);

        void           setPublicKey(const ByteArray derPublicKey);

        void           setSignatureAlgorithm(SigAlg sigAlg);
        
        void           setSignature(const ByteArray& sig);

        void           setExtensions(const X509v3CertificateExtensions& ext);

    private:
        CertificateData_Priv& operator=(const CertificateData_Priv& data);

                     
    };
    
}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_PRIV_HPP
