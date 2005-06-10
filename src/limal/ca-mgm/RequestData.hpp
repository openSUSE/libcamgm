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

  File:       RequestData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_REQUEST_DATA_HPP
#define    LIMAL_CA_MGM_REQUEST_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Read-only data representation of a request
     *
     * This class is a read-only data representation of a request
     */
    class RequestData {
    public:
        virtual ~RequestData();

        blocxx::UInt32      getVersion() const;
        blocxx::UInt32      getKeysize() const;
        DNObject            getSubject() const;
        KeyAlg              getKeyAlgorithm() const;
        Array<blocxx::Int8> getPublicKey() const;
        SigAlg              getSignatureAlgorithm() const;
        String              getSignature() const;
        String              getFingerprint() const;
        X509v3RequestExtension getExtensions() const;
        String              getChallengePassword() const;
        String              getUnstructuredName() const;

    protected:
        RequestData();

        blocxx::UInt32   version;

        DNObject         subject;
        blocxx::UInt32   keysize;

        KeyAlg           pubkeyAlgorithm; // oder enum?

        // DER des public key
        //   man EVP_PKEY_set1_RSA
        //   man EVP_PKEY_get1_RSA
        //   man i2d_RSAPublicKey     => i2d == internal to DER
        //   man d2i_RSAPublicKey     => d2i == DER to internal
        Array<int8>      publicKey;  

        SigAlg           signatureAlgorithm;
        String           signature;     // mit private key verschlüsselter Hash wert
                                        // des Requests

        X509v3RequestExtensions extensions;

        // attributes 
        String challengePassword;
        String unstructuredName;

    private:
        RequestData(const RequestData& data);

        RequestData& operator=(const RequestData& data);

    };

}
}

#endif // LIMAL_CA_MGM_REQUEST_DATA_HPP
