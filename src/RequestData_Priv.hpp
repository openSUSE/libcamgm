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

  File:       RequestData_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_REQUEST_DATA_PRIV_HPP
#define    LIMAL_CA_MGM_REQUEST_DATA_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/RequestData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class RequestData_Priv : public RequestData {
    public:
        RequestData_Priv();
        RequestData_Priv(const String& caName,
                        const String& requestName);
        virtual ~RequestData_Priv();

        void                setVersion(blocxx::UInt32 v);
        void                setKeysize(blocxx::UInt32 size);
        void                setSubject(const DNObject dn);
        void                setKeyAlgorithm(KeyAlg alg);
        void                setPublicKey(const ByteArray key);
        void                setSignatureAlgorithm(SigAlg alg);
        void                setSignature(const String &sig);
        void                setExtensions(const X509v3RequestExtensions &ext);
        void                setChallengePassword(const String &passwd);
        void                setUnstructuredName(const String &name);

    private:
        RequestData_Priv(const RequestData_Priv& data);

        RequestData_Priv& operator=(const RequestData_Priv& data);
        
    };

}
}

#endif // LIMAL_CA_MGM_REQUEST_DATA_PRIV_HPP
