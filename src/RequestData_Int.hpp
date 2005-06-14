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

  File:       RequestData_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_REQUEST_DATA_INT_HPP
#define    LIMAL_CA_MGM_REQUEST_DATA_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/RequestData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class RequestData_Int : public RequestData {
    public:
        RequestData_Int();
        RequestData_Int(const String& caName,
                        const String& requestName);
        virtual ~RequestData_Int();

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
        RequestData_Int(const RequestData_Int& data);

        RequestData_Int& operator=(const RequestData_Int& data);
        
    };

}
}

#endif // LIMAL_CA_MGM_REQUEST_DATA_HPP
