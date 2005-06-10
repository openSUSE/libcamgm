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

  File:       CRLData_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DATA_INT_HPP
#define    LIMAL_CA_MGM_CRL_DATA_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CRLData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CRLData_Int : public CRLData {
    public:
        CRLData_Int();
        CRLData_Int(const String &caName);
        virtual ~CRLData_Int();

        void   setVersion(blocxx::Int32 version);
        void   setValidityPeriod(time_t last,
                                 time_t next);
        void   setIssuerDN(const DNObject& issuer);
        void   setSignatureAlgorithm(SigAlg sigAlg);
        void   setSignature(const String& sig);
        void   setExtensions(const X509v3CRLExtensions& ext);
        void   setRevokationData(const Map<String, RevokationEntry>& data);
        void   addRevokationEntry(const String& oid,
                                  const RevokationEntry& entry);
        void   setRevokationEntry(const String& oid,
                                  const RevokationEntry& entry);
        void   deleteRevokationEntry(const String& oid);

    private:
        CRLData_Int(const CRLData_Int& data);
        
        CRLData_Int& operator=(const CRLData_Int& data);
    };

}
}

#endif // LIMAL_CA_MGM_CRL_DATA_HPP
