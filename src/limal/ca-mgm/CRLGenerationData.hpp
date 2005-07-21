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

  File:       CRLGenerationData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP
#define    LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CRLGenerationExtensions.hpp>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

    class CA;

    /**
     * @brief Data representation to generate a CRL
     *
     * This class is a data representation to generate a CRL.
     */
    class CRLGenerationData {
    public:
        CRLGenerationData();
        CRLGenerationData(CAConfig* caConfig, Type type);
        CRLGenerationData(blocxx::UInt32 hours, 
                          const X509v3CRLGenerationExtensions& ext);
        CRLGenerationData(const CRLGenerationData& data);
        virtual ~CRLGenerationData();
        
        CRLGenerationData& operator=(const CRLGenerationData& data);

        void                          setCRLLifeTime(blocxx::UInt32 hours);
        blocxx::UInt32                getCRLLifeTime() const;

        void                          setExtensions(const X509v3CRLGenerationExtensions& ext);
        X509v3CRLGenerationExtensions getExtensions() const;

        void                          commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        blocxx::UInt32                crlHours;

        X509v3CRLGenerationExtensions extensions;

    };

}
}

#endif // LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP
