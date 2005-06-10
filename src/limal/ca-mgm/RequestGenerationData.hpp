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

  File:       RequestGenerationData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_REQUEST_GENERATION_DATA_HPP
#define    LIMAL_CA_MGM_REQUEST_GENERATION_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.h>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

    /**
     * @brief Data representation for generating a certificate request
     *
     * This class is a data representation for generating a certificate request
     */
    class RequestGenerationData {
    public:
        RequestGenerationData();
        RequestGenerationData(CA& ca, Type type);
        RequestGenerationData(const RequestGenerationData& data);
        virtual ~RequestGenerationData();

        RequestGenerationData& operator=(const RequestGenerationData& data);

        void                setSubject(const DNObject dn);
        DNObject            getSubject() const;

        void                setKeysize(blocxx::UInt32 size);
        blocxx::UInt32      getKeysize() const;

        void                setChallengePassword(const String &passwd);
        String              getChallengePassword() const;

        void                setUnstructuredName(const String &name);
        String              getUnstructuredName() const;

        void                setExtensions(const X509v3RequestExtension &ext);
        X509v3RequestExtension getExtensions() const;

        void                commit2Config(CA& ca, Type type);

    private:

        DNObject         subject;
        blocxx::UInt32   keysize;

        // ???  KeyAlg           pubkeyAlgorithm;


        // ???  SigAlg           signatureAlgorithm;

        // attributes
        String challengePassword;
        String unstructuredName;

        X509v3RequestExtensions extensions;

    };

}
}
#endif //LIMAL_CA_MGM_REQUEST_GENERATION_DATA_HPP
