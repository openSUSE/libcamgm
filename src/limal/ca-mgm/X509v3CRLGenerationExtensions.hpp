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

  File:       X509v3CRLGenerationExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.h>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

    /**
     * @brief Collection of X509v3 extension for generating CRLs
     *
     * This class includes a collection of X509v3 extension for generating CRLs
     */
    class X509v3CRLGenerationExtensions {
    public:
        X509v3CRLGenerationExtensions();
        X509v3CRLGenerationExtensions(CA& ca, Type type);
        X509v3CRLGenerationExtensions(const X509v3CRLGenerationExtensions& extensions);
        virtual ~X509v3CRLGenerationExtensions();

        X509v3CRLGenerationExtensions& operator=(const X509v3CRLGenerationExtensions& extension);

        void                            setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExtension &ext);
        AuthorityKeyIdentifierGenerateExtension getAuthorityKeyIdentifier() const;
        
        void                            setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext);
        IssuerAlternativeNameExtension  getIssuerAlternativeName() const;
        
        void                            commit2Config(CA& ca, Type type);

    private:
        AuthorityKeyIdentifierGenerateExtension authorityKeyIdentifier;
        IssuerAlternativeNameExtension          issuerAlternativeName;

    };

}
}
#endif //LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP
