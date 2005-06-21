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

  File:       SubjectAlternativeNameExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
#define    LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class SubjectAlternativeNameExtension : public ExtensionBase {
    public:
        SubjectAlternativeNameExtension(CA& ca, Type type);
        SubjectAlternativeNameExtension(bool copyEmail = false,
                                        const blocxx::List<LiteralValue> &alternativeNameList = blocxx::List<LiteralValue>());
        SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& extension);

        virtual ~SubjectAlternativeNameExtension();

        SubjectAlternativeNameExtension& operator=(const SubjectAlternativeNameExtension& extension);

        void  setCopyEmail(bool copyEmail);
        bool  getCopyEmail() const;

        void  setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList);
        blocxx::List<LiteralValue> getAlternativeNameList() const;

        void                   addSubjectAltName(const LiteralValue& altName);

        virtual void commit2Config(CA& ca, Type type);

    private:
        bool                           emailCopy;
        blocxx::List<LiteralValue>     altNameList;
    };

}
}

#endif // LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
