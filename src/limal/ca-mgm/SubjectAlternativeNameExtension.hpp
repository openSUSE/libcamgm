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
        SubjectAlternativeNameExtension();
        SubjectAlternativeNameExtension(CA& ca, Type type);
        SubjectAlternativeNameExtension(bool copyEmail,
                                        const blocxx::List<LiteralValue> &alternativeNameList);
        SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& extension);
        
        virtual ~SubjectAlternativeNameExtension();

        SubjectAlternativeNameExtension& operator=(const SubjectAlternativeNameExtension& extension);

        void  setSubjectAlternativeName(bool copyEmail, 
                                        const blocxx::List<LiteralValue> &alternativeNameList = 
                                        blocxx::List<LiteralValue>());

        bool                       getCopyEmail() const;
        blocxx::List<LiteralValue> getAlternativeNameList() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        bool                           emailCopy;
        blocxx::List<LiteralValue>     altNameList;
    };

}
}

#endif // LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
