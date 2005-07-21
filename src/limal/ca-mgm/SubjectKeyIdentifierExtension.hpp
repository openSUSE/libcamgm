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

  File:       SubjectKeyIdentifierExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_SUBJECT_KEY_IDENTIFIER_EXTENSION_HPP
#define    LIMAL_CA_MGM_SUBJECT_KEY_IDENTIFIER_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    class SubjectKeyIdentifierExtension : public ExtensionBase {
    public:
        SubjectKeyIdentifierExtension();
        SubjectKeyIdentifierExtension(CAConfig* caConfig, Type type);
        SubjectKeyIdentifierExtension(bool autoDetect, const String& keyid = String());
        SubjectKeyIdentifierExtension(const SubjectKeyIdentifierExtension& extension);
        virtual ~SubjectKeyIdentifierExtension();

        SubjectKeyIdentifierExtension& operator=(const SubjectKeyIdentifierExtension& extension);

        void setSubjectKeyIdentifier(bool autoDetect, const String& keyId = String());

        bool   isAutoDetectionEnabled() const;

        /**
         * Get the keyID.
         *
         * @return the keyID
         */
        String getKeyID() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:

        bool   autodetect;  // ??
        String keyid;
    };

}
}

#endif // LIMAL_CA_MGM_SUBJECT_KEY_IDENTIFIER_EXTENSION_HPP
