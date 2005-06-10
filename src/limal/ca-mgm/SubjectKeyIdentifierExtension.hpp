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
#include  <limal/ca-mgm/CA.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class SubjectKeyIdentifierExtension : public ExtensionBase {
    public:
        SubjectKeyIdentifierExtension();
        SubjectKeyIdentifierExtension(CA& ca, Type type);
        SubjectKeyIdentifierExtension(bool autoDetect);
        SubjectKeyIdentifierExtension(const String& keyid);
        SubjectKeyIdentifierExtension(const SubjectKeyIdentifierExtension& extension);
        virtual ~SubjectKeyIdentifierExtension();

        SubjectKeyIdentifierExtension& operator=(const SubjectKeyIdentifierExtension& extension);
        /**
         * Set auto detection to true and remove the directly
         * set keyID if available.
         */
        void enableAutoDetection();

        /**
         * Set the defined keyID and disable auto detection.
         * if enabled
         */
        void setKeyID(const String& keyid);

        /**
         * Get the keyID.
         *
         * @return the keyID or the String "hash" if autodetection is enabled
         */
        String getKeyID() const;

        virtual void commit2Config(CA& ca, Type type);

    private:

        bool   autodetect;  // ??
        String keyid;
    };

}
}

#endif // LIMAL_CA_MGM_SUBJECT_KEY_IDENTIFIER_EXTENSION_HPP
