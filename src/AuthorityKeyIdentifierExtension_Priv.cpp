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

  File:       AuthorityKeyIdentifierExtension_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "AuthorityKeyIdentifierExtension_Priv.hpp"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv()
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv(STACK_OF(X509_EXTENSION)* extensions)
    : AuthorityKeyIdentifierExtension()
{
    int crit = 0;
    
    AUTHORITY_KEYID *aki = NULL;
    aki = static_cast<AUTHORITY_KEYID *>(X509V3_get_d2i(extensions, NID_authority_key_identifier,
                                                        &crit, NULL));
    
    if(aki == NULL) {
        
        if(crit == -1) {
            // extension not found
            setPresent(false);

            return;

        } else if(crit == -2) {
            // extension occurred more than once 
            LOGIT_ERROR("Extension occurred more than once");
            BLOCXX_THROW(limal::SyntaxException,
                         "Extension occurred more than once");

        }

        LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
        BLOCXX_THROW(limal::SyntaxException,
                     Format("Unable to parse the certificate (Crit: %2)", crit).c_str());
    }

    if(aki->keyid) {
        for(int i = 0; i < aki->keyid->length; ++i) {

            String d;
            d.format("%02x", aki->keyid->data[i]);

            keyid += d;
            if( (i+1) < aki->keyid->length) {

                keyid += ":";
                
            }
        }
    }
    
    if(aki->issuer) {
        int j;
        GENERAL_NAME *gen;
        for(j = 0; j < sk_GENERAL_NAME_num(aki->issuer); j++) {

            gen = sk_GENERAL_NAME_value(aki->issuer, j);
            
            if(gen->type == GEN_DIRNAME) {
                
                char oline[256];
                X509_NAME_oneline(gen->d.dirn, oline, 256);
                
                DirName += oline;
                
                if( (j+1) < sk_GENERAL_NAME_num(aki->issuer) ) {
                    DirName += '\n';
                }
            }
        }
    }

    if(aki->serial) {
        for(int i = 0; i < aki->serial->length; ++i) {

            String d;
            d.format("%02x", aki->serial->data[i]);

            serial += d;
            if( (i+1) < aki->serial->length) {

                serial += ":";
                
            }
        }
    }

    setPresent(true);

    AUTHORITY_KEYID_free(aki);
}

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv(const AuthorityKeyIdentifierExtension_Priv& extension)
    : AuthorityKeyIdentifierExtension(extension)
{
}

AuthorityKeyIdentifierExtension_Priv::~AuthorityKeyIdentifierExtension_Priv()
{
}

AuthorityKeyIdentifierExtension_Priv&
AuthorityKeyIdentifierExtension_Priv::operator=(const AuthorityKeyIdentifierExtension_Priv& extension)
{
    if(this == &extension) return *this;
    
    AuthorityKeyIdentifierExtension::operator=(extension);
    
    return *this;
}
        
void
AuthorityKeyIdentifierExtension_Priv::setKeyID(const String& kid)
{
    keyid = kid;
}

void
AuthorityKeyIdentifierExtension_Priv::setDirName(const String& dirName)
{
    this->DirName = dirName;
}

void
AuthorityKeyIdentifierExtension_Priv::setSerial(const String& serial)
{
    this->serial = serial;
}

      
