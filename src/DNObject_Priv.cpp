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

  File:       DNObject_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RDNObject_Priv::RDNObject_Priv()
    : RDNObject()
{
}

RDNObject_Priv::RDNObject_Priv(const String& type, const String& value,
                               const String&  prompt,
                               blocxx::UInt32 min,
                               blocxx::UInt32 max)
    : RDNObject()
{
    this->type   = type;
    this->value  = value;
    this->prompt = prompt;
    this->min    = min;
    this->max    = max;
}

RDNObject_Priv::~RDNObject_Priv()
{}

void
RDNObject_Priv::setRDN(const String& type, const String& value,
                       const String&  prompt,
                       blocxx::UInt32 min,
                       blocxx::UInt32 max)
{
    this->type   = type;
    this->value  = value;
    this->prompt = prompt;
    this->min    = min;
    this->max    = max;
}


// ##############################################################

DNObject_Priv::DNObject_Priv(X509_NAME *x509_name)
    : DNObject()
{
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio) {

        LOGIT_ERROR("Can not create a memory BIO");
        BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");
        
    }
    
    X509_NAME_print_ex(bio, x509_name, 0, 
                       ASN1_STRFLGS_ESC_CTRL |
                       ASN1_STRFLGS_ESC_MSB  |
                       XN_FLAG_SEP_MULTILINE |
                       XN_FLAG_FN_LN         |
                       XN_FLAG_SPC_EQ
                       );
    
    // XN_FLAG_SPC_EQ        |     // space after '='
    // XN_FLAG_FN_LN         |     // long names (commonName)
    // XN_FLAG_FN_ALIGN            // add spaces for a nice output

    char *d = NULL;

    int n = BIO_get_mem_data(bio, &d);

    String      name(d, n);
    PerlRegEx   re("(^[\\w]+)\\s=\\s(.+)$");
    StringArray lines = name.tokenize("\n");

    /* 
     * This is one option.
     *
    for(uint j = 0 ; j < lines.size(); ++j) {

        StringArray vals = re.capture(lines[j]);

        if(vals.size() != 3) {
            
            BIO_free(bio);

            LOGIT_ERROR("Can not parse DN line: " << lines[j]);
            BLOCXX_THROW(limal::RuntimeException, 
                         Format("Can not parse DN line: %1", lines[j]).c_str());

        }

        List<RDNObject>::iterator it = dn.begin();
        bool found                   = false;

        for(; it != dn.end(); ++it) {

            if( (*it).getType() == vals[1] ) {

                (*it).setRDNValue(vals[2]);
                found = true;

            }

        }

        if(!found) {
            // What to do here?

            LOGIT_INFO("DN does not match the policy: '" << lines[j] << "'");
        }
    }

    */

    /* and this is the other option */

    List<RDNObject> tmpDN;

    for(uint j = 0 ; j < lines.size(); ++j) {

        StringArray vals = re.capture(lines[j]);

        if(vals.size() != 3) {
            
            BIO_free(bio);

            LOGIT_ERROR("Can not parse DN line: " << lines[j]);
            BLOCXX_THROW(limal::RuntimeException, 
                         Format("Can not parse DN line: %1", lines[j]).c_str());

        }

        tmpDN.push_back(RDNObject_Priv(vals[1], vals[2]));

    }
    
    setDN(tmpDN);
    
    BIO_free(bio);

}

DNObject_Priv::~DNObject_Priv()
{
}

DNObject_Priv::DNObject_Priv(const DNObject_Priv& obj)
    : DNObject(obj)
{
}

DNObject_Priv&
DNObject_Priv::operator=(const DNObject_Priv& obj)
{
    if(this == &obj) return *this;
    
    DNObject::operator=(obj);

    return *this;
}
