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

  File:       DNObject.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ca-mgm/CAConfig.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RDNObject::RDNObject(const RDNObject& rdn)
    : type(rdn.type), value(rdn.value)
{}

RDNObject::~RDNObject()
{}

RDNObject&
RDNObject::operator=(const RDNObject& rdn)
{
    if(this == &rdn) return *this;
    
    type  = rdn.type;
    value = rdn.value;

    return *this;
}

void
RDNObject::setRDNValue(const String& value)
{
    this->value = value;
}


blocxx::String
RDNObject::getType() const
{
    return type;
}

blocxx::String
RDNObject::getValue() const
{
    return value;
}

bool
RDNObject::valid() const
{
    if(type.empty()) {
        LOGIT_DEBUG("type is empty");
        return false;
    }
    /*
      if(value.empty()) {
      LOGIT_DEBUG("value is empty");
      return false;
      }
    */
    // FIXME: define and check pre defined types ?

    return true;
}

blocxx::StringArray
RDNObject::verify() const
{
    StringArray result;

    if(type.empty()) {
        result.append("type is empty");
    }
    /*
      if(value.empty()) {
      result.append("value is empty");
      }
    */
    // FIXME: define and check pre defined types ?

    LOGIT_DEBUG_STRINGARRAY("RDNObject::verify()", result);

    return result;
}

blocxx::StringArray
RDNObject::dump() const
{
    StringArray result;
    result.append("RDNObject::dump()");

    result.append(type + "=" + value);

    return result;
}

// protected

RDNObject::RDNObject()
    : type(String()), value(String())
{
}


// ######################################################################

DNObject::DNObject()
    : dn(blocxx::List<RDNObject>())
{
    dn.push_back(RDNObject_Priv("countryName", ""));
    dn.push_back(RDNObject_Priv("stateOrProvinceName", ""));
    dn.push_back(RDNObject_Priv("localityName", ""));
    dn.push_back(RDNObject_Priv("organizationName", ""));
    dn.push_back(RDNObject_Priv("organizationalUnitName", ""));
    dn.push_back(RDNObject_Priv("commonName", ""));
    dn.push_back(RDNObject_Priv("emailAddress", ""));
}

DNObject::DNObject(CAConfig* caConfig, Type type)
    : dn(blocxx::List<RDNObject>())
{
    if(type == Client_Cert || type == Server_Cert ||
       type == CA_Cert     || type == CRL           ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

#if 0

    // FIXME: does not work till we get the exact order of the keys 
    //        like it is in the configfiles

    bool p = caConfig->exists(type2Section(type, false), "distinguished_name");
    if(!p) {
        LOGIT_ERROR("missing section 'distinguished_name' in config file");
        BLOCXX_THROW(limal::SyntaxException, 
                     "missing section 'distinguished_name' in config file");
    }
    String dnSect = caConfig->getValue(type2Section(type, false), 
                                       "distinguished_name");

    StringList dnKeys = caConfig->getKeylist(dnSect);

    if(dnKeys.empty()) {
        LOGIT_ERROR("Can not parse Section " << dnSect);
        BLOCXX_THROW(limal::SyntaxException, 
                     Format("Can not parse Section %1", dnSect).c_str());
    }
    StringList::const_iterator it = dnKeys.begin();

    String fieldName;
    String prompt;
    String defaultValue;
    String min;
    String max;

    Array<Map<String, String> > configDN;

    for(; it != dnKeys.end(); ++it) {

        if((*it).endsWith("_default", String::E_CASE_INSENSITIVE)) {

            if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE)) {
                
                defaultValue = caConfig->getValue(dnSect, *it);

            } else {
                LOGIT_INFO("Wrong order of section '" << dnSect <<
                           "'. FieldName is '" << fieldName <<
                           "' but parsed Key is '" << *it << 
                           "'. Ignoring value.");
                continue;
            }

        } else if((*it).endsWith("_min", String::E_CASE_INSENSITIVE)) {

            if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE)) {

                min = caConfig->getValue(dnSect, *it);

            } else {
                LOGIT_INFO("Wrong order of section '" << dnSect <<
                           "'. FieldName is '" << fieldName <<
                           "' but parsed Key is '" << *it << 
                           "'. Ignoring value.");
                continue;
            }

        } else if((*it).endsWith("_max", String::E_CASE_INSENSITIVE)) {

            if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE)) {

                max = caConfig->getValue(dnSect, *it);

            } else {
                LOGIT_INFO("Wrong order of section '" << dnSect <<
                           "'. FieldName is '" << fieldName <<
                           "' but parsed Key is '" << *it << 
                           "'. Ignoring value.");
                continue;
            }

        } else {
            // A new fieldName

            // commit values
            if(!fieldName.empty()) {

                dn.push_back(RDNObject_Priv(fieldName, defaultValue));
                //FIXME: do something with the other values too

            }

            // reset
            prompt       = String();
            defaultValue = String();
            min          = String();
            max          = String();

            fieldName    = *it;
            prompt       = caConfig->getValue(dnSect, *it);

        }

    }
    // commit the last values
    if(!fieldName.empty()) {
        
        dn.push_back(RDNObject_Priv(fieldName, defaultValue));
        //FIXME: do something with the other values too
        
    }
#endif

    dn.push_back(RDNObject_Priv("countryName", ""));
    dn.push_back(RDNObject_Priv("stateOrProvinceName", ""));
    dn.push_back(RDNObject_Priv("localityName", ""));
    dn.push_back(RDNObject_Priv("organizationName", ""));
    dn.push_back(RDNObject_Priv("organizationalUnitName", ""));
    dn.push_back(RDNObject_Priv("commonName", ""));
    dn.push_back(RDNObject_Priv("emailAddress", ""));

}

DNObject::DNObject(const blocxx::List<RDNObject> &dn)
    : dn(dn)
{
    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

DNObject::DNObject(const DNObject& dn)
    : dn(dn.dn)
{}

DNObject::~DNObject()
{}

DNObject&
DNObject::operator=(const DNObject& dn)
{
    if(this == &dn) return *this;
    
    this->dn = dn.dn;
    
    return *this;
}

void
DNObject::setDN(const blocxx::List<RDNObject> &dn)
{
    StringArray r = checkRDNList(dn);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->dn = dn;
}

blocxx::List<RDNObject>
DNObject::getDN() const
{
    return dn;
}

bool
DNObject::valid() const
{
    if(dn.empty()) {
        LOGIT_DEBUG("empty DN");
        return false;
    }
    StringArray r = checkRDNList(dn);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    return true;
}

blocxx::StringArray
DNObject::verify() const
{
    StringArray result;

    if(dn.empty()) {
        result.append("empty DN");
    }
    result.appendArray(checkRDNList(dn));
    
    LOGIT_DEBUG_STRINGARRAY("DNObject::verify()", result);
    
    return result;
}

blocxx::StringArray
DNObject::checkRDNList(const blocxx::List<RDNObject>& list) const
{
    StringArray result;
    
    blocxx::List<RDNObject>::const_iterator it = list.begin();
    for(; it != list.end(); ++it) {
        result.appendArray((*it).verify());
    }
    return result;
}

blocxx::StringArray
DNObject::dump() const
{
    StringArray result;
    result.append("DNObject::dump()");

    blocxx::List< RDNObject >::const_iterator it = dn.begin();
    for(; it != dn.end(); ++it) {
        result.appendArray((*it).dump());
    }

    return result;
}
