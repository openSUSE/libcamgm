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

#include  <limal/ca-mgm/CA.hpp>
#include  "DNObjectImpl.hpp"
#include  "DNObject_Priv.hpp"

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

RDNObject_Priv::RDNObject_Priv()
	: RDNObject()
{}
	
RDNObject_Priv::RDNObject_Priv(const String& type, const String& value,
                               const String&  prompt,
                               blocxx::UInt32 min,
                               blocxx::UInt32 max)
	: RDNObject()
{
	m_impl->type   = type;
	m_impl->value  = value;
	m_impl->prompt = prompt;
	m_impl->min    = min;
	m_impl->max    = max;
}

RDNObject_Priv::~RDNObject_Priv()
{}

void
RDNObject_Priv::setRDN(const String& type, const String& value,
                       const String&  prompt,
                       blocxx::UInt32 min,
                       blocxx::UInt32 max)
{
	m_impl->type   = type;
	m_impl->value  = value;
	m_impl->prompt = prompt;
	m_impl->min    = min;
	m_impl->max    = max;
}


// ##############################################################

DNObject_Priv::DNObject_Priv(X509_NAME *x509_name)
	: DNObject()
{
	BIO *bio = BIO_new(BIO_s_mem());
	if(!bio)
	{
		LOGIT_ERROR("Can not create a memory BIO");
		BLOCXX_THROW(limal::MemoryException,
		             __("Can not create a memory BIO"));
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

	for(uint j = 0 ; j < lines.size(); ++j)
	{
		StringArray vals = re.capture(lines[j]);

		if(vals.size() != 3)
		{            
			BIO_free(bio);

			LOGIT_ERROR("Can not parse DN line: " << lines[j]);
			BLOCXX_THROW(limal::RuntimeException, 
			             Format(__("Can not parse DN line: %1"), lines[j]).c_str());
		}

		tmpDN.push_back(RDNObject_Priv(vals[1], vals[2]));
	}
    
	setDN(tmpDN);
    
	BIO_free(bio);
}

DNObject_Priv::~DNObject_Priv()
{}

DNObject_Priv::DNObject_Priv(const DNObject_Priv& obj)
	: DNObject(obj)
{}

DNObject_Priv::DNObject_Priv(const DNObject& obj)
	: DNObject(obj)
{}

DNObject_Priv&
DNObject_Priv::operator=(const DNObject_Priv& obj)
{
	if(this == &obj) return *this;
    
	DNObject::operator=(obj);

	return *this;
}

void
DNObject_Priv::setDefaults2Config(CA& ca)
{
	bool p = ca.getConfig()->exists("req_ca", "distinguished_name");
	if(!p)
	{
		LOGIT_ERROR("missing section 'distinguished_name' in config file");
		BLOCXX_THROW(limal::SyntaxException, 
		             __("Missing section 'distinguished_name' in config file"));
	}
	String dnSect = ca.getConfig()->getValue("req_ca", "distinguished_name");
	
	StringList dnKeys = ca.getConfig()->getKeylist(dnSect);
	
	if(dnKeys.empty())
	{
		LOGIT_ERROR("Can not parse Section " << dnSect);
		BLOCXX_THROW(limal::SyntaxException, 
		             Format(__("Can not parse Section %1"), dnSect).c_str());
	}
	StringList::const_iterator it = dnKeys.begin();
	Array<Array<blocxx::String> > newDNSect;
	
	String lastFieldName;
	String defaultValue;
	
	for(; it != dnKeys.end(); ++it)
	{
		if((*it).endsWith("_default", String::E_CASE_INSENSITIVE))
		{
			// delete the old default value
			// if there is a new one we add it later
			ca.getConfig()->deleteValue(dnSect, *it);
			continue;
		}
		if(lastFieldName != *it)
		{
			// we enter a new fieldName
			// let's have a look if we need and have a default for lastFieldName

			if(!(lastFieldName.startsWith("commonName", String::E_CASE_INSENSITIVE) ||
			     lastFieldName.startsWith("emailAddress", String::E_CASE_INSENSITIVE)))
			{
				// do we have a default for lastFiledName?
				blocxx::List<RDNObject>::const_iterator rdnIT;
				
				for(rdnIT = m_impl->dn.begin(); rdnIT != m_impl->dn.end(); ++rdnIT)
				{
					if((*rdnIT).getType() == lastFieldName)
					{
						defaultValue = (*rdnIT).getValue();
						break;
					}
				}
				if(defaultValue != "")
				{
					Array<blocxx::String> line(2, "");
					line[0] = lastFieldName + "_default";
					line[1] = defaultValue;
					newDNSect.push_back(line);
				}
			}
			
			lastFieldName = *it;
			defaultValue = "";
		}

		Array<blocxx::String> line(2, "");
		line[0] = *it;
		line[1] = ca.getConfig()->getValue(dnSect, *it);
		newDNSect.push_back(line);
		ca.getConfig()->deleteValue(dnSect, *it);
	}

	Array<Array<blocxx::String> >::const_iterator newIT;

	for(newIT = newDNSect.begin(); newIT != newDNSect.end(); ++newIT)
	{
		ca.getConfig()->setValue(dnSect, (*newIT)[0], (*newIT)[1]);
	}
}

}
}

