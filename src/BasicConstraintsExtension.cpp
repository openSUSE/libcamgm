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

  File:       BasicConstraintsExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class BasicConstraintsExtImpl
{
public:

	BasicConstraintsExtImpl()
		: ca(false)
		, pathlen(-1)
	{}

	BasicConstraintsExtImpl(bool isCA, int32_t pathLength)
		: ca(isCA)
		, pathlen(pathLength)
	{}

	BasicConstraintsExtImpl(const BasicConstraintsExtImpl& impl)
		: ca(impl.ca)
		, pathlen(impl.pathlen)
	{}

	BasicConstraintsExtImpl* clone() const
	{
		return new BasicConstraintsExtImpl(*this);
	}

	bool           ca;
	int32_t  pathlen;

};


BasicConstraintsExt::BasicConstraintsExt()
	: ExtensionBase()
	, m_impl(new BasicConstraintsExtImpl())
{}

BasicConstraintsExt::BasicConstraintsExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new BasicConstraintsExtImpl())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "basicConstraints");
	if(p)
	{
		bool          isCA = false;
		int32_t pl   = -1;

		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "basicConstraints"));
		if(0 == str::compareCI(sp[0], "critical"))  setCritical(true);

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if(0 == str::compareCI(*it, "ca:true"))  isCA = true;
			else if(0 == str::compareCI(*it, "ca:false"))  isCA = false;
			else if(str::startsWithCI(*it, "pathlen:"))
			{
				std::vector<std::string> plA = PerlRegEx(":").split(*it);
				pl = str::strtonum<int32_t>(plA[1]);
			}
		}
		setBasicConstraints(isCA, pl);
	}
	setPresent(p);
}

BasicConstraintsExt::BasicConstraintsExt(bool isCa, int32_t pathLength)
	: ExtensionBase()
	, m_impl(new BasicConstraintsExtImpl(isCa, pathLength))
{
	setPresent(true);
}

BasicConstraintsExt::BasicConstraintsExt(const BasicConstraintsExt& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

BasicConstraintsExt::~BasicConstraintsExt()
{}


BasicConstraintsExt&
BasicConstraintsExt::operator=(const BasicConstraintsExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl  = extension.m_impl;

	return *this;
}

void
BasicConstraintsExt::setBasicConstraints(bool isCa, int32_t pathLength)
{
	m_impl->ca      = isCa;
	m_impl->pathlen = pathLength;
	setPresent(true);
}

bool
BasicConstraintsExt::isCA() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("BasicConstraintsExt is not present");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("BasicConstraintsExt is not present."));
	}
	return m_impl->ca;
}

int32_t
BasicConstraintsExt::getPathLength() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("BasicConstraintsExt is not present");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("BasicConstraintsExt is not present."));
	}
	return m_impl->pathlen;
}

void
BasicConstraintsExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid BasicConstraintsExt object");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid BasicConstraintsExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		std::string basicConstraintsString;

		if(isCritical()) basicConstraintsString += "critical,";

		if(isCA())
		{
			basicConstraintsString += "CA:TRUE";
			if(getPathLength() > -1)
			{
				basicConstraintsString += ",pathlen:"+str::numstring(getPathLength());
			}
		}
		else
		{
			basicConstraintsString += "CA:FALSE";
		}
		ca.getConfig()->setValue(type2Section(type, true), "basicConstraints", basicConstraintsString);
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "basicConstraints");
	}
}

bool
BasicConstraintsExt::valid() const
{
	if(!isPresent())
	{
		LOGIT_DEBUG("return BasicConstraintsExt::valid() is true");
		return true;
	}

	if(isCA() && getPathLength() < -1)
	{
		LOGIT_DEBUG("return BasicConstraintsExt::valid() is false");
		return false;
	}
	if(!isCA() && getPathLength() != -1)
	{
		LOGIT_DEBUG("return BasicConstraintsExt::valid() is false");
		return false;
	}
	LOGIT_DEBUG("return BasicConstraintsExt::valid() is true");
	return true;
}

std::vector<std::string>
BasicConstraintsExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(isCA() && getPathLength() < -1)
	{
		result.push_back(str::form("invalid value for pathLength(%d). Has to be >= -1",
		                     getPathLength()));
	}
	if(!isCA() && getPathLength() != -1)
	{
		result.push_back(str::form("invalid value for pathLength(%d). Has to be -1",
		                     getPathLength()));
	}
	LOGIT_DEBUG_STRINGARRAY("BasicConstraintsExt::verify()", result);
	return result;
}

std::vector<std::string>
BasicConstraintsExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("BasicConstraintsExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("CA = " + str::toString(isCA()));
	result.push_back("pathlen = " + str::numstring(getPathLength()));

	return result;
}

}
