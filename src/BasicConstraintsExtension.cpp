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
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class BasicConstraintsExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:

	BasicConstraintsExtImpl()
		: ca(false)
		, pathlen(-1)
	{}

	BasicConstraintsExtImpl(bool isCA, blocxx::Int32 pathLength)
		: ca(isCA)
		, pathlen(pathLength)
	{}

	BasicConstraintsExtImpl(const BasicConstraintsExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, ca(impl.ca)
		, pathlen(impl.pathlen)
	{}

	BasicConstraintsExtImpl* clone() const
	{
		return new BasicConstraintsExtImpl(*this);
	}

	bool           ca;
	blocxx::Int32  pathlen;
		
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
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1"), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "basicConstraints");
	if(p)
	{
		bool          isCA = false;
		blocxx::Int32 pl   = -1;

		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "basicConstraints"));
		if(sp[0].equalsIgnoreCase("critical"))  setCritical(true); 

		StringArray::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if((*it).equalsIgnoreCase("ca:true"))  isCA = true; 
			else if((*it).equalsIgnoreCase("ca:false"))  isCA = false;
			else if((*it).startsWith("pathlen:", String::E_CASE_INSENSITIVE))
			{
				StringArray plA = PerlRegEx(":").split(*it);
				pl = plA[1].toInt32();
			}
		}
		setBasicConstraints(isCA, pl);
	}
	setPresent(p);
}

BasicConstraintsExt::BasicConstraintsExt(bool isCa, blocxx::Int32 pathLength)
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
BasicConstraintsExt::setBasicConstraints(bool isCa, blocxx::Int32 pathLength)
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
		BLOCXX_THROW(limal::RuntimeException,
		             __("BasicConstraintsExt is not present"));
	}
	return m_impl->ca;
}

blocxx::Int32
BasicConstraintsExt::getPathLength() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("BasicConstraintsExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("BasicConstraintsExt is not present"));
	}
	return m_impl->pathlen;
}

void
BasicConstraintsExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid BasicConstraintsExt object");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid BasicConstraintsExt object"));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1"), type).c_str());
	}

	if(isPresent())
	{
		String basicConstraintsString;

		if(isCritical()) basicConstraintsString += "critical,";

		if(isCA())
		{
			basicConstraintsString += "CA:TRUE";
			if(getPathLength() > -1)
			{
				basicConstraintsString += ",pathlen:"+String(getPathLength());
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

blocxx::StringArray
BasicConstraintsExt::verify() const
{
	blocxx::StringArray result;

	if(!isPresent()) return result;
    
	if(isCA() && getPathLength() < -1)
	{
		result.append(Format("invalid value for pathLength(%1). Has to be >= -1",
		                     getPathLength()).toString());
	}
	if(!isCA() && getPathLength() != -1)
	{
		result.append(Format("invalid value for pathLength(%1). Has to be -1",
		                     getPathLength()).toString());
	}
	LOGIT_DEBUG_STRINGARRAY("BasicConstraintsExt::verify()", result);
	return result;
}

blocxx::StringArray
BasicConstraintsExt::dump() const
{
	StringArray result;
	result.append("BasicConstraintsExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	result.append("CA = " + Bool(isCA()).toString());
	result.append("pathlen = " + String(getPathLength()));

	return result;
}

}
}
