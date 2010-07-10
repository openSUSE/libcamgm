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

  File:       CRLReason.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLReason.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <limal/Date.hpp>
#include  <limal/String.hpp>


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class CRLReasonImpl
{
public:
	CRLReasonImpl()
		: reason("none")
		, compromiseDate(0)
		, holdInstruction("holdInstructionNone")
	{}

	CRLReasonImpl(const std::string& reason)
		: reason(reason)
		, compromiseDate(0)
		, holdInstruction("holdInstructionNone")
	{}

	CRLReasonImpl(const CRLReasonImpl& impl)
		: reason(impl.reason)
		, compromiseDate(impl.compromiseDate)
		, holdInstruction(impl.holdInstruction)
	{}

	~CRLReasonImpl() {}

	CRLReasonImpl* clone() const
	{
		return new CRLReasonImpl(*this);
	}

	std::string         reason;

	// used if reason is keyCompromise or CACompromise.
	// 0 == no compromise Date set
	time_t         compromiseDate;

	// used if reason is certificateHold
	// possible values:
	//    holdInstructionNone,
	//    holdInstructionCallIssuer,
	//    holdInstructionReject
	// or an OID
	std::string         holdInstruction;

};


// ----------------------------------------------------------------------------

CRLReason::CRLReason()
	: m_impl(new CRLReasonImpl())
{}

// ----------------------------------------------------------------------------

CRLReason::CRLReason(const std::string& reason)
	: m_impl(new CRLReasonImpl(reason))
{
	if(!checkReason(reason))
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid revoke reason %s."), reason.c_str()).c_str());
	}
}

// ----------------------------------------------------------------------------

CRLReason::CRLReason(const CRLReason& reason)
	: m_impl(reason.m_impl)
{}

// ----------------------------------------------------------------------------

CRLReason::~CRLReason()
{}

// ----------------------------------------------------------------------------

CRLReason&
CRLReason::operator=(const CRLReason& reason)
{
	if(this == &reason) return *this;

	m_impl = reason.m_impl;

	return *this;
}

// ----------------------------------------------------------------------------

void
CRLReason::setReason(const std::string& reason)
{
	if(!checkReason(reason))
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             // %s is the wrong reason string
		             str::form(__("Invalid revoke reason %s."), reason.c_str()).c_str());
	}
	m_impl->reason = reason;
}

// ----------------------------------------------------------------------------

std::string
CRLReason::getReason() const
{
	return m_impl->reason;
}

// ----------------------------------------------------------------------------

void
CRLReason::setHoldInstruction(const std::string& holdInstruction)
{
	std::string r = checkHoldInstruction(holdInstruction);
	if(!r.empty())
	{
		LOGIT_ERROR(r);
		CA_MGM_THROW(ca_mgm::ValueException, r.c_str());
	}

	m_impl->holdInstruction = holdInstruction;
	m_impl->reason = "certificateHold";
}

// ----------------------------------------------------------------------------

std::string
CRLReason::getHoldInstruction() const
{
	if(0 != str::compareCI(m_impl->reason, "certificateHold"))
	{
		LOGIT_ERROR("Reason is not certificateHold");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Reason is not certificateHold."));
	}
	return m_impl->holdInstruction;
}

// ----------------------------------------------------------------------------

void
CRLReason::setKeyCompromiseDate(time_t compromiseDate)
{
	m_impl->compromiseDate  = compromiseDate;
	m_impl->reason = "keyCompromise";
}

// ----------------------------------------------------------------------------

time_t
CRLReason::getKeyCompromiseDate() const
{
	if(0 != str::compareCI(m_impl->reason, "keyCompromise"))
	{
		LOGIT_ERROR("Reason is not keyCompromise");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Reason is not keyCompromise."));
	}
	return m_impl->compromiseDate;
}

// ----------------------------------------------------------------------------

std::string
CRLReason::getKeyCompromiseDateAsString() const
{
	if(0 != str::compareCI(m_impl->reason, "keyCompromise"))
	{
		LOGIT_ERROR("Reason is not keyCompromise");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Reason is not keyCompromise."));
	}
	std::string time;

	if(m_impl->compromiseDate != 0)
	{
		Date dt(m_impl->compromiseDate);
		time = std::string(dt.form("%Y%m%d%H%M%SZ", true));
	}

	return time;
}

// ----------------------------------------------------------------------------

void
CRLReason::setCACompromiseDate(time_t compromiseDate)
{
	m_impl->compromiseDate  = compromiseDate;
	m_impl->reason = "CACompromise";
}

// ----------------------------------------------------------------------------

time_t
CRLReason::getCACompromiseDate() const
{
	if(0 != str::compareCI(m_impl->reason, "CACompromise"))
	{
		LOGIT_ERROR("Reason is not CACompromise");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Reason is not CACompromise."));
	}
	return m_impl->compromiseDate;
}

// ----------------------------------------------------------------------------

std::string
CRLReason::getCACompromiseDateAsString() const
{
	if(0 != str::compareCI(m_impl->reason, "CACompromise"))
	{
		LOGIT_ERROR("Reason is not CACompromise");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Reason is not CACompromise."));
	}
	std::string time;

	if(m_impl->compromiseDate != 0)
	{
		Date dt(m_impl->compromiseDate);
		time = std::string(dt.form("%Y%m%d%H%M%SZ", true));
	}

	return time;
}

// ----------------------------------------------------------------------------

bool
CRLReason::valid() const
{
	if(0 == str::compareCI(m_impl->reason, "certificateHold"))
	{
		std::string r = checkHoldInstruction(m_impl->holdInstruction);
		if(!r.empty())
		{
			LOGIT_DEBUG(r);
			return false;
		}
	}
	// do not check compromise date, because a keyCompromise
	// and CACompromise without a compromiseDate is valid

	return checkReason(m_impl->reason);
}

// ----------------------------------------------------------------------------

std::vector<std::string>
CRLReason::verify() const
{
	std::vector<std::string> result;

	if(0 == str::compareCI(m_impl->reason, "certificateHold"))
	{
		std::string err = checkHoldInstruction(m_impl->holdInstruction);
		if(!err.empty())
		{
			result.push_back(err);
		}
	}
	else if(!checkReason(m_impl->reason))
	{
		result.push_back(str::form("Invalid revoke reason: %s", m_impl->reason.c_str()));
	}

	//    compromiseDate == 0 is now a valid date

	LOGIT_DEBUG_STRINGARRAY("CRLReason::verify()", result);
	return result;
}

// ----------------------------------------------------------------------------

std::vector<std::string>
CRLReason::dump() const
{
	std::vector<std::string> result;
	result.push_back("CRLReason::dump()");

	result.push_back(str::form("Revoke Reason = %s", m_impl->reason.c_str()));

	if(0 == str::compareCI(m_impl->reason, "certificateHold"))
	{
		result.push_back("hold Instruction =" + m_impl->holdInstruction);
	}
	else if(0 == str::compareCI(m_impl->reason, "keyCompromise") ||
	        0 == str::compareCI(m_impl->reason, "CACompromise"))
	{
		result.push_back("compromise Date = " + str::numstring(m_impl->compromiseDate));
	}

	return result;
}

// ----------------------------------------------------------------------------
// private:
// ----------------------------------------------------------------------------

std::string
CRLReason::checkHoldInstruction(const std::string& hi) const
{
	if(0 != str::compareCI(hi, "holdInstructionNone")       &&
	   0 != str::compareCI(hi, "holdInstructionCallIssuer") &&
	   0 != str::compareCI(hi, "holdInstructionReject")     &&
	   !initOIDCheck().isValid(hi)) {

		   return (str::form("Invalid holdInstruction: %s", hi.c_str()));
	   }
	return std::string();
}

// ----------------------------------------------------------------------------

bool
CRLReason::checkReason(const std::string& reason) const
{
	if(0 == str::compareCI(reason, "none")                 ||
	   0 == str::compareCI(reason, "unspecified")          ||
	   0 == str::compareCI(reason, "keyCompromise")        ||
	   0 == str::compareCI(reason, "CACompromise")         ||
	   0 == str::compareCI(reason, "affiliationChanged")   ||
	   0 == str::compareCI(reason, "superseded")           ||
	   0 == str::compareCI(reason, "cessationOfOperation") ||
	   0 == str::compareCI(reason, "certificateHold")      ||
	   0 == str::compareCI(reason, "removeFromCRL"))
	{
		return true;
	}
	return false;
}

// ----------------------------------------------------------------------------

}
