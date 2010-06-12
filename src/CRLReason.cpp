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
#include  <blocxx/Format.hpp>
#include  <limal/Date.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class CRLReasonImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	CRLReasonImpl()
		: reason("none")
		, compromiseDate(0)
		, holdInstruction("holdInstructionNone")
	{}

	CRLReasonImpl(const String& reason)
		: reason(reason)
		, compromiseDate(0)
		, holdInstruction("holdInstructionNone")
	{}

	CRLReasonImpl(const CRLReasonImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, reason(impl.reason)
		, compromiseDate(impl.compromiseDate)
		, holdInstruction(impl.holdInstruction)
	{}

	~CRLReasonImpl() {}

	CRLReasonImpl* clone() const
	{
		return new CRLReasonImpl(*this);
	}

	String         reason;

	// used if reason is keyCompromise or CACompromise.
	// 0 == no compromise Date set
	time_t         compromiseDate;

	// used if reason is certificateHold
	// possible values:
	//    holdInstructionNone,
	//    holdInstructionCallIssuer,
	//    holdInstructionReject
	// or an OID
	String         holdInstruction;

};


// ----------------------------------------------------------------------------

CRLReason::CRLReason()
	: m_impl(new CRLReasonImpl())
{}

// ----------------------------------------------------------------------------

CRLReason::CRLReason(const String& reason)
	: m_impl(new CRLReasonImpl(reason))
{
	if(!checkReason(reason))
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             Format(__("Invalid revoke reason %1."), reason).c_str());
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
CRLReason::setReason(const String& reason)
{
	if(!checkReason(reason))
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             // %1 is the wrong reason string
		             Format(__("Invalid revoke reason %1."), reason).c_str());
	}
	m_impl->reason = reason;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getReason() const
{
	return m_impl->reason;
}

// ----------------------------------------------------------------------------

void
CRLReason::setHoldInstruction(const String& holdInstruction)
{
	String r = checkHoldInstruction(holdInstruction);
	if(!r.empty())
	{
		LOGIT_ERROR(r);
		BLOCXX_THROW(ca_mgm::ValueException, r.c_str());
	}

	m_impl->holdInstruction = holdInstruction;
	m_impl->reason = "certificateHold";
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getHoldInstruction() const
{
	if(!m_impl->reason.equalsIgnoreCase("certificateHold"))
	{
		LOGIT_ERROR("Reason is not certificateHold");
		BLOCXX_THROW(ca_mgm::RuntimeException,
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
	if(!m_impl->reason.equalsIgnoreCase("keyCompromise"))
	{
		LOGIT_ERROR("Reason is not keyCompromise");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("Reason is not keyCompromise."));
	}
	return m_impl->compromiseDate;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getKeyCompromiseDateAsString() const
{
	if(!m_impl->reason.equalsIgnoreCase("keyCompromise"))
	{
		LOGIT_ERROR("Reason is not keyCompromise");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("Reason is not keyCompromise."));
	}
	String time;

	if(m_impl->compromiseDate != 0)
	{
		Date dt(m_impl->compromiseDate);
		time = String(dt.form("%Y%m%d%H%M%SZ", true));
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
	if(!m_impl->reason.equalsIgnoreCase("CACompromise"))
	{
		LOGIT_ERROR("Reason is not CACompromise");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("Reason is not CACompromise."));
	}
	return m_impl->compromiseDate;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getCACompromiseDateAsString() const
{
	if(!m_impl->reason.equalsIgnoreCase("CACompromise"))
	{
		LOGIT_ERROR("Reason is not CACompromise");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("Reason is not CACompromise."));
	}
	String time;

	if(m_impl->compromiseDate != 0)
	{
		Date dt(m_impl->compromiseDate);
		time = String(dt.form("%Y%m%d%H%M%SZ", true));
	}

	return time;
}

// ----------------------------------------------------------------------------

bool
CRLReason::valid() const
{
	if(m_impl->reason.equalsIgnoreCase("certificateHold"))
	{
		String r = checkHoldInstruction(m_impl->holdInstruction);
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

std::vector<blocxx::String>
CRLReason::verify() const
{
	std::vector<blocxx::String> result;

	if(m_impl->reason.equalsIgnoreCase("certificateHold"))
	{
		String err = checkHoldInstruction(m_impl->holdInstruction);
		if(!err.empty())
		{
			result.push_back(err);
		}
	}
	else if(!checkReason(m_impl->reason))
	{
		result.push_back(Format("Invalid revoke reason", m_impl->reason));
	}

	//    compromiseDate == 0 is now a valid date

	LOGIT_DEBUG_STRINGARRAY("CRLReason::verify()", result);
	return result;
}

// ----------------------------------------------------------------------------

std::vector<blocxx::String>
CRLReason::dump() const
{
	std::vector<blocxx::String> result;
	result.push_back("CRLReason::dump()");

	result.push_back(Format("Revoke Reason = %1", m_impl->reason));

	if(m_impl->reason.equalsIgnoreCase("certificateHold"))
	{
		result.push_back("hold Instruction =" + m_impl->holdInstruction);
	}
	else if(m_impl->reason.equalsIgnoreCase("keyCompromise") ||
	        m_impl->reason.equalsIgnoreCase("CACompromise"))
	{
		result.push_back("compromise Date = " + String(m_impl->compromiseDate));
	}

	return result;
}

// ----------------------------------------------------------------------------
// private:
// ----------------------------------------------------------------------------

blocxx::String
CRLReason::checkHoldInstruction(const String& hi) const
{
	if(!hi.equalsIgnoreCase("holdInstructionNone")       &&
	   !hi.equalsIgnoreCase("holdInstructionCallIssuer") &&
	   !hi.equalsIgnoreCase("holdInstructionReject")     &&
	   !initOIDCheck().isValid(hi)) {

		   return (Format("Invalid holdInstruction: %1", hi).toString());
	   }
	return String();
}

// ----------------------------------------------------------------------------

bool
CRLReason::checkReason(const String& reason) const
{
	if(reason.equalsIgnoreCase("none")                 ||
	   reason.equalsIgnoreCase("unspecified")          ||
	   reason.equalsIgnoreCase("keyCompromise")        ||
	   reason.equalsIgnoreCase("CACompromise")         ||
	   reason.equalsIgnoreCase("affiliationChanged")   ||
	   reason.equalsIgnoreCase("superseded")           ||
	   reason.equalsIgnoreCase("cessationOfOperation") ||
	   reason.equalsIgnoreCase("certificateHold")      ||
	   reason.equalsIgnoreCase("removeFromCRL"))
	{
		return true;
	}
	return false;
}

// ----------------------------------------------------------------------------

}
