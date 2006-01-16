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

  File:       CRLReason.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_REASON_HPP
#define    LIMAL_CA_MGM_CRL_REASON_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {


	class CRLReason {
	public:

		CRLReason();

		/**
		 * Constructor
		 *
		 * @param reason revocation reason. Valid strings are: none,
		 * unspecified, keyCompromise, CACompromise, affiliationChanged,
		 * superseded, cessationOfOperation, certificateHold and removeFromCRL
		 */
		CRLReason(const String& reason);
		CRLReason(const CRLReason& reason);
		virtual ~CRLReason();

		CRLReason& operator=(const CRLReason& reason);

		/**
		 * Set a new revocation reason
		 *
		 * @param reason revocation reason. Valid strings are: none,
		 * unspecified, keyCompromise, CACompromise, affiliationChanged,
		 * superseded, cessationOfOperation, certificateHold and removeFromCRL
		 */
		void
		setReason(const String& reason);

		/**
		 * Return the revocation reason as string
		 */
		String
		getReason() const;

		/**
		 * Set reason to certificateHold and add a hold instruction
		 *
		 * @param holdInstruction valid strings are: holdInstructionNone,
		 * holdInstructionCallIssuer, holdInstructionReject or an OID
		 */
		void
		setHoldInstruction(const String& holdInstruction);
        
		String
		getHoldInstruction() const;

		/**
		 * Set reason to keyCompromise and add the compromise date
		 *
		 * @param compromiseDate the date when the key was compromised
		 */
		void
		setKeyCompromiseDate(time_t compromiseDate);
        
		time_t
		getKeyCompromiseDate() const;
        
		String
		getKeyCompromiseDateAsString() const;

		/**
		 * Set reason to CACompromise and add the compromise date
		 *
		 * @param compromiseDate the date when the CA was compromised
		 */
		void
		setCACompromiseDate(time_t compromiseDate);
        
		time_t
		getCACompromiseDate() const;
        
		String
		getCACompromiseDateAsString() const;

		virtual bool
		valid() const;
        
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	private:

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

        
		blocxx::String
		checkHoldInstruction(const String& hi) const;
        
		bool
		checkReason(const String& reason) const;
                
	};

}
}

#endif // LIMAL_CA_MGM_CRL_REASON_HPP
