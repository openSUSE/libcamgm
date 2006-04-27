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

  File:       LiteralValues.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_LITERAL_VALUES_HPP
#define    LIMAL_CA_MGM_LITERAL_VALUES_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class LiteralValueImpl;
	
	/**
	 * A Literal Value is a pair of a type and a value
	 * Valid types are: URI, DNS, RID, IP and email
	 */
	class LiteralValue {
	public:
		LiteralValue();

		/**
		 * Constructor
		 *
		 * @param type Valid types are: URI, DNS, RID, IP and email
		 * @param value a value for the type
		 */
		LiteralValue(const String &type, const String &value);

		/**
		 * Constructor
		 *
		 * @param value in the form <type>:<value>
		 *              Valid types are: URI, DNS, RID, IP and email
		 */
		LiteralValue(const String& value);
		LiteralValue(const LiteralValue& value);

#ifndef SWIG

		LiteralValue&
		operator=(const LiteralValue& value);

#endif
		
		virtual ~LiteralValue();

		/**
		 * Set new values
		 *
		 * @param type Valid types are: URI, DNS, RID, IP and email
		 * @param value a value for the type
		 */
		void
		setLiteral(const String &type, const String &value);

		/**
		 * Set new values
		 *
		 * @param value in the form <type>:<value>
		 *              Valid types are: URI, DNS, RID, IP and email
		 */
		void
		setValue(const String &value);

		/**
		 * Return the type of this Literal Value
		 */
		String
		getType() const;

		/**
		 * Return the value of this Literal Value
		 */
		String
		getValue() const;

		virtual bool
		valid() const;
		
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

		/**
		 * Return the LiteralValue in the form <type>:<value>
		 */
		String
		toString() const;

#ifndef SWIG

		friend bool
		operator==(const LiteralValue &l, const LiteralValue &r);

		friend bool
		operator<(const LiteralValue &l, const LiteralValue &r);

#endif
		
	private:
		blocxx::COWIntrusiveReference<LiteralValueImpl> m_impl;
    	
	};

}
}

#endif // LIMAL_CA_MGM_LITERAL_VALUES_HPP
