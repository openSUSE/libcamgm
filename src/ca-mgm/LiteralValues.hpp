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
#ifndef    CA_MGM_LITERAL_VALUES_HPP
#define    CA_MGM_LITERAL_VALUES_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include <ca-mgm/PtrTypes.hpp>


namespace CA_MGM_NAMESPACE {

	class LiteralValueImpl;
	class CA;

	/**
	 * A Literal Value is a pair of a type and a value
	 * Valid types are: URI, DNS, RID, IP, email,
	 * 1.3.6.1.4.1.311.20.2.3 (ms-upn)
	 * and 1.3.6.1.5.2.2 (KRB5PrincipalName)
	 */
	class LiteralValue {
	public:
		LiteralValue();

		/**
		 * Constructor
		 *
		 * @param type Valid types are: URI, DNS, RID, IP, email, 1.3.6.1.4.1.311.20.2.3 and 1.3.6.1.5.2.2
		 * @param value a value for the type
		 */
		LiteralValue(const std::string &type, const std::string &value);

		/**
		 * Constructor
		 *
		 * @param value in the form &lt;type&gt;:&lt;value&gt;
		 *              Valid types are: URI, DNS, RID, IP, email, 1.3.6.1.4.1.311.20.2.3 and 1.3.6.1.5.2.2
		 */
		LiteralValue(const std::string& value);
		LiteralValue(const LiteralValue& value);

#ifndef SWIG

		LiteralValue&
		operator=(const LiteralValue& value);

#endif

		virtual ~LiteralValue();

		/**
		 * Set new values
		 *
		 * @param type Valid types are: URI, DNS, RID, IP, email, 1.3.6.1.4.1.311.20.2.3 and 1.3.6.1.5.2.2
		 * @param value a value for the type
		 */
		void
		setLiteral(const std::string &type, const std::string &value);

		/**
		 * Set new values
		 *
		 * @param value in the form &lt;type&gt;:&lt;value&gt;
		 *              Valid types are: URI, DNS, RID, IP, email, 1.3.6.1.4.1.311.20.2.3 and 1.3.6.1.5.2.2
		 */
		void
		setValue(const std::string &value);

		/**
		 * Return the type of this Literal Value
		 */
		std::string
		getType() const;

		/**
		 * Return the value of this Literal Value
		 */
	    std::string
		getValue() const;

		virtual bool
		valid() const;

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

		/**
		 * Return the LiteralValue in the form &lt;type&gt;:&lt;value&gt;
		 */
	    std::string
		toString() const;

		/**
		 * Return the string for the configuration. This method silently ignore
		 * unsupported types like othername.
		 */
		std::string
		commit2Config(CA& ca, Type type, uint32_t num) const;

#ifndef SWIG

		friend bool
		operator==(const LiteralValue &l, const LiteralValue &r);

		friend bool
		operator<(const LiteralValue &l, const LiteralValue &r);

#endif

	private:
		ca_mgm::RWCOW_pointer<LiteralValueImpl> m_impl;

	};
}

#endif // CA_MGM_LITERAL_VALUES_HPP
