/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             core library                             |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       ValueCheck.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValueCheck.hpp
 * @brief  Utility classes to check a string value.
 */
#ifndef    LIMAL_VALUE_CHECK_HPP
#define    LIMAL_VALUE_CHECK_HPP

#include  <limal/ca-mgm/config.h>
#include  <blocxx/String.hpp>
#include  <blocxx/RefCount.hpp>
#include  <list>

namespace LIMAL_NAMESPACE
{

/**
 * ValueCheck forward declaration.
 */
class ValueCheck;

// -------------------------------------------------------------------
/**
 * @brief Base class to check a value.
 *
 * The ValueCheckBase class, is a abstract base class, allowing
 * to implement a single check on a string value.
 *
 * A check derived from this class can be combined in ValueCheck
 * class to expressions.
 *
 * @see ValueRegExCheck, ValueIntCheck and the ValueCheck class.
 */
class ValueCheckBase
{
public:
	/**
	 * Destructor.
	 */
	virtual
	~ValueCheckBase()
	{
	}

	/**
	 * Evaluates a check for the specified string value
	 * parameter to a boolean or throws an exception
	 * on failure.
	 *
	 * For example, if you want a check that evaluates
	 * whether the value (e.g. @c "2") is lower than @c 5,
	 * implement it as:
	 * @code
	 *      return (value.toInt() < 5);
	 * @endcode
	 *
	 * The blocxx toInt() method may throw an string
	 * conversion exception.
	 *
	 * @param value The value to evaluate.
	 * @return The boolean result of the check.
	 */
	virtual bool
	isValid(const std::string &value) const = 0;

	/**
	 * Returns a string explaining / showing the check.
	 *
	 * For example, if your check implements the evaluation
	 * whether the value (e.g. @c "2") is lower than @c 5,
	 * implement it as:
	 * @code
	 *	return str::form("MyCheck('%1' < 5)", value);
	 * @endcode
	 *
	 * The resulting string will be @c "MyCheck('2' < 5)"
	 * if the value parameter string was @c "2".
	 *
	 * @param value The value to evaluate.
	 * @return A string showing the check.
	 */
	virtual std::string
	explain(const std::string &value) const = 0;

protected:
	/**
	 * Default constructor.
	 */
	ValueCheckBase()
		: m_rcnt(0)
	{
	}

private:
	/**
	 * Copy constructor, private.
	 * Use the default constructor to implement
	 * a copy constructor in your derived class.
	 */
	ValueCheckBase(const ValueCheckBase &);

	/**
	 * Copy operator, private.
	 */
	ValueCheckBase & operator = (const ValueCheckBase &);

	/**
	 * Permit the ValueCheck class the access
	 * to the reference counter.
	 */
	friend class ValueCheck;

	/**
	 * The atomic reference counter variable.
	 */
	blocxx::RefCount m_rcnt;
};


// -------------------------------------------------------------------
/**
 * @brief Expression chain for checking values.
 *
 * The ValueCheck class allows to construct a simple expression.
 * It contains one or more single checks derived from ValueCheckBase
 * or also sub-expressions, that are combined with @b And, @b Or and
 * @b Not operators.
 *
 * The check can be evaluated for a value using the isValid() method,
 * showed as string with the explain() method and of course stored
 * in a variable and used to check values multiple times.
 *
 * @code
 *	//
 *	// Construct a check:
 *	//
 *	//	(val =~ /^[-]?[0-9]{1,}$/)
 *	//	And
 *	//	(
 *	//		(val >= 0 And val <= 99)
 *	//		Or
 *	//		(val >= -5 Or val <= 5)
 *	//		And
 *	//		Not(val == 7)
 *	//	)
 *	//
 *	ValueCheck check = ValueCheck(
 *		new ValueRegExCheck("^[-]?[0-9]{1,}$")
 *	).And(
 *		ValueCheck(
 *			new ValueIntCheck(Int64(0), Int64(99))
 *		).Or(
 *			new ValueIntCheck(Int64(-5), Int64(5))
 *		).And(
 *			ValueCheck(
 *				new ValueIntCheck(Int64(7), Int64(7))
 *			).Not()
 *		)
 *	);
 *
 *	// Print out what the check does for value "42":
 *	std::cout << check.explain("42") << endl;
 *
 *	// Evaluate the value "-3" and print out the result:
 *	std::cout << check.isValid("-3") << endl;
 *
 * @endcode
 *
 * @see ValueRegExCheck, ValueIntCheck classes.
 */
class ValueCheck: public ValueCheckBase
{
public:
	/**
	 * Default constructor.
	 * Since it does not contain any check, the isValid()
	 * and and explain() will throw an error until a check
	 * is assigned using the operator=().
	 */
	ValueCheck();

	/**
	 * Single check assignment constructor.
	 * @param check Pointer to a single check.
	 */
	ValueCheck(ValueCheckBase *check);

	/**
	 * Single check assignment operator.
	 * @param check Pointer to a single check.
	 * @return Reference to the current object.
	 */
	ValueCheck & operator=(ValueCheckBase *check);

	/**
	 * Check expression copy constructor.
	 * @param ref Reference to a check expression.
	 */
	ValueCheck(const ValueCheck &ref);

	/**
	 * Check expression assignment operator.
	 * @param ref Reference to a check expression.
	 * @return Reference to the current object.
	 */
	ValueCheck & operator=(const ValueCheck &ref);

	/**
	 * Destructor.
	 */
	virtual ~ValueCheck();

	/**
	 * Evaluates a the specified string value parameter to a
	 * boolean using the single checks and sub-expressions it
	 * contains.
	 *
	 * @param value The string value to evaluate.
	 * @return The boolean result of the check.
	 */
	virtual bool
	isValid(const std::string &value) const;

	/**
	 * Returns a string explaining / showing the checks that
	 * will be done for the specified string value parameter.
	 *
	 * @param value A string value.
	 * @return A string showing the check (list).
	 */
	virtual std::string
	explain(const std::string &value) const;

	/**
	 * Append a sub-expression to the list of checks
	 * using the E_OR relationship operator.
	 *
	 * @param ref Reference to the sub-expression.
	 * @return Reference to the current object.
	 */
	ValueCheck&
	And(const ValueCheck &ref);

	/**
	 * Append a single check to the list of checks
	 * using the E_AND relationship operator.
	 *
	 * @param check Pointer to a single value check.
	 * @return Reference to the current object.
	 */
	ValueCheck&
	And(ValueCheckBase *check);

	/**
	 * Append a sub-expression to the list of checks
	 * using the E_OR relationship operator.
	 *
	 * @param ref Reference to the sub-expression.
	 * @return Reference to the current object.
	 */
	ValueCheck&
	Or(const ValueCheck &ref);

	/**
	 * Append a single check to the list of checks
	 * using the E_OR relationship operator.
	 *
	 * @param check Pointer to a single value check.
	 * @return Reference to the current object.
	 */
	ValueCheck&
	Or(ValueCheckBase *check);

	/**
	 * Negate the result of the current expression.
	 *
	 * @note There is no difference between:
	 * @code
	 *	ValueCheck(...).Not().And(...)
	 * @endcode
	 * and
	 * @code
	 *	ValueCheck(...).And(...).Not()
	 * @endcode
	 * Both are negating the complete expression
	 * like: Not( (...) And (...) )
	 *
	 * @return Reference to the current object.
	 */
	ValueCheck&
	Not();

private:
	/*
	** Relationship operators
	*/
	enum ECheckOp { E_AND, E_OR };

	/**
	 * Private constructor used to add the value check
	 * reference to the current expression list.
	 *
	 * @param ref Reference to a value check.
	 * @param op  Relation to the current or last
	 *            expression in the list.
	 */
	ValueCheck(const ValueCheck &ref, ECheckOp op);

	/**
	 * Increment the reference counter of the check.
	 * @param ptr Pointer to a value check.
	 */
	void
	incRCnt(ValueCheckBase *ptr);

	/**
	 * Decrement the reference counter of the check
	 * and delete the object if needed.
	 * @param ptr Pointer to a value check.
	 */
	void
	delRCnt(ValueCheckBase *ptr);

	/**
	 * Check relationship operator to the parent check.
	 */
	ECheckOp			m_cop;

	/**
	 * Whether to negate the result of the current chain.
	 */
	bool				m_neg;

	/**
	 * Pointer to the current (reference counted) check.
	 */
	ValueCheckBase *		m_self;

	/**
	 * List of further checks in the chain.
	 */
	std::list<ValueCheck>	m_list;
};


}       // End of LIMAL_NAMESPACE
#endif  // LIMAL_VALUE_CHECK_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
