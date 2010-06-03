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

  File:       ValueIntCheck.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValueIntCheck.hpp
 * @brief  Implements an integer range check
 *
 * @todo
 * Any idea how to implement this as template class
 * like ValueRangeCheck<Int64>(min, max) inclusive
 * a proper differentiation of the string conversion
 * function... value.toUInt64() vs. value.toInt64() ?
 *
 */
#ifndef    LIMAL_VALUE_INT_CHECK_HPP
#define    LIMAL_VALUE_INT_CHECK_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ValueCheck.hpp>

#include  <blocxx/Types.hpp>
#include  <blocxx/String.hpp>

namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
/**
 * @brief Integer range value check.
 *
 * The ValueIntCheck implements a simple integer range check
 * that can be used in ValueCheck.
 */
class ValueIntCheck: public ValueCheckBase
{
public:
	/**
	 * Constructor using a UInt64 range.
	 *
	 * @param minValue Minimal value for the range.
	 * @param maxValue Maximal value for the range.
	 * @param inclusiveRange Whether to check if the value is
	 * less (inclusiveRange=false) if less or equal the maxValue.
	 */
	ValueIntCheck(blocxx::UInt64 minValue,
	              blocxx::UInt64 maxValue,
	              bool inclusiveRange = true);

	/**
	 * Constructor using a Int64 range.
	 *
	 * @param minValue Minimal value for the range.
	 * @param maxValue Maximal value for the range.
	 * @param inclusiveRange Whether to check if the value is
	 * less (inclusiveRange=false) if less or equal the maxValue.
	 */
	ValueIntCheck(blocxx::Int64 minValue,
	              blocxx::Int64 maxValue,
	              bool inclusiveRange = true);

	/**
	 * Constructor using int range.
	 *
	 * Note: This constructor will be used by default,
	 * if you simply call:
	 *
	 *      ValueIntCheck(0, 42)
	 *
	 * To avoid conversion problems on 64 bit integers,
	 * you should choose the right constructors:
	 *
	 *      ValueIntCheck( Int64(0),  Int64(42))
	 *      ValueIntCheck(UInt64(0), UInt64(42))
	 *
	 * instead...
	 *
	 * @param minValue Minimal value for the range.
	 * @param maxValue Maximal value for the range.
	 * @param inclusiveRange Whether to check if the value is
	 * less (inclusiveRange=false) if less or equal the maxValue.
	 */
	ValueIntCheck(int            minValue,
	              int            maxValue,
	              bool inclusiveRange = true);

	/**
	 * Return whether the specified value is fits into
	 * the integer range.
	 *
	 * @param value A string value.
	 * @return true, if the value fits into the range.
	 * @throws blocxx::StringConversionException if the
	 * value can't be converted to a integer value.
	 */
	virtual bool
	isValid(const blocxx::String &value) const;

	/**
	 * Return a string showing the integer range check.
	 *
	 * @param value A string value.
	 * @return A string showing the check.
	 */
	virtual blocxx::String
	explain(const blocxx::String &value) const;

private:
	bool	m_sign;
	bool	m_incl;
	union {
		blocxx::Int64   s;
		blocxx::UInt64  u;
	}	m_min;
	union {
		blocxx::Int64   s;
		blocxx::UInt64  u;
	}	m_max;
};


}       // End of LIMAL_NAMESPACE

#endif  // LIMAL_VALUE_INT_CHECK_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
