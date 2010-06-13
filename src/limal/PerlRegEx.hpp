/*******************************************************************************
* Copyright (C) 2005 Novell, Inc. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  - Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
*  - Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
*  - Neither the name of Quest Software, Inc., Novell, Inc., nor the names of its
*    contributors may be used to endorse or promote products derived from this
*    software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL Quest Software, Inc., Novell, Inc., OR THE
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
* OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/
/**
 * @author Marius Tomaschewski
 */

#ifndef   LIMAL_PERL_REGEX_HPP
#define   LIMAL_PERL_REGEX_HPP

#include <limal/String.hpp>
#include <vector>

#include <pcre.h>

namespace ca_mgm
{

/**
 * Perl compatible Regular Expression wrapper class and utility functions.
 *
 * The PerlRegEx implementation depends on avaliability of the pcre library.
 *
 * Consult the pcre_compile(3), pcre_exec(3) and pcreapi(3) manual pages
 * for informations about details of the pcre implementation.
 *
 * @note This class does NOT wrap all features provided by the pcre library!
 */
class PerlRegEx
{
public:
	/** Native PCRE vector of integers.
	 * It contains captured substring offsets pairs. Each even index
	 * number points to a start and odd index number the corresponding
	 * end of the matched substring.
	 */
	typedef std::vector<int>              MatchVector;

	/// POSIX RegEx like structure for captured substring offset pair.
	struct match_t {
		int rm_so; //!< start offset of the regex match
		int rm_eo; //!< end offset of the regex match
	};

	/// POSIX RegEx like match array with captured substring offsets.
	typedef std::vector<match_t>          MatchArray;

	/**
	 * Create a new PerlRegEx object without compilation.
	 */
	PerlRegEx();

	/**
	 * Create a new PerlRegEx object and compile the regular expression.
	 *
	 * @param  regex   A perl regular expression pattern.
	 * @param  cflags  Bitwise-or of compile() flags.
	 * @throws RegExCompileException on compilation failure.
	 */
	PerlRegEx(const std::string &regex, int cflags = 0);

	/**
	 * Create a new PerlRegEx as (deep) copy of the specified reference.
	 * If the reference is compiled, the new object will be compiled
	 * as well.
	 *
	 * @param ref The PerlRegEx object reference to copy.
	 * @throws RegExCompileException on compilation failure.
	 */
	PerlRegEx(const PerlRegEx &ref);

	/**
	 * Destroy this PerlRegEx object.
	 */
	~PerlRegEx();

	/**
	 * Assign the specified PerlRegEx reference. If the reference
	 * is compiled, the current object will be (re)compiled.
	 *
	 * @param ref The PerlRegEx object reference to assign from.
	 * @throws RegExCompileException on compilation failure.
	 */
	PerlRegEx&          operator = (const PerlRegEx &ref);

	/**
	 * Compile the regular expression pattern contained in the string.
	 *
	 * @param  regex   A regular expression pattern.
	 * @param  cflags  Bitwise-or of compilation flags.
	 * @return         True on successful compilation,
	 *                 false on failure.
	 *
	 * The @c cflags parameter can be set to one or a bitwise-or of
	 * the following option flags. Consult the pcre_compile(3) and
	 * pcreapi(3) manual pages for the complete list and detailed
	 * description.
	 *
	 * Most of the compile options can be set also directly in the
	 * pattern string using the (?<option character>) notation as
	 * listed bellow.
	 *
	 * @arg @c i @c PCRE_CASELESS  match upper and lower case letters
	 * @arg @c m @c PCRE_MULTILINE the "^" and "$" matches begin and
	 *                                end of a line instead of the string
	 * @arg @c s @c PCRE_DOTALL    dot metacharacters matches also
	 *                                newlines
	 * @arg @c x @c PCRE_EXTENDED  ignore not escaped whitespaces
	 * @arg @c U @c PCRE_UNGREEDY  invert "greediness" of quantifiers
	 * @arg @c PCRE_UTF8              causes to act in UTF8 mode
	 * @arg @c PCRE_ANCHORED          force pattern to be "anchored"
	 * @arg @c PCRE_NO_AUTO_CAPTURE   behave as if "(" parenthesis is
	 *                                followed by a "?:"
	 */
	bool            compile(const std::string &regex,
	                        int          cflags = 0);

	/**
	 * Return the last error code generated by compile or one of the
	 * executing methods.
	 *
	 * In case of a compile error, the returned value points to the
	 * position (character offset) in the regex pattern string, where
	 * where the error was discovered.
	 *
	 * In all other cases, the result of the pcre_exec function call
	 * is returned.
	 *
	 * @return      pcre_exec result or compile error position.
	 */
	int             errorCode();

	/**
	 * Return the error message string for the last error code.
	 *
	 * @return      The error message or empty string
	 *              if no expression was compiled.
	 */
	std::string          errorString() const;

	/**
	 * @return      The regular expression pattern string.
	 */
	std::string          patternString() const;

	/**
	 * @return      The compilation flags used in compile() method.
	 */
	int             compileFlags() const;

	/**
	 * @return true, if the current regex object is compiled.
	 */
	bool            isCompiled() const;

	/**
	 * @{
	 * Execute regular expression matching against the string.
	 * The matching starts at the specified index and return
	 * true on match of false if no match found.
	 *
	 * @note In contrast to the PosixRegEx class, the PCRE
	 * library supports a string index (startoffset) and
	 * is able to look behind the starting point.
	 * If the regex makes use of the "start of string/line"
	 * metacharacter (^), the regex may not match if index
	 * is greater than 0.
	 *
	 * The expected maximal number of matching substrings can be
	 * specified in @c count. If the default value of 0 is used,
	 * the detected count by pcre_fullinfo will be used.
	 * @note If the specified count is greater 0 but smaller than
	 * the effectively number of found matches, false is returned
	 * (failure, error code 0).
	 * If the specified count is greater 0 and greater than the
	 * the effectively number of found matches, unused offsets
	 * at the end are filled with to -1.
	 *
	 * If no match was found, the @c sub array will be empty
	 * and false is returned.
	 * If a match is found and the expression was compiled to
	 * capture substrings, the @c sub array will be filled with
	 * the captured substring offsets. The first (index 0) offset
	 * pair points to the start of the first match and the end of
	 * the last match. Unused / optional capturing subpattern
	 * offsets will be set to -1.
	 *
	 * The resulting MatchVector is twice as large as the number
	 * of captured substrings, the resulting MatchArray equal.
	 *
	 * Consult the pcre_exec(3) and pcreapi(3) manual pages
	 * for the complete and detailed description.
	 *
	 * @param  sub     array for substring offsets
	 * @param  str     string to match
	 * @param  index   match string starting at index
	 * @param  count   number of expected substring matches
	 * @param  eflags  execution flags described bellow
	 * @return         true on match or false
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws AssertionException if the count value is too big
	 *         (would cause integer overflow).
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * The @c eflags parameter can be set to 0 or one or
	 * a bitwise-or of the following options:
	 *
	 * @arg @c PCRE_NOTBOL   The circumflex character (^) will
	 *                       not match the beginning of string.
	 * @arg @c PCRE_NOTEOL   The dollar sign ($) will not match
	 *                       the end of string.
	 * @arg @c PCRE_ANCHORED Match only at the first position
	 * @arg @c PCRE_NOTEMPTY An empty string is not a valid match
	 * @arg @c PCRE_NO_UTF8_CHECK Do the string for UTF-8 validity
	 *         (only relevant if PCRE_UTF8 was set at compile time)
	 *
	 * @par Example:
	 * @code
	 * std::string      str("foo = bar trala hoho");
	 *
	 * MatchArray  vsub;
	 * if( PerlRegEx("=").execute(vsub, str) && !vsub.empty())
	 * {
	 *   //
	 *   // vsub[0] is 4,
	 *   // vsub[1] is 5
	 *   //
	 * }
	 *
	 * MatchArray  rsub;
	 * if( PerlRegEx("=").execute(rsub, str) && !rsub.empty())
	 * {
	 *   //
	 *   // rsub[0].rm_so is 4,
	 *   // rsub[0].rm_eo is 5
	 *   //
	 * }
	 *
	 * @endcode
	 */
	bool            execute(MatchVector   &sub,
	                        const std::string  &str,
	                        size_t index = 0,
	                        size_t count = 0,
	                        int   eflags = 0);
	bool            execute(MatchArray    &sub,
	                        const std::string  &str,
	                        size_t index = 0,
	                        size_t count = 0,
	                        int   eflags = 0);
	/* @} */

	/**
	 * Search in string and return an array of captured substrings.
	 *
	 * @param  str     string to search in
	 * @param  index   match string starting at index
	 * @param  count   expected substring count
	 * @param  eflags  execution flags, see execute()
	 * @return         array of captured substrings
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws RegExExecuteException on execute failures.
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * @par Example:
	 * @code
	 * std::string      str("Foo = bar trala hoho");
	 * PerlRegEx   reg("^((?i)[a-z]+)[ \t]*=[ \t]*(.*)$");
	 * std::vector<std::string> out = reg.capture(str);
	 * //
	 * // out is { "Foo = bar trala hoho",
	 * //          "Foo",
	 * //          "bar trala hoho"
	 * //        }
	 * @endcode
	 */
	std::vector<std::string>     capture(const std::string &str,
	                        size_t index = 0,
	                        size_t count = 0,
	                        int   eflags = 0);

	/**
	 * Replace (substitute) the first or all matching substrings.
	 *
	 * Substring(s) matching regular expression are replaced with
	 * the string provided in @c rep and a new, modified string
	 * is returned.
	 * If no matches are found, a copy of 'str' string is returned.
	 *
	 * The rep string can contain capturing references "\\1" to "\\9"
	 * that will be substituted with the corresponding captured string.
	 * Prepended "\\" before the reference disables (switches to skip)
	 * the substitution. Note, the notation using double-slash followed
	 * by a digit character, not just "\1" like the "\n" escape sequence.
	 *
	 * @param  str     string that should be matched
	 * @param  rep     replacement substring with optional references
	 * @param  global  if to replace the first or all matches
	 * @param  eflags  execution flags, see execute() method
	 * @return         new string with modification(s)
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws RegExExecuteException on execute failures.
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * @par Example:
	 * @code
	 * std::string      str("//foo/.//bar/hoho");
	 * PerlRegEx   reg("([/]+(\\.?[/]+)?)");
	 * std::string      out = reg.replace(str, "/");
	 * //
	 * // out is "/foo/bar/hoho"
	 * //
	 * @endcode
	 */
	std::string          replace(const std::string &str,
	                        const std::string &rep,
	                        bool  global = false,
	                        int   eflags = 0);

	/**
	 * Split the specified string into an array of substrings.
	 * The regular expression is used to match the separators.
	 *
	 * If the empty flag is true, empty substring are included
	 * in the resulting array.
	 *
	 * If no separators were found, and the empty flag is true,
	 * the array will contain the input string as its only element.
	 * If the empty flag is false, a empty array is returned.
	 *
	 * @param  str     string that should be splitted
	 * @param  empty   whether to capture empty substrings
	 * @param  eflags  execution flags, see execute() method
	 * @return         array of resulting substrings
	 *                 or empty array on failure
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws RegExExecuteException on execute failures.
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * @par Example:
	 * @code
	 * std::string      str("1.23, .50 , , 71.00 , 6.00");
	 * std::vector<std::string> out1 = PerlRegEx("([ \t]*,[ \t]*)").split(str);
	 * //
	 * // out1 is { "1.23", ".50", "71.00", "6.00" }
	 * //
	 * @endcode
	 */
	std::vector<std::string>     split  (const std::string &str,
	                        bool  empty  = false,
	                        int   eflags = 0);

	/**
	 * Match all strings in the array against regular expression.
	 * Returns an array of matching strings.
	 *
	 * @param  src     list of strings to match
	 * @param  eflags  execution flags, see execute() method
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws RegExExecuteException on execute failures.
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * @par Example:
	 * @code
	 * std::vector<std::string> src;
	 * src.push_back("\t");
	 * src.push_back("one");
	 * src.push_back("");
	 * src.push_back("two");
	 * src.push_back(" 	");
	 * std::vector<std::string> out = PerlRegEx("[^ \t]").grep(src);
	 * //
	 * // out is { "one", "two" }
	 * //
	 * @endcode
	 */
	std::vector<std::string>     grep   (const std::vector<std::string> &src,
	                        int   eflags = 0);

	/**
	 * Execute regular expression matching against the string.
	 * The matching starts at the specified index and return
	 * true on match of false if no match found.
	 *
	 * See execute() method for description of the @c index
	 * and @c eflags parameters.
	 *
	 * @param  str     string to match
	 * @param  index   match string starting index
	 * @param  eflags  execution flags, see execute() method
	 * @return         true on match or false
	 * @throws RegExCompileException if regex is not compiled.
	 * @throws RegExExecuteException on execute failures.
	 * @throws OutOfBoundsException if the index is greater
	 *         than the string length.
	 *
	 * @par Example:
	 * @code
	 * std::string      str("foo = bar ");
	 * if( PerlRegEx("^[a-z]+[ \t]*=[ \t]*.*$").match(str))
	 * {
	 * }
	 * @endcode
	 */
	bool            match  (const std::string  &str,
	                        size_t index = 0,
	                        int   eflags = 0) const;

private:
	pcre           *m_pcre;
	int             m_flags;
	mutable int     m_ecode;
	mutable std::string  m_error;
	std::string          m_rxstr;
};

} // End of BLOCXX_NAMESPACE


#endif // LIMAL_PERL_REGEX_HPP
/* vim: set ts=8 sts=8 sw=8 ai noet: */

