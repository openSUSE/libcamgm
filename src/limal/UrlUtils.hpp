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

  File:       UrlUtils.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   UrlUtils.hpp
 * @brief  LiMaL url utilities.
 */
#ifndef   LIMAL_URLUTILS_HPP
#define   LIMAL_URLUTILS_HPP

#include <limal/ca-mgm/config.h>
#include <limal/ByteBuffer.hpp>
#include <limal/Exception.hpp>
#include <limal/String.hpp>

#include <map>
#include <vector>

// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

// -------------------------------------------------------------------
/**
 * @class UrlException
 * Base class common for all URL exceptions.
 */
CA_MGM_DECLARE_EXCEPTION (Url);


// -------------------------------------------------------------------
/**
 * @class UrlParsingException
 * Thrown if the url or a component can't be parsed at all.
 */
CA_MGM_DECLARE_EXCEPTION2(UrlParsing,      UrlException);


// -------------------------------------------------------------------
/**
 * @class UrlDecodingException
 * Thrown if the encoded string contains a NUL byte (%00).
 */
CA_MGM_DECLARE_EXCEPTION2(UrlDecoding,     UrlException);


// -------------------------------------------------------------------
/**
 * @class UrlBadComponentException
 * Thrown if a url component is invalid.
 */
CA_MGM_DECLARE_EXCEPTION2(UrlBadComponent, UrlException);


// -------------------------------------------------------------------
/**
 * @class UrlNotAllowedException
 * Thrown if scheme does not allow a component.
 */
CA_MGM_DECLARE_EXCEPTION2(UrlNotAllowed,   UrlException);


// -------------------------------------------------------------------
/**
 * @class UrlNotSupportedException
 * Thrown if a feature e.g. parsing of a component
 * is not supported for the url/scheme.
 */
CA_MGM_DECLARE_EXCEPTION2(UrlNotSupported, UrlException);


// -------------------------------------------------------------------
/** A parameter map container.
 * A string map, containing key and value pairs parsed from a
 * PathParam- or Query-String.
 */
typedef std::map<std::string,std::string>	ParamMap;


// -------------------------------------------------------------------
/**
 * Simple structure containing main url components.
 */
struct UrlComponents
{
	std::string  scheme;
	std::string  authority;
	std::string	pathdata;
	std::string  querystr;
	std::string  fragment;
	bool            has_scheme;
	bool            has_authority;
	bool            has_querystr;
	bool            has_fragment;
};


// -------------------------------------------------------------------
/**
 * Simple structure containing url authority components.
 */
struct UrlAuthority
{
	std::string  user;
	std::string  pass;
	std::string  host;
	std::string  port;
	bool            has_user;
	bool            has_pass;
	bool            has_port;
};


// -------------------------------------------------------------------
/** Encoding flags.
 */
typedef enum {
    E_ENCODED, //!< Flag to request encoded string(s).
    E_DECODED  //!< Flag to request decoded string(s).
} EEncoding;


// -------------------------------------------------------------------
/** Encodes a string using URL percent encoding.
 *
 * By default, all characters except of "a-zA-Z0-9_.-" will be encoded.
 * Additional characters from the set ":/?#[]@!$&'()*+,;=", that are
 * safe for a URL compoent without encoding, can be specified in the
 * @p safe argument.
 *
 * If the @p eflag parameter is set to E_ENCODED, then already encoded
 * substrings will be detected and not encoded a second time.
 *
 * The following function call will encode the "@" character as "%40",
 * but skip encoding of the "%" character, because the @p eflag is set
 * to E_ENCODED and "%ba" is detected as a valid encoded character.
 * @code
 *   ca_mgm::url::encode("foo%bar@localhost", "", E_ENCODED);
 * @endcode
 * With @p eflag set to E_DECODED, the "%" character would be encoded
 * as well. The complete encoded string would be "foo%25bar%40localhost".
 *
 * @param str      A string to encode.
 * @param safe     Characters safe to skip in encoding,
 *                 e.g. "/" for path names.
 * @param eflag    If to detect and skip already encoded substrings.
 * @return A percent encoded string.
 */
std::string
encode(const std::string    &str,
       const std::string    &safe = "",
       ca_mgm::url::EEncoding   eflag = E_DECODED);


// -------------------------------------------------------------------
/** Encodes a byte buffer using URL percent encoding.
 *
 * For more informations, see encode() function.
 *
 * @param buf      A string buffer to encode (binary data).
 * @param safe     Characters safe to skip in encoding,
 *                 e.g. "/" for path names.
 * @param eflag    If to detect and skip already encoded substrings.
 * @return A percent encoded string.
 */
std::string
encode_buf(const ca_mgm::ByteBuffer &buf,
           const std::string    &safe = "",
           ca_mgm::url::EEncoding   eflag = E_DECODED);


// -------------------------------------------------------------------
/** Decodes a percent-encoded string into a string.
 *
 * Replaces all occurences of @c "%<hex><hex>" in the @p str string
 * with the character encoded using the two hexadecimal digits that
 * follows the "%" character.
 *
 * For example, the encoded string "%40%3F%3D%26%25" will be decoded
 * to "@?=&%".
 *
 * @param str      A string to decode.
 * @return A decoded strig.
 * @throws UrlDecodingException if @p str contains encoded NUL byte.
 */
std::string
decode(const std::string &str);


// -------------------------------------------------------------------
/** Decodes a percent-encoded string into a byte buffer.
 *
 * Replaces all occurences of @c "%<hex><hex>" in the @p str string
 * with the character encoded using the two hexadecimal digits that
 * follows the "%" character.
 *
 * For example, the encoded string "%40%3F%3D%26%25" will be decoded
 * to "@?=&%".
 *
 * @param str      An encoded string to decode.
 * @param allowNUL A flag, if @c "%00" (encoded @c '\\0') is allowed.
 * @return A byte buffer with decoded strig.
 * @throws UrlDecodingException if @p allowNUL @p str contains
 *         encoded NUL byte (@c "%00").
 */
ca_mgm::ByteBuffer
decode_buf(const std::string &str, bool allowNUL);


// -------------------------------------------------------------------
/** Encode one character.
 *
 * Encode the specified character @p c into its @c "%<hex><hex>"
 * representation.
 *
 * @param c        A character to encode.
 * @return A percent encoded representation of the character,
 *         e.g. %20 for a ' ' (space).
 */
std::string
encode_octet(const unsigned char c);


// -------------------------------------------------------------------
/** Decode one character.
 *
 * Decode the @p hex parameter pointing to (at least) two hexadecimal
 * digits into its character value and return it.
 *
 * Example:
 * @code
 *   char *str = "%40";
 *   char *pct = strchr(str, '%');
 *   int   chr = pct ? decode_octet(pct+1) : -1;
 *      // chr is set to the '@' ASCII character now.
 * @endcode
 *
 * @param hex     Pointer to two hex characters representing
 *                the character value in percent-encoded strings.
 * @return The value (0-255) encoded in the @p hex characters or -1
 *         if @p hex does not point to two hexadecimal characters.
 */
int
decode_octet(const char *hex);


// -------------------------------------------------------------------
/** Split into a parameter array.
 *
 * Splits a parameter string @p pstr at @p psep characters into an
 * array of substrings.
 *
 * Usual parameter separators are @c '&' for Query- and @c ',' for
 * PathParams-Strings.
 *
 * @param pstr    Reference to the PathParam- or Query-String to split.
 * @param psep    Parameter separator character to split at.
 * @return The resulting parameter array.
 * @throws UrlNotSupportedException if @p psep separator is empty.
 */
std::vector<std::string>
split(const std::string &pstr,
      const std::string &psep);


// -------------------------------------------------------------------
/** Split into a parameter map.
 *
 * Splits a parameter string @p pstr into substrings using @p psep as
 * separator and then, each substring into key and value pair using
 * @p vsep as separator between parameter key and value and adds them
 * to the parameter map @p pmap.
 *
 * If a parameter substring doesn't contain any value separator @p vsep,
 * the substring is used as a parameter key and value is set to an empty
 * string.
 *
 * Usual parameter separators are @c '&' for Query- and @c ',' for
 * PathParam-Strings. A usual parameter-value separator is @c '=' for
 * both, Query- and PathParam-Strings.
 *
 * If the encoding flag @p eflag is set to @p E_DECODED, then the key
 * and values are dedcoded before they are stored in the map.
 *
 * @param pstr    Reference to the PathParam- or Query-String to split.
 * @param psep    Separator character to split key-value pairs.
 * @param vsep    Separator character to split key and value.
 * @param eflag   Flag if the key and value strings should be URL percent
 *                decoded before they're stored in the map.
 * @return The resulting parameter map.
 * @throws UrlNotSupportedException if @p psep or @p vsep separator
 *         is empty.
 */
ca_mgm::url::ParamMap
split(const std::string &pstr,
      const std::string &psep,
      const std::string &vsep,
      EEncoding            eflag = E_ENCODED);


// -------------------------------------------------------------------
/** Join parameter array into a string.
 *
 * Creates a string containing all substrings from the @p parr separated
 * by @p psep separator character. The substrings in @p parr should be
 * already URL percent encoded and should't contain @p psep characters.
 *
 * Usual parameter separators are @c '&' for Query- and @c ',' for
 * PathParam-Strings.
 *
 * @param parr    Reference to encoded parameter array.
 * @param psep    Parameter separator character to use.
 * @return A parameter string.
 */
std::string
join(const std::vector<std::string> &parr,
     const std::string      &psep);


// -------------------------------------------------------------------
/** Join parameter map to a string.
 *
 * Creates a string containing all parameter key-value pairs from the
 * parameter map @p pmap, that will be joined using the @p psep character
 * and the parameter key is separated from the parameter value using the
 * @p vsep character. Both, key and value will be automatically encoded.
 *
 * Usual parameter separators are @c '&' for Query- and @c ',' for
 * PathParam-Strings. A usual parameter-value separator is @c '=' for
 * both, Query- and PathParam-Strings.
 *
 * See encode() function from details about the @p safe characters.
 *
 * @param pmap    Reference to a parameter map.
 * @param psep    Separator character to use between key-value pairs.
 * @param vsep    Separator character to use between keys and values.
 * @param safe    List of characters to accept without encoding.
 * @return A URL percent-encoded parameter string.
 * @throws UrlNotSupportedException if @p psep or @p vsep separator
 *         is empty.
 */
std::string
join(const ca_mgm::url::ParamMap &pmap,
     const std::string       &psep,
     const std::string       &vsep,
     const std::string       &safe);


// -------------------------------------------------------------------
/*
 * Parse the @p url string by common URL separator characters
 * and return an url main component structure.
 * @returns An url components structure.
 */
UrlComponents
parse_url_string(const std::string &url);


// -------------------------------------------------------------------
/*
 * Parse the @p authority string and return the URL authority
 * components structure.
 * @returns An string array containing authority components.
 */
UrlAuthority
parse_url_authority(const std::string &authority);


// -------------------------------------------------------------------
}      // End url namespace
}      // End of LIMAL_NAMESPACE
#endif // LIMAL_URLUTILS_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
