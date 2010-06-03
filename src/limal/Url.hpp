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

  File:       Url.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   Url.hpp
 * @brief  LiMaL url implementation.
 */
#ifndef   LIMAL_URL_HPP
#define   LIMAL_URL_HPP

#include <limal/ca-mgm/config.h>
#include <limal/UrlBase.hpp>


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

/**
 * \class Url
 * \brief Url manipulation class.
 *
 * The generic URL (URI) syntax and its main components are defined in
 * RFC3986 (http://rfc.net/rfc3986.html) Section 3, "Syntax Components".
 * The scheme specific URL syntax and semantics is defined in the
 * specification of the particular scheme. See also RFC1738
 * (http://rfc.net/rfc1738.html), that defines specific syntax for
 * several URL schemes.
 *
 * This class provides methods to access and manipulate generic and
 * common scheme-specific URL components (or using the more general
 * term, URI components).
 * To consider the scheme-specifics of a URL, the Url class contains
 * a reference object pointing to a UrlBase or derived object, that
 * implements the scheme specifics.
 *
 * Using the Url::registerScheme() method, it is possible to register
 * a preconfigured or derived UrlBase object for a specific scheme
 * name. The registered object will be cloned to handle all URL's
 * containing the specified scheme name.
 *
 * \par RFC3986, Syntax Components:
 *
 * The generic URI syntax consists of a hierarchical sequence of
 * components referred to as the scheme, authority, path, query,
 * and fragment.
 *
 * \code
 *    URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *
 *    hier-part   = "//" authority path-abempty
 *                / path-absolute
 *                / path-rootless
 *                / path-empty
 * \endcode
 *
 * The scheme and path components are required, though the path may be
 * empty (no characters).
 * When authority is present, the path must either be empty or begin
 * with a slash ("/") character.
 * When authority is not present, the path cannot begin with two slash
 * characters ("//").
 * These restrictions result in five different ABNF rules for a path
 * (Section 3.3), only one of which will match any given URI reference.
 *
 * The following are two example URIs and their component parts:
 * \code
 *      foo://example.com:8042/over/there?name=ferret#nose
 *      \_/   \______________/\_________/ \_________/ \__/
 *       |           |            |            |        |
 *    scheme     authority       path        query   fragment
 *       |   _____________________|__
 *      / \ /                        \
 *      urn:example:animal:ferret:nose
 * \endcode
 *
 */
class Url
{
public:
	/**
	 * Encoding flags.
	 */
	typedef ca_mgm::url::EEncoding    EEncoding;

	/**
	 * View options.
	 */
	typedef ca_mgm::url::ViewOptions  ViewOptions;


	~Url();
	Url();

	/**
	 * Create a new Url object as shared copy of the given one.
	 *
	 * Upon return, both objects will point to the same underlying
	 * object. This state will remain until one of the object is
	 * modified.
	 *
	 * \param url The Url object to make a copy of.
	 * \throws url::UrlException if copy fails (should not happen).
	 */
	Url(const Url &url);


	/**
	 * Create a new Url object as shared copy of the given reference.
	 *
	 * Upon return, both objects will point to the same underlying
	 * object. This state will remain until one of the object is
	 * modified.
	 *
	 * \param url The URL implementation reference to make a copy of.
	 * \throws url::UrlException if reference is empty.
	 */
	Url(const ca_mgm::url::UrlRef &url);


	/**
	 * \brief Construct a Url object from percent-encoded URL string.
	 *
	 * Parses the \p urlString string using the parseUrl() method
	 * and assings the result to the new created object.
	 *
	 * \param urlString A percent-encoded URL string.
	 * \throws url::UrlParsingException if parsing of the url fails
	 *         and may also contain an sub-exception - see parseUrl().
	 */
	Url(const blocxx::String &urlString);


	// -----------------
	/**
	 * \brief Parse a percent-encoded URL string.
	 *
	 * Trys to parses the given string into generic URL components
	 * and created a clone of a scheme-specialized object or a new
	 * UrlBase object.
	 *
	 * \param urlString A percent-encoded URL string.
	 * \return           A reference to a (derived) UrlBase object or
	 *                   empty reference if the \p urlString string
	 *                   does not match the generic URL syntax.
	 * \throws url::UrlParsingException if parsing of the url fails
	 *         and may also contain an chained url sub-exception, e.g.
	 *         url::UrlNotAllowedException,
	 *         url::UrlBadComponentException,
	 *         url::UrlNotSupportedException.
	 */
	static url::UrlRef
	parseUrl(const blocxx::String &urlString);


	// -----------------
	/**
	 * \brief Assigns parsed percent-encoded URL string to the object.
	 *
	 * Parses \p urlString string using the parseUrl() method
	 * and assigns the result to the current object.
	 * 
	 * \param urlString A percent-encoded URL string.
	 * \return A reference to this Url object.
	 * \throws url::UrlParsingException if parsing of the url fails
	 *         and may also contain an sub-exception - see parseUrl().
	 */
	Url&
	operator = (const blocxx::String &urlString);


	/**
	 * \brief Assign shared copy of \p url to the current object.
	 *
	 * Upon return, both objects will point to the same underlying
	 * object. This state will remain until one of the object is
	 * modified.
	 *
	 * \param url The Url object to make a copy of.
	 * \return A reference to this Url object.
	 */
	Url&
	operator = (const Url &url);


	// -----------------
	/**
	 * \brief Returns scheme names known to this object.
	 * \return An array with scheme names known by this object.
	 */
	blocxx::StringArray
	getKnownSchemes() const;


	/**
	 * \brief Verifies specified scheme name.
	 *
	 * Verifies the generic syntax of the specified \p scheme name
	 * and if it is contained in the current object's list of known
	 * schemes (see getKnownSchemes()) if the list is not empty.
	 *
	 * The default implementation in the UrlBase class returns an
	 * emtpy list of known schemes, causing a check of the generic
	 * syntax only.
	 *
	 * \return True, if generic scheme name syntax is valid and
	 *         the scheme name is known to the current object.
	 */
	bool
	isValidScheme(const blocxx::String &scheme) const;


	/**
	 * \brief Verifies the Url.
	 *
	 * Verifies if the current object contains a non-empty scheme
	 * name. Additional semantical URL checks may be performed by
	 * derived UrlBase objects.
	 *
	 * \return True, if the Url seems to be valid.
	 */
	bool
	isValid() const;


	// -----------------
	/**
	 * Returns a default string representation of the Url object.
	 *
	 * By default, a password in the URL will be hidden.
	 *
	 * \return A default string representation of the Url object.
	 */
	blocxx::String
	toString() const;

	/**
	 * Returns a string representation of the Url object.
	 *
	 * To include a password in the resulting Url string, use:
	 * \code
	 *    url.toString(url.getViewOptions() +
	 *                 url::ViewOptions::WITH_PASSWORD);
	 * \endcode
	 *
	 * \param opts  A combination of view options.
	 * \return A string representation of the Url object. 
	 */
	blocxx::String
	toString(const ViewOptions &opts) const;

	/**
	 * Returns a complete string representation of the Url object.
	 *
	 * This function ignores the configuration of the view options
	 * in the current object (see setViewOption()) and forces to
	 * return an string with all URL components included.
	 *
	 * \return A complete string representation of the Url object.
	 */
	blocxx::String
	toCompleteString() const;


	// -----------------
	/**
	 * Returns the scheme name of the URL.
	 * \return Scheme name of the current Url object.
	 */
	blocxx::String
	getScheme() const;


	// -----------------
	/**
	 * Returns the encoded authority component of the URL.
	 *
	 * The returned authority string does not contain the leading
	 * "//" separator characters, but just its "user:pass@host:port"
	 * content only.
	 *
	 * \return The encoded authority component string.
	 */
	blocxx::String
	getAuthority() const;

	/**
	 * Returns the username from the URL authority.
	 * \param eflag Flag if the usename should be percent-decoded or not.
	 * \return The username sub-component from the URL authority.
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getUsername(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Returns the password from the URL authority.
	 * \param eflag Flag if the password should be percent-decoded or not.
	 * \return The password sub-component from the URL authority.
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getPassword(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Returns the hostname or IP from the URL authority.
	 *
	 * In case the Url contains an IP number, it may be surrounded
	 * by "[" and "]" characters, for example "[::1]" for an IPv6
	 * localhost address.
	 *
	 * \param eflag Flag if the host should be percent-decoded or not.
	 * \return The host sub-component from the URL authority.
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getHost(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Returns the port from the URL authority.
	 * \return The port sub-component from the URL authority.
	 */
	blocxx::String
	getPort() const;


	// -----------------
	/**
	 * Returns the encoded path component of the URL.
	 *
	 * The path data contains the path name, optionally
	 * followed by path parameters separated with a ";"
	 * character, for example "/foo/bar;version=1.1".
	 *
	 * \return The encoded path component of the URL.
	 */
	blocxx::String
	getPathData() const;

	/**
	 * Returns the path name from the URL.
	 * \param eflag Flag if the path should be decoded or not.
	 * \return The path name sub-component without path parameters
	 *  from Path-Data component of the URL.
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getPathName(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Returns the path parameters from the URL.
	 * \return The encoded path parameters from the URL.
	 */
	blocxx::String
	getPathParams() const;

	/**
	 * Returns an array with path parameter substrings.
	 *
	 * The default path parameter separator is the \c ',' character.
	 * A schema specific object may overide the default separators.
	 *
	 * For example, the path parameters string "foo=1,bar=2" is splited
	 * by default into an array containing the substrings "foo=1" and
	 * "bar=2".
	 *
	 * \return The path parameters splited into an array of substrings.
	 */
	blocxx::StringArray
	getPathParamsArray() const;

	/**
	 * Returns a string map with path parameter keys and values.
	 *
	 * The default path parameter separator is the \c ',' character,
	 * the default key/value separator for the path parameters is
	 * the \c '=' character.
	 * A schema specific object may overide the default separators.
	 *
	 * For example, the path parameters string "foo=1,bar=2" is splited
	 * into a map containing "foo" = "1" and "bar" = "2" by default.
	 *
	 * \param eflag Flag if the path parameter keys and values should
	 *               be decoded or not.
	 * \return The path parameters key and values as a string map.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	ca_mgm::url::ParamMap
	getPathParamsMap(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Return the value for the specified path parameter.
	 *
	 * For example, if the path parameters string is "foo=1,bar=2"
	 * the method will return the substring "1" for the param key
	 * "foo" and "2" for the param key "bar".
	 *
	 * \param param The path parameter key.
	 * \param eflag Flag if the path parameter keys and values should
	 *              be decoded or not.
	 * \return The value for the path parameter key or empty string.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getPathParam(const blocxx::String &param,
		     EEncoding            eflag = ca_mgm::url::E_DECODED) const;


	// -----------------
	/**
	 * Returns the encoded query string component of the URL.
	 *
	 * The query string is returned without first "?" (separator)
	 * character. Further "?" characters as in e.g. LDAP URL's
	 * remains in the returned string.
	 *
	 * \return The encoded query string component of the URL.
	 */
	blocxx::String
	getQueryString() const;

	/**
	 * Returns an array with query string parameter substrings.
	 *
	 * The default query string parameter separator is the \c '&'
	 * character.
	 * A schema specific object may overide the default separators.
	 *
	 * For example, the query string "foo=1&bar=2" is splited by
	 * default into an array containing the substrings "foo=1" and
	 * "bar=2".
	 *
	 * \return The query string splited into an array of substrings.
	 */
	blocxx::StringArray
	getQueryStringArray() const;

	/**
	 * Returns a string map with query parameter and their values.
	 *
	 * The default query string parameter separator is the \c ','
	 * character, the default key/value separator the \c '=' character.
	 * A schema specific object may overide the default separators.
	 *
	 * For example, the query string "foo=1&bar=2" is splited by
	 * default into a map containing "foo" = "1" and "bar" = "2".
	 *
	 * \param eflag Flag if the query string keys and values should
	 *               be decoded or not.
	 * \return The query string as a key/value string map.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	ca_mgm::url::ParamMap
	getQueryStringMap(EEncoding eflag = ca_mgm::url::E_DECODED) const;

	/**
	 * Return the value for the specified query parameter.
	 *
	 * For example, if the query string is "foo=1,bar=2" the method
	 * will return the substring "1" for the param key "foo" and
	 * "2" for the param key "bar".
	 *
	 * \param param The query parameter key.
	 * \param eflag Flag if the query parameter keys and values should
	 *              be decoded or not.
	 * \return The value for the query parameter key or empty string.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getQueryParam(const blocxx::String &param,
		      EEncoding            eflag = ca_mgm::url::E_DECODED) const;


	// -----------------
	/**
	 * Returns the encoded fragment component of the URL.
	 * \param eflag Flag if the fragment should be percent-decoded or not.
	 * \return The encoded fragment component of the URL.
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	blocxx::String
	getFragment(EEncoding eflag = ca_mgm::url::E_DECODED) const;


	// -----------------
	/**
	 * \brief Set the scheme name in the URL.
	 * \param scheme The new scheme name.
	 * \throws url::UrlBadComponentException if the \p scheme
	 *         contains an invalid character or is empty.
	 */
	void
	setScheme(const blocxx::String &scheme);


	// -----------------
	/**
	 * \brief Set the authority component in the URL.
	 *
	 * The \p authority string shoud contain the "user:pass@host:port"
	 * sub-components without any leading "//" separator characters.
	 *
	 * \param authority The encoded authority component string.
	 * \throws url::UrlNotAllowedException if the \p authority
	 *         has to be empty in for the current scheme.
	 * \throws url::UrlBadComponentException if the \p authority
	 *         contains an invalid character.
	 * \throws url::UrlParsingException if \p authority parsing fails.
	 */
	void
	setAuthority(const blocxx::String &authority);

	/**
	 * \brief Set the username in the URL authority.
	 * \param user  The new username.
	 * \param eflag If the \p username is encoded or not.
	 * \throws url::UrlNotAllowedException if the \p user
	 *         has to be empty in for the current scheme
	 * \throws url::UrlBadComponentException if the \p user
	 *         contains an invalid character.
	 */
	void
	setUsername(const blocxx::String &user,
		    EEncoding            eflag = ca_mgm::url::E_DECODED);

	/**
	 * \brief Set the password in the URL authority.
	 * \param pass  The new password.
	 * \param eflag If the \p password is encoded or not.
	 * \throws url::UrlNotAllowedException if the \p pass
	 *         has to be empty in for the current scheme.
	 * \throws url::UrlBadComponentException if the \p pass
	 *         contains an invalid character.
	 */
	void
	setPassword(const blocxx::String &pass,
		    EEncoding            eflag = ca_mgm::url::E_DECODED);

	/**
	 * \brief Set the hostname or IP in the URL authority.
	 *
	 * The \p host parameter may contain a hostname, an IPv4 address
	 * in dotted-decimal form or an IPv6 address literal encapsulated
	 * within square brackets (RFC3513, Sect. 2.2).
	 *
	 * A hostname may contain national alphanumeric UTF8 characters
	 * (letters other than ASCII a-z0-9), that will be encoded.
	 * This function allows to specify both, a encoded or decoded
	 * hostname.
	 *
	 * Other IP literals in "[v ... ]" square bracket format are not
	 * supported by the implementation in UrlBase class.
	 *
	 * \param host The new hostname or IP address.
	 * \throws url::UrlNotAllowedException if the \p host (authority)
	 *         has to be empty in for the current scheme.
	 * \throws url::UrlBadComponentException if the \p host is invalid.
	 */
	void
	setHost(const blocxx::String &host,
		EEncoding            eflag = ca_mgm::url::E_DECODED);

	/**
	 * \brief Set the port number in the URL authority.
	 * \param port The new port number.
	 * \throws url::UrlNotAllowedException if the \p port (authority)
	 *         has to be empty in for the current scheme.
	 * \throws url::UrlBadComponentException if the \p port is invalid.
	 */
	void
	setPort(const blocxx::String &port);


	// -----------------
	/**
	 * \brief Set the path data component in the URL.
	 *
	 * By default, the \p pathdata string may include path
	 * parameters separated by the ";" separator character.
	 *
	 * \param pathdata The encoded path data component string.
	 * \throws url::UrlBadComponentException if the \p pathdata
	 *         contains an invalid character.
	 */
	void
	setPathData(const blocxx::String &pathdata);

	/**
	 * \brief Set the path name.
	 * \param path  The new path name.
	 * \param eflag If the \p path name is encoded or not.
	 * \throws url::UrlBadComponentException if the \p path name
	 *         contains an invalid character.
	 */
	void
	setPathName(const blocxx::String &path,
		    EEncoding            eflag = ca_mgm::url::E_DECODED);

	/**
	 * \brief Set the path parameters.
	 * \param params The new encoded path parameter string.
	 * \throws url::UrlBadComponentException if the path \p params
	 *         contains an invalid character.
	 */
	void
	setPathParams(const blocxx::String &params);

	/**
	 * \brief Set the path parameters.
	 * \param parray The array with encoded path parameters.
	 * \throws url::UrlBadComponentException if the \p parray
	 *         contains an invalid character.
	 */
	void
	setPathParamsArray(const blocxx::StringArray &parray);

	/**
	 * \brief Set the path parameters.
	 * \param pmap The map with decoded path parameters.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 */
	void
	setPathParamsMap(const ca_mgm::url::ParamMap &pmap);

	/**
	 * \brief Set or add value for the specified path parameter.
	 * \param param The decoded path parameter name.
	 * \param value The decoded path parameter value.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	void
	setPathParam(const blocxx::String &param, const blocxx::String &value);


	// -----------------
	/**
	 * \brief Set the query string in the URL.
	 * \param querystr The new encoded query string.
	 * \throws url::UrlBadComponentException if the \p querystr
	 *         contains an invalid character.
	 */
	void
	setQueryString(const blocxx::String &querystr);

	/**
	 * \brief Set the query parameters.
	 * \param qarray The array with encoded query parameters.
	 * \throws url::UrlBadComponentException if the \p qarray
	 *         contains an invalid character.
	 */
	void
	setQueryStringArray(const blocxx::StringArray &qarray);

	/**
	 * \brief Set the query parameters.
	 * \param qmap The map with decoded query parameters.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 */
	void
	setQueryStringMap(const ca_mgm::url::ParamMap &qmap);

	/**
	 * \brief Set or add value for the specified query parameter.
	 * \param param The decoded query parameter name.
	 * \param value The decoded query parameter value.
	 * \throws url::UrlNotSupportedException if parameter parsing
	 *         is not supported for a URL (scheme).
	 * \throws url::UrlDecodingException if the decoded result string
	 *         would contain a '\\0' character.
	 */
	void
	setQueryParam(const blocxx::String &param, const blocxx::String &value);


	// -----------------
	/**
	 * \brief Set the fragment string in the URL.
	 * \param fragment The new fragment string.
	 * \param eflag If the \p fragment is encoded or not.
	 * \throws url::UrlBadComponentException if the \p fragment
	 *         contains an invalid character.
	 */
	void
	setFragment(const blocxx::String &fragment,
		    EEncoding            eflag = ca_mgm::url::E_DECODED);


	// -----------------
	/**
	 * Return the view options of the current object.
	 *
	 * This method is used to query the view options
	 * used by the asString() method.
	 *
	 * \return The current view option combination.
	 */
	ViewOptions
	getViewOptions() const;

	/**
	 * Change the view options of the current object.
	 *
	 * This method is used to change the view options
	 * used by the asString() method.
	 *
	 * \param vopts New view options combination.
	 */
	void
	setViewOptions(const ViewOptions &vopts);

	/**
	 * Stream output operator.
	 * @param os  The output stream reference.
	 * @param url The Url object.
	 * @param The output stream reference.
	 */
	friend std::ostream &
	operator<<(std::ostream &os, const Url &url);

private:
	url::UrlRef m_impl;
};


// -------------------------------------------------------------------
}      // End url namespace
}      // End of LIMAL_NAMESPACE
#endif // LIMAL_URLUTILS_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
