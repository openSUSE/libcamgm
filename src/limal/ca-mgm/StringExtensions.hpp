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

  File:       std::stringExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_STRING_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_STRING_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class StringExtensionImpl;

	class StringExtension : public ExtensionBase {

	public:
		StringExtension();
		virtual ~StringExtension();

		virtual void   setValue(const std::string &v) = 0;
		virtual std::string getValue() const = 0;

		virtual void commit2Config(CA& ca, Type type) const = 0;

		virtual bool                 valid() const = 0;
		virtual std::vector<std::string>  verify() const = 0;

		virtual std::vector<std::string>  dump() const = 0;

	protected:
		StringExtension(const std::string &v );
		StringExtension(const StringExtension& extension);

		StringExtension& operator=(const StringExtension& extension);

		blocxx::COWIntrusiveReference<StringExtensionImpl> m_impl;

	};

	class NsBaseUrlExt : public StringExtension {
	public:
		NsBaseUrlExt();
		NsBaseUrlExt(const std::string &v);
		NsBaseUrlExt(CAConfig* caConfig, Type type);
		NsBaseUrlExt(const NsBaseUrlExt &extension);
		virtual ~NsBaseUrlExt();

#ifndef SWIG

		NsBaseUrlExt& operator=(const NsBaseUrlExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const ;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};

	class NsRevocationUrlExt : public StringExtension {
	public:
		NsRevocationUrlExt();
		NsRevocationUrlExt(const std::string &v);
		NsRevocationUrlExt(CAConfig* caConfig, Type type);
		NsRevocationUrlExt(const NsRevocationUrlExt &extension);
		virtual ~NsRevocationUrlExt();

#ifndef SWIG

		NsRevocationUrlExt& operator=(const NsRevocationUrlExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};

	class NsCaRevocationUrlExt : public StringExtension {
	public:
		NsCaRevocationUrlExt();
		NsCaRevocationUrlExt(const std::string &v);
		NsCaRevocationUrlExt(CAConfig* caConfig, Type type);
		NsCaRevocationUrlExt(const NsCaRevocationUrlExt &extension);
		virtual ~NsCaRevocationUrlExt();

#ifndef SWIG

		NsCaRevocationUrlExt& operator=(const NsCaRevocationUrlExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};

	class NsRenewalUrlExt : public StringExtension {
	public:
		NsRenewalUrlExt();
		NsRenewalUrlExt(const std::string &v);
		NsRenewalUrlExt(CAConfig* caConfig, Type type);
		NsRenewalUrlExt(const NsRenewalUrlExt &extension);
		virtual ~NsRenewalUrlExt();

#ifndef SWIG

		NsRenewalUrlExt& operator=(const NsRenewalUrlExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};
	class NsCaPolicyUrlExt : public StringExtension {
	public:
		NsCaPolicyUrlExt();
		NsCaPolicyUrlExt(const std::string &v);
		NsCaPolicyUrlExt(CAConfig* caConfig, Type type);
		NsCaPolicyUrlExt(const NsCaPolicyUrlExt &extension);
		virtual ~NsCaPolicyUrlExt();

#ifndef SWIG

		NsCaPolicyUrlExt& operator=(const NsCaPolicyUrlExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};
	class NsSslServerNameExt : public StringExtension {
	public:
		NsSslServerNameExt();
		NsSslServerNameExt(const std::string &v);
		NsSslServerNameExt(CAConfig* caConfig, Type type);
		NsSslServerNameExt(const NsSslServerNameExt &extension);
		virtual ~NsSslServerNameExt();

#ifndef SWIG

		NsSslServerNameExt& operator=(const NsSslServerNameExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};
	class NsCommentExt : public StringExtension {
	public:
		NsCommentExt();
		NsCommentExt(const std::string &v);
		NsCommentExt(CAConfig* caConfig, Type type);
		NsCommentExt(const NsCommentExt &extension);
		virtual ~NsCommentExt();

#ifndef SWIG

		NsCommentExt& operator=(const NsCommentExt& extension);

#endif

		void           setValue(const std::string &v);
		std::string         getValue() const;

		virtual void commit2Config(CA& ca, Type type) const;

		virtual bool                 valid() const;
		virtual std::vector<std::string>  verify() const;

		virtual std::vector<std::string>  dump() const;
	};

}

#endif // LIMAL_CA_MGM_STRING_EXTENSION_HPP
