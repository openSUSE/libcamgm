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

  File:       X509v3RequestExtensionsImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_REQUEST_EXTS_IMPL_HPP
#define    LIMAL_CA_MGM_X509V3_REQUEST_EXTS_IMPL_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>


namespace CA_MGM_NAMESPACE {

class X509v3RequestExtsImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	X509v3RequestExtsImpl()
		: nsSslServerName(NsSslServerNameExt()),
		nsComment(NsCommentExt()),
		keyUsage(KeyUsageExt()),
		nsCertType(NsCertTypeExt()),
		basicConstraints(BasicConstraintsExt()),
		extendedKeyUsage(ExtendedKeyUsageExt()),
		subjectKeyIdentifier(SubjectKeyIdentifierExt()),
		subjectAlternativeName(SubjectAlternativeNameExt())
	{}

	X509v3RequestExtsImpl(CAConfig* caConfig, Type type)
		: nsSslServerName(caConfig, type),
		nsComment(caConfig, type),
		keyUsage(caConfig, type),
		nsCertType(caConfig, type),
		basicConstraints(caConfig, type),
		extendedKeyUsage(caConfig, type),
		subjectKeyIdentifier(caConfig, type),
		subjectAlternativeName(caConfig, type)
	{}

	X509v3RequestExtsImpl(const X509v3RequestExtsImpl& impl)
		: COWIntrusiveCountableBase(impl),
		nsSslServerName(impl.nsSslServerName),
		nsComment(impl.nsComment),
		keyUsage(impl.keyUsage),
		nsCertType(impl.nsCertType),
		basicConstraints(impl.basicConstraints),
		extendedKeyUsage(impl.extendedKeyUsage),
		subjectKeyIdentifier(impl.subjectKeyIdentifier),
		subjectAlternativeName(impl.subjectAlternativeName)
	{}

	~X509v3RequestExtsImpl() {}

	X509v3RequestExtsImpl* clone() const
	{
		return new X509v3RequestExtsImpl(*this);
	}

	/* std::string extensions */

	NsSslServerNameExt        nsSslServerName;
	NsCommentExt              nsComment;

	/* Bit std::strings */
	KeyUsageExt               keyUsage;
	NsCertTypeExt             nsCertType;

	BasicConstraintsExt       basicConstraints;
	ExtendedKeyUsageExt       extendedKeyUsage;
	SubjectKeyIdentifierExt   subjectKeyIdentifier;
	SubjectAlternativeNameExt subjectAlternativeName;

	// AuthorityInfoAccessExt    authorityInfoAccess;  // ???
};

}
#endif     /* LIMAL_CA_MGM_X509V3_REQUEST_EXTS_IMPL_HPP */
