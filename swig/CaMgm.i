%module "LIMAL::CaMgm"

%include "limal.i"

%{
#include <limal/ca-mgm/config.h>
#include <limal/ca-mgm/LocalManagement.hpp>
#include <limal/ca-mgm/CA.hpp>
%}

%include limal/ca-mgm/config.h
%include limal/ca-mgm/CommonData.hpp
%include limal/ca-mgm/DNObject.hpp
%include limal/ca-mgm/LiteralValues.hpp

%include limal/ca-mgm/ExtensionBase.hpp
%include limal/ca-mgm/StringExtensions.hpp
%include limal/ca-mgm/BitExtensions.hpp
%include limal/ca-mgm/BasicConstraintsExtension.hpp
%include limal/ca-mgm/SubjectKeyIdentifierExtension.hpp
%include limal/ca-mgm/SubjectAlternativeNameExtension.hpp

%include limal/ca-mgm/X509v3RequestExtensions.hpp
%include limal/ca-mgm/RequestGenerationData.hpp

%include limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp
%include limal/ca-mgm/IssuerAlternativeNameExtension.hpp

%include limal/ca-mgm/X509v3CRLGenerationExtensions.hpp
%include limal/ca-mgm/CRLGenerationData.hpp

%include limal/ca-mgm/AuthorityInfoAccessExtension.hpp
%include limal/ca-mgm/CRLDistributionPointsExtension.hpp
%include limal/ca-mgm/CertificatePoliciesExtension.hpp

%include limal/ca-mgm/X509v3CertificateIssueExtensions.hpp
%include limal/ca-mgm/CertificateIssueData.hpp



%include limal/ca-mgm/RequestData.hpp

%include limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp
%include limal/ca-mgm/CRLReason.hpp

%include limal/ca-mgm/X509v3CRLExtensions.hpp
%include limal/ca-mgm/CRLData.hpp

%include limal/ca-mgm/X509v3CertificateExtensions.hpp
%include limal/ca-mgm/CertificateData.hpp


%include limal/ca-mgm/CAConfig.hpp
%include limal/ca-mgm/LocalManagement.hpp
%include limal/ca-mgm/CA.hpp
