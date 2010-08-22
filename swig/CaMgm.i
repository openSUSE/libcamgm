%module "CaMgm"

%{
#include <limal/ca-mgm/config.h>
#include <limal/ca-mgm/LocalManagement.hpp>
#include <limal/ca-mgm/CA.hpp>
%}

#ifdef SWIGPERL
%include <camgm_exceptions.i>
%include <camgm_types.i>
%include <camgm_std_list.i>
%include <camgm_std_map.i>
%include <camgm_std_vector.i>
%include <camgm_CommonTypes.i>
#else
%include <stl.i>
%include <std_list.i>
#endif

%template(StringArray) std::vector<std::string>;
%template(StringList)  std::list<std::string>;
%template(StringMap)   std::map<std::string, std::string>;
%template(Int32List)   std::list<int32_t>;


typedef std::vector<std::string> StringArray;

%include limal/ca-mgm/config.h
%include limal/ca-mgm/CommonData.hpp
%include limal/ca-mgm/DNObject.hpp
%include limal/ca-mgm/LiteralValues.hpp

%include limal/ca-mgm/ExtensionBase.hpp
%include limal/ca-mgm/StringExtensions.hpp
%include limal/ca-mgm/BitExtensions.hpp
%include limal/ca-mgm/ExtendedKeyUsageExt.hpp
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

%template(StringArrayList) std::list<std::vector<std::string> >;
%template(StringMapArray)  std::vector<std::map<std::string, std::string> >;

%template(AuthorityInformationList) std::list<ca_mgm::AuthorityInformation>;
%template(UserNoticeList)           std::list<ca_mgm::UserNotice>;
%template(CertificatePolicyList)    std::list<ca_mgm::CertificatePolicy>;
%template(RevocationEntryMap)       std::map<std::string, ca_mgm::RevocationEntry>;
%template(LiteralValueList)         std::list<ca_mgm::LiteralValue>;
%template(RDNObjectList)            std::list<ca_mgm::RDNObject>;

