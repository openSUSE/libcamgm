%module "CaMgm"

%{
#include <ca-mgm/config.h>
#include <ca-mgm/LocalManagement.hpp>
#include <ca-mgm/CA.hpp>
%}

#ifdef SWIGPERL
%include <camgm_exceptions.i>
%include <camgm_types.i>
%include <camgm_std_list.i>
%include <camgm_std_map.i>
%include <camgm_std_vector.i>
#else
%include <stl.i>
%include <std_list.i>
%include <stdint.i>
#endif

%{
#include <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/LogControl.hpp>
%}

namespace ca_mgm
{
    class ByteBuffer
    {
    public:
        ByteBuffer();
        ByteBuffer(const char *str);
        ByteBuffer(const char *ptr, size_t len);
        ByteBuffer(const ByteBuffer &buf);
        ~ByteBuffer();
        void        clear();
        bool        empty() const;
        size_t      size() const;
        const char* data() const;
        char        at(size_t pos) const;
        void        append(const char *ptr, size_t len);
        void        append(char c);
    };

    namespace logger
    {
      enum LogLevel {
        E_FATAL = 1,
        E_ERROR = 2,
        E_WARN  = 3,
        E_INFO  = 4,
        E_DEBUG = 5
      };
    }

    class LogControl
    {
    public:
      /** Singleton access. */
      static LogControl instance();
      void logNothing();
      void logToStdErr();
      void setLogLevel( logger::LogLevel level_r );
      void logfile( const std::string & logfile_r );
      void logfile( const std::string & logfile_r, mode_t mode_r );
      void setShortLineFormater();
    private:
      LogControl();
    };
}


%template(StringArray) std::vector<std::string>;
%template(StringList)  std::list<std::string>;
%template(StringMap)   std::map<std::string, std::string>;
%template(Int32List)   std::list<int32_t>;
%template(RDNObjectList)            std::list<ca_mgm::RDNObject>;
%template(AuthorityInformationList) std::list<ca_mgm::AuthorityInformation>;
%template(UserNoticeList)           std::list<ca_mgm::UserNotice>;
%template(CertificatePolicyList)    std::list<ca_mgm::CertificatePolicy>;
%template(RevocationEntryMap)       std::map<std::string, ca_mgm::RevocationEntry>;
%template(LiteralValueList)         std::list<ca_mgm::LiteralValue>;


typedef std::vector<std::string> StringArray;

%include ca-mgm/config.h
%include ca-mgm/CommonData.hpp
%include ca-mgm/DNObject.hpp
%include ca-mgm/LiteralValues.hpp

%include ca-mgm/ExtensionBase.hpp
%include ca-mgm/StringExtensions.hpp
%include ca-mgm/BitExtensions.hpp
%include ca-mgm/ExtendedKeyUsageExt.hpp
%include ca-mgm/BasicConstraintsExtension.hpp
%include ca-mgm/SubjectKeyIdentifierExtension.hpp
%include ca-mgm/SubjectAlternativeNameExtension.hpp

%include ca-mgm/X509v3RequestExtensions.hpp
%include ca-mgm/RequestGenerationData.hpp

%include ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp
%include ca-mgm/IssuerAlternativeNameExtension.hpp

%include ca-mgm/X509v3CRLGenerationExtensions.hpp
%include ca-mgm/CRLGenerationData.hpp

%include ca-mgm/AuthorityInfoAccessExtension.hpp
%include ca-mgm/CRLDistributionPointsExtension.hpp
%include ca-mgm/CertificatePoliciesExtension.hpp

%include ca-mgm/X509v3CertificateIssueExtensions.hpp
%include ca-mgm/CertificateIssueData.hpp



%include ca-mgm/RequestData.hpp

%include ca-mgm/AuthorityKeyIdentifierExtension.hpp
%include ca-mgm/CRLReason.hpp

%include ca-mgm/X509v3CRLExtensions.hpp
%include ca-mgm/CRLData.hpp

%include ca-mgm/X509v3CertificateExtensions.hpp
%include ca-mgm/CertificateData.hpp


%include ca-mgm/CAConfig.hpp
%include ca-mgm/LocalManagement.hpp
%include ca-mgm/CA.hpp

%template(StringArrayList) std::list<std::vector<std::string> >;
%template(StringMapArray)  std::vector<std::map<std::string, std::string> >;


