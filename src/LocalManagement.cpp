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

  File:       LocalManagement.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <ca-mgm/LocalManagement.hpp>

#include  <ca-mgm/PathInfo.hpp>
#include  <ca-mgm/PathName.hpp>
#include  <ca-mgm/PathUtils.hpp>

#include  "CertificateData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "Utils.hpp"
#include  "Commands.hpp"
#include  "OpenSSLUtils.hpp"

#include <unistd.h>
#include <sys/file.h>

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

namespace {
inline std::string errno2String(int e) {
        // FIXME: make strerror working
std::string s = "(" + std::string(::strerror(e)) + ")";
return s;
}
}

void
LocalManagement::importAsLocalCertificate(const std::string &pkcs12File,
                                          const std::string &password,
                                          const std::string &destinationCAsDir,
                                          const std::string &destinationCertFile,
                                          const std::string &destinationKeyFile)
{

	importAsLocalCertificate(readFile(pkcs12File),
	                         password, destinationCAsDir,
	                         destinationCertFile, destinationKeyFile);

}

void
LocalManagement::importAsLocalCertificate(const ByteBuffer &pkcs12Data,
                                          const std::string     &password,
                                          const std::string     &destinationCAsDir,
                                          const std::string     &destinationCertFile,
                                          const std::string     &destinationKeyFile)
{
	ByteBuffer out = OpenSSLUtils::pkcs12ToPEM(pkcs12Data, password, "");

	std::string data(out.data(), out.size());

	std::vector< std::map<std::string, std::string> > list;

	std::string info;
	std::string cert;
	std::string subject;
	std::string issuer;
	std::string keyID;

	std::vector<std::string> dataList = PerlRegEx("\n").split(data);

	if(dataList.size() <= 1) {

		LOGIT_ERROR("Cannot split certificate output");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Cannot split certificate output."));

	}

	PerlRegEx endRegex("^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$");
	PerlRegEx beginRegex("^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$");
	PerlRegEx keyIDRegex("^\\s+localKeyID:\\s*([0-9a-fA-F\\s]+)\\s*$");
	PerlRegEx subjectRegex("^subject=(.*)\\s*$");
	PerlRegEx issuerRegex("^issuer=(.*)\\s*$");

	std::vector<std::string>::const_iterator lineIT = dataList.begin() + 1;

	for(; lineIT != dataList.end(); ++lineIT) {

		if(!info.empty()) {

			cert += (*lineIT)+"\n";

			if(endRegex.match(*lineIT)) {

				std::vector<std::string> ia = endRegex.capture(*lineIT);
				if(ia.size() == 2 && ia[1] == info) {

					std::map<std::string, std::string> v;
					v["info"]    = info;
					v["data"]    = cert;
					v["keyID"]   = keyID;
					v["subject"] = subject;
					v["issuer"]  = issuer;

					list.push_back(v);

					LOGIT_DEBUG(">>>> SAVE MAP: \ninfo = " << info <<
					            "\ndata = " << cert <<
					            "\nkeyID = " << keyID <<
					            "\nsubject = " << subject <<
					            "\nissuer = " << issuer);

				}

				info.erase();
				cert.erase();
				keyID.erase();
				subject.erase();
				issuer.erase();
			}
		} else {

			if(beginRegex.match(*lineIT)) {

				std::vector<std::string> ia = beginRegex.capture(*lineIT);
				if(ia.size() == 2 ) {

					info = ia[1];
					cert += (*lineIT)+"\n";

				} else {
					LOGIT_DEBUG("Problem with beginRegex size:" << ia.size());
                    // FIXME: do something here ?
				}
			} else {

				if(keyIDRegex.match(*lineIT)) {

					std::vector<std::string> ia = keyIDRegex.capture(*lineIT);
					if(ia.size() == 2 ) {

						keyID = ia[1];

					} else {
						LOGIT_DEBUG("Problem with keyIDRegex size:" << ia.size());
                        // FIXME: do something here ?
					}
				} else if(subjectRegex.match(*lineIT)) {

					std::vector<std::string> ia = subjectRegex.capture(*lineIT);
					if(ia.size() == 2 ) {

						subject = ia[1];

					} else {
						LOGIT_DEBUG("Problem with subjectRegex size:" << ia.size());
                        // FIXME: do something here ?
					}
				} else if(issuerRegex.match(*lineIT)) {

					std::vector<std::string> ia = issuerRegex.capture(*lineIT);
					if(ia.size() == 2 ) {

						issuer = ia[1];

					} else {
						LOGIT_DEBUG("Problem with issuerRegex size:" << ia.size());
                        // FIXME: do something here ?
					}
				} else {
					LOGIT_DEBUG("Unknown line:" << *lineIT);
				}
			}
		}
	}

	keyID.erase();

	std::string serverCertIssuer;

	std::string serverCert;
	std::string serverKey;
	std::string srvIssuerCert;
	std::vector<std::string> restCA;

    // search for the server certificate

	std::vector< std::map<std::string, std::string> >::iterator certMap = list.begin();

	for(; certMap != list.end(); ++certMap) {

		std::map<std::string, std::string>::iterator keyIT = (*certMap).find("keyID");
		std::map<std::string, std::string>::iterator subjectIT = (*certMap).find("subject");

		if( keyIT != (*certMap).end() &&
		    !((*keyIT).second.empty()) &&
		    subjectIT != (*certMap).end() &&
		    !((*subjectIT).second.empty()) ) {

			    keyID            = (*keyIT).second;
			    serverCertIssuer = (*(*certMap).find("issuer")).second;
			    serverCert       = (*(*certMap).find("data")).second;
			    (*(*certMap).find("data")).second.erase();
			    (*(*certMap).find("keyID")).second.erase();
			    break;
		    }
	}

    // search for the private key

	certMap = list.begin();

	for(; certMap != list.end(); ++certMap) {

		std::map<std::string, std::string>::iterator keyIT = (*certMap).find("keyID");

		if( keyIT != (*certMap).end() &&
		    (*keyIT).second == keyID ) {

			    serverKey        = (*(*certMap).find("data")).second;
			    (*(*certMap).find("data")).second.erase();
			    break;
		    }
	}

    // search for the ca which issuered the server certificate

	certMap = list.begin();

	for(; certMap != list.end(); ++certMap) {

		std::map<std::string, std::string>::iterator subjectIT = (*certMap).find("subject");

		if( subjectIT != (*certMap).end() &&
		    (*subjectIT).second == serverCertIssuer ) {

			    srvIssuerCert        = (*(*certMap).find("data")).second;
			    (*(*certMap).find("data")).second.erase();
			    break;
		    }
	}

    // collect the rest CAs

	certMap = list.begin();

	for(; certMap != list.end(); ++certMap) {

		std::map<std::string, std::string>::iterator dataIT = (*certMap).find("data");

		if( dataIT != (*certMap).end() &&
		    !(*dataIT).second.empty() ) {

			    restCA.push_back( (*dataIT).second );

		    }
	}

	if(!serverCert.empty() && !serverKey.empty()) {

		path::PathName pn(destinationCertFile);
		path::PathInfo pi(pn.dirName());

		if(!pi.exists()) {

			int r = createDirRecursive(pi.path());

			if(r != 0) {

				LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
				CA_MGM_THROW(ca_mgm::SystemException,
				             str::form(__("Cannot create directory %s: %s."),
				                    pi.toString().c_str(), errno2String(r).c_str()).c_str());

			}
		}

		writeFile(ByteBuffer(serverCert.c_str(), serverCert.length()),
		          destinationCertFile);


		pn = path::PathName(destinationKeyFile);
		pi.stat(pn.dirName());

		if(!pi.exists()) {

			int r = createDirRecursive(pi.path());

			if(r != 0) {

				LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
				CA_MGM_THROW(ca_mgm::SystemException,
				             str::form(__("Cannot create directory %s: %s."),
				                    pi.toString().c_str(), errno2String(r).c_str()).c_str());

			}
		}

		writeFile(ByteBuffer(serverKey.c_str(), serverKey.length()),
		          destinationKeyFile, true, 0600);


		pi.stat(destinationCAsDir);
		if(!pi.exists() ) {

			int r = createDirRecursive(pi.path());

			if(r != 0) {

				LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
				CA_MGM_THROW(ca_mgm::SystemException,
				             str::form(__("Cannot create directory %s: %s."),
				                    pi.toString().c_str(), errno2String(r).c_str()).c_str());

			}
		}

		if(!srvIssuerCert.empty()) {

			pi.stat(destinationCAsDir);

			if(!pi.isDir()) {

				LOGIT_ERROR( "'" << pi.toString() <<"' is not a directory");
				CA_MGM_THROW(ca_mgm::ValueException,
				             str::form(__("%s is not a directory."), pi.toString().c_str()).c_str());

			}

			writeFile(ByteBuffer(srvIssuerCert.c_str(), srvIssuerCert.length()),
			          pi.toString() + "/YaST-CA.pem");

			for(uint i = 0; i < restCA.size(); ++i) {

				writeFile(ByteBuffer(restCA[i].c_str(), restCA[i].length()),
				          pi.toString() + "/YaST-CA-" + str::numstring(i) + ".pem");
			}

			if(path::PathName::equal(pi.toString(), "/etc/pki/trust/anchors/") ||
                           path::PathName::equal(pi.toString(), "/usr/share/pki/trust/anchors/"))
                        {
                            updateCADir();
                        }
                        else
                        {
                            rehashCAs(pi.toString());
                        }
		}

	} else {

		LOGIT_ERROR("Invalid certificate file.");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             __("Invalid certificate file."));
	}
}


void
LocalManagement::importCommonServerCertificate(const std::string &pkcs12File,
                                               const std::string &password)
{
        importAsLocalCertificate(readFile(pkcs12File),
                                 password,
                                 "/etc/pki/trust/anchors/",
                                 "/etc/ssl/servercerts/servercert.pem",
                                 "/etc/ssl/servercerts/serverkey.pem");
}

void
LocalManagement::importCommonServerCertificate(const ByteBuffer &pkcs12Data,
                                               const std::string    &password)
{
	importAsLocalCertificate(pkcs12Data,
	                         password,
	                         "/etc/pki/trust/anchors/",
	                         "/etc/ssl/servercerts/servercert.pem",
	                         "/etc/ssl/servercerts/serverkey.pem");
}

CertificateData
LocalManagement::getCertificate(const std::string &file,
                                FormatType    type)
{
	return CertificateData_Priv(file, type);
}

RequestData
LocalManagement::getRequest(const std::string &file,
                            FormatType    type)
{
	return RequestData_Priv(file, type);
}

CRLData
LocalManagement::getCRL(const std::string &file,
                        FormatType    type)
{
	return CRLData_Priv(file, type);
}

CertificateData
LocalManagement::getCertificate(const ByteBuffer &data,
                                FormatType    type)
{
	return CertificateData_Priv(data, type);
}

RequestData
LocalManagement::getRequest(const ByteBuffer &data,
                            FormatType    type)
{
	return RequestData_Priv(data, type);
}

CRLData
LocalManagement::getCRL(const ByteBuffer &data,
                        FormatType    type)
{
	return CRLData_Priv(data, type);
}


ByteBuffer
LocalManagement::readFile(const std::string& file)
{
	path::PathInfo filePi(file);
	if(!filePi.exists()) {

		LOGIT_ERROR("File not found: " << filePi.toString());
		CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
		                 str::form(__("File not found: %s."), filePi.toString().c_str()).c_str(),
		                 E_FILE_NOT_FOUND);

	}

	if(filePi.size() > (1024*1024)) {

		LOGIT_ERROR("File too big: " << filePi.toString());
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("File too big: %s."), filePi.toString().c_str()).c_str());

	}

	int fd = ::open(file.c_str(), O_RDONLY);
	if(fd == -1) {

		LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
		CA_MGM_THROW_ERRNO_MSG1(ca_mgm::SystemException,
		                        str::form(__("Cannot open file %s."), file.c_str()).c_str(),
		                        errno);

	}

	ByteBuffer  ret;
	size_t      i = 1;

	while( i != 0 ) {
		char *buf = new char[1025];
		i = ::read(fd, buf, 1024);

		if(i == size_t(-1)) {

			delete(buf);
			::close(fd);

			LOGIT_ERROR("Cannot read from file: " << file << "(" << errno << ")");
			CA_MGM_THROW_ERRNO_MSG1(ca_mgm::SystemException,
			                        str::form(__("Cannot read from file %s."), file.c_str()).c_str(),
			                        errno);
		}

		ret.append(buf, i);

		delete [] buf;
	}

	close(fd);

	return ret;
}

void
LocalManagement::writeFile(const ByteBuffer& data,
                           const std::string &file,
                           bool overwrite,
                           mode_t mode)
{
	path::PathInfo pi(file);
	if(pi.exists() && !overwrite) {

		LOGIT_ERROR ("File already exists: " << file );
		CA_MGM_THROW_ERR(ca_mgm::SystemException,
		                 str::form(__("File already exists: %s."), file.c_str()).c_str(),
		                 E_FILE_EXISTS);

	}

	int fd = ::open(file.c_str(), O_CREAT|O_TRUNC|O_WRONLY, mode);
	if(fd == -1) {

		LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
		CA_MGM_THROW_ERRNO_MSG1(ca_mgm::SystemException,
		                        str::form(__("Cannot open file %s."), file.c_str()).c_str(),
		                        errno);

	}

    if(::flock(fd, LOCK_EX|LOCK_NB) != 0)
    {
      close(fd);
      LOGIT_ERROR("Cannot get lock on file: " << file << "(" << errno << ")");
      CA_MGM_THROW_ERRNO_MSG1(ca_mgm::SystemException,
                              str::form(__("Cannot get lock on file %s."), file.c_str()).c_str(),
                              errno);
    }
	size_t st = ::write(fd, data.data(), data.size());

	if(st == size_t(-1))
    {
      ::flock(fd, LOCK_UN);
      ::close(fd);

		LOGIT_ERROR("Cannot write to file: " << file << "(" << errno << ")");
		CA_MGM_THROW_ERRNO_MSG1(ca_mgm::SystemException,
		                        str::form(__("Cannot write to file %s."), file.c_str()).c_str(),
		                        errno);
	}

    ::fsync(fd);
    ::flock(fd, LOCK_UN);
    ::close(fd);
}

ByteBuffer
LocalManagement::x509Convert(const ByteBuffer &certificate, FormatType inform,
                             FormatType outform)
{
	return OpenSSLUtils::x509Convert(certificate, inform, outform);
}

ByteBuffer
LocalManagement::rsaConvert(const ByteBuffer &key,
                            FormatType inform,
                            FormatType outform,
                            const std::string &inPassword,
                            const std::string &outPassword,
                            const std::string &algorithm)
{
	return OpenSSLUtils::rsaConvert(key, inform, outform,
	                                inPassword, outPassword, algorithm);
}

ByteBuffer
LocalManagement::crlConvert(const ByteBuffer &crl,
                            FormatType inform,
                            FormatType outform)
{
	return OpenSSLUtils::crlConvert(crl, inform, outform);
}

ByteBuffer
LocalManagement::reqConvert(const ByteBuffer &req,
                            FormatType inform,
                            FormatType outform )
{
	return OpenSSLUtils::reqConvert(req, inform, outform);
}

ByteBuffer
LocalManagement::createPKCS12(const ByteBuffer &certificate,
                              const ByteBuffer &key,
                              const std::string     &inPassword,
                              const std::string     &outPassword,
                              const ByteBuffer &caCert,
                              const std::string     &caPath,
                              bool              withChain )
{
	return OpenSSLUtils::createPKCS12(certificate, key, inPassword,
	                                  outPassword, caCert, caPath, withChain);
}

ByteBuffer
LocalManagement::pkcs12ToPEM(const ByteBuffer &pkcs12,
                             const std::string     &inPassword,
                             const std::string     &outPassword,
                             const std::string     &algorithm)
{
	return OpenSSLUtils::pkcs12ToPEM(pkcs12, inPassword,
	                                 outPassword, algorithm);
}

}
