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

#include  <limal/ca-mgm/LocalManagement.hpp>

#include  <limal/PathInfo.hpp>
#include  <limal/PathName.hpp>
#include  <limal/PathUtils.hpp>

#include  "CertificateData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "Utils.hpp"
#include  "Commands.hpp"
#include  "OpenSSLUtils.hpp"

#include  <blocxx/File.hpp>
#include  <blocxx/System.hpp>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

namespace {
inline blocxx::String errno2String(int e) {
        // FIXME: make strerror working
blocxx::String s = System::errorMsg(e);
s = "(" + blocxx::String(e) + ")";
return s;
}
}

void
LocalManagement::importAsLocalCertificate(const String &pkcs12File,
                                          const String &password,
                                          const String &destinationCAsDir,
                                          const String &destinationCertFile,
                                          const String &destinationKeyFile)
{

	importAsLocalCertificate(readFile(pkcs12File),
	                         password, destinationCAsDir,
	                         destinationCertFile, destinationKeyFile);

}

void
LocalManagement::importAsLocalCertificate(const ByteBuffer &pkcs12Data,
                                          const String     &password,
                                          const String     &destinationCAsDir,
                                          const String     &destinationCertFile,
                                          const String     &destinationKeyFile)
{
	ByteBuffer out = OpenSSLUtils::pkcs12ToPEM(pkcs12Data, password, "");

	String data(out.data(), out.size());

	Array< Map<String, String> > list;

	String info;
	String cert;
	String subject;
	String issuer;
	String keyID;

	StringArray dataList = PerlRegEx("\n").split(data);

	if(dataList.size() <= 1) {

		LOGIT_ERROR("Cannot split certificate output");
		BLOCXX_THROW(limal::RuntimeException,
		             __("Cannot split certificate output."));

	}

	PerlRegEx endRegex("^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$");
	PerlRegEx beginRegex("^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$");
	PerlRegEx keyIDRegex("^\\s+localKeyID:\\s*([0-9a-fA-F\\s]+)\\s*$");
	PerlRegEx subjectRegex("^subject=(.*)\\s*$");
	PerlRegEx issuerRegex("^issuer=(.*)\\s*$");

	StringArray::const_iterator lineIT = dataList.begin() + 1;

	for(; lineIT != dataList.end(); ++lineIT) {

		if(!info.empty()) {

			cert += (*lineIT)+"\n";

			if(endRegex.match(*lineIT)) {

				StringArray ia = endRegex.capture(*lineIT);
				if(ia.size() == 2 && ia[1] == info) {

					Map<String, String> v;
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

				StringArray ia = beginRegex.capture(*lineIT);
				if(ia.size() == 2 ) {

					info = ia[1];
					cert += (*lineIT)+"\n";

				} else {
					LOGIT_DEBUG("Problem with beginRegex size:" << ia.size());
                    // FIXME: do something here ?
				}
			} else {

				if(keyIDRegex.match(*lineIT)) {

					StringArray ia = keyIDRegex.capture(*lineIT);
					if(ia.size() == 2 ) {

						keyID = ia[1];

					} else {
						LOGIT_DEBUG("Problem with keyIDRegex size:" << ia.size());
                        // FIXME: do something here ?
					}
				} else if(subjectRegex.match(*lineIT)) {

					StringArray ia = subjectRegex.capture(*lineIT);
					if(ia.size() == 2 ) {

						subject = ia[1];

					} else {
						LOGIT_DEBUG("Problem with subjectRegex size:" << ia.size());
                        // FIXME: do something here ?
					}
				} else if(issuerRegex.match(*lineIT)) {

					StringArray ia = issuerRegex.capture(*lineIT);
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

	String serverCertIssuer;

	String serverCert;
	String serverKey;
	String srvIssuerCert;
	Array<String> restCA;

    // search for the server certificate

	Array< Map<String, String> >::iterator certMap = list.begin();

	for(; certMap != list.end(); ++certMap) {

		Map<String, String>::iterator keyIT = (*certMap).find("keyID");
		Map<String, String>::iterator subjectIT = (*certMap).find("subject");

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

		Map<String, String>::iterator keyIT = (*certMap).find("keyID");

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

		Map<String, String>::iterator subjectIT = (*certMap).find("subject");

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

		Map<String, String>::iterator dataIT = (*certMap).find("data");

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
				BLOCXX_THROW(limal::SystemException,
				             Format(__("Cannot create directory %1: %2."),
				                    pi.toString(), errno2String(r)).c_str());

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
				BLOCXX_THROW(limal::SystemException,
				             Format(__("Cannot create directory %1: %2."),
				                    pi.toString(), errno2String(r)).c_str());

			}
		}

		writeFile(ByteBuffer(serverKey.c_str(), serverKey.length()),
		          destinationKeyFile, true, 0600);


		pi.stat(destinationCAsDir);
		if(!pi.exists() ) {

			int r = createDirRecursive(pi.path());

			if(r != 0) {

				LOGIT_ERROR("Cannot create directory '" << pi.toString() << "' :" << errno2String(r));
				BLOCXX_THROW(limal::SystemException,
				             Format(__("Cannot create directory %1: %2."),
				                    pi.toString(), errno2String(r)).c_str());

			}
		}

		if(!srvIssuerCert.empty()) {

			pi.stat(destinationCAsDir);

			if(!pi.isDir()) {

				LOGIT_ERROR( "'" << pi.toString() <<"' is not a directory");
				BLOCXX_THROW(limal::ValueException,
				             Format(__("%1 is not a directory."), pi.toString()).c_str());

			}

			writeFile(ByteBuffer(srvIssuerCert.c_str(), srvIssuerCert.length()),
			          pi.toString() + "/YaST-CA.pem");

			for(uint i = 0; i < restCA.size(); ++i) {

				writeFile(ByteBuffer(restCA[i].c_str(), restCA[i].length()),
				          pi.toString() + "/YaST-CA-" + String(i) + ".pem");
			}

			rehashCAs(pi.toString());

		}

	} else {

		LOGIT_ERROR("Invalid certificate file.");
		BLOCXX_THROW(limal::SyntaxException,
		             __("Invalid certificate file."));
	}
}


void
LocalManagement::importCommonServerCertificate(const String &pkcs12File,
                                               const String &password)
{
importAsLocalCertificate(readFile(pkcs12File),
                         password,
                         "/etc/ssl/certs/",
                         "/etc/ssl/servercerts/servercert.pem",
                         "/etc/ssl/servercerts/serverkey.pem");
}

void
LocalManagement::importCommonServerCertificate(const ByteBuffer &pkcs12Data,
                                               const String    &password)
{
	importAsLocalCertificate(pkcs12Data,
	                         password,
	                         "/etc/ssl/certs/",
	                         "/etc/ssl/servercerts/servercert.pem",
	                         "/etc/ssl/servercerts/serverkey.pem");
}

CertificateData
LocalManagement::getCertificate(const String &file,
                                FormatType    type)
{
	return CertificateData_Priv(file, type);
}

RequestData
LocalManagement::getRequest(const String &file,
                            FormatType    type)
{
	return RequestData_Priv(file, type);
}

CRLData
LocalManagement::getCRL(const String &file,
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
LocalManagement::readFile(const String& file)
{
	path::PathInfo filePi(file);
	if(!filePi.exists()) {

		LOGIT_ERROR("File not found: " << filePi.toString());
		BLOCXX_THROW_ERR(limal::RuntimeException,
		                 Format(__("File not found: %1."), filePi.toString()).c_str(),
		                 E_FILE_NOT_FOUND);

	}

	if(filePi.size() > (1024*1024)) {

		LOGIT_ERROR("File too big: " << filePi.toString());
		BLOCXX_THROW(limal::RuntimeException,
		             Format(__("File too big: %1."), filePi.toString()).c_str());

	}

	int fd = ::open(file.c_str(), O_RDONLY);
	if(fd == -1) {

		LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
		BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
		                        Format(__("Cannot open file %1."), file).c_str(),
		                        errno);

	}

	File fileObject(fd);
	ByteBuffer  ret;
	size_t      i = 1;

	while( i != 0 ) {
		char *buf = new char[1025];
		i = fileObject.read(buf, 1024);

		if(i == size_t(-1)) {

			delete(buf);
			fileObject.close();

			LOGIT_ERROR("Cannot read from file: " << file << "(" << errno << ")");
			BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
			                        Format(__("Cannot read from file %1."), file).c_str(),
			                        errno);
		}

		ret.append(buf, i);

		delete [] buf;
	}

	fileObject.close();

	return ret;
}

void
LocalManagement::writeFile(const ByteBuffer& data,
                           const String &file,
                           bool overwrite,
                           mode_t mode)
{
	path::PathInfo pi(file);
	if(pi.exists() && !overwrite) {

		LOGIT_ERROR ("File already exists: " << file );
		BLOCXX_THROW_ERR(limal::SystemException,
		                 Format(__("File already exists: %1."), file).c_str(),
		                 E_FILE_EXISTS);

	}

	int fd = ::open(file.c_str(), O_CREAT|O_TRUNC|O_WRONLY, mode);
	if(fd == -1) {

		LOGIT_ERROR("Cannot open file: " << file << "(" << errno << ")");
		BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
		                        Format(__("Cannot open file %1."), file).c_str(),
		                        errno);

	}

	File fileObject(fd);

	int r = fileObject.getLock();
	if(r != 0) {

		LOGIT_ERROR("Cannot get lock on file: " << file << "(" << errno << ")");
		BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
		                        Format(__("Cannot get lock on file %1."), file).c_str(),
		                        errno);

	}

	size_t st = fileObject.write(data.data(), data.size());

	if(st == size_t(-1)) {

		fileObject.unlock();
		fileObject.close();

		LOGIT_ERROR("Cannot write to file: " << file << "(" << errno << ")");
		BLOCXX_THROW_ERRNO_MSG1(limal::SystemException,
		                        Format(__("Cannot write to file %1."), file).c_str(),
		                        errno);
	}

	fileObject.flush();
	fileObject.unlock();
	fileObject.close();
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
                            const String &inPassword,
                            const String &outPassword,
                            const String &algorithm)
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
                              const String     &inPassword,
                              const String     &outPassword,
                              const ByteBuffer &caCert,
                              const String     &caPath,
                              bool              withChain )
{
	return OpenSSLUtils::createPKCS12(certificate, key, inPassword,
	                                  outPassword, caCert, caPath, withChain);
}

ByteBuffer
LocalManagement::pkcs12ToPEM(const ByteBuffer &pkcs12,
                             const String     &inPassword,
                             const String     &outPassword,
                             const String     &algorithm)
{
	return OpenSSLUtils::pkcs12ToPEM(pkcs12, inPassword,
	                                 outPassword, algorithm);
}

}
}
