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

  File:       OpenSSLUtils.cpp

  Author:     Michael Calmer
  Maintainer: Michael Calmer
/-*/

#include "OpenSSLUtils.hpp"

#include <limal/Exception.hpp>
#include <limal/PathUtils.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathName.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/Exec.hpp>
#include <blocxx/EnvVars.hpp>
#include <blocxx/System.hpp>
#include <blocxx/DateTime.hpp>

#include "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;


OpenSSLUtils::OpenSSLUtils(const String &configFile,
                           const String &command,
                           const String &tmpDir)
	: m_cmd(command), m_tmp(tmpDir), m_conf(configFile)
{
	path::PathInfo pi(configFile);

	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("File does not exist: " << configFile);
		BLOCXX_THROW_ERR(ca_mgm::ValueException,
		                 Format(__("File does not exist: %1."), configFile).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(tmpDir);
	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR("Directory does not exist: " << tmpDir);
		BLOCXX_THROW_ERR(ca_mgm::ValueException,
		                 Format(__("Directory does not exist: %1."), tmpDir).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(command);
	if(!pi.exists() || !pi.isFile() || !pi.isX())
	{
		LOGIT_ERROR("Invalid command: " << command);
		BLOCXX_THROW(ca_mgm::ValueException,
		             Format(__("Invalid command %1."), command).c_str());
	}

	path::PathName r = path::PathName::dirName(configFile);
	if( r.toString() == "")
	{
		m_rand = "./.rand";
	}
	else
	{
		m_rand = r.toString() + "/.rand";
	}
}

void
OpenSSLUtils::createRSAKey(const String &outFile,
                           const String &password,
                           UInt32        bits,
                           const String &cryptAlgorithm)
{
	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "genrsa ";
	debugCmd += "-out ";
	debugCmd += outFile + " ";

	if(!cryptAlgorithm.empty())
	{
		debugCmd += "-passout env:pass ";
		debugCmd += "-" + cryptAlgorithm + " ";
	}

	debugCmd += String(bits);

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", password);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::createRequest(const DNObject &dn,
                            const String   &outFile,
                            const String   &keyFile,
                            const String   &password,
                            const String   &extension,
                            FormatType      outForm,
                            const String   &challengePassword,
                            const String   &unstructuredName)
{
	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "req -new ";

	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	if(!extension.empty())
	{
		debugCmd += "-reqexts " + extension + " ";
	}

	debugCmd += "-key " + keyFile + " ";

	if(outForm == E_PEM)
	{
		debugCmd += "-outform PEM ";
	}
	else
	{
		debugCmd += "-outform DER ";
	}

	debugCmd += "-out " + outFile + " ";

	debugCmd += "-passin env:pass ";

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", password);

	blocxx::String stdInput;
	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	blocxx::List<RDNObject> dnList = dn.getDN();
	blocxx::List<RDNObject>::const_iterator it;

	for(it = dnList.begin(); it != dnList.end(); ++it)
	{
		stdInput += (*it).getValue() + "\n";
	}

	stdInput += challengePassword + "\n";
	stdInput += unstructuredName  + "\n";

	// LOGIT_DEBUG("INPUT: " << stdInput);  // disclose secure data

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env,
		                                           -1, -1, stdInput);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::createSelfSignedCertificate(const String &outFile,
                                          const String &keyFile,
                                          const String &requestFile,
                                          const String &password,
                                          const String &extension,
                                          UInt32        days,
                                          bool          noEmailDN)
{
	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(requestFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid request file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid request file specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "req -x509 ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	if(noEmailDN)
	{
		debugCmd += "-noemailDN ";
	}

	debugCmd += "-passin env:pass ";

	if(!extension.empty())
	{
		debugCmd += "-extensions " + extension + " ";
	}

	debugCmd += "-days " + String(days) + " ";

	debugCmd += "-in "  + requestFile + " ";
	debugCmd += "-key " + keyFile + " ";
	debugCmd += "-out " + outFile + " ";

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", password);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::signRequest(const String &requestFile,
                          const String &outFile,
                          const String &caKeyFile,
                          const String &caPassword,
                          const String &extension,
                          const String &startDate,
                          const String &endDate,
                          const String &caSection,
                          const String &outDir,
                          bool          noEmailDN,
                          bool          noUniqueDN,
                          bool          noText)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(requestFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid request file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid request file specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -batch ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-passin env:pass ";

	if(!caSection.empty())
	{
		debugCmd += "-name "  + caSection   + " ";
	}

	if(!extension.empty())
	{
		debugCmd += "-extensions " + extension + " ";
	}

	debugCmd += "-startdate " + startDate + " ";
	debugCmd += "-enddate "   + endDate   + " ";

	if(noEmailDN)
	{
		debugCmd += "-noemailDN ";
	}
	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}
	if(noText)
	{
		debugCmd += "-notext ";
	}

	debugCmd += "-in "  + requestFile + " ";
	debugCmd += "-out " + outFile + " ";

	if(!outDir.empty())
	{
		debugCmd += "-outdir " + outDir + " ";
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);
	//LOGIT_DEBUG("PASSWORD: " << caPassword);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", caPassword);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::revokeCertificate(const blocxx::String &caCertFile,
                                const blocxx::String &caKeyFile,
                                const blocxx::String &caPassword,
                                const blocxx::String &certFile,
                                const CRLReason      &reason,
                                bool                  noUniqueDN)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	pi.stat(certFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid certificate file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid certificate file specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-revoke " + certFile + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}

	if(!reason.getReason().equalsIgnoreCase("none"))
	{
		String reasonStr = reason.getReason();

		if(reasonStr.equalsIgnoreCase("certificateHold"))
		{
			debugCmd += "-crl_hold " + reason.getHoldInstruction() + " ";
		}
		else if(reasonStr.equalsIgnoreCase("keyCompromise"))
		{
			if(reason.getKeyCompromiseDateAsString() == "")
			{
				debugCmd += "-crl_reason keyCompromise ";
			}
			else
			{
				debugCmd += "-crl_compromise " +
					reason.getKeyCompromiseDateAsString() + " ";
			}
		}
		else if(reasonStr.equalsIgnoreCase("CACompromise"))
		{
			if(reason.getCACompromiseDateAsString() == "")
			{
				debugCmd += "-crl_reason CACompromise ";
			}
			else
			{
				debugCmd += "-crl_CA_compromise " +
					reason.getCACompromiseDateAsString() + " ";
			}
		}
		else
		{
			debugCmd += "-crl_reason " + reasonStr + " ";
		}
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", caPassword);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::issueCRL(const blocxx::String &caCertFile,
                       const blocxx::String &caKeyFile,
                       const blocxx::String &caPassword,
                       blocxx::UInt32        hours,
                       const blocxx::String &outfile,
                       const blocxx::String &extension,
                       bool                  noUniqueDN)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -gencrl ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-out " + outfile + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	debugCmd += "-crlhours " + String(hours) + " ";

	if(!extension.empty())
	{
		debugCmd += "-crlexts " + extension + " ";
	}

	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", caPassword);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::updateDB(const blocxx::String &caCertFile,
                       const blocxx::String &caKeyFile,
                       const blocxx::String &caPassword)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -updatedb ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("pass", caPassword);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	PerlRegEx r("error");

	if( (status != 0 && status != 256) || r.match(errOutput) )
	{
		LOGIT_ERROR("openssl status:" << blocxx::String(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

blocxx::String
OpenSSLUtils::verify(const blocxx::String &certFile,
                     const blocxx::String &caPath,
                     bool                  crlCheck,
                     const blocxx::String &purpose)
{
	path::PathInfo pi(certFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid certificate file specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid certificate file specified."));
	}

	pi.stat(caPath);
	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR("No valid CA directory specified");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("No valid CA directory specified."));
	}

	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "verify ";

	debugCmd += "-CApath " + caPath + " ";

	if(!purpose.empty())
	{
		debugCmd += "-purpose " + purpose + " ";
	}

	if(crlCheck)
	{
		debugCmd += "-crl_check_all ";
	}

	debugCmd += certFile;

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	StringArray lines = PerlRegEx("\n").split(stdOutput);
	StringArray::const_iterator line;

	String result;
	String errMsg;
	String errNum;
	PerlRegEx ok("\\.pem:\\s+(.*)\\s*$");
	PerlRegEx error("^error\\s+(\\d+)\\s+at\\s+\\d+\\s+[\\w\\s]+:(.*)$");

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		StringArray sa = ok.capture(*line);

		if(sa.size() == 2 && sa[1] == "OK")
		{
			result = "OK";
			break;
		}

		sa = error.capture(*line);

		if(sa.size() == 3)
		{
			result = sa[2];
			errMsg = *line;
			errNum = sa[1];
		}
	}

	if(result != "OK")
	{
		if(!errOutput.empty())
		{
			LOGIT_INFO(Format("Certificate invalid! (%1 / %2)", result, errMsg).toString());
			LOGIT_ERROR("openssl stderr:" << errOutput);
		}

		return Format("Certificate invalid! (%1 / %2)", result, errMsg).toString();
	}
	else
	{
		return "";
	}
}

blocxx::String
OpenSSLUtils::status(const blocxx::String &serial)
{
	blocxx::String debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca ";

	debugCmd += "-config " + m_conf + " ";

	debugCmd += "-status " + serial;

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	StringArray lines = PerlRegEx("\n").split(errOutput);
	StringArray::const_iterator line;

	String errMsg;

	PerlRegEx serialMatch(serial + "=(\\w+)\\s+.*$");

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		StringArray sa = serialMatch.capture(*line);

		if(sa.size() == 2)
		{
			return sa[1];
		}
		else
		{
			errMsg += *line + "\n";
		}
	}
	LOGIT_ERROR(Format("Show certificate status with serial '%1' failed.(%2)",
	                   serial, status).toString());
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
	}
	BLOCXX_THROW(ca_mgm::RuntimeException,
	             Format(__("Showing certificate status with serial %1 failed (%2)."),
	                    serial, status).c_str());
}

bool
OpenSSLUtils::checkKey(const blocxx::String &caName,
                       const blocxx::String &password,
                       const blocxx::String &certificateName,
                       const blocxx::String &repository)
{
	String keyFile;

	if(certificateName == "cacert")
	{
		keyFile = repository + "/" + caName + "/cacert.key";
	}
	else
	{
		PerlRegEx r("^[[:xdigit:]]+:([[:xdigit:]]+[\\d-]*)$");
		StringArray sa = r.capture(certificateName);

		if(sa.size() != 2)
		{
			LOGIT_ERROR("Can not parse certificate name");
			BLOCXX_THROW(ca_mgm::RuntimeException,
			             __("Cannot parse the certificate name."));
		}

		keyFile = repository + "/" + caName + "/keys/" + sa[1] + ".key";
	}

	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("Keyfile does not exist");
		BLOCXX_THROW(ca_mgm::SystemException,
		             __("The key file does not exist."));
	}

	blocxx::String debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "rsa -noout -in ";
	debugCmd += keyFile + " ";
	debugCmd += "-passin env:PASSWORD ";

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", m_rand);

	env.addVar("PASSWORD", password);

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// ###################################################
// ### static functions
// ###################################################


ca_mgm::ByteBuffer
OpenSSLUtils::x509Convert(const ByteBuffer &certificate,
                          FormatType inform,
                          FormatType outform )
{
	// FIXME: use tmp file
	blocxx::String inFileName(::tempnam("/tmp/", "x509I"));
	blocxx::String outFileName(::tempnam("/tmp/", "x509O"));

	LocalManagement::writeFile(certificate, inFileName,
	                           false, 0600);

	blocxx::String debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "x509 ";
	debugCmd += "-nameopt ";
	debugCmd += "RFC2253 ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);
	
	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);
	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::rsaConvert(const ByteBuffer &key,
                         FormatType inform,
                         FormatType outform,
                         const String &inPassword,
                         const String &outPassword,
                         const String &algorithm)
{
	// FIXME: use tmp file
	blocxx::String inFileName(::tempnam("/tmp/", "keyIn"));
	blocxx::String outFileName(::tempnam("/tmp/", "keyOt"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(key, inFileName,
	                           false, 0600);

	blocxx::String debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "rsa ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	if(!inPassword.empty() && inform != E_DER)
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}

	if(!outPassword.empty() && outform != E_DER)
	{
		debugCmd += "-passout env:outpass ";

		debugCmd += "-"+ algorithm;
		isOutPassSet = true;
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);

	if(isInPassSet)
	{
		env.addVar("inpass", inPassword);
	}

	if(isOutPassSet)
	{
		env.addVar("outpass", outPassword);
	}

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		// This message is not an error
		if(!PerlRegEx("^writing RSA key$", PCRE_CASELESS).match(errOutput))
		{
			LOGIT_ERROR("openssl stderr:" << errOutput);
			foundError = true;
		}
		else
		{
			LOGIT_DEBUG("openssl stderr:" << errOutput);
		}
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("unable to load Private Key", PCRE_CASELESS).match(msg))
		{
			BLOCXX_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			BLOCXX_THROW(ca_mgm::RuntimeException,
			             Format(__("openssl command failed: %1"),msg).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::crlConvert(const ByteBuffer &crl,
                         FormatType inform,
                         FormatType outform )
{
	// FIXME: use tmp file
	blocxx::String inFileName(::tempnam("/tmp/", "crlIn"));
	blocxx::String outFileName(::tempnam("/tmp/", "crlOt"));

	LocalManagement::writeFile(crl, inFileName,
	                           false, 0600);

	blocxx::String debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "crl ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);
	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::reqConvert(const ByteBuffer &req,
                         FormatType inform,
                         FormatType outform )
{
	// FIXME: use tmp file
	blocxx::String inFileName(::tempnam("/tmp/", "reqIn"));
	blocxx::String outFileName(::tempnam("/tmp/", "reqOt"));

	LocalManagement::writeFile(req, inFileName,
	                           false, 0600);

	blocxx::String debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "req ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);
	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::createPKCS12(const ByteBuffer &certificate,
                           const ByteBuffer &key,
                           const String     &inPassword,
                           const String     &outPassword,
                           const ByteBuffer &caCert,
                           const String     &caPath,
                           bool              withChain )
{
	// FIXME: use tmp file
	blocxx::String inFileName1(::tempnam("/tmp/", "crtIn"));
	blocxx::String inFileName2(::tempnam("/tmp/", "keyIn"));
	blocxx::String inFileName3(::tempnam("/tmp/", "caIn"));
	blocxx::String outFileName(::tempnam("/tmp/", "p12Ot"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(certificate, inFileName1,
	                           false, 0600);
	LocalManagement::writeFile(key, inFileName2,
	                           false, 0600);
	if(!caCert.empty())
	{
		LocalManagement::writeFile(caCert, inFileName3,
		                           false, 0600);
	}

	blocxx::String debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "pkcs12 ";
	debugCmd += "-in ";
	debugCmd += inFileName1 + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";

	debugCmd += "-export ";

	if(!caPath.empty())
	{
		debugCmd += "-CApath ";
		debugCmd += caPath + " ";

		if( withChain )
		{
			debugCmd += "-chain ";
		}
	}

	if(!inPassword.empty())
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}

	if(!outPassword.empty())
	{
		debugCmd += "-passout env:outpass ";
		isOutPassSet = true;
	}
	else
	{
		LOGIT_ERROR("Out password is required");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("The password for encrypting the output is required."));
	}

	debugCmd += "-inkey ";
	debugCmd += inFileName2 + " ";

	if(!caCert.empty())
	{
		debugCmd += "-certfile ";
		debugCmd += inFileName3 + " ";
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);

	if(isInPassSet)
	{
		env.addVar("inpass", inPassword);
	}

	if(isOutPassSet)
	{
		env.addVar("outpass", outPassword);
	}

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName1);
		path::removeFile(inFileName2);
		if(!caCert.empty())
		{
			path::removeFile(inFileName3);
		}
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName1);
		path::removeFile(inFileName2);
		if(!caCert.empty())
		{
			path::removeFile(inFileName3);
		}
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("unable to load Private Key", PCRE_CASELESS).match(msg))
		{
			BLOCXX_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName1);
	path::removeFile(inFileName2);
	if(!caCert.empty())
	{
		path::removeFile(inFileName3);
	}
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::pkcs12ToPEM(const ByteBuffer &pkcs12,
                          const String     &inPassword,
                          const String     &outPassword,
                          const String     &algorithm)
{
	// FIXME: use tmp file
	blocxx::String inFileName(::tempnam("/tmp/", "p12In"));
	blocxx::String outFileName(::tempnam("/tmp/", "x509O"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(pkcs12, inFileName,
	                           false, 0600);

	blocxx::String debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "pkcs12 ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";

	// -nokeys?

	if(!inPassword.empty())
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}
	else
	{
		LOGIT_ERROR("PKCS12 password is required");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("The PKCS12 password is required."));
	}

	if(!outPassword.empty())
	{
		debugCmd += "-passout env:outpass ";
		debugCmd += "-" + algorithm + " ";
		isOutPassSet = true;
	}
	else
	{
		debugCmd += "-nodes ";
	}

	StringArray cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	blocxx::String randfile(::tempnam("/tmp/", ".rand-"));
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	env.addVar("RANDFILE", randfile);

	if(isInPassSet)
	{
		env.addVar("inpass", inPassword);
	}

	if(isOutPassSet)
	{
		env.addVar("outpass", outPassword);
	}

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(blocxx::Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << blocxx::String(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		// This message is not an error
		if(!PerlRegEx("^MAC verified OK$", PCRE_CASELESS).match(errOutput))
		{
			LOGIT_ERROR("openssl stderr:" << errOutput);
			foundError = true;
		}
		else
		{
			LOGIT_DEBUG("openssl stderr:" << errOutput);
		}
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		StringArray sa = errOutput.tokenize("\n\r");
		String msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("invalid password", PCRE_CASELESS).match(msg))
		{
			BLOCXX_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("openssl command failed: %1"), msg).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

blocxx::Array<blocxx::String>
OpenSSLUtils::listCA(const String &repository)
{
	List<String>  tmpList;
	Array<String> retList;

	int r = path::readDir(tmpList, repository, false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << repository <<
		            "(" << System::errorMsg(r) << ") [" << r << "]");
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot read directory: %1 (%2) [%3]."),
		                    repository, System::errorMsg(r), r).c_str());
	}

	tmpList.sort();

	List<String>::const_iterator cont;

	path::PathInfo pi(repository);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(repository + "/" + *cont);

		if(pi.exists() && pi.isDir())
		{
			pi.stat(repository + "/" + *cont + "/openssl.cnf.tmpl");

			if(pi.exists() && pi.isFile())
			{
				pi.stat(repository + "/" + *cont + "/cacert.pem");

				if(pi.exists() && pi.isFile())
				{
					retList.push_back(*cont);
				}
			}
		}
	}
	return retList;
}

blocxx::String
OpenSSLUtils::nextSerial(const String &serialFile)
{
	ByteBuffer b = LocalManagement::readFile(serialFile);

	String s(b.data(), b.size());
	PerlRegEx r("^([[:xdigit:]]+)$");

	StringArray sa = r.capture(s);

	if(sa.size() == 2)
	{
		return sa[1];
	}
	else
	{
		LOGIT_ERROR("No serial number found in " << serialFile);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             Format(__("No serial number found in %1."),
		                    serialFile).c_str());
	}
}

void
OpenSSLUtils::addCAM(const String &caName,
                     const String &md5,
                     const String &dnString,
                     const String &repository)
{
	Array<Array<String> > db = OpenSSLUtils::parseCAMDB(caName, repository);
	Array<Array<String> >::const_iterator it;

	for(it = db.begin(); it != db.end(); ++it)
	{
		if( (*it)[0] == md5 )
		{
			LOGIT_ERROR("Request already exist.");
			BLOCXX_THROW(ca_mgm::RuntimeException,
			             __("The request already exists."));
		}
	}

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	String cam(b.data(), b.size());
	cam += md5 + " " + dnString + "\n";

	LocalManagement::writeFile(ByteBuffer(cam.c_str(), cam.length()),
	                           repository + "/" + caName + "/cam.txt");

}

void
OpenSSLUtils::delCAM(const String &caName,
                     const String &md5,
                     const String &repository)
{
	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	String cam(b.data(), b.size());

	StringArray lines = PerlRegEx("\n").split(cam);

	StringArray::const_iterator line;
	String camNew;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^" + md5);

		if(!r.match(*line))
		{
			camNew += *line + "\n";
		}
	}
	LocalManagement::writeFile(ByteBuffer(camNew.c_str(), camNew.length()),
	                           repository + "/" + caName + "/cam.txt");

}

blocxx::Array<blocxx::Array<blocxx::String> >
OpenSSLUtils::parseCAMDB(const String &caName,
                         const String &repository)
{
	Array<Array<String> > ret;

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	String cam(b.data(), b.size());

	StringArray lines = PerlRegEx("\n").split(cam);

	StringArray::const_iterator line;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^([[:xdigit:]]+[\\d-]*)\\s(.*)$");

		StringArray col = r.capture(*line);

		if(col.size() != 3)
		{
			LOGIT_INFO("Can not parse line '" << *line << "'");
			continue;
		}

		Array<String> a;
		a.push_back(col[1]);
		a.push_back(col[2]);
		ret.push_back(a);
	}
	return ret;
}

blocxx::Array<blocxx::Array<blocxx::String> >
OpenSSLUtils::parseIndexTXT(const String &caName,
                            const String &repository)
{
	Array<Array<String> > ret;

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/index.txt");

	String cam(b.data(), b.size());

	StringArray lines = PerlRegEx("\n").split(cam);

	StringArray::const_iterator line;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^(\\w)\\s([\\d\\w]+)\\s([\\w\\d,.]*)\\s([[:xdigit:]]+)\\s(\\w+)\\s(.*)$");

		StringArray col = r.capture(*line);

		if(col.size() != 7)
		{
			LOGIT_INFO("Can not parse line '" << *line << "'");
			continue;
		}

		Array<String> a;
		a.push_back(col[1]);
		a.push_back(col[2]);
		a.push_back(col[3]);
		a.push_back(col[4]);
		a.push_back(col[5]);
		a.push_back(col[6]);
		ret.push_back(a);
	}
	return ret;
}

blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
OpenSSLUtils::listRequests(const String &caName,
                           const String &repository)
{
	Array<Map<String, String> > ret;
	List<String> tmpList;

	String reqDir = repository + "/" + caName + "/req/";

	int r = path::readDir(tmpList, reqDir , false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << reqDir <<
		            "(" << System::errorMsg(r) << ") [" << r << "]");
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot read directory: %1 (%2) [%3]."),
		                    reqDir, System::errorMsg(r), r).c_str());
	}

	tmpList.sort();

	Array<Array<String> >        camdb = OpenSSLUtils::parseCAMDB(caName, repository);
	List<String>::const_iterator cont;
	path::PathInfo pi(reqDir);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(reqDir + "/" + *cont);

		if(!pi.exists() || !pi.isFile())
		{
			LOGIT_INFO("skipping file " << pi.toString());
			continue;
		}

		PerlRegEx requestR("^([[:xdigit:]]+)-?(\\d*)\\.req$");

		StringArray sa = requestR.capture(*cont);

		if(sa.size() <= 1)
		{
			LOGIT_INFO("unknown filename ... skipping (" << *cont << ")");
			continue;
		}

		String md5 = sa[1];
		String date;

		if(sa.size() == 3 && !sa[2].empty())
		{
			md5 += "-" + sa[2];

			DateTime dt( sa[2].toInt64() );
			date = dt.toString("%Y-%m-%d %H:%M:%S", DateTime::E_LOCAL_TIME);
		}

		Map<String, String> reqLine;
		String              subject;

		reqLine["request"] = md5;
		reqLine["date"]    = date;

		Array<Array<String> >::const_iterator dbIT;
		for(dbIT = camdb.begin(); dbIT != camdb.end(); ++dbIT)
		{
			if( (*dbIT)[0] == md5 )
			{
				subject = (*dbIT)[1];
				break;
			}
		}

		if(subject.empty())
		{
			LOGIT_ERROR("Can not find request subject.");
			BLOCXX_THROW(ca_mgm::RuntimeException,
			             __("Cannot find the request subject."));
		}

		sa.clear();
		while(1)
		{
			StringArray saTmp = PerlRegEx("(.*?[^\\\\])(\\/|$)").capture(subject);
			uint pos = 0;

			if(saTmp.size() >=2)
			{
				pos = saTmp[1].length();
				sa.push_back(saTmp[1]);
			}
			else
			{
				break;
			}
			subject = subject.substring(pos);
		}

		PerlRegEx cR("^C=");
		PerlRegEx stR("^ST=");
		PerlRegEx lR("^L=");
		PerlRegEx oR("^O=");
		PerlRegEx ouR("^OU=");
		PerlRegEx cnR("^CN=");
		PerlRegEx emailR("^emailAddress=");

		PerlRegEx quoteR("\\\\/");

		StringArray::const_iterator it;
		for(it = sa.begin(); it != sa.end(); ++it)
		{
			String toMatch = quoteR.replace(*it, "/", true);
			toMatch = PerlRegEx("^/").replace(toMatch, "");

			if(cR.match(toMatch))
			{
				reqLine["country"]  = toMatch.substring(2);
			}
			else if(stR.match(toMatch))
			{
				reqLine["stateOrProvinceName"]  = toMatch.substring(3);
			}
			else if(lR.match(toMatch))
			{
				reqLine["localityName"]  = toMatch.substring(2);
			}
			else if(oR.match(toMatch))
			{
				reqLine["organizationName"]  = toMatch.substring(2);
			}
			else if(ouR.match(toMatch))
			{
				reqLine["organizationalUnitName"]  = toMatch.substring(3);
			}
			else if(cnR.match(toMatch))
			{
				reqLine["commonName"]  = toMatch.substring(3);
			}
			else if(emailR.match(toMatch))
			{
				reqLine["emailAddress"]  = toMatch.substring(13);
			}
			else
			{
				LOGIT_INFO("Unknown rdn: " << toMatch);
			}
		}
		ret.push_back(reqLine);
	}
	return ret;
}

blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
OpenSSLUtils::listCertificates(const String &caName,
                               const String &repository)
{
	Array<Map<String, String> > ret;
	List<String> tmpList;

	String certDir = repository + "/" + caName + "/newcerts/";

	int r = path::readDir(tmpList, certDir , false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << certDir <<
		            "(" << System::errorMsg(r) << ") [" << r << "]");
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot read directory: %1 (%2) [%3]."),
		                    certDir, System::errorMsg(r), r).c_str());
	}

	tmpList.sort();

	Array<Array<String> >        indexTXT = OpenSSLUtils::parseIndexTXT(caName, repository);
	List<String>::const_iterator cont;
	path::PathInfo pi(certDir);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(certDir + "/" + *cont);

		if(!pi.exists() || !pi.isFile())
		{
			LOGIT_INFO("skipping file " << pi.toString());
			continue;
		}

		PerlRegEx certR("^([[:xdigit:]]+):([[:xdigit:]]+-?\\d*)\\.pem$");

		StringArray sa = certR.capture(*cont);

		if(sa.size() != 3)
		{
			LOGIT_INFO("unknown filename ... skipping (" << *cont << ")");
			continue;
		}

		String serial = sa[1];
		String md5    = sa[2];

		Map<String, String> certLine;
		String              subject;

		certLine["serial"]      = serial;
		certLine["certificate"] = serial + ":" + md5;

		Array<Array<String> >::const_iterator dbIT;
		for(dbIT = indexTXT.begin(); dbIT != indexTXT.end(); ++dbIT)
		{
			if( (*dbIT)[3] == serial )
			{
				subject = (*dbIT)[5];

				if((*dbIT)[0] == "V" )
				{
					certLine["status"] = "Valid";
				}
				else if((*dbIT)[0] == "R" )
				{
					certLine["status"] = "Revoked";
				}
				else if((*dbIT)[0] == "E" )
				{
					certLine["status"] = "Expired";
				}
				else
				{
					certLine["status"] = (*dbIT)[0];
				}
				break;
			}
		}

		if(subject.empty())
		{
			LOGIT_ERROR("Can not find certificate subject.");
			BLOCXX_THROW(ca_mgm::RuntimeException,
			             __("Cannot find the certificate subject."));
		}

		sa.clear();
		while(1)
		{
			StringArray saTmp = PerlRegEx("(.*?[^\\\\])(\\/|$)").capture(subject);
			uint pos = 0;

			if(saTmp.size() >=2)
			{
				pos = saTmp[1].length();
				sa.push_back(saTmp[1]);
			}
			else
			{
				break;
			}
			subject = subject.substring(pos);
		}

		PerlRegEx cR("^C=");
		PerlRegEx stR("^ST=");
		PerlRegEx lR("^L=");
		PerlRegEx oR("^O=");
		PerlRegEx ouR("^OU=");
		PerlRegEx cnR("^CN=");
		PerlRegEx emailR("^emailAddress=");

		PerlRegEx quoteR("\\\\/");

		StringArray::const_iterator it;
		String lastPart;
		for(it = sa.begin(); it != sa.end(); ++it)
		{
			String toMatch = quoteR.replace(*it, "/", true);
			toMatch = PerlRegEx("^/").replace(toMatch, "");

			if(cR.match(toMatch))
			{
				certLine["country"]  = toMatch.substring(2);
				lastPart = "country";
			}
			else if(stR.match(toMatch))
			{
				certLine["stateOrProvinceName"]  = toMatch.substring(3);
				lastPart = "stateOrProvinceName";
			}
			else if(lR.match(toMatch))
			{
				certLine["localityName"]  = toMatch.substring(2);
				lastPart = "localityName";
			}
			else if(oR.match(toMatch))
			{
				certLine["organizationName"]  = toMatch.substring(2);
				lastPart = "organizationName";
			}
			else if(ouR.match(toMatch))
			{
				certLine["organizationalUnitName"]  = toMatch.substring(3);
				lastPart = "organizationalUnitName";
			}
			else if(cnR.match(toMatch))
			{
				certLine["commonName"]  = toMatch.substring(3);
				lastPart = "commonName";
			}
			else if(emailR.match(toMatch))
			{
				certLine["emailAddress"]  = toMatch.substring(13);
				lastPart = "emailAddress";
			}
			else
			{
				if(!lastPart.empty() && (*it).charAt(0) == '/')
				{
					certLine[lastPart]  = certLine[lastPart] + *it;
					LOGIT_DEBUG(Format("Append '%1' to %2", *it, lastPart));
				}
				else
				{
					LOGIT_INFO("Unknown rdn: " << toMatch);
				}
			}
		}
		ret.push_back(certLine);
	}
	return ret;
}

void
OpenSSLUtils::createCaInfrastructure(const String &caName,
                                     const String &repository)
{
	if(caName.empty() || !PerlRegEx("\\w+").match(caName))
	{
		LOGIT_ERROR("Invalid caName: " << caName);
		BLOCXX_THROW(ca_mgm::ValueException,
		             Format(__("Invalid caName: %1."), caName).c_str());
	}

	path::PathInfo pi(repository);

	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR(repository << " does not exist");
		BLOCXX_THROW_ERR(ca_mgm::SystemException,
		                 Format(__("'%1' does not exist."), repository).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(repository + "/" + caName);

	if(pi.exists())
	{
		LOGIT_ERROR(pi.toString() << " still exist");
		BLOCXX_THROW_ERR(ca_mgm::SystemException,
		                 Format(__("%1 still exists."), pi.toString()).c_str(),
		                 E_FILE_EXISTS);
	}

	int r = path::createDir(pi.toString(), 0700);

	if( r != 0 )
	{
		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   pi.toString(), System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    pi.toString(), System::errorMsg(r), r).c_str());
	}

	ByteBuffer tmpl;
	try
	{
		tmpl = LocalManagement::readFile(repository + "/openssl.cnf.tmpl");

		StringArray tmplArray = PerlRegEx("\n").split(String(tmpl.data(), tmpl.size()), true);

		PerlRegEx                   dirR("^\\s*dir\\s*=");
		String                      newConf;
		StringArray::const_iterator line;

		for(line = tmplArray.begin(); line != tmplArray.end(); ++line)
		{
			if(dirR.match(*line))
			{
				newConf += "dir = " + pi.toString() + "/\n";
			}
			else
			{
				newConf += *line + "\n";
			}
		}

		LocalManagement::writeFile(ByteBuffer(newConf.c_str(), newConf.length()),
		                           pi.toString() + "/openssl.cnf.tmpl");
	}
	catch(blocxx::Exception &e)
	{
		path::removeDirRecursive(repository + "/" + caName);

		BLOCXX_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Cannot copy the configuration template."), e);
	}

	String dir = pi.toString() + "/certs";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   dir, System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    dir, System::errorMsg(r), r).c_str());
	}

	dir = pi.toString() + "/crl";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   dir, System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    dir, System::errorMsg(r), r).c_str());
	}

	dir = pi.toString() + "/newcerts";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   dir, System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    dir, System::errorMsg(r), r).c_str());
	}

	dir = pi.toString() + "/req";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   dir, System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    dir, System::errorMsg(r), r).c_str());
	}

	dir = pi.toString() + "/keys";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(Format("Can not create directory: %1 (%2 [%3])",
		                   dir, System::errorMsg(r), r));
		BLOCXX_THROW(ca_mgm::SystemException,
		             Format(__("Cannot create directory: %1 (%2 [%3])."),
		                    dir, System::errorMsg(r), r).c_str());
	}

	try
	{
		LocalManagement::writeFile(ByteBuffer("01"),
		                           pi.toString() + "/serial");
		LocalManagement::writeFile(ByteBuffer(),
		                           pi.toString() + "/index.txt");
		LocalManagement::writeFile(ByteBuffer(),
		                           pi.toString() + "/cam.txt");
	}
	catch(blocxx::Exception &e)
	{
		path::removeDirRecursive(repository + "/" + caName);

		BLOCXX_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Cannot create the file."), e);
	}
}

}
