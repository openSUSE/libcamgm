/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                          limal core library                          |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       Utils.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   Utils.cpp
 * @brief  This file is private for the limal core library.
 *         It implements common utilities, like the gettext
 *         text domain initializaton.
 */
#include <ca-mgm/config.h>

#include "Utils.hpp"
#include <libintl.h>
#include <openssl/objects.h>
#include <pthread.h>
#include <ca-mgm/ExternalProgram.hpp>
#include <ca-mgm/PathUtils.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// -------------------------------------------------------------------
namespace CA_MGM_NAMESPACE
{
namespace
{
	// -----------------------------------------------------------
pthread_once_t g_i18n_init_guard = PTHREAD_ONCE_INIT;


	// -----------------------------------------------------------
void               init_i18n_domain()
{
	bindtextdomain( i18n_domain, LOCALEDIR);
	bind_textdomain_codeset( i18n_domain, "utf8");
}
}


// -------------------------------------------------------------------
const char *       gettext (const char *msgid)
{
	pthread_once(&g_i18n_init_guard, init_i18n_domain);
	return ::dgettext(i18n_domain, msgid);
}


// -------------------------------------------------------------------
const char *       gettext (const char *msgid,
                            const char *plural,
                            unsigned long int n)
{
	pthread_once(&g_i18n_init_guard, init_i18n_domain);
	return ::dngettext(i18n_domain, msgid, plural, n);
}


// -------------------------------------------------------------------
int wrapExecuteProcessAndGatherOutput(
                                       const ExternalProgram::Arguments    &cmd,
                                       std::string        &out,
                                       std::string        &err,
                                       const ExternalProgram::Environment  &env
                                     )
{
  int exitStatus = -1;
  /*
  std::string tmperr(::tempnam("/tmp/", "errfd"));
  int errfd = open(tmperr.c_str(), O_CREAT|O_RDWR|O_EXCL);
  if(errfd == -1)
  {
    ERR << "Cannot open file: " << str::strerror(errno) << std::endl;
    return exitStatus;
  }
  */

  int stderr_pipes[2];

  // create a pair of pipes
  if (pipe(stderr_pipes) != 0)
  {
    // return current stderr
    return exitStatus;
  }
  // get the current flags
  int flags = ::fcntl(stderr_pipes[0],F_GETFL);
  if (flags == -1)
  {
    ERR << strerror(errno) << std::endl;
    return exitStatus;
  }

  // set the non-blocking flag
  flags = flags | O_NONBLOCK;

  // set the updated flags
  flags = ::fcntl(stderr_pipes[0],F_SETFL,flags);

  if (flags == -1)
  {
    ERR << strerror(errno) << std::endl;
    return exitStatus;
  }

  FILE *stderr_output = ::fdopen(stderr_pipes[0], "r");

  ExternalProgram prog( cmd, env, ExternalProgram::Stderr_To_FileDesc,
                        false, stderr_pipes[1], true);

  std::string line;
  for(line = prog.receiveLine();
      ! line.empty();
      line = prog.receiveLine() )
  {
    out += line + "\n";
  }
  exitStatus = prog.close();

  //lseek(errfd, 0, SEEK_SET);
  const unsigned tmpBuffLen = 1024;
  char           tmpBuff[tmpBuffLen];
  uint len = 0;

  do
  {
    len = ::fread(tmpBuff, 1, tmpBuffLen, stderr_output);

    if (len > 0)
    {
      err.append(tmpBuff, len);
    }
  }
  while(len == tmpBuffLen);
  ::fclose(stderr_output);

  if(exitStatus)
  {
    //DBG << prog.execError() << std::endl;
  }
  return exitStatus;
}

/* FIXME: remove
std::vector<std::string>
convStringArray(const std::stringArray &in)
{
  std::vector<std::string> out(in.begin(), in.end());
  return out;
}
*/

void
appendArray(std::vector<std::string> &in, const std::vector<std::string> &arr)
{
  in.insert(in.end(), arr.begin(), arr.end());
}

// -------------------------------------------------------------------
}       // End of CA_MGM_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
