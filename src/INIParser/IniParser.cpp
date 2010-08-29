/**
 * YaST2: Core system
 *
 * Description:
 *   YaST2 SCR: Ini file agent.
 *
 * Authors:
 *   Petr Blahos <pblahos@suse.cz>
 *
 * $Id: IniParser.cc 22864 2005-03-30 14:26:42Z mvidner $
 */

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glob.h>
#include <cassert>


#include "INIParser/IniParser.h"
#include "INIParser/IniFile.h"

namespace CA_MGM_NAMESPACE
{
namespace INI
{

using std::ifstream;
using std::ofstream;

int assert_dir( const std::string & spath)
{
    size_t pos, lastpos = 0;
    int ret = 0;

    if(spath.empty())
	return 0;

    // skip ./
    if(spath.length() > 2 &&
       spath.substr(0,2) == "./")
	lastpos=2;
    // skip /
    else if (spath[0] == '/')
	lastpos=1;

    while((pos = spath.find_first_of('/',lastpos)) != std::string::npos )
    {
	std::string dir = spath.substr(0,pos);
	ret = ::mkdir(dir.c_str(), 0755);
	if(ret == -1)
	{
	    // ignore errors about already existing directorys
	    if(errno == EEXIST)
		ret=0;
	    else
		ret=errno;
	}
	lastpos = pos+1;
    }
    return ret;
}


IniParser::~IniParser ()
{
    // regex deallocation used to be here
}
/**
 * Debugging.
 */
void printPath(const std::vector<std::string>&p, const char*c = "")
{
    int i = 0;
    int len = p.size();
    printf("%s:", c);
    for (;i<len;i++)
	printf("%s ", p[i].c_str());
    printf("\n");
}

bool onlySpaces (const char*str)
{
    while (*str)
    {
	if (' ' != *str && '\t' != *str && '\r' != *str && '\n' != *str)
	    return false;
	str++;
    }
    return true;
}



void IniParser::initFiles (const std::vector<std::string>&f)
{
    multiple_files = true;
    files.clear ();

    int len = f.size();
    for (int i = 0;i<len;i++)
	files.push_back (f[i]);
}
void IniParser::initFiles (const char*fn)
{
    file = fn;
    multiple_files = false;
}
void IniParser::initOptions (const std::vector<std::string>&options)
{
    int len = options.size();
    for (int i = 0;i<len;i++)
    {
	std::string sv = options[i];
#define COMPARE_OPTION(X) if (sv == #X) X = true; else
		    COMPARE_OPTION (ignore_case_regexps)
		    COMPARE_OPTION (ignore_case)
		    COMPARE_OPTION (prefer_uppercase)
		    COMPARE_OPTION (first_upper)
		    COMPARE_OPTION (line_can_continue)
		    COMPARE_OPTION (no_nested_sections)
		    COMPARE_OPTION (global_values)
		    COMPARE_OPTION (repeat_names)
		    COMPARE_OPTION (comments_last)
		    COMPARE_OPTION (join_multiline)
		    COMPARE_OPTION (no_finalcomment_kill)
		    COMPARE_OPTION (read_only)
		    COMPARE_OPTION (flat)
			ERR <<"Option not implemented yet:"<<  sv.c_str() << std::endl;
#undef  COMPARE_OPTION
    }

    if (ignore_case && multiple_files)
    {
       ERR << "When using multiple files, ignore_case does not work" << std::endl;
       ignore_case = false;
    }
}

void IniParser::initRewrite (const std::vector<IoPatternDescr>&rewriteArray)
{
    int len = rewrites.size();
    rewrites.clear ();
    rewrites.reserve (len);

    for (int i = 0; i<len;i++)
    {
	IoPatternDescr val = rewriteArray[i];
	IoPattern p;
	if (p.rx.compile (val.regExpr,
			   REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
	{
	    p.out = std::string (val.out);
	    rewrites.push_back (p);
	}
    }
}

void IniParser::initSubident (const std::string ident)
{
    subindent = std::string(ident);
}

void IniParser::initComments (const std::vector<std::string>&comm)
{
    int len = comm.size();
    linecomments.clear ();
    comments.clear ();
    linecomments.reserve (len);
    comments.reserve (len);
    for (int i = 0;  i < len; i++)
    {
	std::string s = comm[i];
	std::vector<PosixRegEx> & regexes = ('^' == s[0]) ?
	    linecomments : comments;
	PosixRegEx r;
	if (r.compile (s, REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
	{
	    regexes.push_back (r);
	}
    }
}

void IniParser::initSection (const std::vector<SectionDescr>& sect)
{
    int len = sect.size();
    // compile them to regex_t
    sections.clear ();
    sections.reserve (len);
    for (int i = 0;  i < len; i++)
    {
	section s;
	SectionDescr m = sect[i];
	s.end_valid = m.end_valid;
	if (s.end_valid)
	{
	    IoPatternDescr end = m.end;
	    if (!s.end.rx.compile (end.regExpr,
				  REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
		continue;
	    s.end.out = std::string (end.out);
	}
	IoPatternDescr begin = m.begin;
	if (!s.begin.rx.compile (begin.regExpr,
				REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
	{
	    // compile failed
	    continue;
	}
	s.begin.out = std::string(begin.out);
	sections.push_back (s);
    }
}


void IniParser::initParam (const std::vector<EntryDescr>& entries)
{
    int len = entries.size();
    // compile them to regex_t
    params.clear ();
    params.reserve (len);
    for (int i = 0; i < len; i++)
    {
	EntryDescr entry = entries[i];
	param pa;
	pa.multiline_valid = entry.multiline_valid;
	if (entry.multiline_valid)
	{
	    if (pa.begin.compile (entry.multiBegin,
				   REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
	    {
		if (!pa.end.compile (entry.multiEnd,
				    REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
		{
		    ERR <<"Bad regexp(multiline): "<<
				      entry.multiEnd.c_str() << std::endl;
		    pa.multiline_valid = false;
		}
	    }
	    else
	    {
		ERR <<"Bad regexp(multiline): "<<
				  entry.multiBegin.c_str() << std::endl;
	    }
	}

	if (!pa.line.rx.compile ( std::string (entry.line.regExpr),
				 REG_EXTENDED | (ignore_case ? REG_ICASE : 0)))
	{
	    if (pa.multiline_valid)
	    {
		ERR <<"Bad regexp(match): "<<
				  entry.line.regExpr.c_str() << std::endl;
	    }
	    break;
	}
	else
	{
	    pa.line.out = std::string (entry.line.out);
	    params.push_back (pa);
	}
    }
}

int IniParser::scanner_start(const char*fn)
{
    scanner.open(fn);
    scanner_file = fn;
    scanner_line = 0;
    if (!scanner.is_open())
        return -1;
    return 0;
}
void IniParser::scanner_stop()
{
    scanner.close();
    scanner.clear();
}
int IniParser::scanner_get(std::string&s)
{
    if (!scanner)
	return -1;
    s = str::getline (scanner);

    scanner_line++;
    if (line_can_continue && s.length ())
    {
	std::string tmp;
	while (s[s.length()-1] == '\\')
	{
	    tmp = str::getline (scanner);
	    scanner_line++;
	    s = s + "\n" + tmp;
	}
    }
    return 0;
}

#define scanner_error(format,args...) \
	ERR << str::form( "%s:%d " format, scanner_file.c_str (),  scanner_line, ##args).c_str() << std::endl

void StripLine (std::string&l, regmatch_t&r)
{
    std::string out;
    if (r.rm_so>1)
	out = l.substr (0,r.rm_so);
    out = out + l.substr(r.rm_eo);
    l = out;
}

bool FileDescr::changed ()
{
    struct stat st;
    if (stat(fn.c_str(), &st))
    {
//	CA_MGM_LOG_ERROR (logger,"Unable to stat " <<  fn.c_str() << ": " << strerror(errno));
	return false;
    }
    if (timestamp != st.st_mtime)
    {
	timestamp = st.st_mtime;
	return true;
    }
    return false;
}

FileDescr::FileDescr (char*fn_)
{
    fn = fn_;
    sn = fn_;
    struct stat st;
    if (stat(fn_, &st))
    {
//	CA_MGM_LOG_ERROR (logger, "Unable to stat " << fn_ << " : " << strerror(errno));
	timestamp = 0;
    }
    else
    {
    	timestamp = st.st_mtime;
    }
}

int IniParser::parse()
{
    if ( !started)
    {
	ERR <<"Parser not initialized" << std::endl;
	return -1;
    }

    if (multiple_files)
    {
	glob_t do_files;
	int len = files.size ();
	int flags = 0;
	for (int i = 0;i<len;i++)
	{
	    glob (files[i].c_str (),flags, NULL, &do_files);
	    flags = GLOB_APPEND;
	}
	char**f = do_files.gl_pathv;
	for (unsigned int i = 0;i<do_files.gl_pathc;i++, f++)
	{
	    int section_index = -1;
	    std::string section_name = *f;
	    //FIXME: create function out of it.
	    // do we have name rewrite rules?
	    for (size_t j = 0; j < rewrites.size (); j++)
		{
		    RegexMatch m (rewrites[j].rx, section_name);
		    if (m)
		    {
			section_index = j;
			section_name = m[1];
			DBG << "Rewriting " << *f << " to " << section_name.c_str() << std::endl;
			break;
		    }
		}

	    // do we know about the file?
	    std::map<std::string,FileDescr>::iterator ff = multi_files.find (*f);
	    if (ff == multi_files.end())
	    {
		// new file
		if (scanner_start (*f))
		    ERR <<"Cannot open " << *f << std::endl;
		else
		{
		    FileDescr fdsc (*f);
		    multi_files[*f] = fdsc;
		    inifile.initSection (section_name, "", -1, section_index);
		    parse_helper(inifile.getSection(section_name.c_str()));
		    scanner_stop();
		}
	    }
	    else
	    {
		if ((*ff).second.changed ())
		{
		    if (scanner_start (*f))
			ERR <<"Cannot open " << *f << std::endl;
		    else
		    {
			DBG << "File " << *f << " changed. Reloading." << std::endl;
			FileDescr fdsc (*f);
			multi_files [*f] = fdsc;
			inifile.initSection (section_name, "", -1, section_index);
			parse_helper(inifile.getSection(section_name.c_str()));
			scanner_stop();
		    }
		}
	    }
	}
    }
    else
    {
	if (scanner_start (file.c_str()))
	    {
		ERR <<"Can not open " << file.c_str() << std::endl;
		return -1;
	    }
	parse_helper(inifile);
	scanner_stop();
	timestamp = getTimeStamp ();
    }
    return 0;
}

int IniParser::parse_helper(IniSection&ini)
{
    std::string comment = "";
    std::string key = "";
    std::string val = "";
    int state = 0;		// 1: precessing a multiline value
    int matched_by = -1;

    std::string line;
    size_t i;

    // stack of section names
    std::vector<std::string> path;

    //
    // read line
    //
    while (!scanner_get (line))
	{
	    //
	    // check for whole-line comment (always as the first stage)
	    //
	    for (i = 0;i<linecomments.size (); i++)
		{
		    if (RegexMatch (linecomments[i], line))
			{
			    // we have it !!!
			    comment = comment + line + "\n";
			    break;
			}
		}
	    if (i<linecomments.size ()) // found? -> next line
		continue;

	    //
	    // check for comments on line
	    //
	    if (!comments_last)
		{
		    for (i = 0;i<comments.size (); i++)
			{
			    RegexMatch m (comments[i], line);
			    if (m)
			    {
				// we have it !!!
				comment = comment + m[0] + "\n";
				line = m.rest;
				break;
			    }
			}
		}

	    //
	    // are we in broken line?
	    //
	    if (state)
		{
		    RegexMatch m (params[matched_by].end, line);
		    if (m)
		    {
			// it is the end of broken line
			state = 0;
			val = val + (join_multiline ? "" : "\n") + m[1];
			line = m.rest;
			if (!path.size())
			    {   // we are in toplevel section, going deeper
				// check for toplevel values allowance
				if (!global_values)
				    scanner_error ("%s: values at the top level not allowed.", key.c_str ());
				else
				    ini.initValue (key, val, comment, matched_by);
			    }
			else
			    {
				ini.findSection(path).initValue(key, val, comment, matched_by);
			    }
			comment = "";
		    }
		    else
			val = val + (join_multiline ? "" : "\n") + line;
		}
	    if (!state)
		{
		    //
		    // check for section begin
		    //
		    {
			std::string found;

			for (i = 0; i < sections.size (); i++)
			    {
				RegexMatch m (sections[i].begin.rx, line);
				if (m)
				{
				    found = m[1];
				    line = m.rest;
				    break;
				}
			    }
			if (i < sections.size ())
			    {
				// section begin found !!! check conditions
				if (path.size())
				    {   // there were some sections
					// is there need to close previous section?
					if (sectionNeedsEnd(ini.findSection(path).getReadBy()))
					    {
						if(no_nested_sections)
						    {
							scanner_error ("Section %s started but section %s is not finished",
								 found.c_str(),
								 path[path.size()-1].c_str());
							path.pop_back();
						    }
					    }
					else
					    path.pop_back();
				    }
				if (!path.size())
				    {   // we are in toplevel section, going deeper
					ini.initSection (found, comment, i);
				    }
				else
				    {
					if (no_nested_sections)
					    scanner_error ("Attempt to create nested section %s.", found.c_str ());
					else
					{
					    ini.findSection(path).initSection(found, comment, i);
					}
				    }
				comment = "";
				path.push_back(found);
			    }
		    } // check for section begin

		    //
		    // check for section end
		    //
		    {
			std::string found;

			for (i = 0; i < sections.size (); i++)
			    {
				if (!sections[i].end_valid)
				    continue;
				RegexMatch m (sections[i].end.rx, line);
				if (m)
				{
				    found = 1 < m.matches.size () ? m[1]: "";
				    line = m.rest;
				    break;
				}
			    }
			if (i < sections.size ())
			    {
				// we found new section enclosing which
				// means that we can save possible trailing
				// comment
				if (!comment.empty ())
				    {
					if (!path.size())
					    ini.setEndComment (comment.c_str ());
					else
					    {
						ini.findSection(path).setEndComment (comment.c_str ());
					    }
					comment = "";
				    }
				if (!path.size ())
				    scanner_error ("Nothing to close.");
				else if (!found.empty ())
				    {   // there is a subexpression
					int len = path.size ();
					int j;

					for (j = len - 1; j >= 0;j--)
					    if (path[j] == found)
					    {
						path.resize (j);
						break;
					    }
				    	if (j == -1)
					{   // we did not find, so close the first that needs it
					    int m = ini.findEndFromUp (path, i);
					    int toclose = len - 1;
					    if (-1 != m)
					    {
						toclose = m - 1;
					    }
					    scanner_error ("Unexpected closing %s. Closing section %s.", found.c_str(), path[toclose].c_str());
					    path.resize (toclose);
					}
				    }
				else
				    {   // there is no subexpression
					int m = ini.findEndFromUp (path, i);
					if (-1 != m) // we have perfect match
					{
					    path.resize(m - 1);
					}
					else if ((i = path.size ()) > 0)
					{
					    path.resize (i - 1);
					}
				    }
			    }
		    }

		    //
		    // check for line
		    //
		    {
			std::string key,val;
			for (i = 0; i < params.size (); i++)
			{
			    RegexMatch m (params[i].line.rx, line);
			    if (m)
			    {
				key = m[1];
				val = m[2];
				line = m.rest;
				break;
			    }
			}
			if (i != params.size ())
			    {
				if (!path.size())
				    {   // we are in toplevel section, going deeper
					// check for toplevel values allowance
					if (!global_values)
					    scanner_error ("%s: values at the top level not allowed.", key.c_str ());
					else
					    ini.initValue (key, val, comment, i);
				    }
				else
				    {
					ini.findSection(path).initValue(key, val, comment, i);
				    }
				comment = "";
			    }
		    }

		    //
		    // check for broken line
		    //
		    {
			for (i = 0; i < params.size (); i++)
			{
			    if (!params[i].multiline_valid)
				continue;
			    RegexMatch m (params[i].begin, line);
			    if (m)
			    {
				// broken line
				key = m[1];
				val = m[2];
				line = m.rest;
				matched_by = i;
				state = 1;
				break;
			    }
			}
		    }

		    //
		    // check for comments on line
		    //
		    if (comments_last && !comments.empty ())
		    {
			for (i = 0; i < comments.size (); i++)
			{
			    RegexMatch m (comments[i], line);
			    if (m)
			    {
				// we have it !!!
				comment = comment + m[0] + "\n";
				line = m.rest;
				break;
			    }
			}
		    }
		    //
		    // if line is not empty, report it
		    //
		    {
			if (!onlySpaces (line.c_str()))
			    scanner_error ("Extra characters: %s", line.c_str ());
		    }
		}
	}
    if (!comment.empty ())
    {
	if (!no_finalcomment_kill)
	{
	    // kill empty lines at the end of comment
	    int i = comment.length ();
	    const char*p = comment.c_str () + i - 1;
	    while (i)
	    {
		if ('\n' != *p)
		    break;
		i --;
		p --;
	    }
	    if (i > 0)
		i++;
	    comment.erase (i);
	}
	ini.setEndComment (comment.c_str ());
    }

    return 0;
}

void IniParser::UpdateIfModif ()
{
    if (read_only)
        return;
    // #42297: parsing a file with repeat_names cannot remove duplicates
    // so reparsing it would duplicate the whole file.
    // Therefore we do not reparse.
    if (repeat_names)
    {
	DBG << "Skipping possible reparse due to repeat_names" << std::endl;
	return;
    }
    if (multiple_files)
	parse ();
    else
    {
	if (timestamp != getTimeStamp())
	{
	    ERR << "Data file '" <<  file.c_str() << "' was changed externaly!" << std::endl;
	    parse ();
	}
    }
    return ;
}

time_t IniParser::getTimeStamp()
{
    struct stat st;
    if (multiple_files)
    {
	printf ("bad call of getTimeStamp aborting. FIXME\n");//FIXME
	abort ();
    }
    if (stat(file.c_str(), &st))
    {
	ERR << "Unable to stat '" << file.c_str() << "': " << strerror(errno) << std::endl;
	return 0;
    }
    return st.st_mtime;
}
int IniParser::write()
{
    if ( !started)
    {
	ERR <<"Parser not initialized" << std::endl;
	return -1;
    }

    int bugs = 0;
    std::string filename = multiple_files ? files[0] : file;
    if (!inifile.isDirty())
    {
        DBG << "File " << filename << " did not change. Not saving." << std::endl;
	return 0;
    }
    if (read_only)
    {
        DBG << "Attempt to write file " << filename << " that was mounted read-only. Not saving." << std::endl;
	return 0;
    }
    UpdateIfModif ();

    if (multiple_files)
    {
	IniIterator
	    ci = inifile.getContainerBegin (),
	    ce = inifile.getContainerEnd ();

	for (;ci != ce; ++ci)
	    {
		if (ci->t () == SECTION)
		    {
			IniSection&s = ci->s ();
			int wb = s.getRewriteBy (); // bug #19066
			std::string filename = getFileName (s.getName (), wb);

			if (!s.isDirty ()) {
			    DBG << "Skipping file " << filename.c_str() << " that was not changed." << std::endl;
			    continue;
			}
			s.initReadBy ();
			// ensure that the directories exist
			assert_dir (filename);
			ofstream of(filename.c_str());
			if (!of.good())
			{
			    bugs++;
			    ERR <<"Can not open file " << filename.c_str() << "  for write" << std::endl;
			    continue;
			}
			write_helper (s, of, 0);
			s.clean();
			of.close ();
		    }
		else
		    {
			ERR <<"Value "<< ci->e ().getName () <<" encountered at multifile top level" << std::endl;
		    }
	    }
    }
    else
    {
	// ensure that the directories exist
	assert_dir (filename);
	ofstream of(file.c_str());
	if (!of.good())
	{
	    ERR <<"Can not open file " << file.c_str() << " for write" << std::endl;
	    return -1;
	}

	write_helper (inifile, of, 0);

	of.close();
	timestamp = getTimeStamp ();
    }
    inifile.clean ();
    return bugs ? -1 : 0;
}
int IniParser::write_helper(IniSection&ini, ofstream&of, int depth)
{
    char out_buffer[2048];
    std::string indent;
    std::string indent2;
    int readby = ini.getReadBy ();
    if (!subindent.empty ())
    {
	for (int ii = 0; ii<depth - 1;ii++)
	    indent = indent + subindent;
	if (depth)
	    indent2 = indent + subindent;
    }

    if (ini.getComment ()[0])
        of << ini.getComment();
    if (readby>=0 && readby < (int)sections.size ())
	{
	    snprintf (out_buffer, 2048, sections[readby].begin.out.c_str (), ini.getName());
	    of << indent << out_buffer << "\n";
	}

    IniIterator
	ci = ini.getContainerBegin (),
	ce = ini.getContainerEnd ();

    for (;ci != ce; ++ci)
	{
	    if (ci->t () == SECTION)
		{
		    write_helper (ci->s (), of, depth + 1);
		    ci->s ().clean();
		}
	    else
		{
		    IniEntry&e = ci->e ();
		    if (e.getComment ()[0])
			of << e.getComment();
		    if (e.getReadBy()>=0 && e.getReadBy() < (int)params.size ())
			snprintf (out_buffer, 2048, params[e.getReadBy ()].line.out.c_str (), e.getName(), e.getValue());
		    of << indent2 << out_buffer << "\n";
		    e.clean();
		}
	}

    if (ini.getEndComment ()[0])
        of << indent << ini.getEndComment();
    if (readby>=0 && readby < (int) sections.size () && sections[readby].end_valid)
	{
	    snprintf (out_buffer, 2048, sections[readby].end.out.c_str (), ini.getName());
	    of << indent << out_buffer << "\n";
	}
    ini.clean();
    return 0;
}
std::string IniParser::getFileName (const std::string&sec, int rb)
{
    std::string file = sec;
    if (-1 != rb && (int) rewrites.size () > rb)
    {
	int max = rewrites[rb].out.length () + sec.length () + 1;
	char*buf = new char[max + 1];
	snprintf (buf, max, rewrites[rb].out.c_str (), sec.c_str());
	DBG << "Rewriting " <<  sec.c_str() << " to " << buf << std::endl;
	file = buf;
	delete [] buf;
    }
    return file;
}

/**
 * change case of std::string
 * @param str std::string to change
 * @return changed std::string
 */
std::string IniParser::changeCase (const std::string&str) const
{
    std::string tmp = str;
    if (!ignore_case)
      return tmp;
    if (prefer_uppercase)
    {
	tmp = str::toUpper(tmp);
    }
    else
    {
	tmp = str::toLower(tmp);
	if (first_upper
	    && tmp.length() > 0)
	{
	    tmp[0] = toupper(tmp[0]);
	}
    }
    return tmp;
}

}      // End of INI namespace
}      // End of CA_MGM_NAMESPACE


