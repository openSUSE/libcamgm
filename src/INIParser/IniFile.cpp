/**
 * YaST2: Core system
 *
 * Description:
 *   YaST2 SCR: Ini file agent.
 *
 * Authors:
 *   Petr Blahos <pblahos@suse.cz>
 *
 * $Id: IniFile.cc 13144 2004-01-08 11:27:22Z mvidner $
 */

#include <stdio.h>
#include <ctype.h>
#include <cassert>
#include <list>

#include "INIParser/IniFile.h"
#include "INIParser/IniParser.h"

namespace CA_MGM_NAMESPACE
{
namespace INI
{

using std::map;
using std::multimap;
using std::pair;

std::string pathToString(const std::vector<std::string>&p)
{
    if (p.empty()) return std::string(".");
    std::string v;
    for (unsigned c=0; c<p.size(); c++)
    {
	v += ".";
	v += p[c];
    }
    return v;
}


void IniSection::initValue (const std::string&key,const std::string&val,const std::string&comment,int rb)
{
    std::string k = ip->changeCase (key);
    IniEntry e;
    IniEntryIdxIterator exi;
    if (!ip->repeatNames () && (exi = ivalues.find (k)) != ivalues.end ())
	{
	    IniIterator ei = exi->second;
	    // update existing value
	    // copy the old value
	    e = ei->e ();
	    // remove and unindex the old value
	    // This means that container needs to be a list, not Array,
	    // so that iterators kept in ivalues are still valid
	    container.erase (ei);
	    ivalues.erase (exi);
	}
    else
	{
	    // nothing
	}
    // create new value
    e.init (k, comment, rb, val);
    // insert it
    IniContainerElement ce (e);
    container.push_back (ce);
    // index it
    ivalues.insert (IniEntryIndex::value_type (k, --container.end ()));

}
void IniSection::initSection (const std::string&name,const std::string&comment,int rb, int wb)
{
    std::string k = ip->changeCase (name);

    IniSection s (ip);
    IniSectionIdxIterator sxi;
    if (!ip->repeatNames () && (sxi = isections.find (k)) != isections.end ())
	{
	    IniIterator si = sxi->second;
	    s = si->s ();
	    if (!s.dirty)
		{
		    s.comment = comment;
		    s.read_by = rb;
		    if (wb != -2) s.rewrite_by = wb;
		    s.name = k;
		}

	    // remove and unindex the old section
	    container.erase (si);
	    isections.erase (sxi);
	}
    else
	{			// new section
	    s.dirty = false;
	    s.comment = comment;
	    s.read_by = rb;
	    if (wb != -2) s.rewrite_by = wb;
	    s.name = k;
	    s.ip = ip;
	}
    // insert it
    IniContainerElement ce (s);
    container.push_back (ce);
    // index it
    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
}

IniSection& IniSection::findSection(const std::vector<std::string>&path, int from)
{
    std::string k = ip->changeCase (path[from]);
    IniSectionIdxIterator v = isections.find(k);
    if (v == isections.end ())
	{
	    ERR << "Internal error. Section " << k.c_str() << " not found. This can't happen." << std::endl;
	    abort();
	}
    IniSection &s = v->second->s ();
    return from+1 >= (int)path.size() ? s : s.findSection (path, from+1);
}

int IniSection::findEndFromUp (const std::vector<std::string>&path, int wanted, int found, int from)
{


    if (read_by == wanted)
    {
	found = from;
    }

    if (from < (int)path.size())
    {
	std::string k = ip->changeCase (path[from]);
	// find the _last_ section with key k
	pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	    isections.equal_range (k);
	if (r.first == r.second) // empty range = not found
	{
	    ERR << "Internal error. Value " << path[from].c_str() << " not found. This can't happen." << std::endl;
	    abort ();
	}
	IniSection&  s = (--r.second)->second->s ();
	found = s.findEndFromUp (path, wanted, found, from + 1);
    }
    return found;
}

void IniSection::Dump ()
{
    printf("%s<%s>\n", comment.c_str(), name.c_str());

    printf ("{Natural order}\n");
    IniIterator
	ci = getContainerBegin (),
	ce = getContainerEnd ();

    for (;ci != ce; ++ci)
    {
	printf ("{@%p}\n", &*ci);
	IniType t = ci->t ();
	if (t == VALUE)
	{
	    IniEntry &v = ci->e ();
	    printf ("%s%s = %s\n", v.getComment (), v.getName (), v.getValue ());
	}
	else if (t == SECTION)
	{
	    ci->s ().Dump ();
	}
	else
	{
	    printf ("{Unknown type %u}\n", t);
	}
    }

    printf ("{Sections}\n");
    IniSectionIdxIterator
	sxi = isections.begin (),
	sxe = isections.end ();

    for (; sxi != sxe; ++sxi)
    {
	printf ("{%s @%p}\n", sxi->first.c_str (), &*sxi->second);
    }

    printf ("{Values}\n");
    IniEntryIdxIterator
	exi = ivalues.begin (),
	exe = ivalues.end ();

    for (; exi != exe; ++exi)
    {
	printf ("{%s @%p}\n", exi->first.c_str (), &*exi->second);
    }

    printf("</%s>\n", name.c_str());
}

void IniSection::reindex ()
{
    IniIterator
	ci = getContainerBegin (),
	ce = getContainerEnd ();

    ivalues.clear ();
    isections.clear ();

    for (;ci != ce; ++ci)
    {

	if (ci->t () == VALUE)
	{
	    std::string k = ip->changeCase (ci->e ().getName ());
	    ivalues.insert (IniEntryIndex::value_type (k, ci));
	}
	else
	{
	    std::string k = ip->changeCase (ci->s ().getName ());
	    isections.insert (IniSectionIndex::value_type (k, ci));
	}
    }
}

int IniSection::getMyValue (const std::vector<std::string> &p, StringList &out, int what, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    // Find all values and return them according to repeat_names
    StringList results;
    bool found = false;
    pair <IniEntryIdxIterator, IniEntryIdxIterator> r =
	ivalues.equal_range (k);
    IniEntryIdxIterator xi = r.first, xe = r.second;
    for (; xi != xe; ++xi)
    {
	found = true;
	IniEntry& e = xi->second-> e ();
	out.clear();
	switch (what)
	{
	    case 0:  out.push_back (std::string (e.getValue ()));
		results.push_back (std::string (e.getValue ()));
		break;
	    case 1:  out.push_back (std::string (e.getComment()));
		results.push_back (std::string (e.getComment()));
		break;
 	    default: out.push_back (str::numstring (e.getReadBy ()));
		results.push_back (str::numstring (e.getReadBy ()));
		break;
	}
    }

    if (ip->repeatNames ())
    {
	out = results;
	return 0;
    }
    else if (found)
    {
	// nonempty range, the cycle ran once, out has the right value
	return 0;
    }
    // empty range, no such key

    DBG << "Read: Invalid path" << pathToString(p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

int IniSection::getValue (const std::vector<std::string>&p, StringList&out,int what, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    if ( depth + 1 < int(p.size()))
    {
	// it must be a section
	// Get any section of that name
	IniSectionIdxIterator sxi = isections.find (k);
	if (sxi != isections.end())
	{
	    return sxi->second->s ().getValue (p, out, what, depth+1);
	}
	// else error
    }
    else
	{   //We are in THE section. Find value here
	    return getMyValue (p, out, what, depth);
	}

    DBG << "Read: Invalid path" << pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

// Read calls us with the path length >= 2
int IniSection::getSectionProp (const std::vector<std::string>&p, StringList&out, int what, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    // Find the matching sections.
    // If we need to recurse, choose one
    // Otherwise gather properties of all of the leaf sections

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < int(p.size()))
    {
	// recurse
	if (xi != xe)
	{
	    // there's something
	    IniSection& s = (--xe)->second->s ();
	    return s.getSectionProp (p, out, what, depth+1);
	}
	//error
    }
    else
    {
	// bottom level, take all
	StringList results;
	bool found = false;
	for (; xi != xe; ++xi)
	{
	    found = true;
	    IniSection& s = xi->second->s ();
	    out.clear();
	    if (what == 0)
	    {
		out.push_back (s.comment);
		results.push_back (s.comment);
	    }
	    else if (what == 1)
	    {
		out.push_back (str::numstring (s.rewrite_by));
		results.push_back (str::numstring (s.rewrite_by));
	    }
	    else
	    {
		out.push_back (str::numstring (s.read_by));
		results.push_back (str::numstring (s.read_by));
	    }

	}

	if (ip->repeatNames ())
	{
	    out = results;
	    return 0;
	}
	else if (found)
	{
	    // nonempty range, the cycle ran once, out has the right value
	    return 0;
	}
	// empty range, no such key
    }

    DBG << "Read: Invalid path " << pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

int IniSection::getAll (const std::vector<std::string>&p, SectionAll&out, int depth)
{
    if (depth < int(p.size ()))
    {
	// recurse to find the starting section
	// Get any section of that name
	std::string k = ip->changeCase (p[depth]);
	IniSectionIdxIterator sxi = isections.find (k);
	if (sxi != isections.end())
	{
	    return sxi->second->s ().getAll (p, out, depth+1);
	}
	// else error
    }
    else
    {
	out = getAllDoIt ();
	return 0;
    }

    ERR << "Read: Invalid path " << pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

SectionAll IniSection::getAllDoIt ()
{
    SectionAll m = IniBase::getAllDoIt ();

    m.kind = "section";
    m.file = str::numstring(rewrite_by);
    m.value = "";

    IniIterator
	ci = getContainerBegin (),
	ce = getContainerEnd ();

    for (;ci != ce; ++ci)
    {
	// the method is virtual,
	// but the container does not exploit the polymorphism
	SectionAll vm;
	IniType t = ci->t ();
	if (t == VALUE)
	{
	    vm = ci->e ().getAllDoIt ();
	}
	else //if (t == SECTION)
	{
	    vm = ci->s ().getAllDoIt ();
	}
	m.sectionList.push_back (vm);
    }

    return m;
}

int IniSection::Delete (const std::vector<std::string>&p)
{
    if (ip->isFlat ())
	return delValueFlat (p);
    if (p.size() < 2)
    {
	ERR << "I do not know what to delete at " <<  pathToString(p).c_str() << std::endl;
	return -1;
    }
    std::string s (p[0]);
    if (s == "v" || s == "value")
	return delValue (p, 1);
    if (s == "s" || s == "section")
      return delSection (p, 1);
    return -1;
}

int IniSection::Write (const std::vector<std::string>&p, const StringList&v, bool rewrite)
{
    if (ip->isFlat ())
	return setValueFlat (p, v);

    if (p.size() < 2)
    {
	ERR << "I do not know what to write to " <<  pathToString(p).c_str() << std::endl;
	return -1;
    }
    std::string s (p[0]);
    if (s == "v" || s == "value")
	return setValue (p, v, 0, 1);
    if (s == "vc" || s == "value_comment" || s == "valuecomment")
      return setValue (p, v, 1, 1);
    if (s == "vt" || s == "value_type" || s == "valuetype")
      return setValue (p, v, 2, 1);
    if (s == "s" || s == "section" || s == "sc" || s == "section_comment" || s == "sectioncomment")
      return setSectionProp (p, v, 0, 1);
    if (s == "st" || s == "section_type" || s == "sectiontype")
      return setSectionProp (p, v, rewrite? 1:2, 1);
    return -1;
}

int IniSection::setSectionProp (const std::vector<std::string>&p,const StringList&in, int what, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set properties of all of the leaf sections,
    //  creating and deleting if the number of them does not match

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < int(p.size()))
    {
	// recurse
	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    DBG <<  "Write: adding recursively "<< k.c_str () << " to " << pathToString(p).c_str() << std::endl;

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setSectionProp (p, in, what, depth+1);
    }
    else
    {
	// bottom level

	StringList props = in;
	StringList::iterator pi = props.begin();
	StringList::iterator pe = props.end();

	// Go simultaneously through the found sections
	// and the list of parameters, while _either_ lasts
	// Fewer sections-> add them, more sections-> delete them

	while (pi != pe || xi != xe)
	{
	    // watch out for validity of iterators!

	    if (pi == pe)
	    {
		// deleting a section
		delSection1 (xi++);
		// no ++pi
	    }
	    else
	    {
		std::string prop = std::string(*pi);
		IniIterator si;
		if (xi == xe)
		{
		    ///need to add a section ...
		    DBG << "Adding section " << pathToString(p).c_str() << std::endl;
		    // prepare it to have its property set
		    // create it
		    IniSection s (ip, k);
		    s.dirty = true;
		    // insert and index
		    container.push_back (IniContainerElement (s));
		    isections.insert (IniSectionIndex::value_type (k, --container.end ()));
		    si = --container.end ();
		}
		else
		{
		    si = xi->second;
		}

		// set a section's property
		IniSection & s = si->s ();
		if (what == 0)
		    s.setComment (prop);
		else if (what == 1)
		    s.setRewriteBy (str::strtonum<int>(prop));
		else
 		    s.setReadBy (str::strtonum<int>(prop));

		if (xi != xe)
		{
		    ++xi;
		}
		++pi;
	    }
	    // iterators have been advanced already
	}
	return 0;
    }
}

void IniSection::delSection1 (IniSectionIdxIterator sxi)
{
    dirty = true;
    IniIterator si = sxi->second;
    container.erase (si);
    isections.erase (sxi);
}

int IniSection::delSection(const std::vector<std::string>&p, int depth)
{
    std::string k = ip->changeCase (p[depth]);

    // Find the matching sections.
    // If we need to recurse, choose one
    // Otherwise kill them all

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (depth + 1 < int(p.size()))
    {
	// recurse
	if (xi != xe)
	{
	    // there's something
	    IniSection& s = (--xe)->second->s ();
	    return s.delSection (p, depth+1);
	}
	//error
	ERR << "Delete: Invalid path" << pathToString(p).c_str() << "[" << depth << "]" << std::endl;
	return -1;
    }
    else
    {
	// bottom level, massacre begins
	if (xi == xe)
	{
	    DBG <<  "Can not delete " << pathToString(p).c_str() <<". Key does not exist." << std::endl;
	}
	while (xi != xe)
	{
	    delSection1 (xi++);
	}
    }
    return 0;
}

int IniSection::WriteAll (const std::vector<std::string>&p, const SectionAll& in, int depth)
{
    INF << "This function has not been tested cause it is not needed at the moment." << std::endl;
    if (depth < int(p.size ()))
    {
	// recurse to find the starting section
	// Get any section of that name
	std::string k = ip->changeCase (p[depth]);
	IniSectionIdxIterator sxi = isections.find (k);
	if (sxi != isections.end())
	{
	    return sxi->second->s ().WriteAll (p, in, depth+1);
	}
	// else error
    }
    else
    {
	return setAllDoIt (in);
    }

    DBG << "Read: Invalid path" << pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

int IniSection::setAllDoIt (const SectionAll &in)
{
    int ret = IniBase::setAllDoIt (in);
    if (ret != 0)
    {
	return ret;
    }

    std::string kind = in.kind;
    if (kind != "section")
    {
	ERR << "Kind should be 'section'" << std::endl;
	return -1;
    }

    rewrite_by = str::strtonum<int>(in.file);

    SectionList l = in.sectionList;

    container.clear ();		// bye, old data
    for (SectionList::iterator i = l.begin(); i != l.end(); ++i)
    {

	SectionAll mitem = *i;

	kind = mitem.kind;

	if (kind == "section")
	{
	    IniSection s (ip);
	    ret = s.setAllDoIt (mitem);
	    if (ret != 0)
	    {
		break;
	    }
	    container.push_back (IniContainerElement (s));
	}
	else if (kind == "value")
	{
	    IniEntry e;
	    e.setAllDoIt (mitem);
	    if (ret != 0)
	    {
		break;
	    }
	    container.push_back (IniContainerElement (e));
	}
	else
	{
	    ERR << "Item in Write (.all) of unrecognized kind " << kind.c_str () << std::endl;
	    ret = -1;
	    break;
	}
    }

    reindex ();
    return ret;
}

int IniSection::setMyValue (const std::vector<std::string> &p, const StringList&in, int what, int depth)
{
    // assert (depth == p.size ()); //not, it can have a .comment suffix
    std::string k = ip->changeCase (p[depth]);
    pair <IniEntryIdxIterator, IniEntryIdxIterator> r =
	ivalues.equal_range (k);
    IniEntryIdxIterator xi = r.first, xe = r.second;

    StringList props = in;
    StringList::iterator pi = props.begin();
    StringList::iterator pe = props.end();

    // Go simultaneously through the found values
    // and the list of parameters, while _either_ lasts
    // Fewer values-> add them, more values-> delete them
    while (pi != pe || xi != xe)
    {
	// watch out for validity of iterators!

	if (pi == pe)
	{
	    // deleting a value
	    delValue1 (xi++);
	    // no ++pi
	}
	else
	{
	    std::string prop = std::string(*pi);
	    IniIterator ei;
	    if (xi == xe)
	    {
		///need to add a value ...
		DBG << "Adding value " <<
				       pathToString (p).c_str() << "=" <<
				       prop.c_str () << std::endl;
		if (what)
		{
		    ERR << "You must add value before changing comment/type. " <<
			     pathToString (p).c_str () << std::endl;
		    return -1;
		}
		// prepare it to have its property set
		// create it
		IniEntry e;
		// need to set its name
		e.setName (k);

		// insert and index
		container.push_back (IniContainerElement (e));
		ivalues.insert (IniEntryIndex::value_type (k, --container.end ()));
		ei = --container.end ();
	    }
	    else
	    {
		ei = xi->second;
	    }

	    // set a value's property
	    IniEntry & e = ei->e ();
	    switch (what)
	    {
		case 0:	e.setValue   (prop); break;
		case 1:	e.setComment (prop); break;
		default:	e.setReadBy  (str::strtonum<int>(prop));break;
	    }

	    if (xi != xe)
	    {
		++xi;
	    }
	    ++pi;
	}
	// iterators have been advanced already
    }
    dirty = true;
    return 0;
}

int IniSection::setValue (const std::vector<std::string>&p,const StringList&in,int what, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    // Find the matching sections.
    // If we need to recurse, choose one, creating if necessary
    // Otherwise set all the matching values
    //  creating and deleting if the number of them does not match

    if (depth + 1 < int(p.size()))
    {
	// recurse
	pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	    isections.equal_range (k);
	IniSectionIdxIterator xi = r.first, xe = r.second;

	IniIterator si;
	if (xi == xe)
	{
	    // not found, need to add it;
	    DBG << "Write: adding recursively " << k.c_str () << " to " <<  pathToString(p).c_str() << std::endl;

	    IniSection s (ip, k);
	    container.push_back (IniContainerElement (s));
	    isections.insert (IniSectionIndex::value_type (k, --container.end ()));

	    si = --container.end ();
	}
	else
	{
	    // there's something, choose last
	    si = (--xe)->second;
	}
	return si->s ().setValue (p, in, what, depth+1);
    }
    else
    {
	// bottom level
	return setMyValue (p, in, what, depth);
    }
}

void IniSection::delValue1 (IniEntryIdxIterator exi)
{
    dirty = true;
    IniIterator ei = exi->second;
    container.erase (ei);
    ivalues.erase (exi);
}

void IniSection::delMyValue (const std::string &k)
{
    pair <IniEntryIdxIterator, IniEntryIdxIterator> r =
	ivalues.equal_range (k);
    IniEntryIdxIterator xi = r.first, xe = r.second;

    if (xi == xe)
    {
	DBG << "Can not delete " << k.c_str() << " Key does not exist." << std::endl;
    }
    while (xi != xe)
    {
	delValue1 (xi++);
    }
}

int IniSection::delValue (const std::vector<std::string>&p, int depth)
{
    std::string k = ip->changeCase (p[depth]);
    // Find the matching sections.
    // If we need to recurse, choose one
    // Otherwise kill all values of the name

    if (depth + 1 < int(p.size()))
    {
	// recurse
	pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	    isections.equal_range (k);
	IniSectionIdxIterator xi = r.first, xe = r.second;

	if (xi != xe)
	{
	    // there's something
	    IniSection& s = (--xe)->second->s ();
	    return s.delValue (p, depth+1);
	}
	//error
	ERR << "Delete: Invalid path "<< pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
	return -1;
    }
    else
    {
	// bottom level, massacre begins
	delMyValue (k);
    }
    return 0;
}

int IniSection::myDir (StringList& l, IniType what)
{
    IniIterator i = container.begin (), e = container.end ();
    for (; i != e; ++i)
    {
	if (i->t () == what)
	{
	    std::string n = (what == SECTION) ?
		i->s ().getName () :
		i->e ().getName ();
	    l.push_back (n);
	}
    }
    return 0;
}

int IniSection::dirValueFlat (const std::vector<std::string>&p, StringList&l)
{
    // This function used to discard p and always return Dir (.)
    // #21574
    if (p.size () != 0)
    {
	// Leave l empty.
	// Maybe we should differentiate between Dir (.existing_value)
	// and Dir (.bogus) ?
	return 0;
    }

    return myDir (l, VALUE);
}

int IniSection::getValueFlat (const std::vector<std::string>&p, StringList&out)
{
    if (!p.size ())
	return -1;
    std::string k = ip->changeCase (p[0]);
    bool want_comment = p.size()>1 && p[1]=="comment";

    return getMyValue (p, out, want_comment, 0);
}

int IniSection::delValueFlat (const std::vector<std::string>&p)
{
    if (!p.size ())
	return -1;
    std::string k = ip->changeCase (p[0]);

    delMyValue (k);
    return 0;
}

int IniSection::setValueFlat (const std::vector<std::string>&p, const StringList &in)
{
    if (!p.size ())
	return -1;
    std::string k = ip->changeCase (p[0]);
    bool want_comment = p.size()>1 && p[1]=="comment";

    return setMyValue (p, in, want_comment, 0);
}

int IniSection::Read (const std::vector<std::string>&p, StringList&out, bool rewrite)
{
    if (ip->isFlat ())
	return getValueFlat (p, out);

    if (p.size()<2)
	{
	    ERR << "I do not know what to read from " <<  pathToString(p).c_str() << std::endl;
	    return -1;
	}
    std::string s (p[0]);
    if (s == "v" || s == "value")
	return getValue (p, out, 0, 1);
    else if (s == "vc" || s == "value_comment" || s == "valuecomment")
	return getValue (p, out, 1, 1);
    else if (s == "vt" || s == "value_type" || s == "valuetype")
	return getValue (p, out, 2, 1);
    else if (s == "sc" || s == "section_comment" || s == "sectioncomment")
	return getSectionProp (p, out, 0, 1);
    else if (s == "st" || s == "section_type" || s == "sectiontype")
	return getSectionProp (p, out, rewrite? 1:2, 1);

    ERR << "I do not know what to read from " <<  pathToString(p).c_str() << std::endl;
    return -1;
}

int IniSection::ReadAll (const std::vector<std::string>&p, SectionAll&out)
{
    INF << "This function has not been tested cause it is not needed at the moment." << std::endl;
    if (p.size() >= 1 && p[0] == "all")
    {
	return getAll (p, out, 1);
    }
    else
    {
	return -1;
    }
}

int IniSection::Dir (const std::vector<std::string>&p, StringList&l)
{
    if (ip->isFlat ())
	return dirValueFlat (p, l);
    if (p.empty())
	{
	    ERR << "I do not know what to dir from "<< pathToString(p).c_str() << std::endl;
	    return -1;
	}

    std::string s (p[0]);
    if (s == "v" || s == "value")
	return dirHelper (p, l, 0, 1);
    else if (s == "s" || s == "section")
	return dirHelper (p, l, 1, 1);

    ERR << "I do not know what to dir from "<< pathToString(p).c_str() << std::endl;
    return -1;
}
int IniSection::dirHelper (const std::vector<std::string>&p, StringList&out,int get_sect,int depth)
{
    if (depth >= int(p.size()))
    {
	return myDir (out, get_sect? SECTION: VALUE);
    }

    // recurse
    std::string k = ip->changeCase (p[depth]);

    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (k);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (xi != xe)
    {
	// there's something
	IniSection& s = (--xe)->second->s ();
	return s.dirHelper (p, out, get_sect, depth+1);
    }
    //error
    DBG << "Dir: Invalid path "<< pathToString (p).c_str() << "[" << depth <<"]" << std::endl;
    return -1;
}

/*
IniEntry&IniSection::getEntry (const char*n)
{
    IniEntryMapIterator i = values.find(n);
    if (i == values.end())
	{
	ERR << "Internal error. Value " << n << " not found in section " << name.c_str();
	    abort() << std::endl;
	}
    return (*i).second;
}
*/

int IniSection::getSubSectionRewriteBy (const char*name)
{
    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (name);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (xi == xe)
    {
	return -1;
    }
    return (--xe)->second->s ().getRewriteBy ();
}

IniSection&IniSection::getSection (const char*n)
{
    pair <IniSectionIdxIterator, IniSectionIdxIterator> r =
	isections.equal_range (n);
    IniSectionIdxIterator xi = r.first, xe = r.second;

    if (xi == xe)
    {
	ERR << "Internal error. Section " << n << " not found in section " << name.c_str() << std::endl;
	abort();
    }
    return (--xe)->second->s ();
}

void IniSection::setEndComment (const char*c)
{
    if (comment.empty () && container.empty ())
	comment = c;
    else
	end_comment = c;
}
bool IniSection::isDirty ()
{
    if (dirty)
	return true;
    // every write dirtyfies not only value but section too
    // so it is enough for us to find the first dirty section
    IniSectionIdxIterator xi = isections.begin (), xe = isections. end ();
    for (; xi != xe; ++xi)
    {
	if (xi->second->s ().isDirty ())
	  return true;
    }
    return false;
}
void IniSection::clean()
{
    dirty = false;
    IniIterator i = container.begin (), e = container.end ();
    for (; i != e; ++i)
    {
	if (i->t () == SECTION)
	{
	    i->s ().clean ();
	}
	else
	{
	    i->e ().clean ();
	}
    }
}

IniIterator IniSection::getContainerBegin ()
{
    return container.begin ();
}

IniIterator IniSection::getContainerEnd ()
{
    return container.end ();
}

}      // End of INI namespace
}      // End of CA_MGM_NAMESPACE

